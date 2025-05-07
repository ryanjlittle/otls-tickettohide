"""Key derivation and key schedule logic for TLS 1.3.i

Includes code for pre-shared keys (i.e. tickets)."""

import time
import json

from util import b64enc, b64dec
from spec import kwdict
from tls_common import *
from tls13_spec import (
    Handshake,
    ExtensionType,
    HandshakeType,
    PskBinders,
    CipherSuite,
    PskKeyExchangeMode,
)
from tls_crypto import (
    get_hash_alg,
    StreamCipher,
    hkdf_extract,
    hkdf_expand_label,
    derive_secret,
)


class TicketInfo:
    def __init__(self, ticket_id, secret, csuite, modes, mask, lifetime, creation=None):
        self._id = ticket_id
        self._secret = secret
        self._csuite = csuite
        self._modes = tuple(modes)
        self._mask = mask
        self._lifetime = lifetime
        self._creation = time.time() if creation is None else creation

    def to_dict(self):
        return {
            'ticket_id': b64enc(self._id),
            'secret': b64enc(self._secret),
            'csuite': int(self._csuite),
            'modes': [int(mode) for mode in self._modes],
            'mask': self._mask,
            'lifetime': self._lifetime,
            'creation': self._creation,
        }

    def dump(self, *args, **kwargs):
        return json.dump(self.to_dict(), *args, **kwargs)

    def dumps(self, *args, **kwargs):
        return json.dumps(self.to_dict(), *args, **kwargs)

    @classmethod
    def from_dict(cls, d):
        return cls(
            ticket_id = b64dec(d['ticket_id']),
            secret = b64dec(d['secret']),
            csuite = CipherSuite(d['csuite']),
            modes = tuple(PskKeyExchangeMode(code) for code in d['modes']),
            mask = d['mask'],
            lifetime = d['lifetime'],
            creation = d['creation'],
        )

    @classmethod
    def load(cls, *args, **kwargs):
        return cls.from_dict(json.load(*args, **kwargs))

    @classmethod
    def loads(cls, *args, **kwargs):
        return cls.from_dict(json.loads(*args, **kwargs))

    @property
    def secret(self):
        return self._secret

    @property
    def csuite(self):
        return self._csuite

    @property
    def modes(self):
        return set(self._modes)

    def add_psk_ext(self, chello, send_time):
        # chello should be prepacked and without the PSK extension
        if send_time is None:
            send_time = time.time()
        oage = (round((send_time - self._creation) * 1000) + self._mask) % 2**32
        dummy_binder = b'\xdd' * get_hash_alg(self.csuite).digest_size

        # construct extension with dummy binder
        binder_list = [dummy_binder]
        psk_ext = kwdict(
            typ  = ExtensionType.PRE_SHARED_KEY,
            data = kwdict(
                identities = [kwdict(
                    identity              = self._id,
                    obfuscated_ticket_age = oage,
                )],
                binders    = binder_list,
            ),
        )

        # add dummy extension to chello
        extensions = list(chello.body.extensions)
        assert all(ext.typ != ExtensionType.PRE_SHARED_KEY for ext in extensions)
        extensions.append(psk_ext)
        body = chello.body._asdict() | {'extensions': extensions}
        new_chello = chello._asdict() | {'body': body}

        # insert actual binder and return the (new) client hello object
        actual_binder = self.get_binder_key(Handshake.prepack(new_chello), 0)
        binder_list[0] = actual_binder
        logger.info(f'inserting psk with id {self._id[:12]}... and  binder {actual_binder} into client hello')
        return Handshake.prepack(new_chello)

    def get_binder_key(self, chello, index, prefix=b''):
        # chello should be unpacked
        # binder keys in chello should be filled in but will be ignored
        # prefix is (optionally) a transcript prefix, e.g. from a hello retry
        hst = HandshakeTranscript()
        kc = KeyCalc(hst)
        kc.cipher_suite = self._csuite
        hst.add(HandshakeType.SERVER_HELLO, False, prefix)

        # find index of this ticket
        exts = chello.body.extensions
        if not exts or exts[-1].typ != ExtensionType.PRE_SHARED_KEY:
            raise TlsError("expected PRE_SHARED_KEY extension to come last")
        pske = exts[-1].data
        if len(pske.identities) <= index or pske.identities[index].identity != self._id:
            raise TlsError("did not find this ticket in the identities list")

        raw_hello = Handshake.pack(chello)
        pbinds = PskBinders.pack(pske.binders)
        assert raw_hello.endswith(pbinds)
        hst.add(HandshakeType.CLIENT_HELLO, True, raw_hello[:-len(pbinds)])

        kc.psk = self._secret
        binder = kc.get_verify_data(kc.binder_key, hst[-1])

        if len(pske.binders) != len(pske.identities) or len(binder) != len(pske.binders[index]):
            raise TlsError("binder key in clienthello has the wrong length")

        return binder

    def find(self, chello, prefix=b'', age_tolerance=5):
        """Looks for this ticket in the given (unpacked) client hello.
        Returns the matching index within the client hello PSK list, or None.
        """
        psk_ext = chello.body.extensions[-1]
        assert psk_ext.typ == ExtensionType.PRE_SHARED_KEY
        for (index, (ident, oage)) in enumerate(psk_ext.data.identities):
            if ident == self._id:
                logger.info(f'found matching ticket id {self._id.hex()[:16]}... at index {index}')
                if self.get_binder_key(chello, index, prefix) != psk_ext.data.binders[index]:
                    raise TlsError(f'ticket binder {psk_ext.data.binders[index]} does not match expected {self.get_binder_key(chello, index, prefix)}')
                age = (oage - self._mask) / 1000
                if abs(age - (time.time() - self._creation)) > age_tolerance:
                    raise TlsError(f'ticket age {age} is too far off from expected {time.time() - self._creation}')
                if age > self._lifetime:
                    raise TlsError(f'ticket age {age} exceeds lifetime {self._lifetime}')
                logger.info(f'ticket from {age} seconds ago has valid binder and age')
                return index


class HandshakeTranscript:
    def __init__(self):
        self._hash_alg = None
        self._backlog = []

    @property
    def hash_alg(self):
        return self._hash_alg

    @hash_alg.setter
    def hash_alg(self, ha):
        if self._hash_alg is not None:
            raise ValueError("hash_alg already set")
        self._hash_alg = ha
        self._running = self._hash_alg.hasher()
        self._history = [self._running.digest()]
        self._lookup = {}
        for item in self._backlog:
            self.add(*item)
        del self._backlog

    def add(self, typ, from_client, data):
        if self._hash_alg is None:
            self._backlog.append((typ, from_client, data))
        else:
            self._running.update(data)
            current = self._running.digest()
            self._lookup[typ, from_client] = current
            self._history.append(current)

    def __getitem__(self, key):
        match key:
            case (HandshakeType(), bool()):
                return self._lookup[key]
            case HandshakeType():
                return self._lookup[key, False]
            case int():
                return self._history[key]
            case _:
                raise KeyError("invalid key type; should be (typ,bool), typ, or int")


class KeyCalc:
    # rfc8446#section-7.1

    _DERIVATIONS = {
        'binder_key':
            ('early_secret', b'res binder', 0),
        'client_early_traffic_secret':
            ('early_secret', b'c e traffic', HandshakeType.CLIENT_HELLO),
        'derived0':
            ('early_secret', b'derived', 0),
        'client_handshake_traffic_secret':
            ('handshake_secret', b'c hs traffic', HandshakeType.SERVER_HELLO),
        'server_handshake_traffic_secret':
            ('handshake_secret', b's hs traffic', HandshakeType.SERVER_HELLO),
        'derived1':
            ('handshake_secret', b'derived', 0),
        'client_application_traffic_secret':
            ('master_secret', b'c ap traffic', (HandshakeType.FINISHED, False)),
        'server_application_traffic_secret':
            ('master_secret', b's ap traffic', (HandshakeType.FINISHED, False)),
        'resumption_master_secret':
            ('master_secret', b'res master', (HandshakeType.FINISHED, True)),
    }

    def __init__(self, hs_trans):
        super().__setattr__('_mem', {})
        self._hs_trans = hs_trans

    def ticket_info(self, ticket, *args, **kwargs):
        # rfc8446#section-4.6.1
        ticket_secret = hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = self.resumption_master_secret,
            label    = b'resumption',
            cont     = ticket.ticket_nonce,
            length   = self.hash_alg.digest_size,
        )
        return TicketInfo(
            ticket_id = ticket.ticket,
            secret    = ticket_secret,
            csuite    = self.cipher_suite,
            mask      = ticket.ticket_age_add,
            lifetime  = ticket.ticket_lifetime,
            *args, **kwargs)

    def get_verify_data(self, base_key, transcript_hash):
        # rfc8446#section-4.4
        finished_key = hkdf_expand_label(
            hash_alg = self.hash_alg,
            secret   = base_key,
            label    = b'finished',
            cont     = b'',
            length   = self.hash_alg.digest_size,
        )
        return self.hash_alg.hmac_hash(key=finished_key, msg=transcript_hash)

    def __getattr__(self, name):
        try:
            return self._mem[name]
        except KeyError:
            pass
        match name:
            case 'zero':
                value = b'\x00' * self.hash_alg.digest_size
            case 'early_secret':
                value = hkdf_extract(self.hash_alg, salt=self.zero, ikm=self.psk)
            case 'handshake_secret':
                value = hkdf_extract(
                    hash_alg = self.hash_alg,
                    salt = self.derived0,
                    ikm = self.kex_secret,
                )
            case 'master_secret':
                value = hkdf_extract(
                    hash_alg = self.hash_alg,
                    salt = self.derived1,
                    ikm = self.zero,
                )
            case 'server_cv_message':
                # rfc8446#section-4.4.3
                return b''.join([
                    b'\x20'*64,
                    b'TLS 1.3, server CertificateVerify',
                    b'\x00',
                    self._hs_trans[HandshakeType.CERTIFICATE, False],
                ])
            case 'server_finished_verify':
                base_key = self.server_handshake_traffic_secret
                if self.psk is self.zero:
                    thash = self._hs_trans[
                        HandshakeType.CERTIFICATE_VERIFY, False]
                else:
                    thash = self._hs_trans[
                        HandshakeType.ENCRYPTED_EXTENSIONS, False]
                return self.get_verify_data(base_key, thash)
            case 'client_finished_verify':
                base_key = self.client_handshake_traffic_secret
                thash = self._hs_trans[HandshakeType.FINISHED, False]
                return self.get_verify_data(base_key, thash)
            case _:
                try:
                    secret, text, lookup = self._DERIVATIONS[name]
                except KeyError:
                    raise KeyError(f'cannot compute this key until {name} is known') from None
                value = derive_secret(
                    hash_alg   = self.hash_alg,
                    secret     = getattr(self, secret),
                    label      = text,
                    msg_digest = self._hs_trans[lookup],
                )
        logger.info(f'calculated {name} = {value[:10].hex()}...{value[-10:].hex()}')
        self._mem[name] = value
        return value

    def __setattr__(self, name, value):
        if name in self._mem:
            raise ValueError(f'value for {name} already set')
        elif name == 'cipher_suite':
            self._hs_trans.hash_alg = self.hash_alg = get_hash_alg(value)
        elif value is None:
            value = self.zero
        self._mem[name] = value

