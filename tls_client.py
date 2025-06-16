"""High-level logic for TLS 1.3 client-side handshake."""

import time
from collections import namedtuple
from collections.abc import Iterable
from typing import Self, Any, override
from dataclasses import dataclass, field
from secrets import SystemRandom
from random import Random
import enum

from util import same_args
from spec import UnpackError
from tls_common import *
from tls13_spec import (
    ClientStates,
    ClientSecrets,

    Record,
    ContentType,
    Version,

    Handshake,
    HandshakeTypes,
    HandshakeVariant,
    ClientHelloHandshake,
    ServerHelloHandshake,
    EncryptedExtensionsHandshake,
    CertificateHandshake,
    CertificateVerifyHandshake,
    FinishedHandshake,
    NewSessionTicketHandshake,

    ExtensionTypes,
    ClientExtension,
    ClientExtensionVariant,
    ServerNameClientExtension,
    GenericClientExtension,
    SupportedGroupsClientExtension,
    SignatureAlgorithmsClientExtension,
    SupportedVersionsClientExtension,
    PskKeyExchangeModesClientExtension,
    KeyShareClientExtension,
    EncryptedClientHelloClientExtension,
    PreSharedKeyClientExtension,

    KeyShareServerExtension,
    SupportedVersionsServerExtension,
    PreSharedKeyServerExtension,
    ServerNameServerExtension,
    SupportedGroupsServerExtension,
    EncryptedClientHelloServerExtension,

    ECHClientHelloType,
    OuterECHClientHello,
    InnerECHClientHello,

    CipherSuite,
    NamedGroup,
    SignatureScheme,
    PskKeyExchangeMode,
    HpkeKdfId,
    HpkeAeadId,

    ECHConfigVariant,
)
from tls_crypto import (
    get_kex_alg,
    get_sig_alg,
    get_hash_alg,
    get_cipher_alg,
    extract_x509_pubkey,
    KexAlg,
    DEFAULT_KEX_GROUPS,
    DEFAULT_KEX_MODES,
    DEFAULT_SIGNATURE_SCHEMES,
    DEFAULT_CIPHER_SUITES,
    DEFAULT_HPKE_CSUITES,
)
from tls_records import (
    RecordTranscript,
    DataBuffer,
    RecordReader,
    RecordWriter,
    HandshakeBuffer,
    Connection,
    HOST_NAME_TYPE,
    DEFAULT_LEGACY_VERSION,
    DEFAULT_LEGACY_COMPRESSION,
    AbstractHandshake,
    PayloadProcessor,
    CCS_MESSAGE,
)
from tls_keycalc import KeyCalc, HandshakeTranscript, TicketInfo
from tls_ech import EchType, OuterPrep, server_accepts_ech

class PskOption(enum.Enum):
    NONE   = enum.auto()
    GREASE = enum.auto()
    TICKET = enum.auto()

@dataclass
class _ChelloExtensions:
    ORDER: ClassVar[tuple[ExtensionTypes,...]] = (
        ExtensionTypes.SERVER_NAME,
        ExtensionTypes.ENCRYPTED_CLIENT_HELLO,
        ExtensionTypes.LEGACY_EC_POINT_FORMATS,
        ExtensionTypes.SUPPORTED_GROUPS,
        ExtensionTypes.LEGACY_SESSION_TICKET,
        ExtensionTypes.LEGACY_ENCRYPT_THEN_MAC,
        ExtensionTypes.LEGACY_EXTENDED_MASTER_SECRET,
        ExtensionTypes.SIGNATURE_ALGORITHMS,
        ExtensionTypes.SUPPORTED_VERSIONS,
        ExtensionTypes.PSK_KEY_EXCHANGE_MODES,
        ExtensionTypes.KEY_SHARE,
        ExtensionTypes.PRE_SHARED_KEY,
    )

    exts: dict[ExtensionType, ClientExtensionVariant] = field(default_factory=dict)

    def add(self, ext: ClientExtensionVariant) -> None:
        assert ext.typ not in self.exts
        assert ext.typ in self.ORDER
        self.exts[ext.typ] = ext

    def get(self) -> list[ClientExtensionVariant]:
        ext_list: list[ClientExtensionVariant] = []
        for etype in self.ORDER:
            try:
                ext = self.exts[etype]
            except KeyError:
                continue
            ext_list.append(ext)
        return ext_list


def _build_ch_inner(
    hostname: str|None,
    options: ClientOptions,
    session_id: bytes,
    outer_extensions: _ChelloExtensions,
    rgen: Random,
) -> ClientHelloHandshake:
    extensions = _ChelloExtensions(outer_extensions.exts)
    extensions.add(EncryptedClientHelloClientExtension.create(
        variant = InnerECHClientHello.create(),
    ))

    pass #TODO FIXME

def build_client_hello(
    hostname: str|None = None,
    options: ClientOptions = DEFAULT_CLIENT_OPTIONS,
    rseed: int|None = None,


    #TODO cleanup
    #sni: str|None = None, # server name indication
    #ciphers: Iterable[CipherSuite]|None = None, # default, replace with DEFAULT_CIPHER_SUITES or ticket.csuite
    #kex_groups: Iterable[NamedGroup] = DEFAULT_KEX_GROUPS,
    #kex_share_groups: Iterable[NamedGroup]|None = None, # defaults to the first one in kex_groups
    #sig_algs: Iterable[SignatureScheme] = DEFAULT_SIGNATURE_SCHEMES,
    #psk_option: PskOption = PskOption.NONE,
    #ticket: TicketInfo|None = None, # must match psk_option
    #psk_modes: Iterable[PskKeyExchangeMode] = DEFAULT_KEX_MODES,
    #send_time: float|None = None, # default to current time
    #rseed: int|None = None, # optional seed for repeatability; NOT secure
    #ech_type: EchType = EchType.OUTER,
    #ech_config: ECHConfigVariant|None = None # OUTER ECH with no config means GREASE
) -> tuple[ClientHelloHandshake, ClientSecrets]:
    """Returns (unpacked) ClientHello handshake struct and ClientSecrets tuple."""

    rgen = SystemRandom() if rseed is None else Random(rseed)

    # will hold all extensions to be added to this CH
    extensions = _ChelloExtensions()

    # generate key exchange secrets and shares
    kex_sks: list[bytes] = []
    shares: list[tuple[NamedGroup, bytes]] = []
    for group in options.data.kex_shares:
        kex = get_kex_alg(group)
        secret = kex.gen_private(rgen)
        share = kex.get_public(secret)
        kex_sks.append(secret)
        shares.append((group, share))

    if not shares and ticket is None and ech_prep is None:
        raise ValueError("need either DHE or PSK (or both), but got neither")

    if shares:
        # send the DHKE public keys
        extensions.add(KeyShareClientExtension.create(shares))

    # which groups supported for key exchange
    extensions.add(SupportedGroupsClientExtension.create(kex_groups))

    # which signature algorithms allowed for CertificateVerify message
    extensions.add(SignatureAlgorithmsClientExtension.create(sig_algs))

    # indicate only TLS 1.3 is supported
    extensions.add(SupportedVersionsClientExtension.create([Version.TLS_1_3]))

    # indicate whether DHE must still be done on resumption with a ticket
    extensions.add(PskKeyExchangeModesClientExtension.create(psk_modes))

    # generate session id (shared between inner/outer ECH)
    sesid = rgen.randbytes(32)

    # generate pre shared key extension and secret, if applicable
    match len(options.data.tickets):
        case 0:
            ticket = None
            psk_secret = None
        case 1:
            ticket = options.data.tickets[0]
            psk_secret = ticket.secret
            if not options.data.send_psk:
                logger.warning("Ticket given but will not be sent in client hello")
        case _:
            raise TlsTODO("multiple tickets in CH not yet supported")
    psk_factory = PskExtFactory(
        send_psk = options.data.send_psk,
        ticket = ticket,
        send_time = options.send_time.data,
        rgen = rgen,
    )

    ech_prep: OuterPrep|None = None

    # create inner CH if using ECH
    if options.data.send_ech:
        if len(options.data.ech_configs):
            if len(options.data.ech_configs) != 1:
                raise TlsTODO("multiple ECH configs in CH not yet supported")

            match options.data.ech_configs[0].variant:
                case Draft24ECHConfig() as econfig:
                    pass
                case _:
                    raise TlsError(f"Unrecognized ECH config type {options.data.ech_configs[0].selector}")

            inner_ch = _build_ch_inner(
                hostname = hostname,
                session_id = sesid,
                psk_factory = psk_factory,
                outer_exts = exts,
                rgen = rgen,
            )

            ech_prep = OuterPrep(econfig, inner_ch)
            hostname = ech_prep.outer_sni
            psk_factory = dataclasses.replace(psk_factory, force_grease=True)

            extensions.add(ech_prep.dummy_ext)

        else:
            # GREASE ECH
            extensions.add(EncryptedClientHelloClientExtension.create(
                variant = OuterECHClientHello.create(
                    cipher_suite = DEFAULT_HPKE_CSUITES[0],
                    config_id = rgen.randrange(2**8),
                    enc = rgen.randbytes(32),
                    payload = rgen.randbytes(239),
                ),
            ))

    # fill in client hello extension entries
    if hostname is not None:
        extensions.add(ServerNameClientExtension.create(
            [(HOST_NAME_TYPE, hostname)]
        ))

    #legacy extensions

    # indicates all point formats are accepted (legacy)
    extensions.add(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_EC_POINT_FORMATS,
        data = bytes.fromhex('03000102'),
    ))

    # more backwards compatibility empty info,
    # probably not necessary but who knows
    extensions.add(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_SESSION_TICKET,
        data = b'',
    ))
    extensions.add(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_ENCRYPT_THEN_MAC,
        data = b'',
    ))
    extensions.add(GenericClientExtension.create(
        selector = ExtensionTypes.LEGACY_EXTENDED_MASTER_SECRET,
        data = b'',
    ))

    # calculate client hello handshake message without PSK
    ch = ClientHelloHandshake.create(
        legacy_version     = DEFAULT_LEGACY_VERSION,
        client_random      = rgen.randbytes(32),
        session_id         = sesid,
        ciphers            = ciphers,
        legacy_compression = DEFAULT_LEGACY_COMPRESSION,
        extensions         = extensions.get(),
    )

    # add PRE_SHARED_KEY extension if requested
    ch = psk_factory(ch)

    # fix ECH extension if needed
    if ech_prep:
        ch = ech_prep.fill_outer(ch)

    return ch, secrets #FIXME secretS


@dataclass
class ClientHandshake(AbstractHandshake, PayloadProcessor):
    chello         : ClientHelloHandshake
    state          : ClientStates                 = ClientStates.START
    psk            : bytes|None                   = None
    sni            : str|None                     = None
    kexes          : dict[NamedGroup, bytes]      = field(default_factory=dict)
    inner_ch       : ClientHelloHandshake|None    = None
    psk_modes      : Iterable[PskKeyExchangeMode] = PskKeyExchangeMode.all()
    hs_trans       : HandshakeTranscript          = field(default_factory=HandshakeTranscript)
    key_calc       : KeyCalc                      = field(init=False)
    tickets        : list[TicketInfo]             = field(default_factory=list)
    ech_configs    : list[ECHConfigVariant]       = field(default_factory=list)
    rreader        : RecordReader|None            = None
    rwriter        : RecordWriter|None            = None
    cert_chain     : list[bytes]                  = field(default_factory=list)
    cert_pubkey    : bytes|None                   = None

    def __post_init__(self) -> None:
        self.key_calc = KeyCalc(self.hs_trans)

    @classmethod
    def create(cls, ch: ClientHelloHandshake, secrets: ClientSecrets) -> Self:
        psk: bytes|None = secrets.psk.uncreate()

        need_kex_mode = need_psk = (psk is not None)

        # extract some data from the client hello
        sni: str|None = None
        kexes: dict[NamedGroup, bytes] = {}

        psk_modes = PskKeyExchangeMode.all()

        inner_ch = secrets.inner_ch.data

        for ext in (ch if inner_ch is None else inner_ch).data.extensions.uncreate():
            match ext:
                case ServerNameClientExtension():
                    try:
                        sni = ext.data[0].host_name
                    except IndexError:
                        pass
                case KeyShareClientExtension():
                    for (group, _), private in zip(ext.uncreate(), secrets.kex_sks):
                        kexes[NamedGroup.create(group)] = private
                case PskKeyExchangeModesClientExtension():
                    psk_modes = tuple(ext.data)
                    need_kex_mode = False
                case PreSharedKeyClientExtension():
                    assert need_psk
                    need_psk = False
                case GenericClientExtension():
                    match ext.typ:
                        case ExtensionTypes.EARLY_DATA:
                            raise TlsTODO("no support for 0RTT early data yet")

        assert not need_kex_mode and not need_psk, "needed psk and psk exchange mode extensions in client hello but didn't get them"

        return cls(
            chello = ch,
            psk = psk,
            sni = sni,
            kexes = kexes,
            psk_modes = psk_modes,
            inner_ch = inner_ch,
        )

    @override
    @property
    def started(self) -> bool:
        return self.state != ClientStates.START

    @override
    @property
    def connected(self) -> bool:
        return self.state == ClientStates.CONNECTED

    @override
    @property
    def can_send(self) -> bool:
        return self.state == ClientStates.CONNECTED

    @override
    @property
    def can_recv(self) -> bool:
        return self.state == ClientStates.CONNECTED

    @override
    def begin(self, rreader: RecordReader, rwriter: RecordWriter) -> None:
        assert self.state == ClientStates.START
        assert self.rreader is None and self.rwriter is None
        self.rreader = rreader
        self.rreader.hs_buffer = HandshakeBuffer(owner=self)
        self.rwriter = rwriter
        self.send_hello()

    def _send_hs_msg(self, msg: HandshakeVariant, vers:Version = DEFAULT_LEGACY_VERSION) -> None:
        logger.info(f"sending hs message {msg.typ} to server")
        raw = msg.pack()
        assert self.rwriter is not None
        self.rwriter.send(Record.create(
            typ     = ContentType.HANDSHAKE,
            version = vers,
            payload = raw,
        ))
        if msg.typ == HandshakeTypes.CLIENT_HELLO and self.inner_ch is not None:
            self.hs_trans.add(hs=self.inner_ch, from_client=True)
        else:
            self.hs_trans.add(hs=msg, from_client=True)

    def send_hello(self) -> None:
        assert self.state == ClientStates.START
        self._send_hs_msg(self.chello, Version.TLS_1_0)
        self.state = ClientStates.WAIT_SH

    @override
    def process_hs_payload(self, raw: bytes) -> None:
        try:
            msg = Handshake.unpack(raw)
        except UnpackError as e:
            raise TlsError("Malformed handshake message") from e
        self.hs_trans.add(hs=msg.variant, from_client=False)
        logger.info(f"Received handshake message {msg.typ} with length {len(raw)}")

        match (self.state, msg.variant):
            case (ClientStates.WAIT_SH, ServerHelloHandshake() as shello):
                self._process_server_hello(shello)
            case (ClientStates.WAIT_EE, EncryptedExtensionsHandshake() as ee):
                self._process_ee(ee)
            case ((ClientStates.WAIT_CERT_CR | ClientStates.WAIT_CERT), CertificateHandshake() as cert):
                self._process_cert(cert)
            case (ClientStates.WAIT_CV, CertificateVerifyHandshake() as cv):
                self._process_cv(cv)
            case (ClientStates.WAIT_FINISHED, FinishedHandshake() as fin):
                self._process_finished(fin)
            case (ClientStates.CONNECTED, NewSessionTicketHandshake() as nst):
                self._process_ticket(nst)
            case _:
                raise TlsError(f"Unexpected {msg.typ} in state {self.state}")

    def _process_server_hello(self, sh: ServerHelloHandshake) -> None:
        if sh.data.server_random.hex() == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
            # it's the sha256 hash of 'HelloRetryRequest'
            raise TlsTODO("HelloRetryRequest not yet implemented")

        if self.inner_ch is not None:
            if server_accepts_ech(self.inner_ch, sh):
                logger.info("ECH accepted and confirmed by server")
            else:
                raise TlsError("server rejected true ECH")

        csuite = sh.data.cipher_suite

        kex_secret = None
        got_psk = False

        for ext in sh.data.extensions.uncreate():
            match ext:
                case KeyShareServerExtension():
                    group = ext.data.group
                    private = self.kexes[group]
                    try:
                        kex = get_kex_alg(group)
                    except ValueError:
                        raise TlsError(f"no implementation for kex group {group}")
                    kex_secret = kex.exchange(private, ext.data.pubkey)
                case SupportedVersionsServerExtension():
                    assert ext.data.uncreate() == Version.TLS_1_3.value
                case PreSharedKeyServerExtension():
                    if ext.data != 0:
                        raise TlsError(f'unexpected index in PRE_SHARED_KEY: {ext.data}')
                    got_psk = True
                case _:
                    logger.warning("Ignoring server extension", ext.typ)

        match ((kex_secret is not None), (self.psk is not None), got_psk):
            case (True, True, True):
                if not any(m == PskKeyExchangeMode.PSK_DHE_KE for m in self.psk_modes):
                    raise TlsError("server wants PSK_DHE_KE but client didn't ask for it")
            case (False, True, True):
                if not any(m == PskKeyExchangeMode.PSK_KE for m in self.psk_modes):
                    raise TlsError("server wants PSK_KE but client didn't ask for it")
            case (True, False, False):
                pass
            case other:
                raise TlsError(f"unclear what PSK/DHE mode to use:; check triple is {other}")

        # inform components of the cipher suite implementation
        try:
            get_hash_alg(csuite)
            get_cipher_alg(csuite)
        except ValueError as e:
            raise TlsError(f"cipher suite {csuite} not supported") from e
        self.key_calc.cipher_suite = csuite

        # set up handshake keys
        self.key_calc.set_psk(self.psk)
        self.key_calc.set_kex_secret(kex_secret)
        assert self.rreader is not None
        self.rreader.rekey(self.key_calc.cipher_suite,
                            self.key_calc.server_handshake_traffic_secret)

        logger.info(f"Finished processing server hello")
        self.state = ClientStates.WAIT_EE

    def _process_ee(self, ee: EncryptedExtensionsHandshake) -> None:
        for ext in ee.data.data:
            match ext.variant:
                case ServerNameServerExtension() as sne:
                    if sne.data:
                        raise TlsError(f"SERVER_NAME extension data should be empty, but got {ext.data}")
                case SupportedGroupsServerExtension():
                    # only informational; ignore
                    pass
                case EncryptedClientHelloServerExtension() as eche:
                    logger.info(f'received {len(eche.data.data)} ECH configs in server EE')
                    self.ech_configs.extend(eche.data.data)
                case _:
                    logger.warning(f"Ignoring server extension extension of type {ext.typ}")

        logger.info(f"Finished processing server encrypted extensions")
        if self.psk is None:
            self.state = ClientStates.WAIT_CERT_CR
        else:
            self.state = ClientStates.WAIT_FINISHED

    def _process_cert(self, cert: CertificateHandshake) -> None:
        if cert.data.certificate_request_context:
            raise TlsError(f"certificate_request_context field should be empty")
        for cert_struct in cert.data.certificate_list:
            if cert_struct.extensions:
                raise TlsError(f"certificate extensions should be empty")
            self.cert_chain.append(cert_struct.cert_data)
        logger.info(f"Received a length-{len(self.cert_chain)} certificate chain"
            f" with lengths {[len(x) for x in self.cert_chain]}")
        self.cert_pubkey = extract_x509_pubkey(self.cert_chain[0])

        self.state = ClientStates.WAIT_CV

    def _process_cv(self, cv: CertificateVerifyHandshake) -> None:
        logger.info(f"Received a length-{len(cv.data.signature)} sig of type {cv.data.algorithm}")
        sig_alg = cv.data.algorithm
        try:
            sigscheme = get_sig_alg(sig_alg)
        except ValueError as e:
            raise TlsError(f"signature algorithm {sig_alg} not supported") from e
        assert self.cert_pubkey is not None
        check = sigscheme.verify(
            pubkey    = self.cert_pubkey,
            signature = cv.data.signature,
            data      = self.key_calc.server_cv_message,
        )
        if check:
            logger.info("certificate verify signature check passed")
        else:
            raise TlsError("signature check failed in CERTIFICATE_VERIFY")

        self.state = ClientStates.WAIT_FINISHED

    def _process_finished(self, sf: FinishedHandshake) -> None:
        if sf.data != self.key_calc.server_finished_verify:
            raise TlsError("verify data in server finished message doesn't match")
        logger.info(f"Received correct SERVER FINISHED.")

        logger.info(f"Sending change cipher spec to server")
        assert self.rwriter is not None
        self.rwriter.send(CCS_MESSAGE)

        self.rwriter.rekey(self.key_calc.cipher_suite,
                           self.key_calc.client_handshake_traffic_secret)

        client_finished = FinishedHandshake.create(self.key_calc.client_finished_verify)
        self._send_hs_msg(client_finished)
        logger.info(f"Sent CLIENT FINISHED. Handshake complete!")

        assert self.rreader is not None
        self.rreader.rekey(self.key_calc.cipher_suite,
                           self.key_calc.server_application_traffic_secret)
        self.rwriter.rekey(self.key_calc.cipher_suite,
                           self.key_calc.client_application_traffic_secret)

        self.state = ClientStates.CONNECTED

    def _process_ticket(self, nst: NewSessionTicketHandshake) -> None:
        self.tickets.append(self.key_calc.ticket_info(nst.data, modes=self.psk_modes))
        logger.info("got and stored a reconnect ticket")

@dataclass
class Client(Connection):
    handshake: ClientHandshake

    @classmethod
    def create(cls, ch: ClientHelloHandshake, secrets: ClientSecrets) -> Self:
        return cls(
            transcript = RecordTranscript(is_client=True),
            handshake = ClientHandshake.create(ch, secrets),
        )

    @property
    def tickets(self) -> tuple[TicketInfo,...]:
        return tuple(self.handshake.tickets)

    @property
    def ech_configs(self) -> tuple[ECHConfigVariant,...]:
        return tuple(self.handshake.ech_configs)


@same_args(build_client_hello)
def build_client(*args: Any, **kwargs: Any) -> Client:
    ch, secrets = build_client_hello(*args, **kwargs)
    return Client.create(ch, secrets)
