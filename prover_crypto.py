"""Classes to handle TLS crypto for the proof protocol"""
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import cached_property
from random import Random
from secrets import SystemRandom
from typing import Iterable, override

from cryptography.hazmat.primitives.ciphers import Cipher

from proof_common import ProverError
from proof_spec import ClientHelloValues
from tls13_spec import Version, \
    ClientState, CipherSuite, ClientOptions, NamedGroup, ClientHelloHandshake, KeyShareClientExtension, \
    SupportedGroupsClientExtension, SignatureAlgorithmsClientExtension, SupportedVersionsClientExtension, \
    PskKeyExchangeModesClientExtension, GenericClientExtension, ExtensionTypes, EncryptedClientHelloClientExtension, \
    InnerECHClientHello, Uint64, PreSharedKeyClientExtension, \
    ClientExtensionVariant, ECHConfigVariant, ServerNameClientExtension, ServerHelloHandshake, \
    KeyShareServerExtension, SupportedVersionsServerExtension, PreSharedKeyServerExtension, HandshakeTypes, ContentType, \
    RecordHeader, ClientStates, EncryptedExtensionsHandshake, FinishedHandshake
from tls_client import ClientHandshake, build_client_hello, _ChelloExtensions, connect_client
from tls_common import TlsError, TlsTODO, logger
from tls_crypto import get_kex_alg, DEFAULT_SIGNATURE_SCHEMES, get_hash_alg, \
    get_cipher_alg, DEFAULT_KEX_MODES
from tls_ech import OuterPrep, server_accepts_ech
from tls_keycalc import KeyCalc, HandshakeTranscript, TicketInfo, current_time_milli
from tls_records import RecordWriter, DEFAULT_LEGACY_VERSION, DEFAULT_LEGACY_COMPRESSION, RecordTranscript, DataBuffer, \
    RecordReader, InnerPlaintext, CCS_MESSAGE
from tls_server import ServerID

DEFAULT_PROVER_CLIENT_OPTIONS = ClientOptions.create(
send_sni = True,
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256],
    kex_shares = [NamedGroup.X25519],
    kex_groups = [NamedGroup.X25519],
    sig_algs = DEFAULT_SIGNATURE_SCHEMES,
    send_psk = True,
    tickets = (),
    psk_modes = DEFAULT_KEX_MODES,
    send_time = None,
    send_ech = True,
    ech_configs = (),
)

@dataclass
class ProverSecrets:
    index: int
    queries: list[bytes]

@dataclass
class ProverHandshake(ClientHandshake):
    inner_ch: ClientHelloHandshake = field()
    kexes: dict[NamedGroup, bytes] = field(init=False)
    server_kex_shares: list[tuple[NamedGroup, bytes]] = field(default_factory=list)

    @override
    def __post_init__(self) -> None:
        super().__post_init__()
        self.key_calc.use_psk = True

        got_psk_kex_mode: bool = False
        got_psk: bool = False

        for ext in self.inner_ch.data.extensions.uncreate():
            match ext:
                case ServerNameClientExtension():
                    try:
                        self.sni = ext.data[0].host_name
                    except IndexError:
                        pass
                case PskKeyExchangeModesClientExtension():
                    self.psk_modes = tuple(ext.data)
                    got_psk_kex_mode = True
                case PreSharedKeyClientExtension():
                    got_psk = True
                case GenericClientExtension():
                    match ext.typ:
                        case ExtensionTypes.EARLY_DATA:
                            raise TlsTODO("no support for 0RTT early data yet")
        assert got_psk_kex_mode and got_psk, "needed psk and psk exchange mode extensions in client hello but didn't get them"

    @override
    def _process_server_hello(self, sh: ServerHelloHandshake):
        if sh.data.server_random.hex() == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
            # it's the sha256 hash of 'HelloRetryRequest'
            raise TlsTODO("HelloRetryRequest not yet implemented")

        if server_accepts_ech(self.inner_ch, sh):
            logger.info("ECH accepted and confirmed by server")
        else:
            raise TlsError("server rejected true ECH")

        csuite = sh.data.cipher_suite

        got_psk = False
        got_kex_share = False

        for ext in sh.data.extensions.uncreate():
            match ext:
                case KeyShareServerExtension():
                    self.kex_group = ext.data.group
                    try:
                        get_kex_alg(self.kex_group)
                    except ValueError:
                        raise TlsError(f"no implementation for kex group {self.kex_group}")
                    self.server_kex_shares.append((ext.data.group, ext.data.pubkey))
                    got_kex_share = True
                case SupportedVersionsServerExtension():
                    assert ext.data.uncreate() == Version.TLS_1_3.value
                case PreSharedKeyServerExtension():
                    if ext.data != 0:
                        raise TlsError(f'unexpected index in PRE_SHARED_KEY: {ext.data}')
                    got_psk = True
                case _:
                    logger.warning("Ignoring server extension", ext.typ)


        if not got_psk:
            raise ProverError("server did not accept ticket")
        if not got_kex_share:
            raise ProverError("server did not provide kex share")

        # inform components of the cipher suite implementation
        try:
            get_hash_alg(csuite)
            get_cipher_alg(csuite)
        except ValueError as e:
            raise TlsError(f"cipher suite {csuite} not supported") from e
        self.key_calc.cipher_suite = csuite

        self.state = ClientStates.WAIT_EE
        logger.info(f"finished processing server hello.")

    @override
    def _process_ee(self, ee: EncryptedExtensionsHandshake) -> None:
        # kludgey way to force the handshake to follow a PSK resumption, without storing the PSK itself
        super()._process_ee(ee)
        self.state = ClientStates.WAIT_FINISHED

    @override
    def _process_finished(self, sf: FinishedHandshake) -> None:
        # Same code as in ClientHandshake, but without re-keying to the application keys
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

        self.state = ClientStates.CONNECTED

    def recv_message(self) -> None:
        if self.rreader is None:
            raise AttributeError('not connected')
        self.rreader.fetch()

class ProverClient:
    """Manages connection to a single TLS server from the prover."""

    server: ServerID
    handshake: ProverHandshake
    sock: socket.socket|None = None
    app_data_in: DataBuffer
    options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS
    ech_configs: tuple[ECHConfigVariant, ...]|None = None
    rseed: int|None = None

    def __init__(self, server: ServerID, rseed=None) -> None:

        self.server = server
        self.app_data_in = DataBuffer()
        self.rseed = rseed


    def __del__(self):
        """Fallback way to close the socket. The expected use is to close the connection manually when it's no
        longer needed. If that doesn't happen, this closes the socket when the object is deleted."""
        self.close()

    def create_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def close(self):
        if self.sock is not None:
            self.sock.close()

    def obtain_ech_config(self) -> None:
        options = DEFAULT_PROVER_CLIENT_OPTIONS.replace(send_psk=False)

        # run a client handshake on a temporary socket. This will fetch the first ECH config of the server (if one exists)
        with connect_client(self.server.hostname, self.server.port, options=options, rseed=self.rseed) as client:
            client.close_notify()
            if len(client.ech_configs) == 0:
                raise ProverError('no ECH configs obtained')
            self.ech_configs = client.ech_configs

        self.options = self.options.replace(ech_configs=self.ech_configs[:1])
        logger.info(f'obtained ECH public key: {self.ech_configs[0].data.key_config.public_key}')


    def build_ech(self, hello_vals: ClientHelloValues) -> None:
        if self.ech_configs is None:
            raise AttributeError('no ECH config stored')
        if hello_vals.hostname != self.server.hostname:
            raise ValueError('hostname mismatch')

        # TODO: test remove
        try:
            build_client_hello(hello_vals.hostname, self.options, self.rseed)
        except:
            pass

        ech, inner_ch = build_prover_client_hello(hello_vals, self.options, self.rseed)
        self.handshake = ProverHandshake(chello=ech, inner_ch=inner_ch)

    def connect(self) -> None:
        if self.sock is None:
            raise AttributeError('no socket created')
        if self.handshake.connected:
            raise AttributeError('already connected')
        try:
            self.sock.connect((self.server.hostname, self.server.port))
        except ConnectionRefusedError:
            raise ProverError(f'couldn\'t connect to the server: {self.server.hostname}:{self.server.port}')

        logger.info(f'connected to server')

    def send_ech(self) -> None:
        if self.sock is None:
            raise AttributeError('no socket created')
        if not self.handshake.connected:
            self.connect()

        rfile = self.sock.makefile('rb')
        wfile = self.sock.makefile('wb')
        transcript = RecordTranscript(is_client=True)
        rreader = RecordReader(rfile, transcript, self.app_data_in)
        rwriter = RecordWriter(wfile, transcript)

        # send ECH
        self.handshake.begin(rreader, rwriter)

        # receive server hello
        self.handshake.recv_message()

    @property
    def handshake_transcript_hash(self) -> bytes:
        # returns the hash of [CH, SH]
        return self.handshake.key_calc.hs_trans[HandshakeTypes.SERVER_HELLO]

    @property
    def application_transcript_hash(self) -> bytes:
        # returns the hash of [CH, SH, ..., SF]
        return self.handshake.key_calc.hs_trans[HandshakeTypes.FINISHED]

    def finish_handshake(self) -> None:
        if self.handshake.rreader is None or self.handshake.rwriter is None:
            raise AttributeError('handshake not started')
        self.handshake.rreader.rekey(
            self.handshake.key_calc.cipher_suite,
            self.handshake.key_calc.server_handshake_traffic_secret
        )
        self.handshake.rwriter.rekey(
            self.handshake.key_calc.cipher_suite,
            self.handshake.key_calc.server_handshake_traffic_secret
        )

        while not self.handshake.connected:
            self.handshake.recv_message()

class DummyClient(ProverClient):
    def set_handshake_secret(self, handshake_secret: bytes) -> None:
        self.handshake.key_calc.handshake_secret = handshake_secret

    @property
    def master_secret(self) -> bytes:
        return self.handshake.key_calc.master_secret

class TwoPCClient(ProverClient):
    def set_chts_shts(self, chts: bytes, shts: bytes) -> None:
        self.handshake.key_calc.client_handshake_traffic_secret = chts
        self.handshake.key_calc.server_handshake_traffic_secret = shts

class ProverCryptoManager:
    servers: list[ServerID]
    secrets: ProverSecrets
    clients: list[ProverClient] = []
    client_key_share: bytes
    client_key_iv: bytes
    server_key_share: bytes
    server_key_iv: bytes
    ciphersuite: CipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256
    rseed: int|None = None

    def __init__(
        self,
        servers: list[ServerID],
        secrets: ProverSecrets,
        rseed: int|None = None
    ) -> None:
        self.servers = servers
        self.secrets = secrets
        self.rseed = rseed

        for i, server in enumerate(servers):
            rseed = None if rseed is None else rseed + i
            if i == secrets.index:
                self.clients.append(TwoPCClient(server, rseed))
            else:
                self.clients.append(DummyClient(server, rseed))

    @property
    def twopc_client(self) -> TwoPCClient:
        client = self.clients[self.secrets.index]
        assert isinstance(client, TwoPCClient)
        return client

    def create_sockets(self):
        for client in self.clients:
            client.create_socket()

    def close_sockets(self):
        for client in self.clients:
            client.close()

    def obtain_ech_configs(self):
        with ThreadPoolExecutor(max_workers=len(self.servers), thread_name_prefix='prover') as executor:
            futures = [executor.submit(lambda x: x.obtain_ech_config(),client) for client in self.clients]

        # this ensures any exception encountered in a thread will be raised
        [f.result() for f in futures]

    def build_ech_configs(self, hello_vals: list[ClientHelloValues]):
        for (client, vals) in zip(self.clients, hello_vals):
            client.build_ech(vals)

    def send_and_recv_hellos(self) -> None:
        with ThreadPoolExecutor(max_workers=len(self.servers), thread_name_prefix='prover') as executor:
            futures = [executor.submit(lambda x: x.send_ech(), client) for client in self.clients]

        # this ensures any exception encountered in a thread will be raised
        [f.result() for f in futures]

    @property
    def server_key_shares(self) -> list[list[tuple[NamedGroup, bytes]]]:
        return [client.handshake.server_kex_shares for client in self.clients]

    @property
    def dummy_master_secrets(self) -> list[bytes]:
        secrets: list[bytes] = []
        for client in self.clients:
            match client:
                case DummyClient():
                    secrets.append(client.master_secret)
                case TwoPCClient():
                    secrets.append(b'\x00'*32)
        return secrets

    @property
    def real_server_handshake_hash(self) -> bytes:
        return self.twopc_client.handshake_transcript_hash

    @property
    def real_server_application_hash(self) -> bytes:
        return self.twopc_client.application_transcript_hash

    @cached_property
    def query_header(self) -> bytes:
        raw_secret = self.secrets.queries[self.secrets.index]
        ptext = InnerPlaintext.create(
            payload = raw_secret,
            typ = ContentType.APPLICATION_DATA,
            padding = 0
        ).pack()
        return RecordHeader.create(
            typ = ContentType.APPLICATION_DATA,
            version = DEFAULT_LEGACY_VERSION,
            size = get_cipher_alg(self.ciphersuite).ctext_size(len(ptext))
        ).pack()

    def set_dummy_handshake_secets(self, secrets: list[bytes]) -> None:
        for i, (client, secret) in enumerate(zip(self.clients, secrets)):
            if i == self.secrets.index:
                continue
            assert isinstance(client, DummyClient)
            client.set_handshake_secret(secret)

    def set_chts_shts(self, chts: bytes, shts: bytes) -> None:
        self.twopc_client.set_chts_shts(chts, shts)

    def finish_handshakes(self):
        for client in self.clients:
            client.finish_handshake()


def build_prover_client_hello(
        hello_vals: ClientHelloValues,
        options: ClientOptions,
        rseed: int|None = None,
) -> tuple[ClientHelloHandshake, ClientHelloHandshake]:

    rgen = SystemRandom() if rseed is None else Random(rseed)

    # will hold all extensions to be added to this CH
    extensions = _ChelloExtensions()

    # standard extensions
    extensions.add(SupportedGroupsClientExtension.create(options.kex_groups))
    extensions.add(SignatureAlgorithmsClientExtension.create(options.sig_algs))
    extensions.add(SupportedVersionsClientExtension.create([Version.TLS_1_3]))
    extensions.add(PskKeyExchangeModesClientExtension.create(options.psk_modes))

    # generate session id (shared between inner/outer ECH)
    sesid = rgen.randbytes(32)

    # build inner CH
    inner_ch = _build_prover_inner_ch(
        hello_vals,
        options,
        extensions.get(),
        sesid,
        rgen
    )

    if len(options.ech_configs) == 0:
        raise ValueError('no ECH config defined')
    elif len(options.ech_configs) > 1:
        raise TlsTODO("multiple ECH configs in CH not yet supported")

    # add dummy ECH extension
    ech_config = options.ech_configs[0].variant
    ech_prep = OuterPrep(ech_config, inner_ch)
    extensions.add(ech_prep.dummy_ext)

    # fill in client hello extension entries
    extensions.add_sni(ech_prep.outer_sni)

    # legacy extensions
    extensions.add(GenericClientExtension.create(
        selector=ExtensionTypes.LEGACY_EC_POINT_FORMATS,
        data=bytes.fromhex('03000102'),
    ))
    extensions.add(GenericClientExtension.create(
        selector=ExtensionTypes.LEGACY_SESSION_TICKET,
        data=b'',
    ))
    extensions.add(GenericClientExtension.create(
        selector=ExtensionTypes.LEGACY_ENCRYPT_THEN_MAC,
        data=b'',
    ))
    extensions.add(GenericClientExtension.create(
        selector=ExtensionTypes.LEGACY_EXTENDED_MASTER_SECRET,
        data=b'',
    ))

    # generate key exchange shares for the outer CH
    kex_shares: list[tuple[NamedGroup, bytes]] = []
    for group in options.kex_shares:
        kex = get_kex_alg(group)
        secret = kex.gen_private(rgen)
        share = kex.get_public(secret)
        kex_shares.append((group, share))
    extensions.add(KeyShareClientExtension.create(kex_shares))

    # calculate client hello handshake message without PSK
    chello = ClientHelloHandshake.create(
        legacy_version = DEFAULT_LEGACY_VERSION,
        client_random = rgen.randbytes(32),
        session_id = sesid,
        ciphers = options.ciphers,
        legacy_compression = DEFAULT_LEGACY_COMPRESSION,
        extensions = extensions.get(),
    )

    # add PSK extension
    chello = add_psk_extension(
        chello,
        hello_vals.ticket_info,
        hello_vals.binder_key,
        options.send_time.data
    )

    # fix ECH extension
    chello = ech_prep.fill_outer(chello)
    return chello, ech_prep.inner_ch

def _build_prover_inner_ch(
        hello_vals: ClientHelloValues,
        options: ClientOptions,
        shared_exts: Iterable[ClientExtensionVariant],
        session_id: bytes,
        rgen: Random
    ) -> ClientHelloHandshake:

    extensions = _ChelloExtensions()
    for ext in shared_exts:
        extensions.add(ext)

    # add INNER ECH extension (empty to allow for server response)
    extensions.add(EncryptedClientHelloClientExtension.create(
        variant=InnerECHClientHello.create(),
    ))

    # add SNI extension
    extensions.add_sni(hello_vals.hostname)

    # add key exchange extension
    extensions.add(KeyShareClientExtension.create([share.uncreate() for share in hello_vals.kex_shares]))

    # build inner CH
    inner_ch = ClientHelloHandshake.create(
        legacy_version = DEFAULT_LEGACY_VERSION,
        client_random = rgen.randbytes(32),
        session_id = session_id,
        ciphers = options.ciphers,
        legacy_compression = DEFAULT_LEGACY_COMPRESSION,
        extensions = extensions.get(),
    )

    # add PSK extension
    inner_ch = add_psk_extension(
        inner_ch,
        hello_vals.ticket_info,
        hello_vals.binder_key,
        options.send_time.data
    )
    return inner_ch


def add_psk_extension(
        chello: ClientHelloHandshake,
        ticket: TicketInfo,
        binder_key: bytes,
        send_time: Uint64|None = None
    ) -> ClientHelloHandshake:
    """
    Computes the PSK extension from a given ticket and adds it to the ClientHello. The PSK is computed directly from
    the binder key, so the resumption secret is not needed.
    """
    extensions = list(chello.data.extensions.uncreate())
    if any(ext.typ == ExtensionTypes.PRE_SHARED_KEY for ext in extensions):
        raise ValueError(f"client hello should not contain PSK extension yet")

    binder_length = get_hash_alg(ticket.csuite).digest_size
    # compute values for dummy psk extension

    oage = ((current_time_milli() if send_time is None else send_time)
            - ticket.creation + ticket.mask) % 2 ** 32
    dummy_binder = b'\xdd' * binder_length

    # construct extension with dummy binder
    dummy_psk_ext = PreSharedKeyClientExtension.create(
        identities=[(ticket.ticket_id, oage)],
        binders=[dummy_binder],
    )

    # add dummy extension to chello
    dummy_chello = chello.replace(extensions=extensions + [dummy_psk_ext])

    actual_binder = compute_binder_val(dummy_chello, binder_key, ticket.csuite)

    actual_psk_ext = dummy_psk_ext.replace(binders=[actual_binder])
    logger.info(f'inserting psk with id {ticket.ticket_id[:12].hex()}... and  binder {actual_binder.hex()} into client hello')
    return chello.replace(extensions=extensions + [actual_psk_ext])


def compute_binder_val(chello: ClientHelloHandshake, binder_key: bytes, csuite: CipherSuite) -> bytes:
    """Computes the binder key for this ticket within the given (unpacked) client hello.
           """
    hst = HandshakeTranscript()

    exts = list(chello.data.extensions)
    pske = exts[-1].uncreate()
    assert isinstance(pske, PreSharedKeyClientExtension), "last extension in client hello should be PSK"

    raw_hello = chello.pack()
    pbinds = pske.data.binders.pack()
    assert raw_hello.endswith(pbinds)

    # compute real binder value
    hst = HandshakeTranscript()
    kc = KeyCalc(hst)
    kc.cipher_suite = csuite
    digest = hst.add_partial(raw_hello[:-len(pbinds)])

    binder_val = kc.get_verify_data(binder_key, digest)

    if len(binder_val) != len(pske.data.binders.data[0]):
        raise TlsError("binder key in client hello has the wrong length")

    return binder_val