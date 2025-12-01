from concurrent.futures import ThreadPoolExecutor
from random import SystemRandom, Random

from tls13.https_client import http_get_req
from tls13.tls13_spec import TicketInfo, ClientOptions, NamedGroup, KeyShareEntry
from tls13.tls_client import connect_client
from tls13.tls_common import TlsError, TlsTODO
from tls13.tls_crypto import get_kex_alg
from tls13.tls_keycalc import KeyCalc, HandshakeTranscript
from tls13.tls_server import ServerID

from tickettohide.proof_common import VerifierError
from tickettohide.prover_crypto import DEFAULT_PROVER_CLIENT_OPTIONS


class VerifierTls:
    """Performs the TLS crypto operations done by the verifier for a single server"""
    server: ServerID
    options: ClientOptions
    key_calc: KeyCalc
    kex_secrets: dict[NamedGroup, bytes]
    kex_shares: list[KeyShareEntry]
    ticket_info: TicketInfo | None = None
    rseed: int|None = None

    def __init__(
            self,
            server: ServerID,
            options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS,
            rseed: int | None = None
    ) -> None:
        self.server = server
        self.options = options
        self.rseed = rseed

        self.key_calc = KeyCalc(HandshakeTranscript())
        self.key_calc.cipher_suite = options.ciphers[0]
        self.kex_shares = []
        self.kex_secrets = {}

        for group in options.kex_shares:
            kex_alg = get_kex_alg(group)
            if self.rseed is None:
                rgen: Random = SystemRandom()
            else:
                rgen = Random(self.rseed)
                self.rseed += 1

            secret = kex_alg.gen_private(rgen)
            share = kex_alg.get_public(secret)
            self.kex_secrets[group] = secret
            self.kex_shares.append(KeyShareEntry.create(group, share))

    def obtain_ticket(self) -> None:
        options = DEFAULT_PROVER_CLIENT_OPTIONS.replace(send_psk=False, send_ech=False)
        with connect_client(self.server.hostname, self.server.port, options=options, rseed=self.rseed) as client:
            # the content of this message doesn't matter, but we need the server to respond with some application data
            # or else they may not send tickets. A basic HTTP get request will get a response from HTTPS servers.
            req = http_get_req(self.server.hostname, '/')
            client.send(req)
            # terminate gracefully
            client.close_notify()
            # collect tickets
            client.recv(2 ** 16)
            if len(client.tickets) == 0:
                raise VerifierError(f'no tickets obtained')
            self.ticket_info = client.tickets[0]

        self.key_calc.set_psk(self.ticket_info.secret)

    def key_exchange(self, kex_shares: list[tuple[NamedGroup, bytes]]) -> None:
        if len(kex_shares) > 1:
            raise TlsTODO('multiple key exchange groups not implemented')
        group, share = kex_shares[0]
        if group not in self.kex_secrets:
            raise ValueError(f'unexpected key exchange group: {group}')
        try:
            kex = get_kex_alg(group)
        except ValueError:
            raise TlsError(f"no implementation for kex group {group}")
        kex_secret = kex.exchange(self.kex_secrets[group], share)
        self.key_calc.set_kex_secret(kex_secret)

    @property
    def binder_key(self) -> bytes:
        if self.ticket_info is None:
            raise AttributeError('ticket not set')
        return self.key_calc.binder_key


    @property
    def handshake_secret(self) -> bytes:
        return self.key_calc.handshake_secret

    @property
    def master_secret(self) -> bytes:
        return self.key_calc.master_secret


class VerifierCryptoManager:
    """Manages the TLS crypto operations done by the verifier"""
    tls_controllers: list[VerifierTls]
    query_commitment: bytes|None = None
    response_commitments: list[bytes]|None = None

    def __init__(
            self,
            servers: list[ServerID],
            options: ClientOptions = DEFAULT_PROVER_CLIENT_OPTIONS,
            rseed : int|None=None
    ) -> None:
        self.tls_controllers = []
        rgen = SystemRandom() if rseed is None else Random(rseed)
        for server in servers:
            new_seed = rgen.getrandbits(64) # give each tls controller a different seed
            self.tls_controllers.append(VerifierTls(server, options, new_seed))

    def obtain_tickets(self) -> None:
        with ThreadPoolExecutor(max_workers=len(self.tls_controllers), thread_name_prefix='verifier') as executor:
            futures = [executor.submit(lambda x: x.obtain_ticket(), conn) for conn in self.tls_controllers]
        # this ensures any exception encountered in a thread will be raised
        [f.result() for f in futures]

    def key_exchange(self, kex_shares: list[list[tuple[NamedGroup, bytes]]]) -> None:
        for (conn, shares) in zip(self.tls_controllers, kex_shares):
            conn.key_exchange(shares)

    @property
    def redacted_tickets(self) -> list[TicketInfo]:
        # remove PSK from each ticket
        return [conn.ticket_info.replace(secret=b'') for conn in self.tls_controllers]

    @property
    def kex_shares(self) -> list[list[KeyShareEntry]]:
        return [conn.kex_shares for conn in self.tls_controllers]

    @property
    def binder_keys(self) -> list[bytes]:
        return [conn.binder_key for conn in self.tls_controllers]

    @property
    def handshake_secrets(self) -> list[bytes]:
        return [conn.handshake_secret for conn in self.tls_controllers]

    @property
    def master_secrets(self) -> list[bytes]:
        return [conn.master_secret for conn in self.tls_controllers]
