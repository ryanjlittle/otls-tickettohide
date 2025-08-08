from concurrent.futures import ThreadPoolExecutor
from random import SystemRandom, Random

from https_client import http_get_req
from proof_common import VerifierError
from prover_crypto import DEFAULT_PROVER_CLIENT_OPTIONS
from tls13_spec import TicketInfo, ClientOptions, NamedGroup, KeyShareEntry
from tls_client import connect_client
from tls_common import TlsError, TlsTODO
from tls_crypto import get_kex_alg
from tls_keycalc import KeyCalc, HandshakeTranscript
from tls_server import ServerID


class VerifierTls:
    """Performs the TLS crypto operations done by the verifier for a single server"""
    server: ServerID
    options: ClientOptions
    key_calc: KeyCalc
    kex_secrets: dict[NamedGroup, bytes] = {}
    kex_shares: list[KeyShareEntry] = []
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

        for group in options.kex_shares:
            kex_alg = get_kex_alg(group)
            if self.rseed is None:
                rgen = SystemRandom()
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
            # the contents of this message don't matter, but we need the server to respond with some application data
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
    commitment: bytes|None = None

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



    # def gen_secrets(self):
    #     if len(self._dh_secrets) > 0 or self._resumption_dh_secret is not None:
    #         raise VerifierError('already generated secrets')
    #     self._dh_secrets = [self._kex.gen_private(self._rgen) for _ in range(self._num_servers)]
    #     self.dh_shares = [self._kex.get_public(secret) for secret in self._dh_secrets]
    #     self._resumption_dh_secret = self._kex.gen_private(self._rgen)
    #     self.resumption_dh_share = self._kex.get_public(self._resumption_dh_secret)
    #
    # def exchange_all(self, server_shares):
    #     if len(self._dh_secrets) == 0:
    #         raise VerifierError('need to generate secrets first')
    #     if len(self._dh_outputs) > 0:
    #         raise VerifierError('already did key exchange')
    #     assert len(server_shares) == self._num_servers
    #     self._dh_outputs = [self._kex.exchange(priv, pub) for (priv,pub) in zip(self._dh_secrets, server_shares)]
    #
    # def compute_handshake_keys(self, hashes):
    #     if len(self._dh_outputs) == 0:
    #         raise VerifierError('need to run key exchange first')
    #     if len(self._key_calcs) > 0:
    #         raise VerifierError('already computed handshake keys')
    #     assert len(hashes) == self._num_servers
    #     hs_keys = []
    #     for i, h in enumerate(hashes):
    #         trans = PartialHandshakeTranscript()
    #         key_calc = KeyCalc(trans)
    #         key_calc.cipher_suite = self._ciphersuite
    #         key_calc.psk = None
    #         trans.set_hash(HandshakeType.SERVER_HELLO, h)
    #         key_calc.kex_secret = self._dh_outputs[i]
    #         self._key_calcs.append(key_calc)
    #         hs_keys.append((key_calc.client_handshake_traffic_secret, key_calc.server_handshake_traffic_secret))
    #     return hs_keys
    #
    # def compute_application_keys(self, hashes):
    #     if len(self._key_calcs) == 0:
    #         raise VerifierError('need to compute handshake keys first')
    #
    #     app_keys = []
    #     for key_calc, h in zip(self._key_calcs, hashes):
    #         key_calc._hs_trans.set_hash(HandshakeType.FINISHED, h, from_client=False)
    #         app_keys.append((key_calc.client_application_traffic_secret, key_calc.server_application_traffic_secret))
    #     return app_keys
    #
    # def get_master_secrets(self):
    #     return [key_calc.master_secret for key_calc in self._key_calcs]
