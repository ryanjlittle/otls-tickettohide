import base64
import json
import socket
import socket
import threading
from random import Random, SystemRandom
from time import sleep

import tls13.tls_common
from tls13.https_client import http_get_req
from tls13.https_server import HttpHandler
from tls13.tls13_spec import ServerSecrets, ClientHelloHandshake, ClientOptions, NamedGroup, CipherSuite
from tls13.tls_client import build_client
from tls13.tls_common import *
from tls13.tls_crypto import gen_server_secrets, DEFAULT_SIGNATURE_SCHEMES, DEFAULT_KEX_MODES
from tls13.tls_keycalc import ServerTicketer
from tls13.tls_records import CloseNotifyException
from tls13.tls_server import ServerID, Server, _ServerThread

from tickettohide.verifier import Verifier
from tickettohide.prover import Prover
from tickettohide.prover_crypto import ProverSecrets

CLIENT_OPTIONS = ClientOptions.create(
send_sni = True,
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256],
    kex_shares = [NamedGroup.X25519],
    kex_groups = [NamedGroup.X25519],
    sig_algs = DEFAULT_SIGNATURE_SCHEMES,
    send_psk = False,
    tickets = (),
    psk_modes = DEFAULT_KEX_MODES,
    send_time = None,
    send_ech = True,
    ech_configs = (),
)

class ProofTest:
    def __init__(self, num_servers, hostname='localhost', min_port=8000, rseed=None):
        self.prover_port = None
        self.prover_host = None
        self.prover_thread = None
        self.server_threads = []
        self.num_servers = num_servers
        self.hostname = hostname
        self.min_port = min_port
        self.rseed = rseed
        self.server_ids = []
        self.prover = None

    def run(self):
        logging.basicConfig(level=logging.INFO)
        self.start_servers()
        self.start_prover()
        self.start_verifier()
        self.prover_thread.join()
        for thread in self.server_threads:
            thread.join()

    def run_on_real_server(self):
        self.server_ids = [ServerID(hostname='test.defo.ie', port=443), ServerID(hostname='tls-ech.dev', port=443)]
        #self.server_ids = [ServerID(hostname='www.w3.org', port=443)]

        self.start_prover()
        self.start_verifier()

        self.prover_thread.join()


    def start_servers(self):
        port = self.min_port
        servers = []
        for i in range(num_servers):
            logger.info(f'Building server {i}')
            servers.append(TestServer(
                self.hostname,
                port=self.min_port+i,
                msg = f'hello from server {i}',
                max_responses=3,
                rseed=self.rseed+i
            ))
            self.server_ids.append(ServerID(self.hostname, self.min_port+i))

        for server in servers:
            thread = threading.Thread(target=server.serve)
            thread.start()
            self.server_threads.append(thread)




    def start_prover(self):
        #self.prover = HttpsProver(self.server_ids, 0, None, rseed=self.rseed) # TODO: these shouldn't be hardcoded
        prover_secrets = ProverSecrets(
            index = 0,
            queries = [http_get_req(server.hostname, '/') for server in self.server_ids],
        )

        def _run_prover(server_ids, secrets):
            with Prover(self.server_ids, prover_secrets, rseed=self.rseed) as prover:
                self.prover = prover
                prover.run()

        self.prover_thread = threading.Thread(
            name='prover',
            target = _run_prover,
            args=(self.server_ids, prover_secrets),
            daemon=True
        )
        self.prover_thread.start()


        while self.prover is None or not self.prover.listening:
            # wait until the server starts up
            sleep(0.1)


    def start_verifier(self):
        with Verifier(self.server_ids, prover_host="127.0.0.1", rseed=self.rseed) as verifier:
            verifier.run()

def experiment_ech_test():
    hostname, port = 'google.com', 443
    client = build_client(sni=hostname)

    def print_file(file):
        content = file.read()
        print(content)


    with socket.create_connection((hostname, port)) as csock:
        client.connect_socket(csock)
        #client.close_notify()
        #client._rreader.fetch()
        # sleep(1)
        #print_file(client.handshake.rreader.file)
        #client.close_notify()


        client.send(http_get_req(hostname, '/'))
        # sleep(1)
       # print_file(client.handshake.rreader.file)
        logger.info('===== ')
        print(f'tickets: {client.tickets}')
        logger.info('=====')


        client.recv(2**16)
        #print_file(client.handshake.rreader.file)
        logger.info('=====')

        print(f'tickets: {client.tickets}')


class TestServer:

    def __init__(
            self,
            hostname: str = 'localhost',
            port: int = 8000,
            secrets: ServerSecrets|None = None,
            ticketer: ServerTicketer|None = None,
            max_responses: int = 1,
            msg: str = '',
            rseed: int|None = None
    ) -> None:
        self.hostname = hostname
        self.port = port
        rgen = SystemRandom() if rseed is None else Random(rseed)

        with open('test_server_secrets.txt', 'rb') as f:
            self.secrets = ServerSecrets.unpack(f.read())

        if ticketer is None:
            ticketer = ServerTicketer(rgen=rgen)
        self.ticketer = ticketer
        self.max_responses = max_responses
        response_contents = msg.encode('utf8')
        self.response_msg = '\r\n'.join([
            'HTTP/1.0 200 OK',
            'Content-type: text/plain',
            f'Content-Length: {len(response_contents)}',
            '\r\n',
        ]).encode('utf8') + response_contents
        self.rseed = rseed

    def _connect(self) -> None:
        svr = Server(self.secrets, self.ticketer, self.rseed)
        with socket.create_server((self.hostname, self.port)) as ssock:
            sock, addr = ssock.accept()
            logger.info(f'got connection from {addr}')
            svr.connect_socket(sock)
            logger.info('handshake complete; sending response')
            svr.send(self.response_msg)
            sock.close()
            logger.info('response sent')

    def serve(self) -> None:
        with socket.create_server((self.hostname, self.port)) as ssock:
            for i in range(self.max_responses):
                logger.info(f'serving on {self.hostname}:{self.port}')
                sock, addr = ssock.accept()
                st = _ServerThread(HttpHandler(), self.secrets, self.ticketer, self.rseed)
                tname = f'{threading.current_thread().name} conn {i+1}'
                sthread = threading.Thread(name=tname, target=st, args=(sock, addr,))
                try:
                    sthread.start()
                except CloseNotifyException:
                    pass
                if self.rseed is not None:
                    self.rseed += 1


if __name__ == '__main__':
    num_servers = 2
    rseed = 0

    try:
        test = ProofTest(num_servers, rseed=rseed)
        test.run_on_real_server()
    except Exception as err:
        print(err)
        exit(1)
    print("PASSED prover and verifier test")

