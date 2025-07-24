import socket
import threading
from io import StringIO
from random import Random
from time import sleep

from https_server import HttpHandler
from prover import HttpsProver
from tls_common import *
from tls_crypto import gen_server_secrets
from tls_keycalc import ServerTicketer
from tls_server import start_server, ServerID, Server, server_thread_info, _ThreadLogFilter, _ServerThread
from verifier import HttpsVerifier

class ProofTest:
    def __init__(self, num_servers, hostname='localhost', min_port=8000, max_port=8100, rseed=None):
        self.prover_port = None
        self.prover_host = None
        self.prover_thread = None
        self.server_threads = []
        self.num_servers = num_servers
        self.hostname = hostname
        self.min_port = min_port
        self.max_port = max_port
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


    def start_servers(self):
        port = self.min_port
        for i in range(num_servers):
            logger.info(f'generating cert and ECH key for server {i}')
            server_secret = gen_server_secrets(rgen=Random(self.rseed+i))
            cert_der = server_secret.cert.cert_der
            ech_pubkeys = [ech.config.data.key_config.public_key for ech in server_secret.eches]
            t = threading.Thread(
                name=f"server {i}",
                target=start_test_server,
                args=(HttpHandler(), self.hostname, port, server_secret, 3, self.rseed+i,),
                daemon=True
            )
            self.server_threads.append(t)
            t.start()
            # start_server(HttpHandler(), self.hostname, port, server_secret, self.rseed)
            logger.info(f'server opened on port {port}')
            self.server_ids.append(ServerID(self.hostname, port, cert_der, ech_pubkeys))
            port += 1



    def start_prover(self):
        self.prover = HttpsProver(self.server_ids, 0, None, rseed=self.rseed) # TODO: these shouldn't be hardcoded

        self.prover_thread = threading.Thread(name='prover',
                                         target = self.prover.run,
                                         daemon=True
        )
        self.prover_thread.start()
        while not self.prover.listening:
            # wait until the server starts up
            sleep(0.1)

        self.prover_host = self.prover.host
        self.prover_port = self.prover.port # this needs to happen after the server is listening, since the port might be dynamically assigned


    def start_verifier(self):
        verifier = HttpsVerifier(self.server_ids, self.prover_host, self.prover_port, rseed=self.rseed)
        verifier.run()

def start_test_server(handler, hostname='localhost', port=0, server_secrets=None, max_connections=1, rseed=None):
    """Starts a temporary server that handles a fixed number of connections and then kills itself"""
    if server_secrets is None:
        logger.info('generating new self-signed server cert and ECH config')
        server_secrets = gen_server_secrets(hostname)

    ticketer = ServerTicketer()

    with socket.create_server((hostname, port)) as ssock:
        for i in range(max_connections):
            logger.info(f'listening for connection to {hostname} on port {port}')
            sock, addr = ssock.accept()
            st = _ServerThread(handler, server_secrets, ticketer, rseed)
            tname = f'{threading.current_thread().name} conn {i+1}'
            sthread = threading.Thread(name=tname, target=st, args=(sock, addr,))
            logger.info(f'launching new thread to handle client connection')
            sthread.start()
            if rseed is not None:
                rseed += 1

        logger.info('processed maximum number of connections, shutting down')

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='[%(threadName)s] %(message)s'
    )
    num_servers = 3
    rseed = 0
    test = ProofTest(num_servers, rseed=rseed)
    test.run()
    for x in test.server_ids:
        print('server id:', x)
