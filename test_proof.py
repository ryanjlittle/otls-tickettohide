import json
import socket
import socket
import threading
from random import Random, SystemRandom
from time import sleep

import tls_common
from https_client import http_get_req
from https_server import HttpHandler
from prover import Prover
from prover_crypto import ProverSecrets
from tls13_spec import ServerSecrets, ClientHelloHandshake
from tls_client import build_client, DEFAULT_CLIENT_OPTIONS
from tls_common import *
from tls_crypto import gen_server_secrets
from tls_keycalc import ServerTicketer
from tls_records import CloseNotifyException
from tls_server import ServerID, Server, _ServerThread
from verifier import Verifier


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
        self.server_ids = [ServerID(hostname='test.defo.ie', port=443), ServerID(hostname='test.defo.ie', port=443)]
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




            # server_secret = gen_server_secrets(rgen=Random(self.rseed+i))
            # cert_der = server_secret.cert.cert_der
            # ech_pubkeys = [ech.config.data.key_config.public_key for ech in server_secret.eches]
            # t = threading.Thread(
            #     name=f"server {i}",
            #     target=start_test_server,
            #     args=(HttpHandler(), self.hostname, port, server_secret, 3, self.rseed+i,),
            #     daemon=True
            # )
            # self.server_threads.append(t)
            # t.start()
            # # start_server(HttpHandler(), self.hostname, port, server_secret, self.rseed)
            # logger.info(f'server opened on port {port}')
            # self.server_ids.append(ServerID(self.hostname, port, cert_der, ech_pubkeys))
            # port += 1



    def start_prover(self):
        #self.prover = HttpsProver(self.server_ids, 0, None, rseed=self.rseed) # TODO: these shouldn't be hardcoded
        prover_secrets = ProverSecrets(
            index = 0,
            queries = [f'hello server {i}'.encode('utf8') for i in range(len(self.server_ids))]
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

        # with Prover(self.server_ids, prover_secrets) as prover:
        #     self.prover = prover
        #
        #     self.prover_thread = threading.Thread(name='prover',
        #                                      target = self.prover.run,
        #                                      daemon=True
        #     )
        #     self.prover_thread.start()


            # while not self.prover.listening:
            #     # wait until the server starts up
            #     sleep(0.1)

            # self.prover_host = self.prover.host
            # self.prover_port = self.prover.port # this needs to happen after the server is listening, since the port might be dynamically assigned


    def start_verifier(self):
        with Verifier(self.server_ids, rseed=self.rseed) as verifier:
            verifier.run()
#
# def start_test_server(handler, hostname='localhost', port=0, server_secrets=None, max_connections=1, rseed=None):
#     """Starts a temporary server that handles a fixed number of connections and then kills itself"""
#     if server_secrets is None:
#         logger.info('generating new self-signed server cert and ECH config')
#         server_secrets = gen_server_secrets(hostname)
#
#     ticketer = ServerTicketer()
#
#     with socket.create_server((hostname, port)) as ssock:
#         for i in range(max_connections):
#             logger.info(f'listening for connection to {hostname} on port {port}')
#             sock, addr = ssock.accept()
#             st = _ServerThread(handler, server_secrets, ticketer, rseed)
#             tname = f'{threading.current_thread().name} conn {i+1}'
#             sthread = threading.Thread(name=tname, target=st, args=(sock, addr,))
#             logger.info(f'launching new thread to handle client connection')
#             sthread.start()
#             if rseed is not None:
#                 rseed += 1
#
#         logger.info('processed maximum number of connections, shutting down')

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
        sleep(1)
        #print_file(client.handshake.rreader.file)
        #client.close_notify()


        client.send(http_get_req(hostname, '/'))
        sleep(1)
       # print_file(client.handshake.rreader.file)
        logger.info('===== ')
        print(f'tickets: {client.tickets}')
        logger.info('=====')


        client.recv(2**16)
        #print_file(client.handshake.rreader.file)
        logger.info('=====')

        print(f'tickets: {client.tickets}')

def test_ech_with_ticket():
    # hostname, port = 'localhost', 8000
    hostname, port = 'test.defo.ie', 443

    # server = TestServer(hostname, port, max_responses=4)
    #
    # thread = threading.Thread(target=server.serve)
    # thread.start()

    options = DEFAULT_CLIENT_OPTIONS
    client0 = build_client(sni=hostname, options=options)
    request = http_get_req(hostname, '/')
    with socket.create_connection((hostname, port)) as csock:
        client0.connect_socket(csock)
        client0.send(request)
        response = client0.recv(2 ** 16)
    assert client0.ech_configs
    assert client0.tickets
    print(f'got tickets and ech configs: {response}')

    # Ticket, no ECH
    options = DEFAULT_CLIENT_OPTIONS.replace(send_ech=False, send_psk=True, tickets=[client0.tickets[0].uncreate()])
    client = build_client(sni=hostname, options=options)
    with socket.create_connection((hostname, port)) as csock:
        client.connect_socket(csock)
        client.send(request)
        response = client.recv(2 ** 16)
    print(f'success with ticket and no ECH: {response}')

    # ECH, no ticket
    # options = DEFAULT_CLIENT_OPTIONS.replace(ech_configs=client0.ech_configs[:1])
    # #client = build_client(sni=hostname, ech_config=client0.ech_configs[0]) # works
    # client = build_client(sni=hostname, options=options) # doesnt work
    #
    # with socket.create_connection((hostname, port)) as csock:
    #     client.connect_socket(csock)
    #     client.send(request)
    #     response = client.recv(2 ** 16)
    # print(f'success with ECH and no ticket: {response}')

    # ECH and ticket
    # options = DEFAULT_CLIENT_OPTIONS.replace(ech_configs=client0.ech_configs[:1], send_psk=True, tickets=[client0.tickets[1].uncreate()])
    # client = build_client(sni=hostname, options=options)
    # with socket.create_connection((hostname, port)) as csock:
    #     client.connect_socket(csock)
    #     client.send(request)
    #     response = client.recv(2 ** 16)
    # print(f'success with ECH and ticket: {response}')



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

    # test_ech_with_ticket()

    test = ProofTest(num_servers, rseed=rseed)

    # with open('prover_outer', 'rb') as f:
    #     prover_trans = ClientHelloHandshake.unpack(f.read())
    #
    # with open('server_outer', 'rb') as f:
    #     server_trans = ClientHelloHandshake.unpack(f.read())

    # test.run()
    test.run_on_real_server()

