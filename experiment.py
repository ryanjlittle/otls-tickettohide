#!/usr/bin/env python3

from tls_common import *
from tls_crypto import *
from tls_keycalc import *
from tls_server import *


class Experiment:
    def __init__(self, hostname='localhost', port=8000):
        self._hostname = hostname
        self._port = port
        self._secrets = gen_server_secrets(self._hostname)
        self._ticketer = ServerTicketer()
        self._count = 0

    def connect(self, msg=None):
        self._count += 1
        if msg is None:
            msg = f'connection #{self._count}'
        svr = Server(self._secrets, self._ticketer)
        with socket.create_server((self._hostname, self._port)) as ssock:
            logger.info('listening on port {self._port}')
            sock, addr = ssock.accept()
            logger.info(f'got connection from {addr}')
            svr.connect_socket(sock)
            logger.info('handshake complete; sending response')
            response_contents = msg.encode('utf8')
            response = '\r\n'.join([
                'HTTP/1.0 200 OK',
                'Content-type: text/plain',
                f'Content-Length: {len(response_contents)}',
                '\r\n',
            ]).encode('utf8') + response_contents
            svr.send(response)
            sock.close()
            logger.info('response sent')
        return svr
