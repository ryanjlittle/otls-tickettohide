#!/usr/bin/env python3

from dataclasses import dataclass, field
from typing import Any
import socket
import logging

from spec import *
from tls13_spec import *
from tls_common import *
from tls_crypto import *
from tls_keycalc import *
from tls_server import *

@dataclass
class Experiment:
    hostname: str = 'localhost'
    port: int = 8000
    secrets: ServerSecrets = field(init=False)
    ticketer: ServerTicketer = field(init=False, default_factory=ServerTicketer)
    count: int = field(init=False, default=0)
    last_svr: Server|None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.secrets = gen_server_secrets(self.hostname)

    def connect(self, msg:str|None=None) -> None:
        self.count += 1
        if msg is None:
            msg = f'connection #{self.count}'
        svr = Server(self.secrets, self.ticketer)
        self.last_svr = svr
        with socket.create_server((self.hostname, self.port)) as ssock:
            logger.info(f'listening on port {self.port}')
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

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    exp = Experiment()
    exp.connect()
