#!/usr/bin/env python3
import argparse

from tls13.tls_records import CloseNotifyException
from tls13.tls_server import *


@dataclass
class BasicServer:
    hostname: str = 'localhost'
    port: int = 8000
    max_connections: int = 3
    secrets: ServerSecrets = field(init=False)
    ticketer: ServerTicketer = field(init=False, default_factory=ServerTicketer)
    count: int = field(init=False, default=0)
    last_svr: Server|None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.secrets = gen_server_secrets(self.hostname)

    def connect(self, msg:str|None=None) -> None:
        self.count += 1
        if msg is None:
            msg = f'Hello, you are client #{self.count}'
        svr = Server(self.secrets, self.ticketer)
        self.last_svr = svr
        with socket.create_server((self.hostname, self.port)) as ssock:
            logger.info(f'listening on port {self.port}')
            sock, addr = ssock.accept()
            logger.info(f'got connection from {addr}')
            svr.connect_socket(sock)
            logger.info('handshake complete')
            try:
                req = svr.recv(1024)
                logger.info(f'received application traffic message: {req}')
            except CloseNotifyException:
                sock.close()
                return
            logger.info('sending response')
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

    def serve(self):
        while self.count < self.max_connections:
            self.connect()
        logger.info(f'received {self.count} connections, shutting down')


def main():
    parser = argparse.ArgumentParser(description="Runs a server")

    parser.add_argument("port", type=int, help="port to listen on")
    parser.add_argument("-hostname", nargs="?", type=str, default="localhost", help="hostname to listen on")
    parser.add_argument("-max_connections", nargs="?", type=int, default=3, help="close after this many connections")

    args = parser.parse_args()

    server = BasicServer(hostname=args.hostname, port=args.port, max_connections=args.max_connections)
    server.serve()


if __name__ == '__main__':
    main()

