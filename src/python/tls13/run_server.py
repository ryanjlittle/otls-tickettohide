#!/usr/bin/env python3
import argparse
from time import perf_counter

from tls13.tls_records import CloseNotifyException
from tls13.tls_server import *


@dataclass
class BasicServer:
    hostname: str = 'localhost'
    port: int = 9000
    max_connections: int = 3
    secrets: ServerSecrets = field(init=False)
    ticketer: ServerTicketer = field(init=False, default_factory=ServerTicketer)
    count: int = field(init=False, default=0)
    threads: list[threading.Thread] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self.secrets = gen_server_secrets(self.hostname)

    def _handle_client(self, conn: socket, addr: Any, msg: str):
        svr = Server(self.secrets, self.ticketer)
        start = perf_counter()
        svr.connect_socket(conn)
        stop = perf_counter()
        logger.info(f'handshake completed in {stop - start} seconds')
        try:
            req = svr.recv(1024)
            logger.info(f'received application traffic message: {req}')
        except CloseNotifyException:
            conn.close()
            return
        logger.info('sending response')
        start = perf_counter()
        response_contents = msg.encode('utf8')
        response = '\r\n'.join([
            'HTTP/1.0 200 OK',
            'Content-type: text/plain',
            f'Content-Length: {len(response_contents)}',
            '\r\n',
        ]).encode('utf8') + response_contents
        svr.send(response)
        conn.close()
        stop = perf_counter()
        logger.info(f'response sent in {stop - start} seconds')

    def serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ssock:
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ssock.bind((self.hostname, self.port))
            ssock.listen()
            logger.info(f'listening on port {self.port}')
            while self.count < self.max_connections:
                self.count += 1
                msg = f'Hello, you are client #{self.count}'
                conn, addr = ssock.accept()
                logger.info(f'got connection from {addr}')
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr, msg),
                    daemon=True
                )
                self.threads.append(thread)
                thread.start()
        for thread in self.threads:
            thread.join()

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

