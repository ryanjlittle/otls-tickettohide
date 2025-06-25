#!/usr/bin/env python3

"""Runs a local example test based on <https://tls13.xargs.org/>.

Be sure to download the example data files first by running

    git clone https://github.com/syncsynchalt/illustrated-tls13
"""

from pathlib import Path
from spec import LimitReader
from tls13_spec import ClientSecrets, ClientHelloHandshake, Record
from tls_client import ClientConnection
from io import BytesIO
import argparse
import logging

logger = logging.getLogger('test_example')

class Example:
    capdir = Path() / 'illustrated-tls13' / 'captures' / 'caps'

    def __init__(self) -> None:
        if not self.capdir.exists():
            raise FileNotFoundError('download example: git clone https://github.com/syncsynchalt/illustrated-tls13')
        self.client_hello = ClientHelloHandshake.unpack(
            Record.unpack_from(
                LimitReader((self.capdir / 'clienthello').open('rb'))
            ).payload
        )
        self.all_from_client = b''.join((self.capdir / fname).read_bytes() for fname in [
            'clienthello',
            'clientccs',
            'clientencfinished',
            'clientencdata',
        ])
        self.all_from_server = b''.join((self.capdir / fname).read_bytes() for fname in [
            'serverhello',
            'serverccs',
            'serverencextensions',
            'serverenccert',
            'serverenccertverify',
            'serverencfinished',
            'serverencticket1',
            'serverencticket2',
            'serverencdata',
        ])
        self.from_client = BytesIO()
        self.from_server = BytesIO(self.all_from_server)
        self.client_secret = bytes(32+i for i in range(32))
        self._started = False
        self._connected = False

    def go(self) -> None:
        self.start()
        self.connect()
        self.send()
        self.recv()
        self.check()

    def start(self) -> None:
        if not self._started:
            logger.info("starting client (preprocess client hello)")
            self.client = ClientConnection.create(
                ch = self.client_hello,
                secrets = ClientSecrets.create(
                    kex_sks = [self.client_secret],
                    psk = None,
                    inner_ch = None,
                ),
            )
            self._started = True

    def connect(self) -> None:
        self.start()
        if not self._connected:
            logger.info("connecting client (receive server replies)")
            self.client.connect_files(self.from_server, self.from_client)
            self._connected = True

    def send(self) -> None:
        if not self._connected:
            self.connect()
        logger.info("sending ping to server")
        sent = self.client.send(b'ping')
        assert sent == 4

    def recv(self) -> None:
        if not self._connected:
            self.connect()
        got = self.client.recv(4)
        logger.info(f"received {got.hex()} from server")
        assert got == b'pong'

    def check(self) -> None:
        assert self.from_client.getvalue() == self.all_from_client
        assert self.from_server.tell() == len(self.all_from_server)
        logger.info("example matches 100%")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = 'Perform three client-server tests on localhost',
    )
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level)
    Example().go()
    print("PASSED Illustrated TLS 1.3 example test")
