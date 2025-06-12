#!/usr/bin/env python3

"""Program to do some ECH experiments/exploration from the client side."""

from typing import Self, BinaryIO
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import socket

from tls_common import *
from util import pp
from spec import LimitReader
from tls13_spec import (
    Record,
    Version,
    ContentType,
    ClientHelloHandshake,
    ServerHelloHandshake,
    ServerNameClientExtension,
    ECHConfigVariant,
)
from tls_client import build_client, build_client_hello

@dataclass
class RecordStream:
    src: LimitReader

    def fetch(self) -> Record:
        return Record.unpack_from(self.src)


@dataclass
class ExCl:
    chello: ClientHelloHandshake
    hostname: str
    port: int

    @classmethod
    def create(cls, chello: ClientHelloHandshake, hostname: str|None=None, port: int=443) -> Self:
        if hostname is None:
            for ext in chello.data.extensions.uncreate():
                match ext:
                    case ServerNameClientExtension() as sni_ext:
                        hostname = sni_ext.data[0].host_name
                        break
            else:
                raise ValueError("no hostname specified and no SNI found")
        assert hostname is not None
        return cls(chello,hostname,port)

    @contextmanager
    def stream(self) -> Iterator[RecordStream]:
        ch_record = Record.create(
            typ = ContentType.HANDSHAKE,
            version = Version.TLS_1_0,
            payload = self.chello.pack(),
        )

        with socket.create_connection((self.hostname, self.port)) as csock:
            writer = csock.makefile('wb')
            reader = csock.makefile('rb')
            ch_record.pack_to(writer)
            yield RecordStream(LimitReader(reader))

    def get_two_records(self) -> tuple[Record,Record]:
        with self.stream() as stream:
            first = stream.fetch()
            second = stream.fetch()
            if second.typ == ContentType.CHANGE_CIPHER_SPEC:
                second = stream.fetch()
            return (first, second)

def get_ech_configs(hostname: str, port: int=443) -> list[ECHConfigVariant]:
    client = build_client(sni=hostname)
    with socket.create_connection((hostname,port)) as csock:
        client.connect_socket(csock)
    return client.handshake.ech_configs


if __name__ == '__main__':
    hostname = 'defo.ie'
    port = 443

    configs = get_ech_configs(hostname, port)
    ch, sec = build_client_hello(sni=hostname, ech_config=configs[0])
    shrec, seerec = ExCl.create(ch).get_two_records()
    assert shrec.typ == ContentType.HANDSHAKE
    sh = ServerHelloHandshake.unpack(shrec.payload)
    assert seerec.typ == ContentType.APPLICATION_DATA
