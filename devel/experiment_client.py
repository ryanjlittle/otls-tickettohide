#!/usr/bin/env python3

"""Program to do some ECH experiments/exploration from the client side."""

from typing import Self, BinaryIO
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import socket
from io import BytesIO

from tls_common import *
from util import pp
from spec import LimitReader
from tls13_spec import (
    Record,
    Version,
    ContentType,
    Handshake,
    ClientHelloHandshake,
    ServerHelloHandshake,
    EncryptedExtensionsHandshake,
    ServerNameClientExtension,
    KeyShareServerExtension,
    PreSharedKeyServerExtension,
    ECHConfigVariant,
    ClientSecrets,
)
from tls_client import build_client, build_client_hello
from tls_records import RecordTranscript, RecordReader, DataBuffer
from tls_keycalc import KeyCalc, HandshakeTranscript
from tls_crypto import get_hash_alg, get_kex_alg
from tls_ech import server_accepts_ech
from https_client import http_get_req

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

def decrypt_ee(cs: ClientSecrets, ch: ClientHelloHandshake, sh: ServerHelloHandshake, eee: Record) -> EncryptedExtensionsHandshake:
    assert len(cs.kex_sks) == 1
    hst = HandshakeTranscript()
    kc = KeyCalc(hst)

    csuite = sh.data.cipher_suite
    kc.cipher_suite = csuite
    kc.set_psk(None)

    for ext in sh.data.extensions.uncreate():
        match ext:
            case KeyShareServerExtension():
                group = ext.data.group
                kex = get_kex_alg(group)
                private = cs.kex_sks[0]
                kex_secret = kex.exchange(private, ext.data.pubkey)
                kc.set_kex_secret(kex_secret)
            case PreSharedKeyServerExtension():
                raise ValueError("can't handle PSK here")

    hst.add(ch, True)
    hst.add(sh, False)

    buf = BytesIO(eee.pack())
    rt = RecordTranscript(True)
    adb = DataBuffer()
    rr = RecordReader(buf, rt, adb)
    rr.rekey(csuite, kc.server_handshake_traffic_secret)

    ee = rr.get_next_record()
    assert ee.typ == ContentType.HANDSHAKE
    match Handshake.unpack_from(LimitReader.from_raw(ee.payload)).variant:
        case EncryptedExtensionsHandshake() as eeh:
            return eeh
        case other:
            raise ValueError(f"expected ee, got {other}")



if __name__ == '__main__':
    #hostname, port = 'google.com', 443
    #hostname, port = 'localhost', 8000
    #hostname, port = 'defo.ie', 443
    #hostname, port = 'tls-ech.dev', 443
    #hostname, port = 'opensubtitles.org', 443
    #hostname, port = 'cloudflare-ech.com', 443
    #hostname, port = 'test.defo.ie', 443
    hostname, port = 'www.w3.org', 443
    if False:
        ch, sec = build_client_hello(sni=hostname)
        shrec, seerec = ExCl.create(ch, port=port).get_two_records()
        assert shrec.typ == ContentType.HANDSHAKE
        sh = ServerHelloHandshake.unpack(shrec.payload)
        assert seerec.typ == ContentType.APPLICATION_DATA
        ee = decrypt_ee(sec, ch, sh, seerec)
        print(f'got ee from {hostname}')

    if False:
        configs = get_ech_configs(hostname, port)
        print(f'got {len(configs)} ech configs from {hostname}')
        ch, sec = build_client_hello(sni=hostname, ech_config=configs[0])
        shrec, seerec = ExCl.create(ch, port=port).get_two_records()
        assert shrec.typ == ContentType.HANDSHAKE
        sh = ServerHelloHandshake.unpack(shrec.payload)
        assert seerec.typ == ContentType.APPLICATION_DATA
        print(f'got two records from {hostname}')

    if False:
        configs = get_ech_configs(hostname, port)
        print(f'got {len(configs)} ech configs from {hostname}')
        ch, sec = build_client_hello(sni=hostname, ech_config=configs[0])
        inner_ch = sec.inner_ch.data
        assert inner_ch is not None
        shrec, seerec = ExCl.create(ch, port=port).get_two_records()
        assert shrec.typ == ContentType.HANDSHAKE
        sh = ServerHelloHandshake.unpack(shrec.payload)
        assert seerec.typ == ContentType.APPLICATION_DATA
        print(f'got two records from {hostname}')
        if server_accepts_ech(inner_ch, sh):
            print(f'SERVER ACCEPTED ECH!!!')
            ee = decrypt_ee(sec, inner_ch, sh, seerec)
        else:
            print('server REJECTED ech')
            ee = decrypt_ee(sec, ch, sh, seerec)
        print(f'got ee from {hostname}')

    if True:
        client0 = build_client(sni=hostname)
        with socket.create_connection((hostname,port)) as csock:
            client0.connect_socket(csock)
        assert client0.ech_configs
        ech_config = client0.ech_configs[0]
        print("Initial connection successful; got ECH config")

        client = build_client(sni=hostname, ech_config=ech_config)
        request = http_get_req(hostname, '/')
        with socket.create_connection((ech_config.data.public_name, port)) as csock:
            client.connect_socket(csock)
            client.send(request)
            response = client.recv(2**16)
            csock.close()
        print("Second connection worked! Response below")
        print()
        print(response.decode())
