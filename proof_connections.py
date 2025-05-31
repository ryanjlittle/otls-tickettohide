"""Managers for network connections between the prover and the verifier, and between the prover and servers.
This should probably be better integrated with the Connection code in tls_records.py
"""
import socket
from abc import ABC, abstractmethod

from proof_common import *
from proof_spec import ProverMsg, VerifierMsg
from spec import force_write, UnpackError
from tls_client import Client
from tls_common import *


class MsgWriter(ABC):
    def __init__(self, out_file):
        self._out_file = out_file

    def send_msg(self, typ, payload):
        raw = self._get_raw(typ, payload)
        assert raw is not None
        force_write(self._out_file, raw)
        logger.info(f'sent message to {self._recipient}: {raw}')

    @abstractmethod
    def _get_raw(self, type, payload):
        pass

class MsgReader(ABC):
    def __init__(self, in_file):
        self._in_file = in_file

    def recv_msg(self):
        message = self._read_object(self._msgtype)
        return message

    @abstractmethod
    def _read_object(self, typ):
        pass

class ProverMsgWriter(MsgWriter):
    """Writes prover messages to be sent to the verifier"""
    def __init__(self, outfile):
        super().__init__(outfile)
        self._recipient = 'verifier'

    def _get_raw(self, type, payload):
        return ProverMsg.pack(type, payload)

class VerifierMsgWriter(MsgWriter):
    """Writes prover messages to be sent to the verifier"""
    def __init__(self, outfile):
        super().__init__(outfile)
        self._recipient = 'prover'

    def _get_raw(self, type, payload):
        return VerifierMsg.pack(type, payload)

class ProverMsgReader(MsgReader):
    """Reads messages sent by the prover, to be read by the verifier"""
    def __init__(self, infile):
        super().__init__(infile)
        self._msgtype = ProverMsg

    def _read_object(self, type):
        try:
            return ProverMsg.unpack_from(self._in_file)
        except (UnpackError, EOFError) as e:
            raise VerifierError("error reading or unpacking record from prover") from e

class VerifierMsgReader(MsgReader):
    """Reads messages sent by the verifier, to be read by the prover"""
    def __init__(self, infile):
        super().__init__(infile)
        self._msgtype = VerifierMsg

    def _read_object(self, type):
        try:
            return VerifierMsg.unpack_from(self._in_file)
        except (UnpackError, EOFError) as e:
            raise ProverError("error reading or unpacking record from verifier") from e

class ProverConnection:
    """Manages connection to the prover from the verifier."""
    def __init__(self, prover_host, prover_port):
        self._prover_host = prover_host
        self._prover_port = prover_port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._write_file = self._sock.makefile('wb')
        self._read_file = self._sock.makefile('rb')
        self._reader = ProverMsgReader(self._read_file)
        self._writer = VerifierMsgWriter(self._write_file)
        self._connected = False

    def __del__(self):
        """Fallback way to close the socket. The expected use is to close the ProverConnection manually when it's no
        longer needed. If that doesn't happen, this closes the socket when the object is deleted."""
        self.close()

    def close(self):
        self._read_file.close()
        self._write_file.close()
        self._sock.close()

    def connect(self):
        if self._connected:
            raise VerifierError("already connected, can't connect again")
        try:
            print((self._prover_host, self._prover_port))
            self._sock.connect((self._prover_host, self._prover_port))
        except ConnectionRefusedError:
            raise VerifierError(f"couldn't connect to the prover on {self._prover_host}:{self._prover_port}. Did you start the prover?")
        self._connected = True
        logger.info(f'connected to prover on port {self._prover_port}')

    def send_msg(self, typ, payload):
        if not self._connected:
            raise VerifierError("can't send application data yet")
        logger.info(f'sending {typ} message to verifier')
        self._writer.send_msg(typ, payload)

    def recv_msg(self):
        if not self._connected:
            raise VerifierError("can't send application data yet")
        return self._reader.recv_msg()

class VerifierConnection:
    """Manages connection to the verifier from the prover."""
    def __init__(self, prover_host='localhost', prover_port=0):
        self._read_file = None
        self._writer = None
        self._reader = None
        self._verifier_port = None
        self._sock = None
        self._write_file = None
        self.host = prover_host
        self.port = prover_port
        self._ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._bound = False
        self._listening = False
        self._connected = False

    def __del__(self):
        """Fallback way to close the socket. The expected use is to close the connection manually when it's no
        longer needed. If that doesn't happen, this closes the socket when the object is deleted."""
        self.close()

    def close(self):
        if self._read_file is not None:
            self._read_file.close()
        if self._write_file is not None:
            self._write_file.close()
        self._ssock.close()

    def bind(self):
        if self._bound:
            raise ProverError('connection already bound')
        self._ssock.bind((self.host, self.port))
        if self.port == 0:
            self.port = self._ssock.getsockname()[1]
        self._bound = True
        logger.info(f'prover bound to {self.host}:{self.port}')


    def accept(self):
        if not self._bound:
            raise ProverError('need to bind connection before accepting')
        self._ssock.listen(1)
        logger.info('prover listening for verifier')
        self._listening = True
        self._sock, self._verifier_port = self._ssock.accept()
        logger.info('connected to verifier')
        self._write_file = self._sock.makefile('wb')
        self._read_file = self._sock.makefile('rb')
        self._reader = VerifierMsgReader(self._read_file)
        self._writer = ProverMsgWriter(self._write_file)

    def send_msg(self, typ, payload):
        if not self._connected:
            raise VerifierError("can't send application data yet")
        logger.info(f'sending {typ} message to prover')
        self._writer.send_msg(typ, payload)

    def recv_msg(self):
        message = self._reader.recv_msg()
        if not self._connected:
            self._connected = True
        return message

def obtain_tickets(server_id):
    host = server_id.hostname
    port = server_id.port
    client = Client.build(host)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            raise ProverError(f"couldn't connect to the server on {host}:{port}. Did you start the server?")
        client.connect_socket(sock) # Does handshake but doesn't process tickets
        client._rreader.fetch()  # Fetch first ticket
        client.send(b'x')  # Just a dummy message
    return client.tickets