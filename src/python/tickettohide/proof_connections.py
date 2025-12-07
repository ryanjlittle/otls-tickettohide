"""Managers for network connections between the prover and the verifier, and between the prover and servers.
This should probably be better integrated with the Connection code in tls_records.py
"""
import socket
from io import BufferedReader, BufferedWriter
from time import sleep
from typing import BinaryIO

from tls13.spec import UnpackError
from tls13.tls_common import *

from tickettohide.proof_common import *
from tickettohide.proof_spec import ProverMsgVariant, VerifierMsgVariant, ProverMsg, VerifierMsg

class MsgWriter(ABC):
    recipient: str
    out_file: BinaryIO
    bytes_sent: int = 0

    def __init__(self, out_file) -> None:
        self.out_file = out_file

    def send_msg(self, msg: ProverMsgVariant|VerifierMsgVariant) -> None :
        msg.pack_to(self.out_file)
        self.bytes_sent += msg.packed_size()
        logger.info(f'sent {msg.typ} message to {self.recipient}: {msg.pack()}')

class MsgReader(ABC):
    sender: str
    in_file: BinaryIO
    bytes_received: int = 0

    def __init__(self, in_file) -> None:
        self._in_file = in_file

class ProverMsgWriter(MsgWriter):
    """Writes prover messages to be sent to the verifier"""
    recipient = 'verifier'

class VerifierMsgWriter(MsgWriter):
    """Writes prover messages to be sent to the verifier"""
    recipient = 'prover'

class ProverMsgReader(MsgReader):
    """Reads messages sent by the prover, to be read by the verifier"""
    msg_type = ProverMsg
    sender = 'prover'

    def recv_msg(self) -> ProverMsgVariant:
        try:
            msg = ProverMsg.unpack_from(self._in_file)
            self.bytes_received += msg.packed_size()
        except (UnpackError, EOFError) as e:
            raise Exception(f'error reading or unpacking record from {self.sender}') from e
        logger.info(f'received message of type {msg.typ} from {self.sender}')
        return msg.uncreate()


class VerifierMsgReader(MsgReader):
    """Reads messages sent by the verifier, to be read by the prover"""
    msg_type = VerifierMsg
    sender = 'verifier'

    def recv_msg(self) -> VerifierMsgVariant:
        try:
            msg = self.msg_type.unpack_from(self._in_file)
            self.bytes_received += msg.packed_size()
        except (UnpackError, EOFError) as e:
            raise Exception(f'error reading or unpacking record from {self.sender}') from e
        logger.info(f'received message of type {msg.typ} from {self.sender}')
        return msg.uncreate()


class AbstractConnection(ABC):
    hostname: str
    port: int
    sock: socket.socket | None = None
    wfile: BufferedWriter | None = None
    rfile: BufferedReader | None = None
    reader: MsgReader | None = None
    writer: MsgWriter | None = None

    def __init__(self, hostname: str, port: int) -> None:
        self.hostname = hostname
        self.port = port

    def __del__(self) -> None:
        """Fallback way to close the socket. The expected use is to close the ProverConnection manually when it's no
        longer needed. If that doesn't happen, this closes the socket when the object is deleted."""
        self.close()

    @abstractproperty
    def connected(self) -> bool: ...

    def close(self) -> None:
        if self.rfile is not None:
            self.rfile.close()
        if self.wfile is not None:
            self.wfile.close()
        if self.sock is not None:
            self.sock.close()

    def send_msg(self, msg: ProverMsgVariant|VerifierMsgVariant) -> None:
        if not self.connected or self.writer is None:
            raise AttributeError("not connected")
        self.writer.send_msg(msg)

    def recv_msg(self) -> ProverMsgVariant|VerifierMsgVariant:
        if not self.connected or self.reader is None:
            raise AttributeError("not connected")
        return self.reader.recv_msg()

    @property
    def bytes_sent(self) -> int:
        if not self.connected or self.writer is None:
            raise AttributeError("not connected")
        return self.writer.bytes_sent

    @property
    def bytes_received(self) -> int:
        if not self.connected or self.writer is None:
            raise AttributeError("not connected")
        return self.reader.bytes_received


class ProverConnection(AbstractConnection):
    """Manages connection to the prover from the verifier."""

    def create_socket(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.wfile = self.sock.makefile('wb')
        self.rfile = self.sock.makefile('rb')
        self.reader = ProverMsgReader(self.rfile)
        self.writer = VerifierMsgWriter(self.wfile)

    @override
    @property
    def connected(self) -> bool:
        if self.sock is None:
            return False
        try:
            self.sock.getpeername()
            return True
        except OSError:
            return False

    def connect(self) -> None:
        if self.connected:
            raise AttributeError("already connected, can't connect again")
        if self.sock is None:
            raise AttributeError("socket not created")
        logger.info(f'connecting to prover on {self.hostname}:{self.port}')

        # Repeatedly try to connect to prover until it succeeds
        while True:
            try:
                self.sock.connect((self.hostname, self.port))
                break
            except ConnectionError:
                sleep(1)
                self.create_socket()

        logger.info(f'connected to prover')


class VerifierConnection(AbstractConnection):
    """Manages connection to the verifier from the prover."""
    conn: socket.socket | None = None
    listening: bool = False

    def create_socket(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    @override
    def close(self) -> None:
        super().close()
        if self.connected and self.conn is not None:
            self.conn.close()

    @override
    @property
    def connected(self) -> bool:
        return self.conn is not None

    def listen(self) -> None:
        if self.sock is None:
            raise AttributeError("socket not created")
        self.sock.bind((self.hostname, self.port))
        logger.info(f'prover bound to {self.hostname}:{self.port}')
        self.listening = True
        self.sock.listen()

        self.conn, addr = self.sock.accept()
        self.listening = False
        logger.info(f'accepted connection from {addr}')
        self.wfile = self.conn.makefile('wb')
        self.rfile = self.conn.makefile('rb')
        self.reader = VerifierMsgReader(self.rfile)
        self.writer = ProverMsgWriter(self.wfile)
