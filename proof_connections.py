"""Managers for network connections between the prover and the verifier, and between the prover and servers.
This should probably be better integrated with the Connection code in tls_records.py
"""
import socket
from io import BufferedReader, BufferedWriter
from typing import BinaryIO

from proof_common import *
from proof_spec import ProverMsgVariant, VerifierMsgVariant, ProverMsg, VerifierMsg
from spec import UnpackError, Spec
from tls13_spec import Record, ContentType
from tls_client import connect_client
from tls_common import *
from tls_records import RecordReader


class MsgWriter(ABC):
    recipient: str
    out_file: BinaryIO

    def __init__(self, out_file) -> None:
        self.out_file = out_file

    def send_msg(self, msg: ProverMsgVariant|VerifierMsgVariant) -> None :
        msg.pack_to(self.out_file)
        logger.info(f'sent {msg.typ} message to {self.recipient}: {msg.pack()}')

class MsgReader(ABC):
    sender: str
    in_file: BinaryIO

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
        if not self.connected:
            raise AttributeError("not connected")
        self.writer.send_msg(msg)

    def recv_msg(self) -> ProverMsgVariant|VerifierMsgVariant:
        if not self.connected:
            raise AttributeError("not connected")
        return self.reader.recv_msg()


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
        try:
            self.sock.getpeername()
            return True
        except OSError:
            return False

    def connect(self) -> None:
        if self.connected:
            raise AttributeError("already connected, can't connect again")
        try:
            self.sock.connect((self.hostname, self.port))
        except ConnectionError:
            raise VerifierError(f"couldn't connect to prover on {self.hostname}:{self.port}. Is the prover running?")

        logger.info(f'connected to prover')


class VerifierConnection(AbstractConnection):
    """Manages connection to the verifier from the prover."""
    conn: socket.socket | None = None
    listening: bool = False

    def create_socket(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @override
    def close(self) -> None:
        super().close()
        if self.connected:
            self.conn.close()

    @override
    @property
    def connected(self) -> bool:
        return self.conn is not None

    def listen(self) -> None:
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


#     message = self._reader.recv_msg()
#     if not self._connected:
#         self._connected = True
#     return message

    # def accept(self):
    #     if not self._bound:
    #         raise ProverError('need to bind connection before accepting')
    #     self.sock.listen(1)
    #     logger.info('prover listening for verifier')
    #     self._listening = True
    #     self._sock, self._verifier_port = self.sock.accept()
    #     logger.info('connected to verifier')
    #     self._write_file = self._sock.makefile('wb')
    #     self._read_file = self._sock.makefile('rb')
    #     self._reader = VerifierMsgReader(self._read_file)
    #     self._writer = ProverMsgWriter(self._write_file)

    # def send_msg(self, msg):
    #     if not self._connected:
    #         raise VerifierError("can't send application data yet")
    #     self._writer.send_msg(msg)
    #
    # def recv_msg(self):
    #     message = self._reader.recv_msg()
    #     if not self._connected:
    #         self._connected = True
    #     return message
    
# class ProverRecordReader(RecordReader):
#     """A record reader that can buffer encrypted records without immediately decrypting them"""
#
#     def __init__(self, file, transcript, app_data_buffer):
#         super().__init__(file, transcript, app_data_buffer)
#         self.buffered_records = []
#
#     def buffer_encrypted_record(self):
#         logger.info('trying to fetch an encrypted record from the incoming stream')
#         try:
#             record = Record.unpack_from(self.file)
#         except (UnpackError, EOFError) as e:
#             raise TlsError("error unpacking record from server") from e
#
#         (typ,vers), payload = record
#         logger.info(f'Fetched a length-{len(payload)} record of type {typ}')
#         self.buffered_records.append(record)
#
#     def buffer_encrypted_records(self, num_records):
#         for _ in range(num_records):
#             self.buffer_encrypted_record()
#
#     def process_buffered_records(self):
#         while len(self.buffered_records) > 0:
#             record = self.buffered_records[0]
#             typ, payload = self._unwrap_record(record)
#             logger.info(f'decrypting buffered record of length {len(payload)}')
#
#             match typ:
#                 case ContentType.CHANGE_CIPHER_SPEC:
#                     pass  # ignore these ones
#                 case ContentType.ALERT:
#                     raise TlsError(f"Received ALERT: {payload}")
#                 case ContentType.HANDSHAKE:
#                     try:
#                         # If we can't decrypt the message, leave it in the buffer and try later
#                         self.hs_buffer.add(payload)
#                     except ProverError:
#                         break
#                 case ContentType.APPLICATION_DATA:
#                     self._app_data_buffer.add(payload)
#                 case _:
#                     raise TlsError(f"Unexpected message type {typ} received")
#
#             self.buffered_records.pop(0)
#
#     def get_next_record(self):
#         if len(self.buffered_records) > 0:
#             logger.warning('attempting to get new encrypted record when buffer is not empty')
#         return super().get_next_record()
#
# def obtain_ticket(server_id):
#     host = server_id.hostname
#     port = server_id.port
#
#     with connect_client(host, port) as client:
#         client._rreader.fetch() # Fetch first ticket
#         client.send(b'x') # Just a dummy message
#
#     return client.tickets
