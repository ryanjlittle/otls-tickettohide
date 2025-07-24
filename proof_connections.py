"""Managers for network connections between the prover and the verifier, and between the prover and servers.
This should probably be better integrated with the Connection code in tls_records.py
"""
import socket

from proof_common import *
from proof_spec import ProverMsg, VerifierMsg
from spec import force_write, UnpackError, LimitReader
from tls13_spec import Record, ContentType, ClientOptions
from tls_client import ClientConnection, connect_client
from tls_common import *
from tls_records import RecordReader


class MsgWriter(ABC):
    def __init__(self, out_file):
        self._out_file = out_file

    def send_msg(self, msg):
        # raw = self._get_raw(typ, payload)
        # assert raw is not None
        msg.pack_to(self._out_file)
        #force_write(self._out_file, raw)
        logger.info(f'sent {msg.typ} message to {self._recipient}: {msg.pack()}')


class MsgReader():
    def __init__(self, in_file):
        self._in_file = in_file

    def recv_msg(self):
        try:
            msg = self._msg_type.unpack_from(self._in_file)
        except (UnpackError, EOFError) as e:
            raise VerifierError(f'error reading or unpacking record from {self._sender}') from e
        logger.info(f'received message of type {msg.typ} from {self._sender}')
        return msg


class ProverMsgWriter(MsgWriter):
    """Writes prover messages to be sent to the verifier"""
    _recipient = 'verifier'


class VerifierMsgWriter(MsgWriter):
    """Writes prover messages to be sent to the verifier"""
    _recipient = 'prover'


class ProverMsgReader(MsgReader):
    """Reads messages sent by the prover, to be read by the verifier"""
    _msg_type = ProverMsg
    _sender = 'prover'


class VerifierMsgReader(MsgReader):
    """Reads messages sent by the verifier, to be read by the prover"""
    _msg_type = VerifierMsg
    _sender = 'verifier'


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

    def send_msg(self, msg):
        if not self._connected:
            raise VerifierError("can't send application data yet")
        self._writer.send_msg(msg)

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

    def send_msg(self, msg):
        if not self._connected:
            raise VerifierError("can't send application data yet")
        self._writer.send_msg(msg)

    def recv_msg(self):
        message = self._reader.recv_msg()
        if not self._connected:
            self._connected = True
        return message
    
class ProverRecordReader(RecordReader):
    """A record reader that can buffer encrypted records without immediately decrypting them"""

    def __init__(self, file, transcript, app_data_buffer):
        super().__init__(file, transcript, app_data_buffer)
        self.buffered_records = []
    
    def buffer_encrypted_record(self):
        logger.info('trying to fetch an encrypted record from the incoming stream')
        try:
            record = Record.unpack_from(self._file)
        except (UnpackError, EOFError) as e:
            raise TlsError("error unpacking record from server") from e

        (typ,vers), payload = record
        logger.info(f'Fetched a length-{len(payload)} record of type {typ}')
        self.buffered_records.append(record)

    def buffer_encrypted_records(self, num_records):
        for _ in range(num_records):
            self.buffer_encrypted_record()
    
    def process_buffered_records(self):
        while len(self.buffered_records) > 0:
            record = self.buffered_records[0]
            typ, payload = self._unwrap_record(record)
            logger.info(f'decrypting buffered record of length {len(payload)}')

            match typ:
                case ContentType.CHANGE_CIPHER_SPEC:
                    pass  # ignore these ones
                case ContentType.ALERT:
                    raise TlsError(f"Received ALERT: {payload}")
                case ContentType.HANDSHAKE:
                    try:
                        # If we can't decrypt the message, leave it in the buffer and try later
                        self.hs_buffer.add(payload)
                    except ProverError:
                        break
                case ContentType.APPLICATION_DATA:
                    self._app_data_buffer.add(payload)
                case _:
                    raise TlsError(f"Unexpected message type {typ} received")

            self.buffered_records.pop(0)

    def get_next_record(self):
        if len(self.buffered_records) > 0:
            logger.warning('attempting to get new encrypted record when buffer is not empty')
        return super().get_next_record()

def obtain_tickets(server_id):
    host = server_id.hostname
    port = server_id.port

    with connect_client(host, port) as client:
        client._rreader.fetch() # Fetch first ticket
        client.send(b'x') # Just a dummy message

    return client.tickets
