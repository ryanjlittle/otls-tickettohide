from abc import ABC
import subprocess
from config import MPC_EXECUTABLE_PATH

""" This class is a wrapper for the real MPC implementation, which is written in C++ """
class TlsMpc(ABC):
    process: subprocess.Popen
    num_servers: int
    hostname: str|None
    port: int
    party: int

    def __init__(self, num_servers: int, port: int=8001, hostname: str|None=None):
        self.num_servers = num_servers
        self.hostname = hostname
        self.port = port

    def begin(self) -> None:
        if self.hostname is not None:
            args = [MPC_EXECUTABLE_PATH, str(self.party), str(self.num_servers), str(self.port), self.hostname]
        else:
            args = [MPC_EXECUTABLE_PATH, str(self.party), str(self.num_servers), str(self.port)]
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=0
        )

    def write_input(self, in_hex: str) -> None:
        if self.process.stdin is None:
            raise AttributeError("need to start subprocess before writing input")
        try:
            self.process.stdin.write(in_hex + '\n')
            self.process.stdin.flush()
        except BrokenPipeError:
            raise RuntimeError("Cannot write: subprocess closed stdin")

    def read_bytes_output(self) -> bytes:
        if self.process.stdout is None:
            raise AttributeError("need to start subprocess before reading output")
        return self.process.stdout.readline().rstrip()

    def read_hex_output(self) -> bytes:
        if self.process.stdout is None:
            raise AttributeError("need to start subprocess before reading output")
        hex_bytes = self.process.stdout.readline().strip()
        return bytes.fromhex(hex_bytes)

    def wait_until_connected(self) -> None:
        # a successful connection will print "connected" twice
        msg1 = self.read_bytes_output()
        msg2 = self.read_bytes_output()
        msg3 = self.read_bytes_output()
        if msg1 != "connected" or msg2 != "connected" or msg3 != "setup complete":
            raise RuntimeError("Connection failed")

    def reveal_and_prove(self) -> None:
        self.write_input("ok")

    def get_communication_amount(self) -> int:
        return int(self.read_bytes_output())

    def finish(self) -> int:
        # returns the exit code of the process
        return self.process.wait()

class ProverMPC(TlsMpc):
    party = 1

    def compute_handshake_secrets(self, index: int, transcript_hash: bytes) -> tuple[bytes, bytes, list[bytes]]:
        self.write_input(str(index))
        self.write_input(transcript_hash.hex())
        # MPC computation goes on in the background

        chts = self.read_hex_output()
        shts = self.read_hex_output()
        dummy_secrets = []
        for _ in range(self.num_servers):
            dummy_secrets.append(self.read_hex_output())
        return chts, shts, dummy_secrets

    def compute_master_secrets(self, transcript_hash: bytes) -> list[bytes]:
        self.write_input(transcript_hash.hex())
        # MPC computation goes on in the background

        dummy_secrets = []
        for _ in range(self.num_servers):
            dummy_secrets.append(self.read_hex_output())
        return dummy_secrets

    def compute_encryption(self, plaintext: bytes, adata: bytes) -> bytes:
        self.write_input(plaintext.hex())
        self.write_input(adata.hex())
        # MPC computation goes on in the background

        ciphertext = self.read_hex_output()
        return ciphertext

    def get_keys(self) -> tuple[bytes, bytes, bytes, bytes]:
        client_key = self.read_hex_output()
        client_iv = self.read_hex_output()
        server_key = self.read_hex_output()
        server_iv = self.read_hex_output()
        return client_key, client_iv, server_key, server_iv


class VerifierMPC(TlsMpc):
    party = 2

    def compute_handshake_secrets(self, handshake_secrets: list[bytes]) -> None:
        if len(handshake_secrets) != self.num_servers:
            raise ValueError("received wrong number of handshake secrets")
        for secret in handshake_secrets:
            self.write_input(secret.hex())
        # MPC computation goes on in the background

    def compute_master_secrets(self, master_secrets: list[bytes]) -> None:
        if len(master_secrets) != self.num_servers:
            raise ValueError("received wrong number of handshake secrets")
        for secret in master_secrets:
            self.write_input(secret.hex())
        # MPC computation goes on in the background

    def compute_encryption(self) -> None:
        # The MPC computation is carrying on in the background, nothing needs to happen here.
        # This function exists to serve as a guidepost for what the MPC is doing.
        pass