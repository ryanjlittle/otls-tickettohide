import argparse
import base64

from prover import Prover
from prover_crypto import ProverSecrets
from tls_common import *
from tls_server import ServerID

def main():
    parser = argparse.ArgumentParser(description="Runs the prover program")

    parser.add_argument("servers", help="File containing a list of server hostnames and ports")
    parser.add_argument("secrets", help="File containing the index of the real server and all secret queries")
    parser.add_argument("main_port", nargs="?", type=int, default=9000, help="Port for high-level communication with verifier")
    parser.add_argument("mpc_port", nargs="?", type=int, default=9001, help="Port for communicating with verifier for MPC computations")
    parser.add_argument("rseed", nargs="?", type=int, default=None, help="Random number generator seed")

    args = parser.parse_args()

    server_ids = []
    with open(args.servers, "r") as f:
        for line in f:
            hostname, port = line.strip().split(':')
            server_ids.append(ServerID(hostname, int(port)))

    with open(args.secrets, "rb") as f:
        index = int.from_bytes(f.readline().strip())
        queries = [base64.b64decode(s) for s in f.readlines()]

    prover_secrets = ProverSecrets(
        index=index,
        queries=queries
    )



    with Prover(server_ids, prover_secrets, port=args.main_port, mpc_port=args.mpc_port, rseed=args.rseed) as prover:
        prover.run()

if __name__ == '__main__':
    main()