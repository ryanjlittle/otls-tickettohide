import argparse
import time

from tls13.tls_common import *
from tls13.tls_server import ServerID

from tickettohide.verifier import Verifier


def main():
    parser = argparse.ArgumentParser(description="Runs the verifier program")

    parser.add_argument("servers", help="File containing a list of server hostnames and ports")
    parser.add_argument("prover_host", nargs="?", default="localhost", help="Prover hostname")
    parser.add_argument("main_port", nargs="?", type=int, default=9000, help="Port for high-level communication with prover")
    parser.add_argument("mpc_port", nargs="?", type=int, default=9001, help="Port for communicating with prover for MPC computations")
    parser.add_argument("rseed", nargs="?", type=int, default=None, help="Random number generator seed")

    args = parser.parse_args()

    server_ids = []
    with open(args.servers, "r") as f:
        for line in f:
            hostname, port = line.strip().split(':')
            server_ids.append(ServerID(hostname, int(port)))


    with Verifier(server_ids, args.prover_host, args.main_port, args.mpc_port, rseed=args.rseed) as verifier:
        start = time.perf_counter()
        verifier.run()
        stop = time.perf_counter()
        print(f'Elapsed time: {stop - start:.6f}')

if __name__ == '__main__':
    main()