#!/bin/bash

set -e

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START_PORT=9000

if [ -z "${BENCHMARK_SERVER_IP}" ]; then
    echo -e "${RED}Environment variable 'BENCHMARK_SERVER_IP' is not set. Run:\n    export BENCHMARK_SERVER_IP=<IP>${RESET}"
    exit 1
fi
if [ -z "${BENCHMARK_PROVER_IP}" ]; then
    echo -e "${RED}Environment variable 'BENCHMARK_PROVER_IP' is not set. Run:\n    export BENCHMARK_PROVER_IP=<IP>${RESET}"
    exit 1
fi

SERVER_IP="${BENCHMARK_SERVER_IP}"
PROVER_IP="${BENCHMARK_PROVER_IP}"

cd $PROJECT_ROOT
source venv/bin/activate
cd ./src/python

values=(1 10 20 30 40 50 60 70 80 90 100)

for i in "${values[@]}"; do
    server_file="servers_${i}_v"
    {
        for ((j=0; j<i; j++)); do
            PORT=$((START_PORT + j))
            echo "${SERVER_IP}:${PORT}"
        done
    } > "${server_file}"

    echo -e "${GREEN}Starting verifier benchmarking, ${i} servers${RESET}"
    python3 -m tickettohide.run_verifier "${server_file}" -prover_host="${BENCHMARK_PROVER_IP}"
    rm "${server_file}"
done

echo -e "${GREEN}Benchmarking complete.${RESET}"
