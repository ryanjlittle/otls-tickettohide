#!/bin/bash

set -e

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCHMARK_FILE="${PROJECT_ROOT}/benchmarks/results_$(date +%s).csv"

if [ -z "${BENCHMARK_SERVER_IP}" ]; then
    echo -e "${RED}Environment variable 'BENCHMARK_SERVER_IP' is not set. Run:\n    export BENCHMARK_SERVER_IP=<IP>${RESET}"
    exit 1
fi

SERVER_IP="${BENCHMARK_SERVER_IP}"
START_PORT=9000

cd $PROJECT_ROOT
source venv/bin/activate
cd ./src/python

values=(1 10 20 30 40 50 60 70 80 90 100)

for i in "${values[@]}"; do
    server_file="servers_${i}_p"
    {
        for ((j=0; j<i; j++)); do
            PORT=$((START_PORT + j))
            echo "${SERVER_IP}:${PORT}"
        done
    } > "${server_file}"

    secrets_file="secrets_${i}"
    {
        echo "0"
        for ((j=0; j<$i; j++)); do
            base64 <<< "test test test test test test test test test test test test test test test test test test test test test test test test test tes"
        done
    } > "${secrets_file}"


    echo -e "${GREEN}Starting prover benchmarking, ${i} servers${RESET}"
    python3 -m tickettohide.run_prover "${server_file}" "${secrets_file}" "${BENCHMARK_FILE}"

    rm "${server_file}" "${secrets_file}"
done

echo -e "${GREEN}Benchmarking complete.\n Results stored in ${BENCHMARK_FILE} ${RESET}"
