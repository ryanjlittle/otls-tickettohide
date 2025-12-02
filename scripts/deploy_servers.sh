#!/bin/bash

set -e

GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

NUM_SERVERS="$1"
START_PORT="$2"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGGING=false
LOG_DIR=""
echo "$PROJECT_ROOT"
if [[ -z "$NUM_SERVERS" || -z "$START_PORT" ]]; then
    echo -e "${RED}Usage: $0 <num_servers> <start_port> [-l <log_dir>]${RESET}"
    exit 1
fi

shift 2
while getopts "l:" flag; do
  case "$flag" in
    l) LOGGING=true && LOG_DIR="$(pwd)/$OPTARG" ;;
  esac
done

cd $PROJECT_ROOT
if [ ! -d "venv" ]; then
  echo -e "${RED}venv directory not found. Run setup.sh first.${RESET}"
  exit 1
fi
source venv/bin/activate

if [ "$LOGGING" = true ] && [ ! -d "$LOG_DIR" ]; then
  mkdir "$LOG_DIR"
fi

cd src/python
for ((i=0; i<NUM_SERVERS; i++)); do
    PORT=$((START_PORT + i))

    # Launch and optionally log output
    if [ "$LOGGING" = true ]; then
      python3 -m tls13.run_server "$PORT" -hostname "0.0.0.0" -max_connections 3 > "${LOG_DIR}/server_${PORT}.log" 2>&1 &
      echo "Started server on port $PORT (log: ${LOG_DIR}/server_${PORT}.log)"
    else
      python3 -m tls13.run_server "$PORT" -hostname "0.0.0.0" &

      #      python3 -m tls13.run_server "$PORT" -hostname "0.0.0.0" -max_connections 3 &
      echo "Started server on port $PORT"
    fi
done

echo -e "${GREEN}All servers launched.${RESET}"

wait

echo -e "${GREEN}All servers closed.${RESET}"
