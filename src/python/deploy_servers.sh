#!/bin/bash

NUM_SERVERS="$1"
START_PORT="$2"

if [[ -z "$NUM_SERVERS" || -z "$START_PORT" ]]; then
    echo "Usage: $0 <num_servers> <start_port>"
    exit 1
fi

if [ ! -d "venv" ]; then
  echo "venv directory not found. Run setup.sh first"
  exit 1
fi
source venv/bin/activate

if [ ! -d "logs" ]; then
  mkdir logs
fi

for ((i=0; i<NUM_SERVERS; i++)); do
    PORT=$((START_PORT + i))

    # Launch and log output
    python3 -m tls13.run_server "$PORT" -hostname "0.0.0.0" -max_connections 3 > "logs/server_${PORT}.log" 2>&1 &
    echo "Started server on port $PORT (log: logs/server_${PORT}.log)"
done

echo "All servers launched."

wait

echo "All servers closed."
