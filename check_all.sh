#!/usr/bin/env bash
set -euo pipefail
source venv/bin/activate
python3 ./tls13_spec_gen.py # re-generate tls13_spec.py
mypy --strict *.py # perform static type checks
python3 ./test_specs.py
python3 ./test_example.py
python3 ./test_client_server.py
echo "ALL CHECKS PASSED!"
