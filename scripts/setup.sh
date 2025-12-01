#!/bin/bash

set -e

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd $PROJECT_ROOT

export OPENSSL_ROOT_DIR=/usr/include/openssl

if [ $# -ne 1 ]; then
    echo -e "${RED}Usage: $0 [-debug|-release]${RESET}"
    exit 1;
fi

if [ "$1" == "-debug" ]; then
  BUILD_TYPE="Debug"
elif [ "$1" == "-release" ]; then
  BUILD_TYPE="Release";
else
  echo -e "${RED}Error: build type must be 'debug' or 'release'${RESET}"
  exit 1
fi

# Install and build primus-emp
if [ -d "primus-emp" ]; then
  echo -e "${YELLOW}Found existing primus-emp installation, skipping compilation.${RESET}"
else
  echo -e "${GREEN}Installing EMP toolkit (Primus lab fork)...${RESET}"
  git clone https://github.com/primus-labs/primus-emp.git
  cd primus-emp
  git checkout 72f3f4f5a5c22a1cd008b27b233c4021f733b978
  echo -e "${GREEN}Compiling EMP toolkit...${RESET}"
  bash compile.sh -$BUILD_TYPE
  cd ..
fi

# Compile C++ code
echo -e "${GREEN}Compiling project C++ code...${RESET}"
bash src/cpp/compile.sh ./primus-emp -$BUILD_TYPE

# Install Python dependencies
echo -e "${GREEN}Installing Python dependencies...${RESET}"
python3.13 -m venv venv
source venv/bin/activate
cd src/python

pip install --upgrade pip
pip install -r requirements.txt

# Python configuration stuff
echo -e "${GREEN}Writing config file...${RESET}"
if [ "$1" == "debug" ]; then
  DEBUG_STR="True"
else
  DEBUG_STR="False"
fi
cat > config.py <<EOF
DEBUG=${DEBUG_STR}
MPC_EXECUTABLE_PATH="${PROJECT_ROOT}/build/bin/tickettohide"
EOF

echo -e "${GREEN}Generating specification code files...${RESET}"
python3 -m tls13.tls13_spec_gen
python3 -m tickettohide.proof_spec_gen

echo -e "${GREEN}Running tests...${RESET}"
python3 -m testing.test_client_server
python3 -m testing.test_specs
python3 -m testing.test_proof

echo -e "${GREEN}Setup complete!${RESET}"