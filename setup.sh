#!/bin/bash

GREEN="\033[0;32m"
RESET="\033[0m"

set -e 

python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}Installing Python dependencies...${RESET}"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}Generating specification code files...${RESET}"
python3 -m tls13.tls13_spec_gen
python3 -m tickettohide.proof_spec_gen

echo -e "${GREEN}Running tests${RESET}"
python3 -m tls13.test_client_server
python3 -m tls13.test_specs

echo -e "${GREEN}Python setup complete${RESET}"
