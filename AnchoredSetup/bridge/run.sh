#!/usr/bin/env bash

# Import standalone python3 environment
source scripts/python_env.sh

if [ $# -eq 0 ]; then
    echo "Usage: $0 <MAC_address>"
    exit 1
fi

export peripheral_address="$1"

shift
sudo -E env PATH=$PATH python3 ./src/BLEDefender.py $@
