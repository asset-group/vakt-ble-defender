#!/usr/bin/env bash

# Get script current path
CURRENT_PATH="$(readlink -e $(dirname ${BASH_SOURCE[0]:-$0}))"
export PATH="$CURRENT_PATH/../runtime/python/install/bin/:$PATH"

alias pip3="python3 -m pip"
alias pio="~/.platformio/penv/bin/pio"
alias platformio="~/.platformio/penv/bin/platformio"
