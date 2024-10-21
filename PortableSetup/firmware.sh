#!/usr/bin/env bash

# cd to script path
cd $(readlink -e $(dirname ${BASH_SOURCE[0]:-$0}))

source ./scripts/python_env.sh

if [ "$1" == "central" ]
then
	shift
	cd firmware_central
	./firmware.py $@
elif [ "$1" == "peripheral" ]
then
	shift
	cd firmware_peripheral
	./firmware.py $@
else
	echo "provide firmware name: \"./firmware.sh central\" or \"./firmware.sh peripheral\""
fi
