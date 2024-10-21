#!/usr/bin/env python

import serial
import time
from DongleUtils import FindDonglePort, NRF52Commands, ConnectionStatus

ser = serial.Serial('/dev/ttyACM0', 115200, rtscts=1)
# Send command
ser.write(NRF52Commands.NRF52_CMD_VERSION)
# Read command result
if ser.read_until(NRF52Commands.NRF52_CMD_VERSION):
	version = ser.read(6)
	if version:
		print("Firmware Version: " + version)

ser.close()
