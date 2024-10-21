#!/usr/bin/env python

import serial
import time
from DongleUtils import FindDonglePort, NRF52Commands, ConnectionStatus

dongle_port = FindDonglePort()
if dongle_port:
	ser = serial.Serial(dongle_port, 115200, rtscts=1)
	# Send command
	ser.write(NRF52Commands.NRF52_CMD_SET_SCAN_MODE)
	print('SCAN Mode Set')

	ser.close()
 