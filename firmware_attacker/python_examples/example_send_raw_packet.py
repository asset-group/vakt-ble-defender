#!/usr/bin/env python

import serial
import time
from DongleUtils import FindDonglePort

dongle_port = FindDonglePort()
if dongle_port:
	print("NRF52 Serial Port: " + dongle_port)
	ser = serial.Serial(dongle_port, 115200, rtscts=1)

	s = 'A70E00C30CEB07A8063176BE8CC35B82C0C0'
	#s = 'A70E00C3FFEB07A8063176BE8CC35B82C0B3'
	#s = 'A70E00C30FEB07A8063176BE8CC35B82C0C3'
	s = s.decode('hex')

	while True:
	    ser.write(s)
	    print('packet sent')
	    time.sleep(1)
	ser.close()
