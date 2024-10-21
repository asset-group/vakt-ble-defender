#!/usr/bin/python3
import serial
import serial.tools.list_ports

ports = serial.tools.list_ports.comports()

for port in ports:
	if 'Bluefruit nRF52840' in port.description or 'Feather nRF52840 Express' in port.description:
		ser = serial.Serial(port.device, 38400, rtscts=1)
		ser.write('\xA6\xC7')
		ser.close()	
		print port.device
	elif 'Open DFU Bootloader' in port.description:
		print port.device


