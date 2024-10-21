#!/usr/bin/env python

import serial
import time
from NRF52_dongle import *

driver = NRF52Dongle('/dev/ttyACM0')

status = driver.get_connection_status()
for attr in status:
	print('%s: %d' % (attr, status[attr]))
