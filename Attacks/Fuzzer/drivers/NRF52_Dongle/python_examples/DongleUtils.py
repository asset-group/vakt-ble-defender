import ctypes
import serial
import serial.tools.list_ports
from enum import Enum


# USB Serial commands
class NRF52Commands:
	NRF52_CMD_FW_VERSION = '\xA6'
	NRF52_CMD_DATA = '\xA7'
	NRF52_CMD_JAMMING = '\x66'
	NRF52_CMD_FIFO_FULL = '\xA1'
	NRF52_CMD_CHECKSUM_ERROR = '\xA8'
	NRF52_CMD_CONFIG_AUTO_EMPTY_PDU = '\xA9'
	NRF52_CMD_CONFIG_ACK = '\xAA'
	NRF52_CMD_BOOTLOADER_SEQ1 = '\xA6'
	NRF52_CMD_BOOTLOADER_SEQ2 = '\xC7'
	NRF52_CMD_LOG = '\x7F'
	NRF52_CMD_VERSION = b'\xB0'
	NRF52_CMD_CONNECTION_STATUS = b'\xB1'
	NRF52_CMD_SET_SCAN_MODE = b'\xB2'


def FindDonglePort():

	ports = serial.tools.list_ports.comports()
	for port in ports:
		if 'Bluefruit nRF52840' in port.description or 'Feather nRF52840 Express' in port.description:
			print('Found dongle at ' + port.device)
			return port.device
		elif 'Open DFU Bootloader' in port.description:
			return port.device

	return None


class ConnectionStatus(ctypes.LittleEndianStructure):
    _fields_ = [
        ("radio_data_mode", ctypes.c_uint8, 1),
        ("data_to_send", ctypes.c_uint8, 1),
        ("data_to_send_retries", ctypes.c_uint8, 3),
        ("radio_connection_requested", ctypes.c_uint8, 1),
        ("wait_end_of_conn_req", ctypes.c_uint8, 1),
        ("wait_buffer_len", ctypes.c_uint8, 1),
    ]
