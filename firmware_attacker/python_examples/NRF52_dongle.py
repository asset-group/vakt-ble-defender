import binascii
import sys
import ctypes
import serial
from colorama import Fore

# USB Serial commands
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


class ConnectionStatus(ctypes.LittleEndianStructure):
    _fields_ = [
        ("radio_data_mode", ctypes.c_uint8, 1),
        ("data_to_send", ctypes.c_uint8, 1),
        ("data_to_send_retries", ctypes.c_uint8, 3),
        ("radio_connection_requested", ctypes.c_uint8, 1),
        ("wait_end_of_conn_req", ctypes.c_uint8, 1),
        ("wait_buffer_len", ctypes.c_uint8, 1),
    ]

    def getdict(self):
        return dict((f, getattr(self, f)) for f,_,_ in self._fields_)


# Driver class
class NRF52Dongle:
    n_debug = False
    n_log = False
    event_counter = 0

    # Constructor ------------------------------------
    def __init__(self, port_name, baudrate=115200, debug=False, logs=True):
        self.serial = serial.Serial(port_name, baudrate, timeout=1)

        self.n_log = logs
        self.n_debug = debug

        if self.n_debug:
            print('NRF52 Dongle: Instance started')

    def close(self):
        self.serial.close()
        self.serial = None
        print('NRF52 Dongle closed')

    def set_scan_mode(self):
        # if self.serial:
        #     data = NRF52_CMD_SET_SCAN_MODE
        #     self.serial.write(data)
        pass

    def set_jamming(self, value):
        if self.serial:
            data = NRF52_CMD_JAMMING + bytearray([value & 0xFF])
            self.serial.write(data)

    def get_version(self):
        if self.serial:
            data = NRF52_CMD_VERSION
            self.serial.write(data)
            if self.serial.read_until(NRF52_CMD_VERSION):
                return self.serial.read(5)

        return None

    def get_connection_status(self):
        if self.serial:
            data = NRF52_CMD_CONNECTION_STATUS
            self.serial.write(data)
            if self.serial.read_until(NRF52_CMD_CONNECTION_STATUS):
                status = self.serial.read(1)
                if status:
                    return ConnectionStatus(ord(status)).getdict()

        return None

    # RAW functions ---------------------------
    def raw_send(self, pkt):
        raw_pkt = bytearray(pkt[:-3])  # Cut the 3 bytes CRC
        crc = chr(sum(raw_pkt) & 0xFF)  # Calculate CRC of raw packet data
        pkt_len = len(raw_pkt)  # Get raw packet data length
        l = bytearray([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF])  # Pack length in 2 bytes (little indian)
        data = NRF52_CMD_DATA + l + raw_pkt + crc
        self.serial.write(data)

        if self.n_debug:
            print('Bytes sent: ' + binascii.hexlify(data).upper())

        return data

    def raw_receive(self):
        c = self.serial.read(1)
        # Receive BLE adv or channel packets
        if c == NRF52_CMD_DATA:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            evt_counter = lb | (hb << 8)
            data = bytearray(self.serial.read(sz))
            checksum = ord(self.serial.read(1))
            if (sum(data) & 0xFF) == checksum:
                # If the data received is correct
                self.event_counter = evt_counter

                if self.n_debug:
                    print("Hex: " + binascii.hexlify(data).upper())
                return data
        # Receive logs from dongle
        elif c == NRF52_CMD_LOG:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            data = self.serial.read(sz)
            if self.n_log:
                print(data)
        elif c == NRF52_CMD_CHECKSUM_ERROR:
            print(Fore.RED + "NRF52_CMD_CHECKSUM_ERROR")
        elif c == NRF52_CMD_FIFO_FULL:
            print(Fore.RED + "NRF52_CMD_FIFO_FULL")
        return None
