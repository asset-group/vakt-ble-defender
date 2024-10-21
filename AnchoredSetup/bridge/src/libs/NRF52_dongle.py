
import sys
import os

# Add libs to python path (#TODO: Remmove this)
sys.path.insert(0, os.getcwd() + '../libs')
sys.path.insert(0, os.getcwd() + './libs')

import ctypes
import serial
import serial.tools.list_ports
from enum import Enum
from binascii import unhexlify, hexlify
from colorama import Fore
from scapy.utils import wrpcap
from scapy.packet import raw
from scapy.layers.bluetooth4LE import BTLE, NORDIC_BLE

# USB Serial commands
NRF52_CMD_DATA_RX = b'\xA7'
NRF52_CMD_DATA_TX = b'\xBB'
NRF52_CMD_CHECKSUM_ERROR = b'\xA8'
NRF52_CMD_CONFIG_AUTO_EMPTY_PDU = b'\xA9'
NRF52_CMD_CONFIG_ACK = b'\xAA'
NRF52_CMD_CONFIG_LOG_TX = b'\xCC'
NRF52_CMD_CONFIG_SN_NESN = b'\xAD'
NRF52_CMD_BOOTLOADER_SEQ1 = b'\xA6'
NRF52_CMD_BOOTLOADER_SEQ2 = b'\xC7'
NRF52_CMD_LOG = b'\x7F'
NRF52_CMD_VERSION = b'\xB0'
NRF52_CMD_CONNECTION_STATUS = b'\xB1'
NRF52_CMD_SET_SCAN_MODE = b'\xB2'
NRF52_CMD_SET_ADV_ADDR = b'\xB3'
NRF52_CMD_SET_BLE_ROLE = b'\xB4'
NRF52_CMD_SET_AUTO_DISCONNECT = b'\xB5'
NRF52_CMD_SET_JAMMING_CONN_IND = b'\x67' # Enable or disable jamming connection request


# Driver Structures

NRF52_USB_VALID_PORTS_DESC = [
    'BLEDefender Peripheral',
    'BLEDefender Central'
    'BLEDefender Dongle',
]


class NRF52_ROLE(Enum):
    CENTRAL = 0
    JAMMER_PERIPHERAL = 1
    PERIPHERAL = 2


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
        return dict((f, getattr(self, f)) for f, _, _ in self._fields_)


# Driver class
class NRF52Dongle:
    event_counter = 0
    port_name = None  # type: str
    version_firmware = None  # type: str
    __n_debug = False
    __n_log = False
    __logs_pcap = False
    __packets_buffer = []
    __pcap_filename = None
    __pcap_tx_handover = False
    __sent_pkt = None

    # Constructor
    def __init__(self, port_name=None, baudrate=115200, debug=False, logs=True, logs_pcap=False, pcap_filename=None):
        if port_name == None:
            found = False
            ports = serial.tools.list_ports.comports()
            for port in ports:
                if 'Bluefruit nRF52840' in port.description:
                    port_name = port.device
                    found = True
            if not found:
                print(Fore.RED + 'nRF52840 was not found')

        self.serial = serial.Serial(port_name, baudrate, timeout=1)
        self.port_name = port_name
        self.__logs_pcap = logs_pcap
        self.__n_log = logs
        self.__n_debug = debug
        if pcap_filename == None:
            self.__pcap_filename = os.path.basename(
                __file__).split('.')[0] + '.pcap'
        else:
            self.pcap_filename = pcap_filename

        # Get firmware version
        self.get_version()
        # Set dongle defaults
        self.set_defaults()

    def close(self):
        '''Close dongle serial port'''

        if self.serial != None:
            self.serial.close()
            del self.serial
            self.serial = None

    def save_pcap(self):
        # save packet just sent
        wrpcap(self.pcap_filename, self.__packets_buffer)
        # del self.packets_buffer
        self.__packets_buffer = []

    def raw_send(self, pkt):
        raw_pkt = bytearray(pkt[:-3])  # Cut the 3 bytes CRC
        # Calculate CRC of raw packet data
        crc = bytearray([sum(raw_pkt) & 0xFF])
        pkt_len = len(raw_pkt)  # Get raw packet data length
        # Pack length in 2 bytes (little infian)
        l = bytearray([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF])
        data = NRF52_CMD_DATA_TX + l + raw_pkt + crc
        self.serial.write(data)

        if self.__n_debug:
            print('Bytes sent: ' + hexlify(data).upper())

        return data

    def send(self, scapy_pkt, print_tx=True, force_pcap_save=False):
        self.raw_send(raw(scapy_pkt))
        if self.__logs_pcap and (self.pcap_tx_handover == 0 or force_pcap_save):
            self.__packets_buffer.append(NORDIC_BLE(
                board=75, protocol=2, flags=0x3) / scapy_pkt)
        if print_tx:
            print(Fore.CYAN + "TX ---> " + scapy_pkt.summary()[7:])

    def raw_receive(self):
        '''Receive BLE adv or channel packets'''

        c = self.serial.read(1)

        if c == NRF52_CMD_DATA_RX or c == NRF52_CMD_DATA_TX:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            channel = ord(self.serial.read(1))
            evt_counter = lb | (hb << 8)
            data = bytearray(self.serial.read(sz))
            checksum = ord(self.serial.read(1))
            if (sum(data) & 0xFF) == checksum:
                # If the data received is correct
                self.event_counter = evt_counter

                if c == NRF52_CMD_DATA_TX:
                    self.__sent_pkt = data
                    n_flags = 0x03
                    ret_data = None
                else:  # Received packets
                    n_flags = 0x01
                    ret_data = data

                if self.__logs_pcap is True and data != None:
                    self.__packets_buffer.append(NORDIC_BLE(
                        board=75, protocol=2, flags=n_flags) / BTLE(data))

                if self.__n_debug:
                    print("Hex: " + hexlify(data).upper())

                return ret_data
        # Receive logs from dongle
        elif c == NRF52_CMD_LOG:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            data = self.serial.read(sz)
            if self.__n_log:
                print(data)
        elif c == NRF52_CMD_CHECKSUM_ERROR:
            print(Fore.RED + "NRF52_CMD_CHECKSUM_ERROR")

        return None

    def set_defaults(self):
        '''Set dongle defaults'''

        self.set_log_tx(0)
        self.set_scanmode()

    def set_bdaddr(self, bdaddr):
        '''
        Set BLE BDAddress (Peripheral only)

        :param bdaddr: BDAddress hex string separated by ':'
        '''

        # Reverse bdaddr to OTA byte order
        bdaddr = bdaddr.split(':')[::-1]
        bdaddr = unhexlify(str().join(bdaddr))

        data = NRF52_CMD_SET_ADV_ADDR + bdaddr
        self.serial.write(data)

    def set_ble_role(self, value):
        '''
        Set BLE Role

        :param value: 0 -> Central (Default); 
                      1 -> Peripheral;
                      2 -> Impersonator       
        '''

        if isinstance(value, str):
            value = {'central': 0,
                     'peripheral': 1,
                     'impersonator': 2}.get(value)

        data = NRF52_CMD_SET_BLE_ROLE + bytearray([value])
        self.serial.write(data)

    def set_sn_nesn(self, value):
        '''
        Set the initial value of NESN and SN

        :param value: 0b01 -> set SN, 0b10 -> set NESN        
        '''

        data = NRF52_CMD_CONFIG_SN_NESN + bytearray([value])
        self.serial.write(data)

    def set_auto_disconnect(self, value):
        '''
        Enable/Disable auto disconnection if connection times out

        :param value: 1 -> Enable, 0 -> Disable      
        '''

        data = NRF52_CMD_SET_AUTO_DISCONNECT + bytearray([value])
        self.serial.write(data)

    def set_jamm_conn_ind(self, value):
        '''
        Enable/Disable connection indication jamming (central only for now)

        :param value: 1 -> Enable, 0 -> Disable      
        '''

        data = NRF52_CMD_SET_JAMMING_CONN_IND + bytearray([value])
        self.serial.write(data)

    def set_log_tx(self, value):
        '''Makes the dongle send back the processed (final) tx packet'''

        data = NRF52_CMD_CONFIG_LOG_TX + bytearray([value])
        self.serial.write(data)
        self.pcap_tx_handover = value

    def get_summary(self):
        '''Return summary of connected dongle'''

        return self.port_name + ' - FW Version: ' + self.version_firmware

    def set_scanmode(self):
        '''Set dongle back to scan mode (default initial mode)'''

        self.serial.write(NRF52_CMD_SET_SCAN_MODE)
        self.serial.flushInput()

    def get_version(self):
        self.serial.write(NRF52_CMD_VERSION)
        version = self.serial.read(6)
        try:
            if b'.' in version:
                self.version_firmware = version.decode(errors='ignore')
                return self.version_firmware
            else:
                print('Error getting firmware version')
                return None
        except Exception as e:
            print('Error getting firmware version')
            return None

    def get_tx_packet(self):
        '''Get last transmitted TX packet'''
        pkt = self.__sent_pkt
        self.__sent_pkt = None
        return pkt

    def get_connection_status(self):
        self.serial.write(NRF52_CMD_CONNECTION_STATUS)
        if self.serial.read_until(NRF52_CMD_CONNECTION_STATUS):
            status = self.serial.read(1)
            if status:
                return ConnectionStatus(ord(status)).getdict()

        return None
