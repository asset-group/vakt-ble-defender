
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap, rdpcap
from scapy.packet import raw
from colorama import Fore
from binascii import unhexlify, hexlify
from enum import Enum
import serial.tools.list_ports
import serial
import ctypes
import sys
import os
from time import sleep
from queue import Queue
import signal

# Add libs to python path (#TODO: Remmove this)
sys.path.insert(0, os.getcwd() + '../libs')
sys.path.insert(0, os.getcwd() + './libs')


# SERIAL COMMANDS WILL NOT BE USED IN THIS CASE

# USB Serial commands
# NRF52_CMD_DATA_RX = b'\xA7'
# NRF52_CMD_DATA_TX = b'\xBB'
# NRF52_CMD_CHECKSUM_ERROR = b'\xA8'
# NRF52_CMD_CONFIG_AUTO_EMPTY_PDU = b'\xA9'
# NRF52_CMD_CONFIG_ACK = b'\xAA'
# NRF52_CMD_CONFIG_LOG_TX = b'\xCC'
# NRF52_CMD_CONFIG_SN_NESN = b'\xAD'
# NRF52_CMD_BOOTLOADER_SEQ1 = b'\xA6'
# NRF52_CMD_BOOTLOADER_SEQ2 = b'\xC7'
# NRF52_CMD_LOG = b'\x7F'
# NRF52_CMD_VERSION = b'\xB0'
# NRF52_CMD_CONNECTION_STATUS = b'\xB1'
# NRF52_CMD_SET_SCAN_MODE = b'\xB2'
# NRF52_CMD_SET_ADV_ADDR = b'\xB3'
# NRF52_CMD_SET_BLE_ROLE = b'\xB4'
# NRF52_CMD_SET_AUTO_DISCONNECT = b'\xB5'


# Driver Structures

NRF52_USB_VALID_PORTS_DESC = [
    'BLEDefender Dongle',
    'Bluefruit nRF52840',
    'Feather nRF52840 Express',
    'Open DFU Bootloader',
    'Bluefruit nRF52840 - Bluefruit Serial'
]

filtered_pkts = []
raw_pkts = []
q1 = Queue()
q2 = Queue()


# class NRF52_ROLE(Enum):
#     CENTRAL = 0
#     JAMMER_PERIPHERAL = 1
#     PERIPHERAL = 2


# class ConnectionStatus(ctypes.LittleEndianStructure):
#     _fields_ = [
#         ("radio_data_mode", ctypes.c_uint8, 1),
#         ("data_to_send", ctypes.c_uint8, 1),
#         ("data_to_send_retries", ctypes.c_uint8, 3),
#         ("radio_connection_requested", ctypes.c_uint8, 1),
#         ("wait_end_of_conn_req", ctypes.c_uint8, 1),
#         ("wait_buffer_len", ctypes.c_uint8, 1),
#     ]

#     def getdict(self):
#         return dict((f, getattr(self, f)) for f, _, _ in self._fields_)


# Driver class
class NRF52Pcap:
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
    def __init__(self, port_name=None, baudrate=115200, debug=False, logs=True, logs_pcap=False, pcap_filename=None, capture=None, direction=1):
        global filtered_pkts, raw_pkts

        if capture == None:
            print("FILE EMPTY !!!")
            self.pkt_none = True
        else:
            self.capture_file = rdpcap(capture)  # Reads the raw pcap file
            self.capture_file_f = []
            pkt_counter = 1
            for c in self.capture_file:
                x = (NORDIC_BLE(c), pkt_counter)
                pkt_counter +=1
                # print(x.summary())
                # pre-filter applied on the capture file
                if BTLE_DATA in x[0] or BTLE_CONNECT_REQ in x[0] or BTLE_SCAN_REQ in x[0] or BTLE_EMPTY_PDU in x[0]:
                    self.capture_file_f.append(x)
                    # c.show()
            # Returns packets NORDIC pattern
            if len(filtered_pkts) == 0:
                filtered_pkts = []
                idx = 0
                while idx < len(self.capture_file_f):
                    i = self.capture_file_f[idx][0]
                    crc = i.flags & 0b0001
                    enc = i.flags & 0b0100
                    mic = i.flags & 0b1000
                    # i.show()
                    # Check if the crc is empty
                    if crc == 0:
                        idx += 1
                        # sleep(2)
                        continue
                    # print(f"summary={i.summary()}, flag={i.flags}, crc={crc}")
 
                    if BTLE_DATA in i:
                        # print(f'crc={crc}, enc={enc}, mic={mic}')
                        # if (enc > 0) and (mic is 0):
                        #     idx += 1
                        #     continue
                        # if i.flags == 0x01:
                        #     idx += 1
                        #     continue
                        # if i.flags == 0x03:
                        #     idx += 1
                        #     continue
                        if i.flags == 0x05:
                            idx += 1
                            continue
                        if i.flags == 0x07:
                            idx += 1
                            continue
                        # just save if the packet has correct crc and mic case is encrypted
                        filtered_pkts.append((i[BTLE], i.flags & 0b0010, self.capture_file_f[idx][1]))
                    else:
                        filtered_pkts.append((i[BTLE], 0b0010, self.capture_file_f[idx][1]))
                    idx += 1
                # filtered_pkts = [(i[BTLE], NORDIC_BLE(i).flags)
                #                  for i in self.capture_file_f]
                # print('------------------DIRECTION HERE-----------------')
                # for c in filtered_pkts:
                #     print(c[0].summary())
                #     print("Direction: ", c[1])
                raw_pkts = [(raw(d[0]), d[1], d[2])
                            for d in filtered_pkts]  # Returns raw packets
                pkt, pktdir, pkt_number = raw_pkts.pop(0)
                # print(f'[{pkt_number}] Direction: {pktdir}')
                if pktdir == 2:
                    q1.put((pkt, pkt_number))
                else:
                    q2.put((pkt, pkt_number))
            self.pkt_none = False
            self.direction = direction

    def close(self):
        '''Close dongle serial port'''
        pass

    def save_pcap(self):
        ''' Save pcap file '''
        pass

    def raw_send(self, pkt):
        ''' Send raw packet data '''
        return None

    def send(self, scapy_pkt, print_tx=True, force_pcap_save=False):
        ''' Send NORDIC formatted packet data'''
        pass

    def raw_receive(self, ret_pkt_counter=False):

        '''Receive raw BLE adv or channel packets'''
        if self.pkt_none == True:
            sleep(0.01)
            return None

        if self.direction == 0:
            pkt, pkt_number = q2.get()

        else:
            pkt, pkt_number = q1.get()

        if (len(raw_pkts) == 0):
            sleep(1)
            print("End of the raw packet")
            os.kill(0, signal.SIGQUIT)
            exit(0)
            return None

        next_pkt, pktdir, pkt_number_next = raw_pkts.pop(0)

        if pktdir == 2:
            q1.put((next_pkt, pkt_number_next))
        else:
            q2.put((next_pkt, pkt_number_next))

        if ret_pkt_counter == False:
            return pkt
        else:
            return (pkt, pkt_number)

    def set_defaults(self):
        '''Set dongle defaults'''
        pass

    def set_bdaddr(self, bdaddr):
        '''
        Set BLE BDAddress (Peripheral only)

        :param bdaddr: BDAddress hex string separated by ':'
        '''
        pass

    def set_ble_role(self, value):
        '''
        Set BLE Role

        :param value: 0 -> Central (Default); 
                      1 -> Peripheral;
                      2 -> Impersonator       
        '''
        pass

    def set_sn_nesn(self, value):
        '''
        Set the initial value of NESN and SN

        :param value: 0b01 -> set SN, 0b10 -> set NESN        
        '''
        pass

    def set_auto_disconnect(self, value):
        '''
        Enable/Disable auto disconnection if connection times out

        :param value: 1 -> Enable, 0 -> Disable      
        '''
        pass

    def set_log_tx(self, value):
        '''Makes the dongle send back the processed (final) tx packet'''
        pass

    def set_scanmode(self):
        '''Set dongle back to scan mode (default initial mode)'''
        pass

    def get_tx_packet(self):
        '''Get last transmitted TX packet'''
        pass

    def get_connection_status(self):
        '''Get connection status from serial port of the dongle'''
        pass
