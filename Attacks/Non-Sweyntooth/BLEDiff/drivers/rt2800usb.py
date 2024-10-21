import socket
import struct
import binascii
import os
from scapy.layers.dot11 import Dot11

# driver netlink commands
NETLINK_CMD_READ_ADDR = 0x00
NETLINK_CMD_WRITE_ADDR = 0x01
NETLINK_CMD_MULTIWRITE_ADDR = 0x02
NETLINK_CMD_MULTIREAD_ADDR = 0x03
NETLINK_CMD_INTERRUPT_RX_ENABLE = 0x04
NETLINK_CMD_FORCE_FLAGS_ENABLE = 0x05
NETLINK_CMD_FORCE_FLAGS_RETRY = 0x06
NETLINK_CMD_SEND_DATA = 0x07;

# rt2080/3080 registers
MAC_ADDR_DW0 = 0x1008
MAC_ADDR_DW1 = 0x100C
MAC_BSSID_DW0 = 0x1010
MAC_BSSID_DW1 = 0x1014

RX_FILTER_CFG = 0x1400
AUTO_RSP_CFG = 0x1404


class RT2800USBNetlink:
    NETLINK_USER = 31
    NETLINK_PID = os.getpid()
    NETLINK_GROUP = 1
    NETLINK_BUFFER_SIZE = 1000000

    n_socket = None
    n_debug = False
    stop_request = False

    # Constructor ------------------------------------
    def __init__(self, mac=0x00, retry_enable=0, filter_unicast=0, filter_control=0, port=NETLINK_USER, pid=NETLINK_PID,
                 group=NETLINK_GROUP, net_buffer=NETLINK_BUFFER_SIZE, debug=n_debug):

        self.n_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, port)
        self.n_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, net_buffer)
        self.n_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, net_buffer)
        self.n_socket.bind((pid, group))

        self.n_debug = debug
        self.NETLINK_BUFFER_SIZE = net_buffer

        if (self.n_debug):
            print('RT2800USBNetlink: Instance started')

    def close(self):
        self.stop_request = True
        self.n_socket.close()
        print('RT2800USB Driver closed')

    # RAW socket functions ---------------------------
    def raw_send(self, data):
        if self.n_debug:
            print('Bytes sent: ' + binascii.hexlify(data))
        self.n_socket.send(data)

    def raw_receive(self):
        data = self.n_socket.recv(self.NETLINK_BUFFER_SIZE)
        if self.n_debug:
            print(str(len(data)) + ' bytes received')
            print("Hex: " + binascii.hexlify(data[::-1]))
            print("Int: " + str(struct.unpack("<L", data)[0]))
        return data

    # Comands -------------------------------------
    def read(self, addr):
        if self.n_debug:
            print('\nREAD command')
        netlink_data = struct.pack('<BL', NETLINK_CMD_READ_ADDR, addr)
        self.raw_send(netlink_data)
        data = self.raw_receive()  # Get reading
        return data

    def write(self, addr, value, size=0):
        if self.n_debug:
            print('\nWRITE command')
        if size == 0:  # normal write
            netlink_data = struct.pack('<BLL', NETLINK_CMD_WRITE_ADDR, addr, value)
        else:
            netlink_data = struct.pack('<BLB' + str(size) + 's', NETLINK_CMD_MULTIWRITE_ADDR, addr, size,
                                       value)  # value here is in bytes

        self.raw_send(netlink_data)
        data = self.raw_receive()  # Get status
        return data

    def send_data(self, data):
        netlink_data = chr(NETLINK_CMD_SEND_DATA) + data  # value here is in bytes
        self.n_socket.send(netlink_data)

    def set_mac(self, mac):
        netlink_data = ''.join((mac.split(':'))).decode('hex')
        data = self.write(MAC_ADDR_DW0, netlink_data, size=6)
        return data

    def set_flags_enable(self, value):
        netlink_data = struct.pack('<BB', NETLINK_CMD_FORCE_FLAGS_ENABLE, value)
        self.raw_send(netlink_data)
        if self.n_debug:
            print('force flags set to ' + str(value))
        return self.raw_receive()

    def set_flags_retry(self, value):
        netlink_data = struct.pack('<BB', NETLINK_CMD_FORCE_FLAGS_RETRY, value)
        self.raw_send(netlink_data)
        if self.n_debug:
            print('retry flags set to ' + str(value))
        return self.raw_receive()

    def set_filter(self, value):
        self.write(RX_FILTER_CFG, value)

    def set_filter_sniffer(self):
        self.write(AUTO_RSP_CFG, 0x0007)
        self.write(RX_FILTER_CFG, 0x0093)

    def set_filter_unicast(self):
        self.write(RX_FILTER_CFG, 0x1BF97)
        #self.write(RX_FILTER_CFG, 0x1BFB7)
        self.write(AUTO_RSP_CFG, 0x0017)

    def set_filter_unicast_only(self):
        self.write(RX_FILTER_CFG, 0x1BFD7)
        self.write(RX_FILTER_CFG, 0x1BFE7)
        #self.write(AUTO_RSP_CFG, 0x0017)

    def set_auto_rsp(self, value):
        self.write(AUTO_RSP_CFG, value)

    def set_interrupt_rx_enable(self):
        netlink_data = struct.pack('<BB', NETLINK_CMD_INTERRUPT_RX_ENABLE, 1)
        self.raw_send(netlink_data)
        if self.n_debug:
            print('RX INTERRUPT set to 1' + str(1))
        return self.raw_receive()

    def set_interrupt_rx_disable(self):
        netlink_data = struct.pack('<BB', NETLINK_CMD_INTERRUPT_RX_ENABLE, 0)
        self.raw_send(netlink_data)
        if self.n_debug:
            print('RX INTERRUPT set to 0')
        return self.raw_receive()

# ------------ DEMO --------------------
# RT2800 = RT2800USBNetlink(debug=True)
# RT2800.set_mac('00:00:00:00:00:00')
# RT2800.set_filter_unicast()
# RT2800.set_filter_sniffer()

# RT2800.set_interrupt_rx_enable()
# RT2800.set_interrupt_rx_disable()

# RT2800.set_flags_enable(1)
# RT2800.set_flags_retry(1)

# RT2800.read(MAC_ADDR_DW0)
# RT2800.read(MAC_ADDR_DW1)
# RT2800.read(RX_FILTER_CFG)

# RT2800.n_debug = False
# while True:
#    data = RT2800.raw_receive()
#    #print(str(len(data)) + " Hex: " + binascii.hexlify(data))
#    d = Dot11(data)
#    print(d.summary())
#    #print(len(data))
