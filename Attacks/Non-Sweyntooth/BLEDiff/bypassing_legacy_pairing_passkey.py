#!/usr/bin/env python2

# Commom imports
import binascii
from binascii import hexlify
import os
import json
import traceback
from time import sleep, time
from serial import SerialException
import time
# PyCryptodome imports
from Crypto.Cipher import AES
from thread import *
import threading
# Flask imports
from flask import Flask, request
from flask_socketio import SocketIO
# Scapy imports
from scapy.layers.bluetooth import HCI_Hdr, L2CAP_Connection_Parameter_Update_Request, _att_error_codes
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import wrpcap, raw
from scapy.packet import Raw

# BTLE Suite
from blesuite.pybt.att import AttributeProtocol
from blesuite.pybt.sm import SM, SecurityManagerProtocol
from blesuite.pybt.gatt import Server, UUID
from blesuite.entities.gatt_device import BLEDevice
import blesuite.utils.att_utils as att_utils
import blesuite.pybt.roles as ble_roles
import blesuite.pybt.gatt as PyBTGATT
from discover import discover_attacker_dongle

# Colorama
from colorama import Fore, Back, Style
from colorama import init as colorama_init

from drivers.NRF52_dongle import NRF52Dongle
import BLESMPServer


print_lock = threading.Lock()
device = None
saved_ATT_Hdr = None
saved_pkt_with_ATT_Hdr = None
scan_response_received = False

print('Finding BDAddress of target...')
os.system('./find_bdaddress.py')

class BLECentralMethods(object):  # type: HierarchicalGraphMachine
    name = 'BLE'
    iterations = 0
    # Default Model paramaters
    master_address = None  # will take these inputs from a git ignored config file 
    slave_address = None    # will take these inputs from socket
    #master_feature_set = 'le_encryption+le_data_len_ext'  # Model dependent
    master_mtu = 247  # TODO: master_mtu
    conn_access_address = 0x5b431498
    conn_interval = 16
    conn_window_offset = 1
    conn_window_size = 2
    conn_channel_map = 0x1FFFFFFFFF
    conn_slave_latency = 0
    conn_timeout = 50
    dongle_serial_port = '/dev/ttyACM2'
    enable_fuzzing = False
    enable_duplication = False
    pairing_pin = '0000'
    scan_timeout = 6  # Time in seconds for detect a crash during scanning
    state_timeout = 3  # state timeout
    monitor_serial_baud = 115200
    monitor_serial_magic_string = 'BLE Host Task Started'
    # -----------------------------------------------------------------------------------
    monitor = None
    # Timers for name reference
    conn_supervision_timer = None  # type: threading.Timer
    conn_general_timer = None  # type: threading.Timer
    scan_timeout_timer = None  # type: threading.Timer
    # Internal instances
    att = None
    smp = None  # type: SM
    driver = None  # type: NRF52Dongle
    # Internal variables
    master_address_raw = None
    slave_address_raw = None
    config_file = 'ble_config.json'
    addr_file = 'addr_config.json'
    iterations = 0
    master_address_type = None

    pkt_received = None
    pkt = None
    peer_address = None
    last_gatt_request = None
    empty_pdu_count = 0
    master_gatt_server = None
    sent_packet = None
    pairing_starting = False
    # Internal Slave params
    slave_address_type = None
    slave_feature_set = None
    slave_ble_version = None
    slave_next_start_handle = None
    slave_next_end_handle = None
    slave_service_idx = None
    slave_characteristic_idx = None
    slave_characteristic = None
    slave_device = None  # type: BLEDevice
    slave_handles = None
    slave_handles_values = None
    slave_handles_idx = None
    slave_ever_connected = False
    slave_connected = False
    slave_crashed = False
    slave_l2cap_fragment = []
    # Internal Encryption params
    conn_ltk = None
    conn_ediv = None
    conn_rand = None
    conn_iv = None
    conn_skd = None
    conn_session_key = None  # Used for LL Encryption
    conn_master_packet_counter = 0  # Packets counter for master (outgoing)
    conn_slave_packet_counter = 0  # Packets counter for slave (incoming)
    conn_encryted = False

    def __init__(self,
                 master_mtu=None,
                 dongle_serial_port=None,
                 baudrate=None):

        colorama_init(autoreset=True)  # Colors autoreset

        self.load_config()
        self.load_initial_addrs()


        if dongle_serial_port is not None:
            self.dongle_serial_port = dongle_serial_port
        if master_mtu is not None:
            self.master_mtu = master_mtu

        self.smp = SecurityManagerProtocol(self)
        BLESMPServer.set_pin_code(bytearray([(ord(byte) - 0x30) for byte in self.pairing_pin]))

        self.master_gatt_server = self.create_gatt_server(mtu=master_mtu)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server,
                                     mtu=master_mtu)
        self.dongle_serial_port = dongle_serial_port
        self.baudrate = baudrate
        self.driver = NRF52Dongle(dongle_serial_port, baudrate)

        if self.master_address is not None:
            self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))
            self.master_address_type = ble_roles.PUBLIC_DEVICE_ADDRESS
        else:
            self.master_address_raw = os.urandom(6)
            self.master_address_type = ble_roles.RANDOM_DEVICE_ADDRESS

        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

        self.smp.initiate_security_manager_for_connection(self.peer_address,
                                                          ble_roles.PUBLIC_DEVICE_ADDRESS,
                                                          self.master_address_raw, self.master_address_type,
                                                          ble_roles.ROLE_TYPE_CENTRAL)


    def set_master_addr(self, new_master_addr):
        self.master_address = new_master_addr.lower()
        self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

    def set_slave_addr(self, new_slave_addr):
        self.slave_address = new_slave_addr.lower()
        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

    def adjust_slave_addr(self, new_slave_addr):
        self.set_slave_addr(new_slave_addr)
        self.smp = SecurityManagerProtocol(self)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server, mtu=self.master_mtu)
        self.smp.initiate_security_manager_for_connection(self.peer_address, 
                                                        ble_roles.PUBLIC_DEVICE_ADDRESS, 
                                                        self.master_address_raw, self.master_address_type,
                                                        ble_roles.ROLE_TYPE_CENTRAL)
        
    def load_initial_addrs(self):
        f = open(self.addr_file, 'r')
        obj = json.loads(f.read())
        f.close()

        self.set_master_addr(obj['MasterAddress'])
        self.set_slave_addr(obj['SlaveAddress'])
        self.master_address_type = obj['MasterAddressType']
        self.slave_address_type = obj['SlaveAddressType']



    def set_config(self, data):
        self.conn_interval = int(data['ConnectionInterval'])
        self.conn_window_offset = int(data['WindowOffset'])
        self.conn_window_size = int(data['WindowSize'])
        self.conn_slave_latency = int(data['SlaveLatency'])
        self.conn_timeout = int(data['ConnectionTimeout'])
        self.master_feature_set = data['MasterFeatureSet']
        self.dongle_serial_port = data['DongleSerialPort']
        self.enable_fuzzing = bool(data['EnableFuzzing'])
        self.enable_duplication = bool(data['EnableDuplication'])
        self.pairing_pin = data['PairingPin']
        self.monitor_serial_port = data['MonitorSerialPort']
        self.monitor_serial_baud = int(data['MonitorSerialBaud'])


    def load_config(self):
        f = open(self.config_file, 'r')
        obj = json.loads(f.read())
        f.close()

        self.set_config(obj)
        
        return True

    @staticmethod
    def create_gatt_server(mtu=23):
        gatt_server = Server(None)
        gatt_server.set_mtu(mtu)

        # Add Generic Access Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1800"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Device Name characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('Greyhound',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A00"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Device Name")

        char1 = service_1.generate_and_add_characteristic('\x00\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A01"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Appearance")

        char1 = service_1.generate_and_add_characteristic('\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A04"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Conn Paramaters")
        # -----

        # Add Immediate Alert Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1802"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Alert Level characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A06"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        # add user description descriptor to characteristic
        char1.generate_and_add_user_description_descriptor("Characteristic 1")
        gatt_server.refresh_database()
        # gatt_server.debug_print_db()
        return gatt_server

    def save_ble_device(self):
        export_dict = self.slave_device.export_device_to_dictionary()
        device_json_output = json.dumps(export_dict, indent=4)
        f = open("bluetooth/device.json", "w")
        f.write(device_json_output)
        f.close()

    def update_slave_handles(self):
        if self.slave_handles:
            del self.slave_handles
        self.slave_handles = []

        if self.slave_handles_values:
            del self.slave_handles_values
        self.slave_handles_values = {}

        self.slave_handles_idx = 0
        for service in self.slave_device.services:
            self.slave_handles.append(service.start)
            for characteristic in service.characteristics:
                self.slave_handles.append(characteristic.handle)
                for descriptor in characteristic.descriptors:
                    self.slave_handles.append(descriptor.handle)

    @staticmethod
    def bt_crypto_e(key, plaintext):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(plaintext)

    def send(self, pkt):
        if pkt is None:
            return

        print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])
        #pkt.show()
        # pkt[BTLE].len = 0x72
        if self.conn_encryted is False:
            # print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])
            self.driver.raw_send(raw(pkt))
        else:
            self.send_encrypted(pkt)

    def send_encrypted(self, pkt):
        try:
            raw_pkt = bytearray(raw(pkt))
            access_address = raw_pkt[:4]
            header = raw_pkt[4]  # Get ble header
            length = raw_pkt[5] + 4  # add 4 bytes for the mic
            crc = '\x00\x00\x00'

            pkt_count = bytearray(struct.pack("<Q", self.conn_master_packet_counter)[:5])  # convert only 5 bytes
            pkt_count[4] |= 0x80  # Set for master -> slave
            if self.conn_iv is None or self.conn_session_key is None:
                return
            nonce = pkt_count + self.conn_iv

            aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic

            aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

            enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])  # get payload and exclude 3 bytes of crc
            self.driver.raw_send(access_address + chr(header) + chr(length) + enc_pkt + mic + crc)
            self.conn_master_packet_counter += 1
        except:
            print ("Can not send!")

    def receive_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        access_address = raw_pkt[:4]
        header = raw_pkt[4]  # Get ble header
        length = raw_pkt[5]  # add 4 bytes for the mic

        if length is 0 or length < 5:
            # ignore empty PDUs
            return pkt
        # Subtract packet length 4 bytes of MIC
        length -= 4

        # Update nonce before decrypting
        pkt_count = bytearray(struct.pack("<Q", self.conn_slave_packet_counter)[:5])  # convert only 5 bytes
        pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
        if self.conn_session_key is None or self.conn_iv is None or pkt is None:
            return

        nonce = pkt_count + self.conn_iv


        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
        aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

        dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc

        try:
            mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
            aes.verify(mic)
            self.conn_slave_packet_counter += 1
            return BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
        except:
            print(Fore.RED + "MIC Wrong")
            self.conn_slave_packet_counter += 1
            p = BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
            # self.machine.report_anomaly(msg='MIC Wrong', pkt=p)
            return None

    # Ble Suite bypass functions
    ff = 0

    def raw_att(self, attr_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / attr_data

            self.send(pkt)

    def raw_smp(self, smp_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / smp_data
            self.send(pkt)

    def reset_dongle_connection(self):
        self.driver.reset()

    # Receive functions
    def sniff(self, timeout = 2):


        # self.retry()
        # timeout variable can be omitted, if you use specific value in the while condition
        # timeout = 2  # [seconds]
        print(Fore.YELLOW + '[!] BLE Sniffing started... ')
        timeout_start = time.time()
        out = 0
        while time.time() < timeout_start + timeout:
            try:
                if self.driver:

                    while time.time() < timeout_start + timeout:
                        data = self.driver.raw_receive()
                        if data:
                            pkt = BTLE(data)
                            out = self.receive_packet(pkt)
                            #print("value of out is: "+str(out))
                            if out == "scan_resp":
                                return out
                    #if out == 1:
                     #break


            except SerialException:
                self.driver = None
                print(Fore.RED + 'Serial busy' + Fore.RESET)


    def receive_packet(self, pkt):
        # self.update_timeout('conn_supervision_timer')
        global scan_response_received
        global saved_ATT_Hdr
        global saved_pkt_with_ATT_Hdr
        print_lines = False
        append_current_pkt = True
        pkts_to_process = []

        # Decrypt packet if link is encrypted

        if self.conn_encryted:
            pkt = self.receive_encrypted(pkt)
            if pkt is None:
                # Integrity check fail. Drop packet to not cause validation confusion
                return

        # Add packet to session packets history
        # Handle L2CAP fragment
        if (BTLE_DATA in pkt and pkt.len != 0) and (pkt.LLID == 0x02 or pkt.LLID == 0x01):
            if pkt.LLID == 0x01 or len(self.slave_l2cap_fragment) == 0:
                self.slave_l2cap_fragment.append(pkt)
                return
            append_current_pkt = False
            self.slave_l2cap_fragment.append(pkt)

        if len(self.slave_l2cap_fragment) > 0:
            p_full = raw(self.slave_l2cap_fragment[0])[:-3]  # Get first raw l2cap start frame
            self.slave_l2cap_fragment.pop(0)  # remove it from list
            idx = 0
            for frag in self.slave_l2cap_fragment:
                if frag.LLID == 0x02:
                    break
                p_full += raw(frag[BTLE_DATA].payload)  # Get fragment bytes
                idx += 1
                # print(Fore.YELLOW + 'fragment')

            del self.slave_l2cap_fragment[:idx]
            p = BTLE(p_full + '\x00\x00\x00')
            p.len = len(p[BTLE_DATA].payload)  # update ble header length
            pkts_to_process.append(p)  # joins all fragements

        # Add currently received packet
        if append_current_pkt:
            pkts_to_process.append(pkt)

        # Process packts in the packet list
        for pkt in pkts_to_process:
            # If packet is not an empty pdu or a termination indication
            if Raw in pkt:
                continue
            if (BTLE_EMPTY_PDU not in pkt) and (LL_TERMINATE_IND not in pkt) and (
                    L2CAP_Connection_Parameter_Update_Request not in pkt) and (
                    BTLE_DATA in pkt or (
                    (BTLE_ADV_IND in pkt or BTLE_SCAN_RSP in pkt) and pkt.AdvA == self.slave_address)):
                # Print packet and state
                print(Fore.CYAN + "RX <--- " + pkt.summary())
                
                print_lines = True
                
                self.pkt_received = True
                self.pkt = pkt
                if ATT_Hdr in pkt:
                    saved_ATT_Hdr = ATT_Hdr
                    saved_pkt_with_ATT_Hdr = pkt

                if "BTLE_ADV / BTLE_ADV_IND" in pkt.summary():
                    print("Received advertising indications")
                if "BTLE_ADV / BTLE_SCAN_RSP" in pkt.summary():
                    print("Received scan response")
                    self.receive_scan_response()
                    scan_response_received = True
                    return "scan_resp"

                if "BTLE_DATA / CtrlPDU / LL_SLAVE_FEATURE_REQ" in pkt.summary():
                    print("Received feature request")
                    self.receive_feature_request()
                    self.send_feature_response()
                        #return 1
                if "BTLE_DATA / CtrlPDU / LL_LENGTH_REQ" in pkt.summary():
                    print("Received length request")
                    self.receive_length_request()
                    self.send_length_response()
                if "BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Exchange_MTU_Request" in pkt.summary():
                    print("Received MTU request")
                    self.receive_mtu_length_request()
                    self.send_mtu_length_response()

                if "BTLE_DATA / CtrlPDU / LL_LENGTH_RSP" in pkt.summary():
                    print("Received length response")
                    self.receive_length_response()

                if "BTLE / BTLE_DATA / CtrlPDU / LL_REJECT_IND" in pkt.summary():
                    print("received LL reject\n")

                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Group_Type_Request" in pkt.summary():
                    print("Recieved PRI Request from OTA")
                    self.send_pri_services_response()

                if "BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Type_Request" in pkt.summary():
                    print("Received read type request")
                if "BTLE / BTLE_DATA / CtrlPDU / LL_VERSION_IND" in pkt.summary():
                    print("Received version response from OTA")
                    self.receive_version_indication()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Exchange_MTU_Response" in pkt.summary():
                    print("Received mtu_resp from OTA")
                    #pkt.show()
                    self.receive_mtu_length_response()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Pairing_Response" in pkt.summary():
                    print("Received Pairing Response from OTA")
                    auth_value = pkt[SM_Pairing_Response].authentication
                    auth_value = auth_value & 0b0010
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Public_Key" in pkt.summary():
                    print("Received public_key_response from OTA")

                    self.pkt.show()
                    self.finish_key_exchange()

                if "BTLE_DATA / CtrlPDU / LL_FEATURE_RSP" in pkt.summary():
                    print("Received feature response")
                    self.receive_feature_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Confirm" in pkt.summary():
                    print("Received sm_confirm from OTA")
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Random" in pkt.summary():
                    print("Received sm_random_received from OTA")

                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_DHKey_Check" in pkt.summary():
                    print("Received dh_key_response from OTA")
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / CtrlPDU / LL_ENC_RSP" in pkt.summary():
                    print("Recieved Encryption Response from OTA")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Group_Type_Response" in pkt.summary():
                    print("Recieved pri_resp from OTA")
                    self.receive_pri_services()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Type_Response" in pkt.summary():
                    print("received char_resp from OTA")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Error_Response" in pkt.summary():
                    print("received att_error")
                if "BTLE / BTLE_DATA / CtrlPDU / LL_START_ENC_REQ" in pkt.summary():
                    print("Recieved Start Encryption Request from OTA")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_START_ENC_RSP" in pkt.summary():
                    print("Recieved Start Encryption Response from OTA")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_PAUSE_ENC_RSP" in pkt.summary():
                    print("Recieved Encryption Pause Response from OTA")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Signing_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Identity_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Identity_Address_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()


                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Find_Information_Response" in pkt.summary():
                    print("received desc_resp from OTA")
                    self.receive_descriptors()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_Response" in pkt.summary():
                    print("received read response")
                    self.finish_readings()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Write_Response" in pkt.summary():
                    print("received write response")
                    self.finish_writing()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Failed" in pkt.summary():
                    pkt.show()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Security_Request" in pkt.summary():
                    #pkt.show()
                    print("received SM_Security_Request")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Encryption_Information" in pkt.summary():
                    print("received SM_Encryption_Information")
                    #pkt.show()
                    self.conn_ltk = pkt.ltk
                    print(Fore.GREEN + "[!] LTK received from OTA: " + hexlify(self.conn_ltk).upper())
                    self.finish_keys()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Master_Identification" in pkt.summary():
                    print("received SM_Master_Identification")
                    #pkt.show()
                    self.conn_ediv = pkt.ediv
                    self.conn_rand = pkt.rand
                    self.finish_keys()

        if print_lines:
            print('----------------------------')
            return 1

    def version_already_received(self):
        if self.slave_ble_version is not None:
            return True
        return False

    def send_pri_services_response(self):
        self.att.read_by_group_type_resp(0x0000, "", None)

    def send_scan_request(self):

        self.conn_encryted = False
        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.slave_address)
        print('Master Type: ' + str(self.master_address_type))
        print('Slave Type: ' + str(self.slave_address_type))
        print('Master: ' + str(self.master_address))
        print('Slave: ' + str(self.slave_address))
        self.send(pkt)

        print(Fore.YELLOW + 'Waiting advertisements from ' + self.slave_address)

    def receive_scan_response(self):
        if self.pkt_received:

            if (BTLE_ADV_NONCONN_IND in self.pkt or BTLE_ADV_IND in self.pkt or BTLE_SCAN_RSP in self.pkt) and \
                    self.pkt.AdvA == self.slave_address.lower():

                if BTLE_ADV_IND in self.pkt and self.slave_address_type != self.pkt.TxAdd:
                    self.slave_address_type = self.pkt.TxAdd  # Get slave address type
                    self.send_scan_request()  # Send scan request again
                else:
                    self.slave_address_type = self.pkt.TxAdd
                    return True

                return True
        return False

    switch = 0

    def send_connection_request(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        self.send(pkt)


    def send_gatt_response(self):
        if self.last_gatt_request is None:
            pkt = self.pkt
            self.last_gatt_request = pkt
        else:
            pkt = self.last_gatt_request

        self.att.marshall_request(None, pkt[ATT_Hdr], self.peer_address)

    def receive_gatt_request(self):
        if ATT_Hdr in self.pkt:
            return True
        return False

    def handle_gatt_response(self):
        if ATT_Hdr in self.pkt:
            self.last_gatt_request = self.pkt
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
            self.last_gatt_request = None
            if ATT_Error_Response in self.sent_packet:
                return False
        return False

    def receive_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            return True
        return False

    def receive_2_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            self.empty_pdu_count += 1
            if self.empty_pdu_count >= 3:
                self.empty_pdu_count = 0
                return True
        return False

    def send_feature_request(self):
        self.master_feature_set = 'le_encryption+le_data_len_ext'
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
            feature_set=self.master_feature_set)
       
        self.send(pkt)
        


    def receive_feature_request(self):
        print("Packet Summary: " + self.pkt.summary() + " " + str(self.pkt_received))
        if self.pkt_received:
            if LL_SLAVE_FEATURE_REQ in self.pkt:
                print("I reached in receive_feature_req")
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_feature_response(self):
        self.master_feature_set = 'le_encryption+le_data_len_ext'
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
            feature_set=self.master_feature_set)

        self.send(pkt)


    def receive_feature_response(self):
        if self.pkt_received:
            if LL_FEATURE_RSP in self.pkt:
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_length_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=self.master_mtu + 4, max_rx_bytes=self.master_mtu + 4)
        self.send(pkt)



    def receive_length_request(self):
        if self.pkt_received:
            if LL_LENGTH_REQ in self.pkt:
                return True
        return False

    def send_length_response(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=self.att.mtu + 4, max_rx_bytes=self.att.mtu + 4)
        self.send(pkt)

    def receive_length_response(self):
        if LL_UNKNOWN_RSP in self.pkt:
            return True
        if LL_LENGTH_RSP in self.pkt:
            return True

        return False

    def send_version_indication(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
        self.send(pkt)


    def receive_version_indication(self):

        if self.pkt_received:
            if LL_VERSION_IND in self.pkt:
                self.slave_ble_version = self.pkt[LL_VERSION_IND].version

                if BTLE_Versions.has_key(self.slave_ble_version):
                    print(Fore.GREEN + "[!] Slave BLE Version: " + str(
                        BTLE_Versions[self.slave_ble_version]) + " - " + hex(self.slave_ble_version))
                else:
                    print(Fore.RED + "[!] Unknown Slave BLE Version: " + hex(self.slave_ble_version))
                self.version_received = True
                return True
        return False

    def receive_security_request(self):
        if SM_Security_Request in self.pkt:
            return True

    def send_security_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
              SM_Security_Request(authentication=self.paring_auth_request)
        self.send(pkt)

    def send_mtu_length_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=self.att.mtu)
        self.send(pkt)


    def receive_mtu_length_request(self):
        if self.pkt_received:
            if ATT_Exchange_MTU_Request in self.pkt:
                return True
        return False


    def send_mtu_length_response(self):
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        




    def receive_mtu_length_response(self):
        if LL_LENGTH_REQ in self.pkt:
            self.send_length_response()
        if ATT_Exchange_MTU_Response in self.pkt:
            self.att.set_mtu(self.pkt.mtu)
            return True



    def send_pair_request_oob(self):
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x03
        

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                pkt[SM_Pairing_Request].oob = 1
                
                #pkt.show()
                self.send(pkt)
        else:
            self.send(self.sent_packet)


    def send_pair_request_no_sc_keyboard_display(self):
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x04 # Keyboard + Display
        

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
               
                if SM_Pairing_Request in pkt:
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                    #pkt.show()
                    self.send(pkt)
                    
        else:
            self.send(self.sent_packet)





    def finish_pair_response(self):
        if self.pkt is None:
            return

        if SM_Hdr in self.pkt:
            self.pkt.show()
            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:

                    res = HCI_Hdr(res)  # type: HCI_Hdr

                    if SM_Hdr in res:

                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        #pkt.show()
                        self.pairing_starting = True

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False
    
    
    
    def finish_keys(self):
        if self.pkt is None:
            return

        if SM_Hdr in self.pkt:
            self.pkt.show()
            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    if SM_Hdr in res:
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        #pkt.show()
                        self.pairing_starting = True
                        self.send(pkt)

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False

    def send_encryption_request(self):
        self.conn_ediv = '\x00'  # this is 0 on first time pairing
        self.conn_rand = '\x00'  # this is 0 on first time pairing
        self.conn_iv = '\x00' * 4  # set IVm (IV of master)
        self.conn_skd = '\x00' * 8
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
                                                                                                rand=self.conn_rand,
                                                                                                skdm=self.conn_skd,
                                                                                                ivm=self.conn_iv)
        #pkt.show()
        self.send(pkt)

    def send_start_encryption_response(self):
        global scan_response_received
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
            #pkt.show()
            self.send(pkt)
        else:
            self.conn_encryted = False

    def receive_encryption_response(self):
        self.pkt.show()
        if LL_ENC_RSP in self.pkt:
            try:
                self.conn_skd += self.pkt.skds  # SKD = SKDm || SKDs
                self.conn_iv += self.pkt.ivs  # IV = IVm || IVs
       
                self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                
                #print(hexlify(self.conn_ltk).upper())
                #print(hexlify(self.conn_skd).upper())
                #print(hexlify(self.conn_session_key).upper())
               
            except:
                #print('error and generating static key of all 00')
                #print(traceback.format_exc())
                #self.pkt.show()
                self.conn_ltk = "00000000000000000000000000000000".decode("hex")
                try:
                    self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                    #print(hexlify(self.conn_ltk).upper())
                    #print(hexlify(self.conn_skd).upper())
                    #print(hexlify(self.conn_session_key).upper())
                except:
                    self.conn_skd = "00000000000000000000000000000000".decode("hex")
                    self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                    #print(hexlify(self.conn_ltk).upper())
                    #print(hexlify(self.conn_skd).upper())
                    #print(hexlify(self.conn_session_key).upper())


            self.conn_master_packet_counter = 0
            

        elif LL_START_ENC_RSP in self.pkt:
            print(Fore.GREEN + "[!] !!! Link Encrypted direct in host !!!")
            # self.send_feature_response()
            return True

        return False

    def finish_key_exchange(self):
        if SM_Hdr in self.pkt:
            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
                if smp_answer is not None and isinstance(smp_answer, list):
                    for res in smp_answer:
                        res = HCI_Hdr(res)  # type: HCI_Hdr
                        if SM_Hdr in res:
                            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                            self.sent_packet = pkt
                            
                            self.send(pkt)
            except:
                pass

        return False



    def send_public_key(self):
         if SM_Hdr is None or self.pkt is None:
             return
         if SM_Hdr in self.pkt:
             try:
                 hci_res = BLESMPServer.send_public_key()
                 if hci_res:
                     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                         SM_Hdr]
                     #pkt.show()
                     self.send(pkt)
             except:
                 pass





    def send_dh_check(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_dh_check()
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    #pkt.show()
                    self.send(pkt)
            except:
                pass


    def send_sign_info(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_sign_info()
                hci_res.show()
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    #pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_sm_random(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_sm_random()
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    #pkt.show()
                    self.send(pkt)
            except:
                pass


    def send_pair_confirm(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_pair_confirm()
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    #pkt.show()
                    self.send(pkt)
            except:
                pass


    def send_pri_services_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_group_type(0x0001, 0xffff, 0x2800, None)
        else:
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2800, None)

    v = 0

    def receive_pri_services(self):
        print("receive_pri_services")
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
           

            if self.discover_gatt_services(pkt, 0x2800):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of primary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Primary service discovered")
            return True

    d = 0

    def send_sec_services_request(self):
        self.slave_next_start_handle = None
        
        if self.slave_next_start_handle is None:
            print("Main case: slave is none\n")
            self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
        else:
            print("Else case: slave is not none\n")
            # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2801, None)
        

    def receive_sec_services(self):
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            if self.discover_gatt_services(pkt, 0x2801):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of secondary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Secondary service discovered")
            return True

    def discover_gatt_services(self, pkt, request_uuid):

        length = pkt.length
        service_data = pkt.data
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
        try:
            if length == 6:  # 4 byte uuid, 2 2-byte handles
                print(Fore.RED + "[IK] Length 6" + "service data " + str(len(service_data)))
                # print("We've got services with 16-bit UUIDs!")
                services = []
                i = 0
                end_loop = False
                while i < len(service_data):
                    services.append(service_data[i:i + 6])
                    i += 6
                # print "Services:", services
                for service in services:
                    try:
                        start = struct.unpack("<h", service[:2])[0]
                        end = struct.unpack("<h", service[2:4])[0]
                        uuid_16 = struct.unpack("<h", service[4:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                        if end == -1:
                            end = 0xffff
                        if start == -1:
                            start = 0xffff
                        self.slave_device.add_service(start, end, uuid_128)
                        if end >= 0xFFFF or end < 0:
                            end_loop = True
                        if self.slave_next_start_handle is None or end >= self.slave_next_start_handle:
                            self.slave_next_start_handle = end + 1
                    except:
                        continue
                if end_loop:
                    return True
            elif length == 20:  # 16 byte uuid, 2 2-byte handles
                # print("We've got services with 128-bit UUIDs!")
                start = struct.unpack("<h", service_data[:2])[0]
                end = struct.unpack("<h", service_data[2:4])[0]
                uuid_128 = struct.unpack("<QQ", service_data[4:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                # print "UUID128:", uuid_128
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if end == -1:
                    end = 0xffff
                if start == -1:
                    start = 0xffff
                self.slave_device.add_service(start, end, uuid_128)
                if end >= 0xFFFF or end < 0:
                    return True
                self.slave_next_start_handle = end + 1
            else:
                print(Fore.RED + "[!] UNEXPECTED PRIMARY SERVICE DISCOVERY RESPONSE. BAILING")
        except:
            pass
            # Send next group type request (next services to discover)
        self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, request_uuid, None)
        return False

    def send_characteristics_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2803, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)

    def receive_characteristics(self):
        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Characteristics discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False

        characteristic_data = raw(self.pkt[ATT_Read_By_Type_Response])
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')

        length = int(characteristic_data[0].encode('hex'), 16)
        characteristic_data = characteristic_data[1:]

        if length == 7:  # 4byte uuid, 2 2-byte handles, 1 byte permission
            characteristics = []
            i = 0
            end_loop = False
            while i < len(characteristic_data):
                characteristics.append(characteristic_data[i:i + 7])
                i += 7
            # print "Services:", services
            for characteristic in characteristics:
                handle = struct.unpack("<h", characteristic[:2])[0]
                perm = struct.unpack("<B", characteristic[2:3])[0]
                value_handle = struct.unpack("<h", characteristic[3:5])[0]
                print ("handle: " + hex(handle))
                print ("perm: " + hex(perm))
                # print "UUID_16:", characteristic[5:].encode('hex')
                uuid_16 = struct.unpack("<h", characteristic[5:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if handle == -1:
                    handle = 0xffff
                if value_handle == -1:
                    value_handle = 0xffff
                self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 21:  # 16 byte uuid, 2 2-byte handles, 1 byte permission
            handle = struct.unpack("<h", characteristic_data[:2])[0]
            perm = struct.unpack("<B", characteristic_data[2:3])[0]
            value_handle = struct.unpack("<h", characteristic_data[3:5])[0]
            print ("handle 21 length: " + hex(handle))
            print ("perm 21 length: " + hex(perm))
            uuid_128 = struct.unpack("<QQ", characteristic_data[5:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if handle == -1:
                handle = 0xffff
            if value_handle == -1:
                value_handle = 0xffff
            self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)
        return False

    def send_includes_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2802, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)

    def receive_includes(self):

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Includes discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False


        include_data = raw(self.pkt[ATT_Read_By_Type_Response])
        length = int(include_data[0].encode('hex'), 16)
        include_data = include_data[1:]

        if length == 8:  # 2 byte handle of this attribute, 2 byte uuid, 2 end group handle, 2 byte handle of included service declaration
            includes = []
            i = 0
            end_loop = False
            while i < len(include_data):
                includes.append(include_data[i:i + 7])
                i += 7
            # print "Services:", services
            for incl in includes:
                handle = struct.unpack("<H", incl[:2])[0]
                included_att_handle = struct.unpack("<H", incl[2:4])[0]
                end_group_handle = struct.unpack("<H", incl[4:6])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                try:
                    included_service_uuid_16 = struct.unpack("<H", incl[6:])[0]
                except:
                    return True
                if handle == -1:
                    handle = 0xffff
                self.slave_device.add_include(handle, included_att_handle, end_group_handle, included_service_uuid_16)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 6:  # 2 byte handle of this attribute, 2 end group handle, 2 byte handle of included service declaration
            handle = struct.unpack("<H", include_data[:2])[0]
            included_att_handle = struct.unpack("<H", include_data[2:4])[0]
            end_group_handle = struct.unpack("<H", include_data[4:6])[0]
            if handle == -1:
                handle = 0xffff
            self.slave_device.add_include(handle, included_att_handle, end_group_handle, None)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)
        return False

    def send_descriptors_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.slave_service_idx = None
            self.slave_characteristic_idx = None
            service = None
            characteristic = None
            i = 0
            j = 0

            if self.slave_device is None:
                return

            # Get the index of the first service and characteristic available
            for _i, _service in enumerate(self.slave_device.services):
                found = False
                for _j, _characteristic in enumerate(_service.characteristics):
                    service = self.slave_device.services[_i]
                    characteristic = _service.characteristics[_j]
                    i = _i
                    j = _j
                    found = True
                    break
                if found is True:
                    break

            if characteristic is None:
                self.att.find_information(None, 0x0001, 0xFFFF)
                return

            start = characteristic.handle + 1
            if (len(service.characteristics) - 1) is 0:
                if (len(self.slave_device.services) - 1) is 0:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            if end == -1 or end > 0xffff:
                end = 0xffff
            if start == -1:
                start = 0xffff

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
        else:
            start = self.slave_next_start_handle
            end = self.slave_next_end_handle
        self.att.find_information(None, start, end)

    cq = 0

    def receive_descriptors(self):

        if ATT_Find_Information_Response in self.pkt:

            bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
            data = raw(self.pkt[ATT_Find_Information_Response])[1:]
            uuid_format = self.pkt[ATT_Find_Information_Response].format
            if uuid_format == 1:  # 16 bit uuid
                mark = 0
                descriptors = []
                while mark < len(data):
                    descriptors.append(data[mark:mark + 4])  # 2 byte handle, 2 byte uuid
                    mark += 4
                for desc in descriptors:
                    try:
                        handle = struct.unpack("<h", desc[:2])[0]
                        uuid_16 = struct.unpack("<h", desc[2:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16],
                                             uuid_128[16:20], uuid_128[20:]))
                        if self.slave_characteristic is not None:
                            self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
                    except:
                        return False

            elif uuid_format == 2:  # 128-bit uuid
                handle = struct.unpack("<h", data[:2])[0]
                uuid_128 = struct.unpack("<QQ", data[2:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))

                self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
        if ATT_Find_Information_Response in self.pkt or ATT_Error_Response in self.pkt:
            print('recebido 1')

            i = self.slave_service_idx
            j = self.slave_characteristic_idx

            if i is None or j is None:
                return False

            if self.slave_device.services is None or len(self.slave_device.services) is 0:
                print(Fore.YELLOW + '[!] No descriptors listed')
                self.update_slave_handles()
                self.slave_next_start_handle = None
                self.slave_next_end_handle = None
                return True

            if self.slave_device.services[i].characteristics is not None and j >= len(
                    self.slave_device.services[i].characteristics):
                print('recebido 2')
                i += 1
                j = 0

                if i >= len(self.slave_device.services):
                    print(Fore.GREEN + '[!] Descriptors discovered')
                    # Proceed
                    self.update_slave_handles()
                    self.slave_next_start_handle = None
                    self.slave_next_end_handle = None

                    return True

                elif self.slave_device.services[i].characteristics is None or len(
                        self.slave_device.services[i].characteristics) is 0:
                    self.slave_service_idx += 1
                    print(Fore.RED + '[!] WRONG 2766')
                    return False
            elif self.slave_device.services[i].characteristics is None:
                self.slave_service_idx += 1
                return False

            service = self.slave_device.services[i]
            characteristic = service.characteristics[j]

            start = characteristic.handle + 1
            if j >= len(service.characteristics) - 1:
                if i >= len(self.slave_device.services) - 1:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
            self.slave_next_start_handle = start
            self.slave_next_end_handle = end
            self.att.find_information(None, start, end)
            return False

        return False

    def send_read_request(self):
        if self.slave_handles is None:
            print("slave_handles is None!!")
            return
        if len(self.slave_handles) > 0:
            try:
                self.att.read(self.slave_handles[self.slave_handles_idx], None)
            except:
                pass
        self.slave_handles_idx += 1


    def finish_readings(self):

        if ATT_Read_Response in self.pkt:
            pkt = self.pkt[ATT_Read_Response]
            try:
                self.slave_handles_values.update({self.slave_handles[self.slave_handles_idx - 1]: pkt.value})
            except:
                pass

        if (ATT_Hdr in self.pkt and self.pkt[ATT_Hdr].opcode is 0x0B) or ATT_Error_Response in self.pkt:
            self.v += 1
            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                self.send_read_request()
            else:
                print(Fore.GREEN + '[!] Readings finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Readings finished')
            return True
        return False

    def send_write_request(self):

        try:
            if self.slave_handles[self.slave_handles_idx] in self.slave_handles_values:
                value = self.slave_handles_values[self.slave_handles[self.slave_handles_idx]]
            else:
                value = '\x00'
            self.att.write_req(self.slave_handles[self.slave_handles_idx], value, None)
        except:
            print("caught exception in send_write_request")
            pass
        if self.slave_handles_idx is None:
            return
        self.slave_handles_idx += 1

    def finish_writing(self):

        if (ATT_Write_Response in self.pkt) or ATT_Error_Response in self.pkt:

            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                self.send_write_request()
            else:
                print(Fore.GREEN + '[!] Writting finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Writting finished')
            return True

    def send_disconn_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND(code=0x13)
        self.send(pkt)


def Main():

    # Cleanup nRF tabs
    os.system("adb shell input tap 1020 314")
    sleep(1)
    os.system("adb shell input tap 1020 314")
    model = BLECentralMethods(
                              master_mtu = 247,
                              dongle_serial_port=discover_attacker_dongle()[0],
                              baudrate=115200)
    model.send_scan_request()
    result = model.sniff()
    while (result != "scan_resp"):
        result = model.sniff()
    model.send_connection_request()
    model.sniff(0.2)
    model.send_feature_request()
    model.sniff(0.2)
    model.send_version_indication()
    model.sniff(0.2)
    model.send_pri_services_request()
    model.sniff(0.2)
    model.send_pair_request_no_sc_keyboard_display()
    time.sleep(1)
    os.system("adb shell input tap 233 351")
    time.sleep(1)
    os.system("adb shell input tap 874 1072")
    time.sleep(1)
    model.sniff(0.2)
    model.send_pair_confirm()
    model.sniff(0.2)
    model.send_sm_random()
    model.sniff(0.2)
    model.send_encryption_request()
    model.sniff(0.2)
    model.send_start_encryption_response()
    model.sniff(0.2)


if __name__ == '__main__':
    Main()
