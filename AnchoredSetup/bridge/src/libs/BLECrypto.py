#!/usr/bin/python
import sys
import os
sys.path.insert(0, os.getcwd() + './libs')

from smp_server import BLESMPServer
from time import sleep
from binascii import hexlify
import platform
import colorama
from colorama import Fore
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import raw
from Crypto.Cipher import AES
from wdissector import WD_DIR_TX, WD_DIR_RX

# Internal vars
conn_skd = None
conn_iv = None
conn_ltk = None
conn_session_key = None
master_address_raw = None
slave_address_raw = None
pairing_procedure = False
encryption_enabled = False

# Autoreset colors
colorama.init(autoreset=True)


class BLEncryption:

    def __init__(self):
        self.conn_tx_packet_counter = 0
        self.conn_rx_packet_counter = 0

    def set_security_settings(self, pkt):
        global paring_auth_request
        # Change security parameters according to slave security request
        # paring_auth_request = pkt[SM_Security_Request].authentication
        print(Fore.YELLOW + 'Slave requested authentication of ' +
              hex(pkt[SM_Security_Request].authentication))
        print(Fore.YELLOW + 'We are using authentication of ' +
              hex(paring_auth_request))

    def config_encryption(self, key, iv, skd):
        global conn_session_key
        global conn_iv
        global conn_skd

        # print("Encryption Configuration")
        conn_session_key = key
        conn_iv = iv
        # print("conn_iv: ", conn_iv)
        conn_skd = skd
        # print("conn_skd: ", conn_skd)
        self.conn_tx_packet_counter = 0
        self.conn_rx_packet_counter = 0

    def bt_crypto_e(self, key, plaintext):
        self.aes = AES.new(key, AES.MODE_ECB)
        return self.aes.encrypt(plaintext)

    def config_central_encryption(self, data):
        global conn_iv
        global conn_skd
        global conn_ltk
        global conn_session_key
        global encryption_enabled
        global pairing_procedure

        if encryption_enabled:
            # After is encrypted
            #print("RX Encryption")
            pkt = BTLE(data)
            pkt = self.receive_encrypted(
                pkt, WD_DIR_RX)  # Decrypt Link Layer

        else:
            # If is not encrypted
            pkt = BTLE(data)  # Receive plain text Link Layer
        
        if pairing_procedure and SM_Hdr in pkt:
            #pkt.show()
            smp_answer = BLESMPServer.send_hci(
                raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / pkt[SM_Hdr]))
            if smp_answer is not None:
                for res in smp_answer:
                    res = HCI_Hdr(res)
                    #res.show()
                    if HCI_Cmd_LE_Start_Encryption_Request in res:
                        # Get LTK from slave encryptyon process
                        conn_ltk = res.ltk
                        # print(f"LTK: {hexlify(conn_ltk)}")

        # --------------- Process Link Layer Packets here ------------------------------------
        elif LL_ENC_RSP in pkt:
            # Get IVs and SKDs from slave encryption response
            conn_skd += pkt[LL_ENC_RSP].skds  # SKD = SKDm || SKDs
            conn_iv += pkt[LL_ENC_RSP].ivs  # IV = IVm || IVs
            # Calculate the session key to initiate the encryption process
            conn_session_key = self.bt_crypto_e(
                conn_ltk[::-1], conn_skd[::-1])
            conn_packet_counter = 0
            print(Fore.GREEN + '           Received SKD: ' +
                    hexlify(conn_skd).decode('utf-8'))
            print(Fore.GREEN + '           Received  IV: ' +
                    hexlify(conn_iv).decode('utf-8'))
            print(Fore.GREEN + '           AES-CCM  Key: ' +
                    hexlify(conn_session_key).decode('utf-8'))

            # Slave will send LL_ENC_RSP before the LL_START_ENC_RSP
        elif LL_START_ENC_REQ in pkt:
            # Configure the encryption process
            self.config_encryption(conn_session_key, conn_iv, conn_skd[::-1])
            encryption_enabled = True
        
        
        return pkt
    
    def config_peripheral_encryption(self, data):
        global conn_iv
        global conn_skd
        global conn_ltk
        global conn_session_key
        global master_address_raw
        global slave_address_raw
        global encryption_enabled
        global pairing_procedure

        if encryption_enabled:
            # After is encrypted
            #print("TX Encryption")
            pkt = BTLE(data)
            pkt = self.receive_encrypted(
                pkt, WD_DIR_TX)  # Decrypt Link Layer

        else:
            # If is not encrypted
            pkt = BTLE(data)  # Receive plain text Link Layer
        
        if pkt is None:
            return None

        if BTLE_CONNECT_REQ in pkt:
            master_address = pkt[BTLE_CONNECT_REQ].InitA
            slave_address = pkt[BTLE_CONNECT_REQ].AdvA
            
            master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), master_address.split(':')))
            master_address_raw = bytes([ord(i) for i in master_address_raw])
            slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), slave_address.split(':')))
            slave_address_raw = bytes([ord(i) for i in slave_address_raw])
            #print(f"master_address={master_address}")
            #print(f"master_address_raw={master_address_raw}")
            #print(f"peripheral_address={slave_address}")
            #print(f"slave_address_raw={slave_address_raw}")
            
        elif SM_Pairing_Request in pkt:
            pairing_iocap = pkt[SM_Pairing_Request].iocap
            paring_auth_request = pkt[SM_Pairing_Request].authentication
            #print(f"pairing_iocap={pairing_iocap}")
            #print(f"paring_auth_request={paring_auth_request}")
            BLESMPServer.configure_connection(master_address_raw, slave_address_raw, 0,
                                            pairing_iocap, paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            pairing_procedure = True

        # --------------- Process Link Layer Packets here ------------------------------------
        elif LL_ENC_REQ in pkt:
            conn_skd = pkt[LL_ENC_REQ].skdm
            conn_iv = pkt[LL_ENC_REQ].ivm
        

        return pkt

    def disable_encryption(self):
        global encryption_enabled
        encryption_enabled = False

    def send_encrypted(self, pkt):
        global conn_session_key
        global conn_iv
        global conn_skd

        raw_pkt = bytearray(raw(pkt))
        #print(raw_pkt)
        aa = raw_pkt[:4]
        header = bytes([raw_pkt[4]])  # Get ble header
        # print("header: ", header[0])
        length = bytes([raw_pkt[5] + 4])  # add 4 bytes for the mic
        crc = b'\x00\x00\x00'  # Dummy CRC (Dongle automatically calculates it)

        pkt_count = bytearray(struct.pack("<Q", self.conn_tx_packet_counter)[
                              :5])  # convert only 5 bytes
        pkt_count[4] |= 0x80  # Set for master -> slave
        nonce = pkt_count + conn_iv

        self.aes = AES.new(conn_session_key, AES.MODE_CCM,
                           nonce=nonce, mac_len=4)  # mac = mic
        # Calculate mic over header cleared of NES, SN and MD
        self.aes.update(bytes([header[0] & 0xE3]))

        # enc_pkt, mic = aes.encrypt_and_digest(bytes(raw_pkt[6:-3]))  # get payload and exclude 3 bytes of crc
        self.conn_tx_packet_counter += 1  # Increment packet counter
        # driver.packets_buffer.append(NORDIC_BLE(board=75, protocol=2, flags=0x3) / raw(aa + header + length + enc_pkt + mic + crc))
        # driver.raw_send(aa + header + length + enc_pkt + mic + crc)
        print(Fore.YELLOW + "TX ---> [Encrypted]{" + pkt.summary()[7:] + '}')

    def receive_encrypted(self, pkt, direction):
        global conn_session_key
        global conn_iv
        global conn_skd

        raw_pkt = bytearray(raw(pkt))
        aa = raw_pkt[:4]
        header = bytes([raw_pkt[4]])  # Get ble header
        length = raw_pkt[5]  # add 4 bytes for the mic

        if length == 0 or length < 5:
            # ignore empty PDUs
            return pkt
        # Subtract packet length 4 bytes of MIC
        length -= 4

        if direction == WD_DIR_RX:
            # Update nonce before decrypting
            pkt_count = bytearray(struct.pack("<Q", self.conn_rx_packet_counter)[
                                  :5])  # convert only 5 bytes
            pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
            self.conn_rx_packet_counter += 1
        else:
            # Update nonce before decrypting
            pkt_count = bytearray(struct.pack("<Q", self.conn_tx_packet_counter)[
                                  :5])  # convert only 5 bytes
            pkt_count[4] |= 0x80  # Set for master -> slave
            self.conn_tx_packet_counter += 1

        nonce = pkt_count + conn_iv

        self.aes = AES.new(conn_session_key, AES.MODE_CCM,
                           nonce=nonce, mac_len=4)  # mac = mic
        # Calculate mic over header cleared of NES, SN and MD
        self.aes.update(bytes([header[0] & 0xE3]))

        # get payload and exclude 3 bytes of crc
        dec_pkt = self.aes.decrypt(raw_pkt[6:-4 - 3])
        try:
            # Get mic from payload and exclude crc
            mic = raw_pkt[6 + length: -3]
            self.aes.verify(mic)

            return BTLE(aa + header + bytes([length]) + dec_pkt + b'\x00\x00\x00')
        except Exception as e:
            print(Fore.RED + "[Invalid]  MIC Wrong: " + str(e) + ', MIC Received: ' + hexlify(mic).decode())
            return None