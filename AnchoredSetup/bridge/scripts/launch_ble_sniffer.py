#!/usr/bin/env python3

import sys
import os
import subprocess
from subprocess import check_output

# Usage: ./launch_ble_sniffer.py <bdaddress> <public|random> <37|37,38,39>
# Example: ./scripts/launch_ble_sniffer.py c8:c9:a3:d3:65:1e public 39

if len(sys.argv) >= 1:
    print(f'WS_BLE_TARGET: {sys.argv[1]}')
    os.environ['WS_BLE_TARGET'] = sys.argv[1]

if len(sys.argv) >= 2:
    print(f'WS_BLE_TARGET_TYPE: {sys.argv[2]}')
    os.environ['WS_BLE_TARGET_TYPE'] = sys.argv[2]

if len(sys.argv) >= 3:
    print(f'WS_BLE_CHANNEL: {sys.argv[3]}')
    os.environ['WS_BLE_CHANNEL'] = sys.argv[3]

ws_out = check_output(['wireshark', '-D'])
if ws_out:
    iface_list = ws_out.decode().split('\n')
    for iface in iface_list:
        if 'nRF Sniffer' in iface:
            iface_number = iface.split('.')[0]
            print(f'Found Sniffer Interface: {iface}, Index: {iface_number}')
            subprocess.Popen(f'wireshark -k -B 256 -i {iface_number}', shell=True, preexec_fn=os.setsid)
            exit(0)

print('No Sniffer Interface found!')
    