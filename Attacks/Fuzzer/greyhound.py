#!/usr/bin/python
from subprocess import Popen
import sys
from wifi.rpyutils import check_root

model_list = {
    'wifi_ap': 'wifi_ap.py',
    'wifi_client': 'wifi_client.py',
    'ble_central': 'ble_central.py'
}

if len(sys.argv) < 2:
    print('Please insert model name, see ./greyhound.py --help')
    sys.exit(-1)

arg = sys.argv[1]

if '--help' in arg:
    print('GreyHound models:\n'
          '---------------------------------------------------------------------------------\n'
          './greyhound.py wifi_ap      | Start an wi-fi access point model (Fuzz Wi-Fi clients)\n'
          './greyhound.py wifi_client  | Start an wi-fi client model (Fuzz Wi-Fi Access Point)\n'
          './greyhound.py ble_central  | Start an BLE central model (Fuzz BLE Perpherals)\n'
          '---------------------------------------------------------------------------------')
    sys.exit(0)

try:
    filename = model_list[arg]
except:
    print('No model found for ' + arg)
    sys.exit(-1)

check_root()
while True:
    print("\nStarting " + arg)
    # os.system("cset shield --force -k on -c 1-3,5-7")
    p = Popen(['chrt --rr 99 python ' + filename], shell=True)
    p.wait()
