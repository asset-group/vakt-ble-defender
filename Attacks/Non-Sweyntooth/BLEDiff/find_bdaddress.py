#!/usr/bin/env ./runtime/python/install/bin/python3

import asyncio
import os
import json
from bleak import BleakScanner

DEFAULT_HCI_DEV='hci1'

if 'BLE_TARGET' in os.environ:
    device_name = os.environ['BLE_TARGET']
else:
    device_name = 'Moto G (5S)'

async def main():
    devices = await BleakScanner.discover(timeout=1, adapter=DEFAULT_HCI_DEV)
    for d in devices:
        #print(d.name)
        if d.name == device_name:
            print(d.address.lower())
            with open('addr_config.json', 'r') as f:
                cfg = json.load(f)
                cfg['SlaveAddress'] = d.address
            with open('addr_config.json', 'w') as f:
                json.dump(cfg, f, indent=4)
            return d.address

asyncio.run(main())
