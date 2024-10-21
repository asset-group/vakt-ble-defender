#!/usr/bin/env python
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
