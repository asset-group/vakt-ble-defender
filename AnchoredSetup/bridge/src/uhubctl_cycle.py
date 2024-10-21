#!/usr/bin/env python3

import json
import uhubctl
from uhubctl import Hub
from time import sleep

UHUBCTL_CFG_PATH = 'uhubctl.json'
DEFAULT_DELAY_TIME = 0.2

def cycle_port(port_name, delay=DEFAULT_DELAY_TIME, device_name=None):
    try:
        hub_path = port_name.split('.')[0]
        port_number = int(port_name.split('.')[-1])
        hub = Hub(hub_path)
        port = hub.add_port(port_number)
        print(f'[Uhubctl] hub_path: {hub_path}, port_number: {port_number}')
        if port.status is False:
            port.status = False
            sleep(delay)
            port.status = True
            sleep(DEFAULT_DELAY_TIME)
        if device_name and device_name not in port.description():
            print(f'[Uhubctl] "{port.description()}" does not match expected "{device_name}"')
            if port.status is True:
                port.status = False
                sleep(delay)
                port.status = True
            return None
        # Cycle port
        print(f'[Uhubctl] Cycling "{device_name}" OFF...')
        port.status = False
        sleep(delay)
        print(f'[Uhubctl] Cycling "{device_name}" ON...')
        port.status = True
        return port
    except Exception as e:
        port = None
        print(e)
        return None

def device_cycle_port(device_name, delay=DEFAULT_DELAY_TIME, cfg_file_name=UHUBCTL_CFG_PATH):

    cfg_file = {}
    port = None
    print(f'[Uhubctl] Config file name: {cfg_file_name}')
    try:
        with open(cfg_file_name, 'r') as f:
            cfg_file = json.load(f)
    except:
        print('[Uhubctl] Config File not found')
        pass

    # Recover previous settings
    if device_name in cfg_file:
        port_name = cfg_file[device_name]
        print(f'[Uhubctl] Cycling device \"{device_name}\" in port {port_name}...')
        port = cycle_port(port_name, delay, device_name)
        if port:
            return True

    if port is None:
        print(f'[Uhubctl] Searching port of device \"{device_name}\"...')
        hubs = uhubctl.discover_hubs()
        for hub in hubs:
            for port in hub.ports:
                dev_name = port.description()
                if dev_name and device_name in dev_name:
                    print(f"Found port: {port}, Name: {dev_name}")
                    # Save json file
                    with open(cfg_file_name, 'w') as f:
                        port_name = str(port).split(' ')[-1]
                        cfg_file[device_name] = port_name
                        json.dump(cfg_file, f)

                    cycle_port(port_name, delay, device_name)
                    return True

    return False

if __name__ == '__main__':
    device_cycle_port('BLEDefender Central')
    # device_cycle_port('BLEDefender Peripheral')