import sys
import os
import ctypes
import json
from wdissector import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from scapy.packet import raw
from colorama import Fore
from time import sleep

# Add libs to python path
sys.path.insert(0, os.getcwd() + '../.')
sys.path.insert(0, os.getcwd() + './libs')
sys.path.insert(0, os.getcwd() + '../libs')

# Read the JSON file containing the filters and flooding attributes
with open("./src/libs/WD_commands.json", 'r') as f:
    wd_commands = json.load(f)

Filters_json = wd_commands["Filters"]
Floods_json = wd_commands["Flooding"]

hdr_rx = NORDIC_BLE(board=75, protocol=2, flags=0x1)
hdr_tx = NORDIC_BLE(board=75, protocol=2, flags=0x3)

class ValidatePacket:
    # Constructor
    def __init__(self):
        global Filters_json, Floods_json
        # ----- WDissector Initialization -----
        print('\n---------------------- WDissector -----------------------')
        # Initialize WDissector instance
        self.wd_instance = wd_init("proto:nordic_ble")
        wdissector_set_log_level(WD_LOG_LEVEL_NONE)
        print("WDissector Version:" + wd_info_version())
        print("WDissector Loaded Profile:" + wd_info_profile())

        # Declaring the filters and fields
        self.filter_options = []
        self.flooding_options = []
        for i in Filters_json:
            if i["obs"] == "filter":
                self.filter_options.append(
                    (wd_filter(i["command"]), i["command"]))
            else:
                self.flooding_options.append(wd_field(i["command"]))
        
        print("QTD Filters:", len(self.filter_options))
        

    def validate_pkt(self, pkt=None, direction=None):
        # Headers from RX and TX roles respectively
        global hdr_rx, hdr_tx
        if pkt is None:
            print(Fore.RED + "[Error] Packet empty.")
            exit(1)
        if direction is None:
            print(Fore.RED+"[Error] Direction incorrect.")
            exit(1)
        elif direction == WD_DIR_RX:
            print("---- RX direction ----")
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_RX)
            self.hdr_ble_nordic = hdr_rx
            
            return True
        else:
            print("---- TX direction ----")
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_TX)
            self.hdr_ble_nordic = hdr_tx
            # Prepare wireshark packet for dissection
            wpkt = self.hdr_ble_nordic / pkt
            # Dissect packet
            wd_packet_dissect(self.wd_instance, bytearray(raw(wpkt)), len(wpkt))
            summary = wd_packet_summary(self.wd_instance)
            print(summary)
            if summary is None:
                return
            # Validate packet
            if summary and 'Malformed' not in summary and 'Unknown' not in summary:
                try:
                    print(pkt.show())
                except:
                    print(Fore.RED + "[Error]", summary)

                if L2CAP_Hdr in pkt and \
                    (pkt[BTLE].Length >= pkt[L2CAP_Hdr].len + 4) and \
                        pkt[L2CAP_Hdr].cid != 0:
                    if SM_Pairing_Request in pkt and \
                            pkt[SM_Pairing_Request].max_key_size != 16:
                        print(Fore.RED + '[Error] ', end='')
                        return False
                    else:
                        print(Fore.GREEN + '[Valid] ', end='')
                        return True
                elif L2CAP_Hdr in pkt:
                    print(Fore.RED + '[Error] ', end='')
                    return False
                else:
                    if summary and 'AUX_CONNECT_REQ' in summary and \
                            pkt.chM > 0 and \
                            pkt.win_offset >= 0 and \
                            pkt.win_offset <= pkt.interval and \
                            pkt.interval >= 6 and \
                            pkt.interval <= 3200 and \
                            pkt.latency >= 0 and \
                            pkt.latency <= ((pkt.interval*2)-1) and \
                            pkt.latency < 500 and \
                            pkt.timeout > ((1+pkt.latency)*pkt.interval*2) and \
                            pkt.timeout >= 10 and \
                            pkt.timeout <= 3200 and \
                            pkt.hop >= 5 and \
                            pkt.hop <= 16 and \
                            (len(hex(pkt.crc_init))-2)*4 >= 20 and \
                            (len(hex(pkt.crc_init))-2)*4 <= 24 and \
                            pkt.SCA >= 0 and \
                            pkt.SCA <= 7:
                        print(Fore.GREEN + '[Valid] ', end='')
                        return True
                    elif summary and 'AUX_CONNECT_REQ' in summary:
                        print(Fore.RED + '[Error] ', end='')
                        return False
                    else:
                        print(Fore.GREEN + '[Valid] ', end='')
                        return True
            else:
                print(Fore.RED + '[Error] ', end='')
                return False
