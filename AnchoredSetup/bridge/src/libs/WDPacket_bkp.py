"""

Important!!!
Cannot use for loop or print in the wd_read_filter or wd_read_field functions

"""
from binascii import hexlify
from time import sleep
from colorama import Fore
from scapy.packet import raw
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from wdissector import \
    Machine, wd_init, wd_field, wd_filter, wd_read_filter, wd_register_filter, packet_read_field_uint64, \
    wd_register_field, wd_packet_dissect, wd_packet_dissectors, wd_packet_layers_count, wd_read_field, \
    wd_packet_show, wd_packet_show_pdml, wd_info_profile, wd_packet_summary, packet_read_value_to_string, \
    wd_set_packet_direction, wd_set_dissection_mode, packet_read_field_string, packet_read_field_display_name, \
    WD_DIR_TX, WD_DIR_RX, WD_MODE_NORMAL, WD_MODE_FAST, WD_MODE_FULL, wd_set_log_level, WD_LOG_LEVEL_DEBUG, \
    wd_info_version, WD_LOG_LEVEL_NOISY
import sys
import os
import ctypes
import json
import signal
import copy
import pprint

sys.path.insert(0, os.getcwd() + './libs')

# Add libs to python path
# sys.path.insert(0, os.getcwd() + '../.')
wd_commands = []
# Read the JSON file containing the filters and flooding attributes
with open("./src/libs/WD_commands.json", 'r') as f:
    wd_commands = json.load(f)

Structure_json = wd_commands["Structure"]
Flooding_json = wd_commands["Flooding"]

hdr_rx = NORDIC_BLE(board=75, protocol=2, flags=0x1)
hdr_tx = NORDIC_BLE(board=75, protocol=2, flags=0x3)


class ValidatePacket:
    # Constructor
    def __init__(self):
        global Structure_json, Flooding_json
        # ----- WDissector Initialization -----
        print('\n---------------------- WDissector -----------------------')
        # Initialize WDissector instance
        self.wd_instance = wd_init("proto:nordic_ble")
        wd_set_dissection_mode(self.wd_instance, WD_MODE_FAST)
        # wd_set_log_level(WD_LOG_LEVEL_NOISY)
        wd_set_log_level(WD_LOG_LEVEL_DEBUG)
        print("WDissector Version:" + wd_info_version())
        print("WDissector Loaded Profile:" + wd_info_profile())

        # Declaring the filters and fields
        self.structure_filter_options = []
        self.structure_field_options = []
        self.flooding_filter_options = []
        self.flooding_field_options = []
        # Event counter for flooding detection
        self.event_counter = None

        for i in Structure_json:
            if i["obs"] == "filter":
                fil = wd_filter(i["command"])
                # If there is any error with a filter or a field, the error message will be
                # a SEGMENTATION FAULT
                if not fil:
                    s = i["command"]
                    print(f"{Fore.RED}Structure Filter Error: wd_filter({s})")
                    exit(1)
                self.structure_filter_options.append(
                    (fil, i["command"]))
            else:
                hfi = wd_field(i["command"])
                if not hfi:
                    s = i["command"]
                    print(f"{Fore.RED}Structure Field Error: wd_field({s})")
                    exit(1)
                self.structure_field_options.append(hfi)

        for j in Flooding_json:
            if j["obs"] == "filter":
                fil = wd_filter(j["command"])
                if not fil:
                    output = j["command"]
                    print(f"{Fore.RED}Flooding Filter Error: wd_filter({output})")
                    exit(1)
                self.flooding_filter_options.append((fil, j["command"]))
            else:
                hfi = wd_field[j["command"]]
                if not hfi:
                    output = j["command"]
                    print(f"{Fore.RED}Flooding Field Error: wd_field({output})")
                    exit(1)
                self.flooding_field_options.append(hfi)

        print(f'{Fore.GREEN}WDissector fully initialized!')
        print("**** Structure ****")
        print("QTD Filters:", len(self.structure_filter_options))
        print("QTD Fields:", len(self.structure_field_options))
        print("------------------------------")
        print("**** Flooding ****")
        print("QTD Filters:", len(self.flooding_filter_options))
        print("QTD Fields:", len(self.flooding_field_options))
        print("------------------------------")


    def register_flooding_filter(self):
        i = 0
        while i < len(self.flooding_filter_options):
            wd_register_filter(
                self.wd_instance, self.flooding_filter_options[i][0]
            )
            i += 1


    def register_flooding_field(self):
        j = 0
        while j < len(self.flooding_field_options):
            wd_register_field(
                self.wd_instance, self.flooding_field_options[j]
            )
            j += 1


    def register_structure_filter(self):
        i = 0
        while i < len(self.structure_filter_options):
            wd_register_filter(
                self.wd_instance, self.structure_filter_options[i][0]
            )
            i += 1


    def register_structure_field(self):
        j = 0
        while j < len(self.flooding_field_options):
            wd_register_field(
                self.wd_instance, self.structure_field_options[j]
            )
            j += 1

    def pkt_layers(self, wpkt=None):
        wd_packet_dissect(self.wd_instance,
                              bytearray(raw(wpkt)), len(wpkt))
        dissectors = wd_packet_dissectors(self.wd_instance)
        print("Dissectors: ", dissectors.split("/"))


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
            self.hdr_ble_nordic = hdr_rx
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_RX)
            wpkt = self.hdr_ble_nordic / pkt
            wd_packet_dissect(self.wd_instance,
                              bytearray(raw(wpkt)), len(wpkt))
            print(f'RX Summary: {wd_packet_summary(self.wd_instance)}')
            return True
        else:
            print("---- TX direction ----")
            self.hdr_ble_nordic = hdr_tx
            # Prepare wireshark packet for dissection
            wpkt = self.hdr_ble_nordic / pkt
            # Register filters and fields here
            self.register_structure_filter()
            self.register_structure_field()
            self.register_flooding_filter()
            self.register_flooding_field()
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_TX)
            # print(hexlify(bytearray(raw(wpkt))))
            # Dissect packet
            # print(len(raw(wpkt)))
                       
            # self.pkt_layers(wpkt)

            wd_packet_dissect(self.wd_instance,
                              bytearray(raw(wpkt)), len(wpkt))

            dissectors = wd_packet_dissectors(self.wd_instance)
            print("Dissectors: ", dissectors.split("/"))

            # Read packet filter (True or False) and field results (ptr or None)
            filter_result = []
            field_result = []
            idx = 0
            while idx < len(self.structure_filter_options):
                filter_result.append(wd_read_filter(
                    self.wd_instance, self.structure_filter_options[idx][0]))
                idx += 1
            fdx = 0
            while fdx < len(self.structure_field_options):
                field_result.append(wd_read_field(
                    self.wd_instance, self.structure_field_options[fdx]))
                fdx += 1

            print("Filter_result", filter_result)
            print("Field_result:", field_result)

            # Print packet summary
            summary = wd_packet_summary(self.wd_instance)
            print("SUMMARY:\n", summary)
            if summary is None:
                return
            # Validate packet
            if summary and 'Malformed' not in summary and 'Unknown' not in summary:
                try:
                    print(pkt.show())
                except:
                    print(Fore.RED + "[Error]", summary)

                if filter_result[1] and filter_result[0]:
                    if filter_result[3] and filter_result[4]:
                        print(Fore.RED + '[Error] ', end='')
                        return False
                    else:
                        print(Fore.GREEN + '[Valid] ', end='')
                        return True
                elif filter_result[1]:
                    print(Fore.RED + '[Error] ', end='')
                    return False
                else:
                    if summary and 'AUX_CONNECT_REQ' in summary and \
                            filter_result[2]:
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
