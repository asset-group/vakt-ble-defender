"""

Important!!!
It is necessary to pass the bytearray(raw(pkt)) to a local variable
before to use the wd_packet_dissect function

If not this will interfe on for and print functions, affecting
the final result

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
    wd_info_version, WD_LOG_LEVEL_NOISY, WD_LOG_LEVEL_NONE
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
        # Set the dissection mode to fast
        wd_set_dissection_mode(self.wd_instance, WD_MODE_FULL)
        # wd_set_log_level(WD_LOG_LEVEL_NOISY)
        wd_set_log_level(WD_LOG_LEVEL_NONE)
        # Set the WDissector to show all the logs
        # wd_set_log_level(WD_LOG_LEVEL_DEBUG)
        print("WDissector Version:" + wd_info_version())
        print("WDissector Loaded Profile:" + wd_info_profile())

        # Declaring the filters and fields
        self.structure_filter_options = []
        self.flooding_filter_options = []
        # Declaring the selected filters for each packet
        self.selected_filter = []
        # Event counter for flooding detection
        self.rsp_counter = 0
        self.req_counter = 0
        self.event_threshold = 0
        self.req_pending = False

        for i in Structure_json.keys():
            # 1st filter to select the layers present in the analyzed packet
            fil_1 = wd_filter(i)
            # If there is any error with a filter or a field, the error message will be
            # a SEGMENTATION FAULT
            if not fil_1:
                s = i
                print(f"{Fore.RED}Layer Filter Error: wd_filter({s})")
                exit(1)

            x = []
            for j in Structure_json[i]:
                # 2nd filter to select the specific filters according to an opcode
                fil_2 = wd_filter(j["opcode"])
                if not fil_2 and j["type"] == "specific":
                    output = j["opcode"]
                    print(f"{Fore.RED}Opcode Filter Error: wd_filter({output})")
                    exit(1)
                j["_opcode"] = fil_2
                # 3rd filter to effectively apply on the packet
                fil_3 = wd_filter(j["command"])
                if not fil_3:
                    output = j["command"]
                    print(f"{Fore.RED}Structure Filter Error: wd_filter({output})")
                    exit(1)
                j["_command"] = fil_3
                x.append(j)
            # All the filter options (1st, 2nd and 3rd)
            self.structure_filter_options.append((fil_1, x))

        for i in Flooding_json.keys():
            fld_1 = wd_filter(i)
            if not fld_1:
                output = i
                print(f"{Fore.RED}Flooding Filter Error: wd_filter({output})")
                exit(1)
            x = []
            for j in Flooding_json[i]:
                fld_2 = wd_filter(j["command"])
                j["_command"] = fld_2
                if not fld_2:
                    output = j["command"]
                    print(f"{Fore.RED}Flooding Filter Error: wd_filter({output})")
                    exit(1)
                x.append(j)
            self.flooding_filter_options.append((fld_1, x))

        print(f'{Fore.GREEN}WDissector fully initialized!')
        print("**** Structure ****")
        print("QTD Filters:", len(self.structure_filter_options))
        print("------------------------------")
        print("**** Flooding ****")
        print("QTD Filters:", len(self.flooding_filter_options))
        print("------------------------------")

    def register_flooding_filter(self):
        # Register the 1st filter to check the layers present in the packet
        i = 0
        while i < len(self.flooding_filter_options):
            wd_register_filter(
                self.wd_instance, self.flooding_filter_options[i][0]
            )
            i += 1

    def register_structure_filter(self):
        # Register the 1st filter to check the layers present in the packet
        i = 0
        while i < len(self.structure_filter_options):
            wd_register_filter(
                self.wd_instance, self.structure_filter_options[i][0]
            )
            i += 1

    def pkt_layers(self, wpkt=None):
        """

        Function responsible for preparing the filters that will be selected
        1 - Dissect the packet received and perform the 1st filter to check the layers. 
        2 - Register all the common filters according to the layer filtered previously.
        3 - Check with the 2nd filter, if the received packet has one specific opcode
            which is necessary apply a specific filter.
        4 - After check the 3 steps and register all the filters that will be used,
            fill the selected_filter list with the results.        

        """
        filter_result = []
        self.selected_filter = []
        # Dissect the packet - the 1st time
        self.x = bytearray(raw(wpkt))
        wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
        idx = 0
        # Check the present layers in the packet
        while idx < len(self.structure_filter_options):
            filter_result.append(wd_read_filter(
                self.wd_instance, self.structure_filter_options[idx][0]))
            idx += 1

        cont = 0
        temp_result = []
        while cont < len(filter_result):
            if filter_result[cont]:
                j = 0
                for j in self.structure_filter_options[cont][1]:
                    if j["type"] == "common":
                        # Register the common filters, according to each layer
                        wd_register_filter(
                            self.wd_instance, j["_command"]
                        )
                        # Save the registered common filter
                        self.selected_filter.append(j["_command"])
                        print("Filtro comum selecionado: ", j["command"])
                        print(j["_command"])
                    else:
                        # Register the opcode filter to check if
                        # there is a specific filter to be selected
                        wd_register_filter(
                            self.wd_instance, j["_opcode"]
                        )
                        # Dissect the packet - 2nd time
                        # self.x = bytearray(raw(wpkt))
                        wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
                        temp_result = wd_read_filter(
                            self.wd_instance, j["_opcode"])
                        if temp_result:
                            # Case there is a specific filter that need
                            # to be register according to the opcode filter
                            wd_register_filter(
                                self.wd_instance, j["_command"]
                            )
                            # Save the registered specific filter
                            self.selected_filter.append(j["_command"])
                            print("Filtro especifico selecionado: ", j["command"])
                            print(j["_command"])
            cont += 1

    def validate_pkt(self, pkt=None, direction=None):
        # Headers from RX and TX roles respectively
        global hdr_rx, hdr_tx
        if pkt is None:
            print(Fore.RED + "[Error] Packet empty.")
            exit(1)
        if direction is None:
            print(Fore.RED + "[Error] Direction incorrect.")
            exit(1)
        elif direction == WD_DIR_RX:
            print("---- RX direction ----")
            self.hdr_ble_nordic = hdr_rx
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_RX)
            wpkt = self.hdr_ble_nordic / pkt
            self.x = bytearray(raw(wpkt))
            wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            print(f'RX Summary: {wd_packet_summary(self.wd_instance)}')
            return True
        else:
            print("---- TX direction ----")
            self.hdr_ble_nordic = hdr_tx
            # Prepare wireshark packet for dissection
            wpkt = self.hdr_ble_nordic / pkt
            # Register filters and fields here
            self.register_structure_filter()
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_TX)
            # Function to select the filter that will be used
            self.pkt_layers(wpkt)
            # Dissect the packet - 3rd time
            # self.x = bytearray(raw(wpkt))
            wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            # print(wd_packet_show_pdml(self.wd_instance))
            # wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            # Read packet filter (True or False) and field results (ptr or None)
            filter_result = []
            idx = 0
            while idx < len(self.selected_filter):
                # print("FILTROOOOOOOOOOO")
                print(self.selected_filter[idx])
                wd_read_filter(self.wd_instance, self.selected_filter[idx])
                x = wd_read_filter(self.wd_instance, self.selected_filter[idx])
                filter_result.append(x)
                idx += 1
            print("Filter_result: ", filter_result) 
            # Print packet summary
            summary = wd_packet_summary(self.wd_instance)
            print("SUMMARY:\n", summary)
            if summary is None:
                return
            # Validate packet
            if summary and 'Malformed' not in summary and 'Unknown' not in summary:
                try:
                    # print(pkt.show())
                    pass
                except:
                    print(Fore.RED + "[Error]", summary)
                # Case all the filters are True the packet will be valid
                # and return True
                # In other case will be invalid and return False
                if all(filter_result) == True:
                    print(Fore.GREEN + '[Valid] ')
                    return True
                else:
                    print(Fore.RED + '[Error] ')
                    return False
            else:
                print(Fore.RED + '[Error] ')
                return False

    def flooding_selection(self, wpkt=None, flag=None):
        filter_result = []
        self.selected_filter = []
        self.x = bytearray(raw(wpkt))
        wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
        idx = 0
        # Check the present layers in the packet
        while idx < len(self.flooding_filter_options):
            filter_result.append(wd_read_filter(
                self.wd_instance, self.flooding_filter_options[idx][0]))
            idx += 1
        cont = 0
        while cont < len(filter_result):
            if filter_result[cont]:
                for j in self.flooding_filter_options[cont][1]:
                    if flag == "request":
                        wd_register_filter(
                            self.wd_instance, j["_command"]
                        )
                        self.selected_filter.append(j["_command"])
                    elif flag == "response":
                        wd_register_filter(
                            self.wd_instance, j["_command"]
                        )
                        self.selected_filter.append(j["_command"])
                    else:
                        wd_register_filter(
                            self.wd_instance, j["_command"]
                        )
                        self.selected_filter.append(j["_command"])
            cont += 1

    def flooding_pkt(self, pkt=None, direction=None, n_event=None):
        # Headers from RX and TX roles respectively
        global hdr_rx, hdr_tx
        filter_result = []
        if pkt is None:
            print(Fore.RED + "[Error] Packet empty.")
            exit(1)
        if direction is None:
            print(Fore.RED + "[Error] Direction incorrect.")
            exit(1)
        elif direction == WD_DIR_RX:
            print("----------------")
            self.register_flooding_filter()
            self.hdr_ble_nordic = hdr_rx
            wpkt = self.hdr_ble_nordic / pkt
            self.flooding_selection(wpkt, flag="response")
            # self.x = bytearray(raw(wpkt))
            wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            idx = 0
            while idx < len(self.selected_filter):
                res = wd_read_filter(self.wd_instance, self.selected_filter[idx])
                if res == True:
                    filter_result.append(res)
                idx += 1
            if len(filter_result) == 0:
                return True
            if all(filter_result):
                self.rsp_counter = n_event
                self.req_pending = False
                print("Reset Flag!!!")
        else:

            print("-----------------")
            self.register_flooding_filter()
            self.hdr_ble_nordic = hdr_tx
            wpkt = self.hdr_ble_nordic / pkt
            self.flooding_selection(wpkt, flag="request")
            # self.x = bytearray(raw(wpkt))
            wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            print("filtro:", self.selected_filter)
            idx = 0
            while idx < len(self.selected_filter):
                res = wd_read_filter(self.wd_instance, self.selected_filter[idx])
                if res == True:
                    filter_result.append(res)
                idx += 1
            print("RESULTADO FILTRO: ", filter_result)
            if len(filter_result) == 0:
                return True
            if all(filter_result) and self.req_pending == False:
                self.req_counter = n_event
                self.req_pending = True
                print("req_counter: ", self.req_counter)
                print("req_pending: ", self.req_pending)
                return True
        event_delta = abs(n_event - self.req_counter)
        print("event_delta: ", event_delta)
        if event_delta >= self.event_threshold:
            return True
        else:
            print(
                f'Request pending, {self.event_threshold - event_delta} events to wait left')
            return False
