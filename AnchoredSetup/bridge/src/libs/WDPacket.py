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
import threading



# Thread to replace the print from python, to avoid buffer problems
p_lock = threading.Lock()
# Thread to avoid possible conflicts between central and peripheral threads
# to receive the packets in order
g_lock = threading.Lock()

# Function to print using the thread


def print_l(*x):
    global p_lock
    with p_lock:
        print(*x)


# Add libs to python path
# sys.path.insert(0, os.getcwd() + '../.')
wd_commands = []
# Read the JSON file containing the filters and flooding attributes
with open("./src/libs/WD_commands.json", 'r') as f:
    wd_commands = json.load(f)

Structure_json = wd_commands["Structure"]
Flooding_json = wd_commands["Flooding"]

hdr_rx = NORDIC_BLE(board=3, protocol=2, flags=0x1, channel=39)
hdr_tx = NORDIC_BLE(board=3, protocol=2, flags=0x3, channel=39)

first_pkt = False
aux_crc = True 

class ValidatePacket:
    # Constructor
    def __init__(self):
        global Structure_json, Flooding_json
        # ----- WDissector Initialization -----
        print_l('\n---------------------- WDissector -----------------------')
        # Initialize WDissector instance
        self.wd_instance = wd_init("proto:nordic_ble")
        # Set the dissection mode to fast
        wd_set_dissection_mode(self.wd_instance, WD_MODE_FULL)
        # wd_set_log_level(WD_LOG_LEVEL_NOISY)
        wd_set_log_level(WD_LOG_LEVEL_NONE)
        # Set the WDissector to show all the logs

        print_l("WDissector Version:" + wd_info_version())
        print_l("WDissector Loaded Profile:" + wd_info_profile())

        # Declaring the Structure filters
        self.structure_filter_options = []
        # Declaring the Flooding filters
        self.flooding_filter_options = []
        # Layer array flooding flag
        self.layer_array_flag = dict()
        # Current flooding layer index
        self.current_flooding_layer = 0
        # Declaring the selected filters for each packet
        self.selected_filter = []
        # Event counter for flooding detection
        self.rsp_counter = 0
        self.req_counter = 0
        # Event threshold to detect the flooding
        self.event_threshold = 0
        # Flag that detects if a request is pending
        self.req_pending = False
        # Flag to enable the check sequence function
        self.check_sn = True
        # First packet master filter
        self.check_first_filter = None

        check_first_string = "btle.master_bd_addr"
        self.check_first_filter = wd_filter(check_first_string)
        # Sequence bits filter
        bits_string = "btle.data_header.next_expected_sequence_number == 1 and btle.data_header.sequence_number == 1"
        self.check_bits = wd_filter(bits_string)

        for i in Structure_json.keys():
            # 1st filter to select the layers present in the analyzed packet
            fil_1 = wd_filter(i)
            # If there is any error with a filter or a field, the error message will be
            # a SEGMENTATION FAULT
            if not fil_1:
                s = i
                print_l(f"{Fore.RED}Layer Filter Error: wd_filter({s})")
                exit(1)

            x = []
            for j in Structure_json[i]:
                # 2nd filter to select the specific filters according to an opcode
                fil_2 = wd_filter(j["opcode"])
                if not fil_2 and j["type"] == "specific":
                    output = j["opcode"]
                    print_l(
                        f"{Fore.RED}Opcode Filter Error: wd_filter({output})")
                    exit(1)
                j["_opcode"] = fil_2
                # 3rd filter to effectively apply on the packet
                fil_3 = wd_filter(j["command"])
                if not fil_3:
                    output = j["command"]
                    print_l(
                        f"{Fore.RED}Structure Filter Error: wd_filter({output})")
                    exit(1)
                j["_command"] = fil_3
                x.append(j)
            # All the filter options (1st, 2nd and 3rd)
            self.structure_filter_options.append((fil_1, x))
        idx = 0
        for i in Flooding_json.keys():
            # 1st filter to select the layers ATT or LL
            fld_1 = wd_filter(i)
            if not fld_1:
                output = i
                print_l(f"{Fore.RED}Flooding Filter Error: wd_filter({output})")
                exit(1)
            # Initialize all the possible layer with False
            self.layer_array_flag[idx] = {
                "req_pending": False, "rsp_pending": False, "req_counter": 0, "rsp_counter": 0}
            x = []
            # 2nd filter to check the opcode of the packet (request/response)
            for j in Flooding_json[i]:
                fld_2 = wd_filter(j["command"])
                j["_command"] = fld_2
                if not fld_2:
                    output = j["command"]
                    print_l(
                        f"{Fore.RED}Flooding Filter Error: wd_filter({output})")
                    exit(1)
                x.append(j)
            # All the flooding options ATT and LL (request/response)
            self.flooding_filter_options.append((fld_1, x))
            idx += 1

        print_l(f'{Fore.GREEN}WDissector fully initialized!')
        print_l("**** Structure ****")
        print_l("QTD Filters:", len(self.structure_filter_options))
        print_l("------------------------------")
        print_l("**** Flooding ****")
        print_l("QTD Filters:", len(self.flooding_filter_options))
        print_l(f'Dictionary flooding: {self.layer_array_flag}')
        print_l("------------------------------")

        # ------------------ State Machine Initialization ------------------
        print('\n--------------------- State Machine ---------------------')
        self.StateMachine = Machine()
        # Load State Mapper configuration
        ret = self.StateMachine.init("./src/configs/ble_config_v3.json")
        if not ret:
            print("Error initializing state machine model")
            exit(1)
        # Load State Machine model
        ret = self.StateMachine.LoadModel("./src/smp_crtl_ll_map_v2.json")
        if not ret:
            print("Error loading state machine model")
            exit(1)

        print(f'Total States Loaded: {self.StateMachine.TotalStates()}')
        print(
            f'Total Transitions Loaded: {self.StateMachine.TotalTransitions()}')

    def register_flooding_filter(self):
        # Register the 1st filter to check the layers ATT or LL in the packet
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
        #print_l("-------After dissection:--------", wd_packet_summary(self.wd_instance))
        idx = 0
        # Check the present layers in the packet
        while idx < len(self.structure_filter_options):
            #print_l("Before append:-----",self.structure_filter_options[idx][0])
            temp_x = wd_read_filter(self.wd_instance, self.structure_filter_options[idx][0])
            #print_l("Temp var----", temp_x)
            filter_result.append(temp_x)
            idx += 1
        #print_l("Filter Result after temp", filter_result)
        cont = 0
        temp_result = []
        f_idx = 0
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
                        #print_l(f"--------------\n[{f_idx}] Filter: {j['command']}\n--------------")
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
                            #print_l(f"--------------\n[{f_idx}] Filter Applied: {j['command']}\n--------------")
                    f_idx += 1
            cont += 1

    def check_sequence(self, wpkt=None):
        global aux_crc
        '''
            Function responsible for checking the sequence bits of the packet
            1 - After received a connection request, identify the first packet
                after the request.
            2 - Check if the first packet of the master has the sequence bits
                equal 1.
            3 - If the result is true, attack is detected and error sequence identified.
            4 - If False, the sequence is correct.
        '''
        # Flag to check the first packet after connection request
        global first_pkt
        # Filter to identify the connection request
        connect_req_string = "btle.advertising_header.pdu_type == 0x5"
        #valid_conn_req_string = "(btle.link_layer_data.interval >= 7 and btle.link_layer_data.interval <= 400) and (btle.link_layer_data.timeout >= 10 and btle.link_layer_data.timeout <= 3200)"
        crc_string = "btle.crc.incorrect"

        crc_filter = wd_filter(crc_string)
        connect_req_filter = wd_filter(connect_req_string)
        #valid_conn_req_filter = wd_filter(valid_conn_req_string)
        
        wd_register_filter(self.wd_instance, connect_req_filter)
        #wd_register_filter(self.wd_instance,valid_conn_req_filter)
        wd_register_filter(self.wd_instance, crc_filter)

        self.x = bytearray(raw(wpkt))
        wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
        res = wd_read_filter(self.wd_instance, connect_req_filter)

        res_crc =  wd_read_filter(self.wd_instance, crc_filter)

        #res_correct_conn_req = wd_read_filter(self.wd_instance, valid_conn_req_filter)
        # After received the connection request register the filters
        # to check the first master packet and the sequence bits
        if res:
            # Set the check flag to True
            first_pkt = True
            if res_crc:
                aux_crc = False
        #if res_correct_conn_req:
        #    aux_valid_conn_req = False


    def validate_pkt(self, pkt=None, direction=None):
        # Headers from RX and TX roles respectively
        global hdr_rx, hdr_tx, first_pkt, aux_crc, aux_valid_conn_req
        if pkt is None:
            print_l(Fore.RED + "[Error] Packet empty.")
            exit(1)
        if direction is None:
            print_l(Fore.RED + "[Error] Direction incorrect.")
            exit(1)
        elif direction == WD_DIR_RX:
            #print_l("---- RX direction ----")
            self.hdr_ble_nordic = hdr_rx
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_RX)
            wpkt = self.hdr_ble_nordic / pkt
            self.y = bytearray(raw(wpkt))
            wd_packet_dissect(self.wd_instance, self.y, len(self.y))
            #print_l(f'RX Summary: {wd_packet_summary(self.wd_instance)}')
            return True
        else:
            #print_l("---- TX direction ----")
            self.hdr_ble_nordic = hdr_tx
            # Prepare wireshark packet for dissection
            wpkt = self.hdr_ble_nordic / pkt
            self.x = bytearray(raw(wpkt))
            # Register filters and fields here
            self.register_structure_filter()
            # Set direction (required for sequence analyser)
            wd_set_packet_direction(self.wd_instance, WD_DIR_TX)
            # Enable the sequence bits checking
            if self.check_sn:
                # Function to check the connection request and initialize
                # the first packet and sequence bits filters
                self.check_sequence(self.x)
                # Filter to identify the first packet of the master
                wd_register_filter(self.wd_instance, self.check_first_filter)
                # Sequence bits filter
                wd_register_filter(self.wd_instance, self.check_bits)
                wd_packet_dissect(self.wd_instance, self.x, len(self.x))
                first_res = wd_read_filter(
                    self.wd_instance, self.check_first_filter)
                # Case is the first packet after the connection request
                if first_res == True and first_pkt == True:
                    # Filter to check the sequence bits
                    sn_nesn_res = wd_read_filter(
                        self.wd_instance, self.check_bits)
                    # Reset the flags from the first packet and disable the sequence checking
                    first_pkt = False
                    self.check_sn = False
                    #if sn_nesn_res:
                    #    print_l(Fore.RED + "[Error] Invalid Sequence. Packet structure is malformed")
                    #    return False
                    if not aux_crc:
                        print_l(Fore.RED + "[Error] Invalid CRC. Packet structure is malformed")
                        return False 
                    #elif not aux_valid_conn_req:
                    #    print_l(Fore.RED + "[Error] Invalid ConnReq. Packet structure is malformed")
                        exit(1)
            # Function to select the filter that will be used
            self.pkt_layers(self.x)
            # Dissect the packet - 3rd time
            # self.x = bytearray(raw(wpkt))
            wd_packet_dissect(self.wd_instance, self.x, len(self.x))
            #print_l(wd_packet_show_pdml(self.wd_instance))
            # wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            # Read packet filter (True or False) and field results (ptr or None)
            filter_result = []
            idx = 0
            while idx < len(self.selected_filter):
                # print_l("FILTROOOOOOOOOOO")
                wd_read_filter(self.wd_instance, self.selected_filter[idx])
                x = wd_read_filter(self.wd_instance, self.selected_filter[idx])
                filter_result.append(x)
                idx += 1
            #print_l("Filter result: ", filter_result)
            # Print packet summary
            summary = wd_packet_summary(self.wd_instance)
            # if len(summary):
            #     print_l("wd_summary:", summary)
            if summary is None:
                return
            # Validate packet
            # if summary and 'Malformed' not in summary and 'Unknown' not in summary:
            if summary and 'Malformed' not in summary:
                try:
                    #print_l(pkt.show())
                    #print_l(Fore.GREEN + '[Valid]')
                    pass
                except:
                    print_l(Fore.RED + "[Error]", summary)
                # Case all the filters are True the packet will be valid
                # and return True
                # In other case will be invalid and return False
                if all(filter_result) == True:
                    #print_l(Fore.GREEN + '[Valid]')
                    return True
                else:
                    #print_l(Fore.RED + '[Error] Packet structure is malformed')
                    try:
                        #wpkt.show()
                        pass
                    except:
                        pass
                    #print_l(f'Filter Result: {filter_result}')
                    return False
                    exit(1)
            else:
                #print_l(Fore.RED + '[Error] Packet structure is malformed')
                try:
                    #wpkt.show()
                    pass
                except:
                    pass
                return False
                exit(1)

    def flooding_selection(self, wpkt=None):
        filter_result = []
        # Save the selected filters according to the layers, type and flag
        self.selected_filter = []
        self.x = bytearray(raw(wpkt))
        # Dissect the packet to filter the layers
        wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
        idx = 0
        # Check the present layers in the packet ATT or LL
        while idx < len(self.flooding_filter_options):
            a = wd_read_filter(
                self.wd_instance, self.flooding_filter_options[idx][0])
            if a:
                self.current_flooding_layer = idx
            filter_result.append(a)
            idx += 1
        cont = 0
        while cont < len(filter_result):
            if filter_result[cont]:
                # According to the layers in the packet check
                # if is a request or a response
                for j in self.flooding_filter_options[cont][1]:
                    # Register request filters
                    if j["type"] == "request":
                        wd_register_filter(
                            self.wd_instance, j["_command"]
                        )
                        # Save the selected filter and the role request
                        self.selected_filter.append((j["_command"], j["type"]))
                    # Register response filters
                    elif j["type"] == "response":
                        wd_register_filter(
                            self.wd_instance, j["_command"]
                        )
                        # Save the selected filter and the role response
                        self.selected_filter.append((j["_command"], j["type"]))
                    # Register indication filters
                    # else:
                    #     wd_register_filter(
                    #         self.wd_instance, j["_command"]
                    #     )
                    #     self.selected_filter.append(j["_command"])
            cont += 1

    def flooding_pkt(self, pkt=None, direction=None, n_event=None):
        '''
            * If sniffer miss a packet this will cause inteference
            on the flooding validation.
            * Include a filter btle.nack to avoid false positives, due to
            missing packet in the capture.
            * Include an array flag validation, depending on the layers
            present in the packet (LL, ATT, SMP).
            * Use the cont from flood_selection to update the array flag
            validation.
        '''
        # Headers from RX and TX roles respectively
        global hdr_rx, hdr_tx
        filter_result = []
        if pkt is None:
            print_l(Fore.RED + "[Error] Packet empty.")
            exit(1)
        if direction is None:
            print_l(Fore.RED + "[Error] Direction incorrect.")
            exit(1)
        elif direction == WD_DIR_RX:
            # RX direction
            # Check the layers in the packet
            self.register_flooding_filter()
            self.hdr_ble_nordic = hdr_rx
            wpkt = self.hdr_ble_nordic / pkt
            # Register the filters acoording to the layers and role
            self.flooding_selection(wpkt)
            # filter_sniffer = wd_filter("btle.nack")
            # wd_register_filter(self.wd_instance, filter_sniffer)
            wd_set_packet_direction(self.wd_instance, direction)
            wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            # sniffer_res = wd_read_filter(self.wd_instance, filter_sniffer)
            idx = 0
            # After selecting the filters according to the layers and role
            # read the filter
            while idx < len(self.selected_filter):
                res = wd_read_filter(
                    self.wd_instance, self.selected_filter[idx][0])
                # If the filter is true save it and the role (request/response)
                if res == True:
                    filter_result.append(res)
                    role = self.selected_filter[idx][1]
                idx += 1
            #print_l("RESULTADO FILTRO RX: ", filter_result)
            # Case filter result is empty, so the packet is not ATT or LL
            # request or response
            if len(filter_result) == 0:
                # print_l(Fore.MAGENTA + "Ponto 3")
                return True
            # Case filter result is true, so verify the role
            if all(filter_result):
                #print_l(filter_result)
                # Verify the role and flags of the selected layer (ATT/LL)
                y = self.layer_array_flag[self.current_flooding_layer]
                # Case the response is detected the req_pending is set to false
                # and a new request could be received
                if role == "response":
                    # Update the request pending
                    y["req_pending"] = False
                    #print_l("Request Reset Flag!!!")
                # Case the request is detected the rsp_pending is set to true
                # and a new responser could be received
                else:
                    # Update the response pending
                    y["rsp_pending"] = True
                    #print_l("Response Reset Flag!!!")
        else:
            # TX direction
            # Check the layers in the packet
            self.register_flooding_filter()
            self.hdr_ble_nordic = hdr_tx
            wpkt = self.hdr_ble_nordic / pkt
            # Register the filters acoording to the layers and role
            self.flooding_selection(wpkt)
            # filter_sniffer = wd_filter("btle.nack")
            # wd_register_filter(self.wd_instance, filter_sniffer)
            wd_set_packet_direction(self.wd_instance, direction)
            wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            # sniffer_res = wd_read_filter(self.wd_instance, filter_sniffer)
            #print_l("filtro:", self.selected_filter)
            idx = 0
            # After selecting the filters according to the layers and role
            # read the filter
            while idx < len(self.selected_filter):
                res = wd_read_filter(
                    self.wd_instance, self.selected_filter[idx][0])
                #print(res)
                # If the filter is true save it and the role (request/response)
                if res == True:
                    filter_result.append(res)
                    role = self.selected_filter[idx][1]
                idx += 1
            #print_l("RESULTADO FILTRO TX: ", filter_result)
            # Case filter list is empty, so the packet is not ATT or LL
            # request or response
            if len(filter_result) == 0:
                # print_l(Fore.MAGENTA + "Ponto 3")
                return True
            
            if all(filter_result):
                y = self.layer_array_flag[self.current_flooding_layer]
                # Case the request pending is available and receives a new request
                if role == "request" and y["req_pending"] == False:
                    # Update the request counter
                    y["req_counter"] = n_event
                    # Update the request pending
                    y["req_pending"] = True
                    # print_l("req_counter: ", y["req_counter"])
                    # print_l("req_pending: ", y["req_pending"])
                    return True
                # Case the response pending is available and receives a new response
                elif role == "response" and y["rsp_pending"] == True:
                    # Update the response counter
                    y["rsp_counter"] = n_event
                    # Update the response pending
                    y["rsp_pending"] = False
                    # print_l("rsp_counter: ", y["rsp_counter"])
                    # print_l("rsp_pending: ", y["rsp_pending"])
                    return True
                elif role == "request" and y["req_pending"] == True:
                    # Case the request pending is busy and receives a new request
                    # Check the difference between the current event and the last request
                    event_delta = abs(n_event - y["req_counter"])
                    # Update the request counter
                    y["req_counter"] = n_event
                elif role == "response" and y["rsp_pending"] == False and y["rsp_counter"] != 0:
                    # Case the response pending is busy and receives a new response
                    # Check the difference between the current event and the last response
                    event_delta = abs(n_event - y["rsp_counter"])
                    # Update the response counter
                    y["rsp_counter"] = n_event
                elif role == "response" and y["rsp_pending"] == False and y["rsp_counter"] == 0:
                    # Case the master initiate sending a response
                    print_l(Fore.RED + "[Error] Response error.")
                    return False
                    exit(1)
                # print_l("event_delta: ", event_delta)
                # print_l("threshold: ", self.event_threshold)
                # Case the difference is greater than the threshold is not flooding
                if event_delta >= self.event_threshold:
                    return True
                # Case the difference is lower than the threshold flooding detected
                else:
                    #print_l(f'Request pending, {self.event_threshold - event_delta} events to wait left')
                    return False
                    exit(1)

    def machine_pkt(self, pkt=None, direction=None):
        if direction == WD_DIR_RX:
            self.hdr_ble_nordic = hdr_rx
        else:
            self.hdr_ble_nordic = hdr_tx
        wpkt = self.hdr_ble_nordic / pkt

        if SM_Pairing_Request in pkt:
            # sc_mitm_string = "btsmp.opcode == 0x01 and btsmp.sc_flag == True and btsmp.mitm_flag == True"
            # sc_no_mitm_string = "btsmp.opcode == 0x01 and btsmp.sc_flag == True and btsmp.mitm_flag == False"

            # sc_mitm_filter = wd_filter(sc_mitm_string)
            # sc_no_mitm_filter = wd_filter(sc_no_mitm_string)
            
            # wd_register_filter(self.wd_instance, sc_mitm_filter)
            # wd_register_filter(self.wd_instance, sc_no_mitm_filter)

            # self.x = bytearray(raw(wpkt))
            # wd_packet_dissect(self.wd_instance, self.x, len(wpkt))

            # res_mitm = wd_read_filter(self.wd_instance, sc_mitm_filter)

            # res_no_mitm =  wd_read_filter(self.wd_instance, sc_no_mitm_filter)
            auth_value = pkt[SM_Pairing_Request].authentication
            if (auth_value & (0x80 | 0x40)) > 0:
                print(Fore.YELLOW + '           =========== Pairing: SC + MitM ===========')
                self.StateMachine.LoadModel('./src/libs/smp_crtl_ll_sc_map_v3.json', merge=False)

            elif (auth_value & 0x80) > 0:
                print(Fore.YELLOW + '           =========== Pairing: SC ===========')
                self.StateMachine.LoadModel('./src/libs/smp_crtl_ll_sc_map_nomitm.json', merge=False)
            else:
                print(Fore.YELLOW + '           =========== Pairing: Legacy Pairing ===========')

            # wd_set_packet_direction(self.wd_instance, WD_DIR_RX)
            # self.StateMachine.PrepareStateMapper(self.wd_instance)
            # self.x = bytearray(raw(wpkt))
            # wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
            # self.StateMachine.RunStateMapper(self.wd_instance, True)

        # Convert to raw and then to bytearray the packet
        self.x = bytearray(raw(wpkt))
        #print_l(f'{Fore.MAGENTA}1) BEFORE Transition:')
        # print_l(f'{Fore.YELLOW}Previous State: {self.StateMachine.GetPreviousStateName()}')
        # print_l(f'{Fore.CYAN}Current State: {self.StateMachine.GetCurrentStateName()}')
        # next_states = self.StateMachine.GetNextStateNames()
        # if len(next_states):
        #    print_l(f'Next Expected States:')
        #    for state in next_states:
        #        print_l(f' {state}')
        # 1) Prepare State Mapper
        self.StateMachine.PrepareStateMapper(self.wd_instance)
        # 2) Set packet direction (WD_DIR_TX or WD_DIR_RX) and decode packet
        # If is a connection request, it is necessary force RX direction according to the state mapper
        if BTLE_CONNECT_REQ in pkt:
            direction = WD_DIR_RX
        wd_set_packet_direction(self.wd_instance, direction)
        wd_packet_dissect(self.wd_instance, self.x, len(wpkt))
        # Case lose the connection and receive a new connection request,
        # reset the state machine adn go to the next state
        if BTLE_CONNECT_REQ in pkt:
            # wpkt.show()
            #print_l("Connection Request Received!")
            transition_valid = self.StateMachine.RunStateMapper(
                self.wd_instance, True)
        elif direction == WD_DIR_RX:
            # 3) Run State Mapper
            # 2nd argument force transition to RX state, so we just need to validate TX
            transition_valid = self.StateMachine.RunStateMapper(
                self.wd_instance, True)
        # Case receive a pairing request go to the next state
        elif SM_Pairing_Request in pkt:
            #print_l("Pairing Request Received!")
            transition_valid = self.StateMachine.RunStateMapper(
                self.wd_instance, True)
        else:
            transition_valid = self.StateMachine.RunStateMapper(
                self.wd_instance, False)
            #return False
        # 4) Validate transition
        # dir_str = "RX" if direction == WD_DIR_RX else "TX"
        # print_l(f'\nReceived {dir_str}: {wd_packet_summary(self.wd_instance)}\n')
        if direction == WD_DIR_TX:
            # print_l(f'{Fore.MAGENTA}2) AFTER Transition ({dir_str}):')
            # print_l(f'{Fore.YELLOW}Previous State: {self.StateMachine.GetPreviousStateName()}')
            # print_l(f'{Fore.CYAN}Current State: {self.StateMachine.GetCurrentStateName()}')
            # color = Fore.GREEN if transition_valid else Fore.RED
            #print_l(f'{color}TX Transition Valid? {transition_valid}')
            return transition_valid
        else:
            return True

