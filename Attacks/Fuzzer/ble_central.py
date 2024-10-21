# Commom imports
import time
from binascii import hexlify
import threading
import os
import sys
import inspect
import json
import logging
from time import sleep, time
from serial import SerialException

# PyCryptodome imports
from Crypto.Cipher import AES

# Flask imports
from flask import Flask, request
from flask_socketio import SocketIO
# Scapy imports
from scapy.layers.bluetooth import HCI_Hdr, L2CAP_Connection_Parameter_Update_Request, _att_error_codes
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import wrpcap, raw
from scapy.packet import Raw

# BTLE Suite
from blesuite.pybt.att import AttributeProtocol
from blesuite.pybt.sm import SM, SecurityManagerProtocol
from blesuite.pybt.gatt import Server, UUID
from blesuite.entities.gatt_device import BLEDevice
import blesuite.utils.att_utils as att_utils
import blesuite.pybt.roles as ble_roles
import blesuite.pybt.gatt as PyBTGATT

# Colorama
from colorama import Fore, Back, Style
from colorama import init as colorama_init

# Project imports
from greyhound.machine import GreyhoundStateMachine
from greyhound import fitness
from greyhound import fuzzing
from greyhound.fuzzing import StateConfig, MutatorRandom, SelectorRandom, SelectorAll
from greyhound.webserver import send_vulnerability, send_fitness, SetFuzzerConfig
from drivers.NRF52_dongle import NRF52Dongle
import BLESMPServer
from monitors.monitor_serial import Monitor

states = [
    {'name': 'SCANNING', 'on_enter': 'send_scan_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    # {'name': 'SCANNING', 'on_enter': 'send_scan_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'INITIATING', 'on_enter': 'send_connection_request', 'timeout': 2, 'on_timeout': 'timeout'},
    {'name': 'GATT_SERVER', 'on_enter': 'send_gatt_response', 'timeout': 0.3, 'on_timeout': 'next'},
    {'name': 'FEATURE_REQ', 'on_enter': 'send_feature_request', 'timeout': 0.3, 'on_timeout': 'retry'},
    {'name': 'FEATURE_RSP', 'on_enter': 'send_feature_response', 'timeout': 0.3, 'on_timeout': 'retry'},
    {'name': 'LENGTH_REQ', 'on_enter': 'send_length_request', 'timeout': 0.3, 'on_timeout': 'retry'},
    {'name': 'LENGTH_RSP', 'on_enter': 'send_length_response'},
    {'name': 'VERSION_REQ', 'on_enter': 'send_version_indication', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'VERSION_RSP', 'on_enter': 'send_version_indication'},
    # {'name': 'SECURITY_RSP', 'on_enter': 'send_feature_request'},
    {'name': 'SECURITY_RSP'},
    {'name': 'MTU_LEN_RSP', 'on_enter': 'send_mtu_length_response'},
    {'name': 'MTU_LEN_REQ', 'on_enter': 'send_mtu_length_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'PRI_SERVICES', 'on_enter': 'send_pri_services_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    # {'name': 'PRI_SERVICES', 'on_enter': 'send_pri_services_request'},
    {'name': 'PAIR_REQUEST', 'on_enter': 'send_pair_request', 'timeout': 10, 'on_timeout': 'retry'},
    {'name': 'ENCRYPTION', 'on_enter': 'send_encryption_request'},
    {'name': 'KEY_EXCHANGE', 'timeout': 0.3, 'on_timeout': 'next'},
    {'name': 'SEC_SERVICES', 'on_enter': 'send_sec_services_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'CHARACTERISTICS', 'on_enter': 'send_characteristics_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'INCLUDES', 'on_enter': 'send_includes_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'DESCRIPTORS', 'on_enter': 'send_descriptors_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'READ', 'on_enter': 'send_read_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'WRITE', 'on_enter': 'send_write_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'DISCONNECT', 'on_enter': 'send_disconn_request'},

]

transitions = [
    # SCANNING -> CONNECTING
    {'trigger': 'update', 'source': 'SCANNING', 'dest': 'INITIATING',
     'conditions': 'receive_scan_response'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'SCANNING', 'dest': 'SCANNING'},

    # ------- Active Slave -----
    # CONNECTING -> FEATURE_RSP
    {'trigger': 'update', 'source': 'INITIATING', 'dest': 'FEATURE_RSP',
     'conditions': 'receive_feature_request', 'before': 'announce_connection'},
    # CONNECTING -> LL_LENGTH_RSP
    {'trigger': 'update', 'source': 'INITIATING', 'dest': 'LENGTH_RSP',
     'conditions': 'receive_length_request', 'before': 'announce_connection'},
    # CONNECTING -> LL_LENGTH_RSP
    {'trigger': 'update', 'source': 'INITIATING', 'dest': 'VERSION_RSP',
     'conditions': 'receive_version_indication', 'before': 'announce_connection'},
    # CONNECTING -> GATT_SERVER
    {'trigger': 'update', 'source': 'INITIATING', 'dest': 'GATT_SERVER',
     'conditions': 'receive_gatt_request', 'before': 'announce_connection'},
    # CONNECTING -> SECURITY_RSP
    {'trigger': 'update', 'source': 'INITIATING', 'dest': 'SECURITY_RSP',
     'conditions': 'receive_security_request', 'before': 'announce_connection'},
    # SECURITY_RSP -> VERSION_RSP
    {'trigger': 'update', 'source': 'SECURITY_RSP', 'dest': 'VERSION_RSP',
     'conditions': 'receive_version_indication'},
    # --> Timeout transition
    {'trigger': 'timeout', 'source': 'INITIATING', 'dest': 'SCANNING'},
    # GATT_SERVER -> FEATURES_REQ
    {'trigger': 'update', 'source': 'GATT_SERVER', 'dest': 'FEATURE_REQ',
     'conditions': 'handle_gatt_response'},
    # GATT_SERVER -> FEATURES_REQ
    {'trigger': 'next', 'source': 'GATT_SERVER', 'dest': 'FEATURE_REQ'},
    # FEATURE_RSP -> LENGTH_RSP
    {'trigger': 'update', 'source': 'FEATURE_RSP', 'dest': 'LENGTH_RSP',
     'conditions': 'receive_length_request'},
    # FEATURE_RSP -> VERSION_RSP
    {'trigger': 'update', 'source': 'FEATURE_RSP', 'dest': 'VERSION_RSP',
     'conditions': 'receive_version_indication'},
    # FEATURE_RSP -> MTU_LEN_RSP
    {'trigger': 'update', 'source': 'FEATURE_RSP', 'dest': 'MTU_LEN_RSP',
     'conditions': 'receive_mtu_length_request'},
    # FEATURE_RSP -> LENGTH_REQ # (Transition to passive slave)
    {'trigger': 'update', 'source': 'FEATURE_RSP', 'dest': 'LENGTH_REQ',
     'conditions': 'receive_2_empty_pdu'},
    # FEATURE_RSP -> FEATURE_RSP
    {'trigger': 'retry', 'source': 'FEATURE_RSP', 'dest': 'FEATURE_RSP'},
    # LENGTH_RSP -> MTU_LEN_RSP
    {'trigger': 'update', 'source': 'LENGTH_RSP', 'dest': 'MTU_LEN_RSP',
     'conditions': 'receive_mtu_length_request'},  # Auto transition
    # LENGTH_RSP -> VERSION_RSP
    {'trigger': 'update', 'source': 'LENGTH_RSP', 'dest': 'VERSION_RSP',
     'conditions': 'receive_version_indication'},  # Auto transition
    # LENGTH_RSP -> LENGTH_RSP
    {'trigger': 'update', 'source': 'LENGTH_RSP', 'dest': 'LENGTH_RSP',
     'conditions': 'receive_length_request'},
    # LENGTH_RSP -> MTU_LEN_REQ
    {'trigger': 'update', 'source': 'LENGTH_RSP', 'dest': 'VERSION_REQ',
     'conditions': 'receive_2_empty_pdu'},
    # VERSION_RSP -> MTU_LEN_RSP
    {'trigger': 'update', 'source': 'VERSION_RSP', 'dest': 'MTU_LEN_RSP',
     'conditions': 'receive_mtu_length_request'},  # Auto transition
    # VERSION_RSP -> FEATURE_RSP
    # {'trigger': 'update', 'source': 'VERSION_RSP', 'dest': 'FEATURE_RSP',
    # 'conditions': 'receive_feature_request'},  # Auto transition
    # VERSION_RSP -> MTU_LEN_REQ
    {'trigger': 'update', 'source': 'VERSION_RSP', 'dest': 'MTU_LEN_REQ',
     'conditions': 'receive_2_empty_pdu'},  # Auto transition
    # # ------------------ ESP32 ----------------------
    # # VERSION_RSP -> FEATURE_RSP
    # {'trigger': 'update', 'source': 'VERSION_RSP', 'dest': 'FEATURE_RSP',
    #  'conditions': 'receive_feature_request'},  # Auto transition
    # # LENGTH_RSP -> SECURITY_RSP
    # {'trigger': 'update', 'source': 'LENGTH_RSP', 'dest': 'SECURITY_RSP',
    #  'conditions': 'receive_security_request'},
    # # SECURITY_RSP -> MTU_LEN_REQ
    {'trigger': 'update', 'source': 'SECURITY_RSP', 'dest': 'FEATURE_REQ',
     'conditions': 'receive_2_empty_pdu'},
    # # ------------------ ESP32 ----------------------
    # MTU_LEN_RSP -> VERSION_REQ  (Response to Request state transition)
    {'trigger': 'update', 'source': 'MTU_LEN_RSP', 'dest': 'VERSION_REQ',
     'conditions': 'receive_empty_pdu'},

    # ---------------------------

    # ------- Passive Slave -----
    # CONNECTING -> FEATURES_REQ
    {'trigger': 'update', 'source': 'INITIATING', 'dest': 'FEATURE_REQ',
     'conditions': 'receive_2_empty_pdu', 'before': 'announce_connection'},
    # FEATURE_REQ -> LENGTH_REQ
    {'trigger': 'update', 'source': 'FEATURE_REQ', 'dest': 'LENGTH_REQ',
     'conditions': 'receive_feature_response'},
    # --> Timeout transition
    {'trigger': 'retry', 'source': 'FEATURE_REQ', 'dest': 'FEATURE_REQ'},
    # LENGTH_REQ -> MTU_LEN_REQ
    {'trigger': 'update', 'source': 'LENGTH_REQ', 'dest': 'MTU_LEN_REQ',
     'conditions': 'receive_length_response'},
    # --> Timeout transition
    {'trigger': 'retry', 'source': 'LENGTH_REQ', 'dest': 'LENGTH_REQ'},
    # MTU_LEN_REQ -> VERSION_REQ
    {'trigger': 'update', 'source': 'MTU_LEN_REQ', 'dest': 'VERSION_REQ',
     'conditions': 'receive_mtu_length_response', 'unless': 'version_already_received'},
    # --> Timeout transition
    {'trigger': 'retry', 'source': 'MTU_LEN_REQ', 'dest': 'MTU_LEN_REQ'},
    # MTU_LEN_REQ -> PRI_SERVICES
    {'trigger': 'update', 'source': 'MTU_LEN_REQ', 'dest': 'PRI_SERVICES',
     'conditions': ['receive_mtu_length_response', 'version_already_received']},
    # ---------------------------

    # VERSION_REQ -> GAP
    {'trigger': 'update', 'source': 'VERSION_REQ', 'dest': 'PRI_SERVICES',
     'conditions': 'receive_version_indication'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'VERSION_REQ', 'dest': 'VERSION_REQ'},
    # PRI_SERVICES -> PAIR_REQUEST
    {'trigger': 'update', 'source': 'PRI_SERVICES', 'dest': 'PAIR_REQUEST',  # Change
     'conditions': 'receive_pri_services'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'PRI_SERVICES', 'dest': 'PRI_SERVICES'},
    # PAIR_REQUEST -> ENCRYPTION
    {'trigger': 'update', 'source': 'PAIR_REQUEST', 'dest': 'ENCRYPTION',
     'conditions': 'finish_pair_response'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'PAIR_REQUEST', 'dest': 'PAIR_REQUEST'},
    # ENCRYPTION -> SEC_SERVICES
    {'trigger': 'update', 'source': 'ENCRYPTION', 'dest': 'KEY_EXCHANGE',
     'conditions': 'receive_encryption_response'},
    # KEY_EXCHANGE -> SEC_SERVICES
    {'trigger': 'update', 'source': 'KEY_EXCHANGE', 'dest': 'SEC_SERVICES',
     'conditions': 'finish_key_exchange'},
    # KEY_EXCHANGE -> SEC_SERVICES
    {'trigger': 'next', 'source': 'KEY_EXCHANGE', 'dest': 'SEC_SERVICES'},
    # SEC_SERVICES -> CHARACTERISTICS
    {'trigger': 'update', 'source': 'SEC_SERVICES', 'dest': 'CHARACTERISTICS',
     'conditions': 'receive_sec_services'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'SEC_SERVICES', 'dest': 'SEC_SERVICES'},
    # CHARACTERISTICS -> INCLUDES
    {'trigger': 'update', 'source': 'CHARACTERISTICS', 'dest': 'INCLUDES',  # Change
     'conditions': 'receive_characteristics'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'CHARACTERISTICS', 'dest': 'CHARACTERISTICS'},
    # INCLUDES -> DESCRIPTORS
    {'trigger': 'update', 'source': 'INCLUDES', 'dest': 'DESCRIPTORS',
     'conditions': 'receive_includes'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'INCLUDES', 'dest': 'INCLUDES'},
    # DESCRIPTORS -> READ
    {'trigger': 'update', 'source': 'DESCRIPTORS', 'dest': 'READ',
     'conditions': 'receive_descriptors'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'DESCRIPTORS', 'dest': 'DESCRIPTORS'},
    # READ -> WRITE
    {'trigger': 'update', 'source': 'READ', 'dest': 'WRITE',
     'conditions': 'finish_readings'},
    # --> Retry transition
    {'trigger': 'retry', 'source': 'READ', 'dest': 'READ'},
    # WRITE -> SCANNING
    {'trigger': 'update', 'source': 'WRITE', 'dest': 'DISCONNECT',
     'conditions': 'finish_writing'},
    # --> timeout transition
    {'trigger': 'retry', 'source': 'WRITE', 'dest': 'WRITE'},
    # DISCONNECT -> SCANNING
    {'trigger': 'update', 'source': 'DISCONNECT', 'dest': 'SCANNING',
     'conditions': 'receive_empty_pdu', 'before': 'announce_disconnection'},
]

states_fuzzer_config = {
    'SCANNING': StateConfig(
        states_expected=[BTLE_DATA, BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,
                         BTLE_SCAN_RSP, BTLE_SCAN_REQ, BTLE_CONNECT_REQ],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[BTLE_SCAN_REQ, BTLE_ADV],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],  # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),
    'INITIATING': StateConfig(
        states_expected=[BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,
                         BTLE_SCAN_REQ, BTLE_CONNECT_REQ, BTLE_DATA, BTLE_SCAN_RSP],
        fuzzable_layers=[BTLE_ADV],
        fuzzable_layers_mutators=[[MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None]],
        fuzzable_layers_mutators_lengths_chance=[5],
        fuzzable_action_transition=None),
    'GATT_SERVER': StateConfig(
        states_expected=[ATT_Hdr, L2CAP_Connection_Parameter_Update_Request, SM_Pairing_Response],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, ATT_Read_By_Type_Response, ATT_Read_Response, ATT_Error_Response,
                         LL_ENC_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5, 5, 5],
        fuzzable_action_transition=None),
    'FEATURE_REQ': StateConfig(
        states_expected=[SM_Security_Request, ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_VERSION_IND,
                         L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP, SM_Pairing_Response, LL_LENGTH_REQ,
                         LL_LENGTH_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_FEATURE_REQ],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
    'FEATURE_RSP': StateConfig(
        states_expected=[ATT_Hdr, LL_LENGTH_REQ, LL_UNKNOWN_RSP, L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP,
                         SM_Pairing_Response],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_FEATURE_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
    'LENGTH_REQ': StateConfig(
        states_expected=[LL_REJECT_IND, LL_LENGTH_REQ, ATT_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, LL_UNKNOWN_RSP,
                         LL_LENGTH_RSP,
                         SM_Pairing_Response, L2CAP_Connection_Parameter_Update_Request, LL_VERSION_IND, LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_LENGTH_REQ],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),

    'LENGTH_RSP': StateConfig(
        states_expected=[ATT_Hdr, LL_SLAVE_FEATURE_REQ, L2CAP_Connection_Parameter_Update_Request, SM_Security_Request,
                         LL_REJECT_IND, LL_VERSION_IND, LL_LENGTH_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_ENC_RSP,
                         SM_Pairing_Response],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_LENGTH_RSP, L2CAP_Connection_Parameter_Update_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 5, 5],
        fuzzable_action_transition=None),
    'VERSION_REQ': StateConfig(
        states_expected=[ATT_Read_By_Group_Type_Response, LL_REJECT_IND, ATT_Hdr, LL_VERSION_IND, LL_UNKNOWN_RSP,
                         LL_FEATURE_RSP,
                         L2CAP_Connection_Parameter_Update_Request, SM_Security_Request, LL_LENGTH_RSP, LL_LENGTH_REQ,
                         SM_Pairing_Response, LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_VERSION_IND],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10, 10],
        fuzzable_action_transition=None),
    'VERSION_RSP': StateConfig(
        states_expected=[ATT_Exchange_MTU_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response,
                         LL_REJECT_IND, LL_VERSION_IND,
                         LL_SLAVE_FEATURE_REQ,
                         L2CAP_Connection_Parameter_Update_Request,
                         LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_VERSION_IND],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
    'MTU_LEN_RSP': StateConfig(
        states_expected=[ATT_Hdr, L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Exchange_MTU_Response, LL_UNKNOWN_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'MTU_LEN_REQ': StateConfig(
        states_expected=[ATT_Exchange_MTU_Response, LL_SLAVE_FEATURE_REQ, SM_Security_Request, ATT_Error_Response,
                         LL_REJECT_IND, LL_FEATURE_RSP, LL_LENGTH_RSP, LL_UNKNOWN_RSP, SM_Pairing_Response,
                         LL_VERSION_IND, ATT_Hdr, LL_LENGTH_REQ, L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Exchange_MTU_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'PRI_SERVICES': StateConfig(
        states_expected=[LL_REJECT_IND, ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_VERSION_IND, LL_LENGTH_RSP, SM_Hdr,
                         L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Group_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'SEC_SERVICES': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, SM_Security_Request, LL_REJECT_IND, LL_LENGTH_RSP,
                         SM_Hdr, L2CAP_Connection_Parameter_Update_Request],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Group_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'CHARACTERISTICS': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_LENGTH_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[25, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'INCLUDES': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_REJECT_IND, LL_UNKNOWN_RSP, LL_LENGTH_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Find_Information_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[25, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'DESCRIPTORS': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_LENGTH_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'READ': StateConfig(
        states_expected=[ATT_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, LL_REJECT_IND],
        fuzzable_layers=[ATT_Hdr, ATT_Read_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'WRITE': StateConfig(
        states_expected=[ATT_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, LL_REJECT_IND],
        fuzzable_layers=[ATT_Hdr, ATT_Write_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[25, 25],
        fuzzable_action_transition=None),
    'DISCONNECT': StateConfig(
        states_expected=[ATT_Hdr, LL_UNKNOWN_RSP, ATT_Error_Response, LL_FEATURE_RSP, BTLE_DATA],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[0, 0],
        fuzzable_action_transition=None),
    'PAIR_REQUEST': StateConfig(
        states_expected=[LL_LENGTH_REQ, SM_Hdr, ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_LENGTH_RSP,
                         L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, SM_Hdr, SM_Pairing_Request, SM_Random, SM_Confirm, SM_Public_Key],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom],
                                  [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom,
                                    SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[30, 30, 30, 30, 30, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[30, 30, 30, 30, 30, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10, 10, 10, 10, 10],
        fuzzable_action_transition=None),
    'ENCRYPTION': StateConfig(
        states_expected=[SM_Failed, L2CAP_Connection_Parameter_Update_Request, SM_DHKey_Check, SM_Random, LL_ENC_RSP,
                         LL_START_ENC_REQ, LL_START_ENC_RSP,
                         ATT_Exchange_MTU_Response, LL_REJECT_IND,
                         LL_UNKNOWN_RSP, LL_FEATURE_RSP, ATT_Exchange_MTU_Request],
        fuzzable_layers=[BTLE_DATA, LL_ENC_REQ, LL_START_ENC_REQ, LL_ENC_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 25, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5, 5],
        fuzzable_action_transition=None),
    'KEY_EXCHANGE': StateConfig(
        states_expected=[LL_LENGTH_RSP, SM_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, ATT_Exchange_MTU_Response,
                         LL_REJECT_IND],
        fuzzable_layers=[BTLE, BTLE_DATA, L2CAP_Hdr, SM_Hdr, SM_Identity_Information, SM_Master_Identification,
                         SM_Identity_Address_Information, SM_Signing_Information],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom],
                                  [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom,
                                    SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[25, 50, 50, 50, 50, 50, 50, 50],
        # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50, 50, 50, 50, 50, 50],
        # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None], [None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5, 5, 5, 5, 5, 5],
        fuzzable_action_transition=None),
    'SECURITY_RSP': StateConfig(
        states_expected=[BTLE_DATA],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_VERSION_IND, LL_FEATURE_RSP, LL_LENGTH_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
}

conn_update = BTLE(access_addr=0x9a328370) / BTLE_DATA() / CtrlPDU() / LL_CONNECTION_UPDATE_REQ(win_size=2,
                                                                                                win_offset=2,
                                                                                                interval=46,  # 36 100
                                                                                                latency=0,
                                                                                                timeout=100,
                                                                                                instant=100
                                                                                                )

chm_update = BTLE(access_addr=0x9a328370) / BTLE_DATA() / CtrlPDU() / LL_CHANNEL_MAP_REQ(chM=0x1FF000000E,
                                                                                         instant=100
                                                                                         )


class BLECentralMethods(object):  # type: HierarchicalGraphMachine
    name = 'BLE'
    iterations = 0
    # Default Model paramaters
    master_address = '5d:36:ac:90:0b:22'
    master_feature_set = 'le_encryption+le_data_len_ext'  # Model dependent
    slave_address = 'd0:16:b4:e1:4b:aa'
    master_mtu = 247  # TODO: master_mtu
    conn_access_address = 0x9a328370
    conn_interval = 16
    conn_window_offset = 1
    conn_window_size = 2
    conn_channel_map = 0x1FFFFFFFFF
    conn_slave_latency = 0
    conn_timeout = 100
    dongle_serial_port = '/dev/ttyACM0'
    enable_fuzzing = False
    enable_duplication = False
    pairing_pin = '0000'
    scan_timeout = 6  # Time in seconds for detect a crash during scanning
    state_timeout = 3  # state timeout
    # pairing_iocap = 0x01  # DisplayYesNo
    pairing_iocap = 0x03  # NoInputNoOutput
    # pairing_iocap = 0x04  # KeyboardDisplay
    # paring_auth_request = 0x00  # No bounding
    paring_auth_request = 0x01  # Bounding
    # paring_auth_request = 0x08 | + 0x01  # Le Secure Connection + bounding
    # paring_auth_request = 0x04 | 0x01  # MITM + bounding
    # paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bounding
    monitor_serial_port = '/dev/ttyUSB0'
    monitor_serial_baud = 115200
    monitor_serial_magic_string = 'BLE Host Task Started'
    # -----------------------------------------------------------------------------------
    monitor = None
    # Timers for name reference
    conn_supervision_timer = None  # type: threading.Timer
    conn_general_timer = None  # type: threading.Timer
    scan_timeout_timer = None  # type: threading.Timer
    # Internal instances
    att = None
    smp = None  # type: SM
    driver = None  # type: NRF52Dongle
    # Internal variables
    master_address_raw = None
    slave_address_raw = None
    config_file = 'ble_config.json'
    iterations = 0
    master_address_type = None

    pkt_received = None
    pkt = None
    peer_address = None
    last_gatt_request = None
    empty_pdu_count = 0
    master_gatt_server = None
    sent_packet = None
    pairing_starting = False
    # Internal Slave params
    slave_address_type = None
    slave_feature_set = None
    slave_ble_version = None
    slave_next_start_handle = None
    slave_next_end_handle = None
    slave_service_idx = None
    slave_characteristic_idx = None
    slave_characteristic = None
    slave_device = None  # type: BLEDevice
    slave_handles = None
    slave_handles_values = None
    slave_handles_idx = None
    slave_ever_connected = False
    slave_connected = False
    slave_crashed = False
    slave_l2cap_fragment = []
    # Internal Encryption params
    conn_ltk = None
    conn_ediv = None
    conn_rand = None
    conn_iv = None
    conn_skd = None
    conn_session_key = None  # Used for LL Encryption
    conn_master_packet_counter = 0  # Packets counter for master (outgoing)
    conn_slave_packet_counter = 0  # Packets counter for slave (incoming)
    conn_encryted = False

    def __init__(self, machine_states, machine_transitions,
                 master_address=None,
                 master_mtu=None,
                 slave_address=None,
                 dongle_serial_port=None,
                 baudrate=None,
                 enable_fuzzing=None,
                 enable_duplication=None,
                 monitor_serial_port=None,
                 monitor_serial_baud=None,
                 monitor_magic_string=None):

        colorama_init(autoreset=True)  # Colors autoreset

        self.load_config()

        # Override loaded settings
        if slave_address is not None:
            self.slave_address = slave_address

        slave_address = self.slave_address

        if master_address is not None:
            self.master_address = master_address

        if dongle_serial_port is not None:
            self.dongle_serial_port = dongle_serial_port

        if enable_fuzzing is not None:
            self.enable_fuzzing = enable_fuzzing

        if enable_duplication is not None:
            self.enable_duplication = enable_duplication

        if monitor_serial_port is not None:
            self.monitor_serial_port = monitor_serial_port

        if monitor_serial_baud is not None:
            self.monitor_serial_baud = monitor_serial_baud

        if monitor_magic_string is not None:
            self.monitor_serial_magic_string = monitor_magic_string

        if master_mtu is not None:
            self.master_mtu = master_mtu

        self.smp = SecurityManagerProtocol(self)
        BLESMPServer.set_pin_code(bytearray([(ord(byte) - 0x30) for byte in self.pairing_pin]))
        # BLESMPServer.set_local_key_distribution(0x07)

        self.master_gatt_server = self.create_gatt_server(mtu=master_mtu)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server,
                                     mtu=master_mtu)
        self.master_address = master_address
        self.slave_address = slave_address

        self.driver = NRF52Dongle(self.dongle_serial_port, baudrate)

        if master_address is not None:
            self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), master_address.split(':')))
            self.master_address_type = ble_roles.PUBLIC_DEVICE_ADDRESS
        else:
            self.master_address_raw = os.urandom(6)
            self.master_address_type = ble_roles.RANDOM_DEVICE_ADDRESS

        self.peer_address = ''.join(slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

        self.smp.initiate_security_manager_for_connection(self.peer_address,
                                                          ble_roles.PUBLIC_DEVICE_ADDRESS,
                                                          self.master_address_raw, self.master_address_type,
                                                          ble_roles.ROLE_TYPE_CENTRAL)

        SetFuzzerConfig(states_fuzzer_config)
        self.machine = GreyhoundStateMachine(states=machine_states,
                                             transitions=machine_transitions,
                                             print_transitions=True,
                                             print_timeout=True,
                                             initial='SCANNING',
                                             idle_state='SCANNING',
                                             before_state_change='state_change',
                                             show_conditions=True,
                                             show_state_attributes=False,
                                             enable_webserver=True)

        # Start serial monitor to detect crashes if available
        self.monitor = Monitor(self.monitor_serial_port, self.monitor_serial_baud,
                               magic_string=self.monitor_serial_magic_string,
                               user_callback=self.scan_timeout_detected)

    # Configuration functions
    def get_config(self):
        obj = {'MasterAddress': self.master_address.upper(),
               'SlaveAddress': self.slave_address.upper(),
               'AccessAdress': hex(self.conn_access_address).split('0x')[1].upper(),
               'ConnectionInterval': self.conn_interval,
               'WindowOffset': self.conn_window_offset,
               'WindowSize': self.conn_window_size,
               'SlaveLatency': self.conn_slave_latency,
               'ChannelMap': hex(self.conn_channel_map).split('0x')[1].upper(),
               'ConnectionTimeout': self.conn_timeout,
               'MasterFeatureSet': self.master_feature_set,
               'DongleSerialPort': self.dongle_serial_port,
               'EnableFuzzing': self.enable_fuzzing,
               'EnableDuplication': self.enable_duplication,
               'PairingPin': self.pairing_pin,
               'MonitorSerialPort': self.monitor_serial_port,
               'MonitorSerialBaud': self.monitor_serial_baud
               }
        return json.dumps(obj, indent=4)

    def set_config(self, data):
        self.master_address = data['MasterAddress']
        self.slave_address = data['SlaveAddress']
        self.conn_access_address = int(data['AccessAdress'], 16)
        self.conn_interval = int(data['ConnectionInterval'])
        self.conn_window_offset = int(data['WindowOffset'])
        self.conn_window_size = int(data['WindowSize'])
        self.conn_slave_latency = int(data['SlaveLatency'])
        self.conn_channel_map = int(data['ChannelMap'], 16)
        self.conn_timeout = int(data['ConnectionTimeout'])
        self.master_feature_set = data['MasterFeatureSet']
        self.dongle_serial_port = data['DongleSerialPort']
        self.enable_fuzzing = bool(data['EnableFuzzing'])
        self.enable_duplication = bool(data['EnableDuplication'])
        self.pairing_pin = data['PairingPin']
        self.monitor_serial_port = data['MonitorSerialPort']
        self.monitor_serial_baud = int(data['MonitorSerialBaud'])

    def save_config(self, obj):
        if self.config_file:
            f = open(self.config_file, 'w')
            f.write(json.dumps(obj, indent=4))
            f.close()

    def load_config(self):
        try:
            f = open(self.config_file, 'r')
            obj = json.loads(f.read())
            f.close()
            self.set_config(obj)
            return True
        except:
            f = open(self.config_file, 'w')
            f.write(self.get_config())
            f.close()
            return False

    # -------------------------------------------
    def state_change(self):
        if self.machine.source != self.machine.destination:
            self.update_timeout('conn_general_timer')
        self.empty_pdu_count = 0

    @staticmethod
    def create_gatt_server(mtu=23):
        gatt_server = Server(None)
        gatt_server.set_mtu(mtu)

        # Add Generic Access Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1800"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Device Name characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('Greyhound',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A00"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Device Name")

        char1 = service_1.generate_and_add_characteristic('\x00\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A01"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Appearance")

        char1 = service_1.generate_and_add_characteristic('\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A04"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Conn Paramaters")
        # -----

        # Add Immediate Alert Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1802"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Alert Level characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A06"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        # add user description descriptor to characteristic
        char1.generate_and_add_user_description_descriptor("Characteristic 1")
        gatt_server.refresh_database()
        # gatt_server.debug_print_db()
        return gatt_server

    def save_ble_device(self):
        export_dict = self.slave_device.export_device_to_dictionary()
        device_json_output = json.dumps(export_dict, indent=4)
        f = open("bluetooth/device.json", "w")
        f.write(device_json_output)
        f.close()

    def update_slave_handles(self):
        if self.slave_handles:
            del self.slave_handles
        self.slave_handles = []

        if self.slave_handles_values:
            del self.slave_handles_values
        self.slave_handles_values = {}

        self.slave_handles_idx = 0
        for service in self.slave_device.services:
            self.slave_handles.append(service.start)
            for characteristic in service.characteristics:
                self.slave_handles.append(characteristic.handle)
                for descriptor in characteristic.descriptors:
                    self.slave_handles.append(descriptor.handle)

    @staticmethod
    def bt_crypto_e(key, plaintext):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(plaintext)

    def send(self, pkt):

        if (self.slave_connected == False and BTLE_DATA in pkt):
            print(Fore.YELLOW + '[!] Skipping packets TX')
            return

        if self.enable_fuzzing:
            fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)

        if self.enable_duplication and (BTLE_DATA in pkt) and (LL_TERMINATE_IND not in pkt):
            fuzzing.repeat_packet(self)

        if self.driver == None:
            return

        if self.slave_crashed == False:
            self.machine.add_packets(
                NORDIC_BLE(board=75, protocol=2, flags=0x3, event_counter=self.driver.event_counter)
                / pkt)  # CRC ans master -> slave direction
        self.sent_packet = pkt

        print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])

        # pkt[BTLE].len = 0x72
        if self.conn_encryted is False:
            self.driver.raw_send(raw(pkt))
            # try:
            #     self.driver.raw_send(raw(pkt))
            # except:
            #     print(Fore.RED + "Fuzzing problem")
        else:
            self.send_encrypted(pkt)

    def send_encrypted(self, pkt):
        try:
            raw_pkt = bytearray(raw(pkt))
            access_address = raw_pkt[:4]
            header = raw_pkt[4]  # Get ble header
            length = raw_pkt[5] + 4  # add 4 bytes for the mic
            crc = '\x00\x00\x00'

            pkt_count = bytearray(struct.pack("<Q", self.conn_master_packet_counter)[:5])  # convert only 5 bytes
            pkt_count[4] |= 0x80  # Set for master -> slave
            nonce = pkt_count + self.conn_iv

            aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
            aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

            enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])  # get payload and exclude 3 bytes of crc
            self.driver.raw_send(access_address + chr(header) + chr(length) + enc_pkt + mic + crc)
            self.conn_master_packet_counter += 1
        except:
            print(Fore.RED + "Fuzzing problem")

    def receive_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        access_address = raw_pkt[:4]
        header = raw_pkt[4]  # Get ble header
        length = raw_pkt[5]  # add 4 bytes for the mic

        if length is 0 or length < 5:
            # ignore empty PDUs
            return pkt
        # Subtract packet length 4 bytes of MIC
        length -= 4

        # Update nonce before decrypting
        pkt_count = bytearray(struct.pack("<Q", self.conn_slave_packet_counter)[:5])  # convert only 5 bytes
        pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
        nonce = pkt_count + self.conn_iv

        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
        aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

        dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc

        try:
            mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
            aes.verify(mic)
            self.conn_slave_packet_counter += 1
            return BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
        except:
            print(Fore.RED + "MIC Wrong")
            self.conn_slave_packet_counter += 1
            p = BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
            # self.machine.report_anomaly(msg='MIC Wrong', pkt=p)
            return None

    # Ble Suite bypass functions
    ff = 0

    def raw_att(self, attr_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / attr_data
            # pkt[BTLE_DATA].LLID = 0
            # pkt[BTLE_DATA].len = 7
            # pkt[L2CAP_Hdr].len = 3
            # pkt.len = 100  # Crash fitbit/Cypress fastly

            self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)

            # if ATT_Read_By_Type_Request and self.state == 'CHARACTERISTICS':  # This Crashes ESP32
            #     print(pkt.command())
            #     self.ff += 1
            #     if self.ff == 2:  # 1 or 2 here
            #         self.ff = 0
            #         print(Fore.YELLOW + 'Sending out of order packet with wrong mic')
            #         self.conn_encryted = False  # this disables encryption
            #         # self.send_disconn_request()
            #         # self.send_disconn_request()
            #         self.send_version_indication()

            # self.send(pkt)
            # if ATT_Read_By_Type_Request in pkt:
            #     self.send(pkt)

    def raw_smp(self, smp_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / smp_data
            self.send(pkt)

    def reset_vars(self):
        self.slave_l2cap_fragment = []
        self.empty_pdu_count = 0
        self.conn_encryted = False
        self.sent_packet = None
        self.conn_master_packet_counter = 0
        self.conn_slave_packet_counter = 0
        self.slave_next_start_handle = None
        self.slave_next_end_handle = None
        self.slave_service_idx = None
        self.slave_characteristic_idx = None
        self.slave_characteristic = None
        self.pairing_starting = False
        self.slave_connected = False
        self.slave_crashed = False
        self.iteration()

    def timeout_detected(self):
        self.machine.reset_state_timeout()
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        print(Fore.LIGHTRED_EX + '[TIMEOUT] !!! Link timeout detected !!!')
        print(Fore.YELLOW + 'Reseting model to state ' + self.machine.idle_state)
        self.machine.reset_machine()
        self.reset_vars()
        self.machine.save_packets()

    def timeout_transition_detected(self):
        self.machine.reset_state_timeout()
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        print(Fore.YELLOW + '[TIMEOUT] !!! State global timeout !!!')
        print(Fore.YELLOW + 'Reseting model to state ' + self.machine.idle_state)
        self.machine.reset_machine()
        self.reset_vars()
        self.machine.save_packets()

    def scan_timeout_detected(self):
        if self.slave_ever_connected:
            self.disable_timeout('conn_general_timer')
            self.machine.report_crash()
            self.slave_ever_connected = False
            self.reset_vars()
            self.machine.save_packets()
            self.slave_crashed = True

    def disable_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            setattr(self, timer_name, None)

    def update_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            self.start_timeout(timer_name, timer.interval, timer.function)

    def start_timeout(self, timer_name, seconds, callback):
        timer = getattr(self, timer_name)
        timer = threading.Timer(seconds, callback)
        setattr(self, timer_name, timer)
        timer.daemon = True
        timer.start()

    def announce_connection(self):
        self.disable_timeout('scan_timeout_timer')
        self.start_timeout('conn_supervision_timer', self.conn_timeout / 100.0, self.timeout_detected)
        self.start_timeout('conn_general_timer', self.state_timeout, self.timeout_transition_detected)
        print(Fore.GREEN + '[!] BLE Connection Established to target device')
        print(Fore.GREEN + '[!] Supervision timeout set to ' + str(self.conn_timeout / 100.0) + ' seconds')
        self.slave_ever_connected = True  # used to detect first connection
        self.slave_connected = True  # used to detect first connection

    def announce_disconnection(self):
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        self.machine.save_packets()
        self.reset_vars()
        print(Fore.YELLOW + '[!] Disconnected from target device')

    def iteration(self):

        fitness.Transition(reset=True)
        state_transitions = fitness.TransitionLastCount
        iterationTime = fitness.Iteration()

        if fitness.IssuePeriod > 0:
            issuePeriod = fitness.IssuePeriod
        else:
            issuePeriod = float('inf')

        print(Back.WHITE + Fore.BLACK +
              "IssueCount:" + str(fitness.IssueCounter) + ' IssuePeriod:{0:.3f}'.format(issuePeriod)
              + ' Transitions:' + str(state_transitions) + ' IterTime:{0:.3f}'.format(
                    iterationTime) + ' TotalIssues: '
              + str(fitness.IssuesTotalCounter))

        send_fitness(fitness.IssueCounter, issuePeriod, state_transitions, iterationTime, self.iterations,
                     fitness.IssuesTotalCounter)

        self.iterations += 1

    # Receive functions

    def sniff(self):
        print(Fore.YELLOW + '[!] BLE Sniffing started...')
        self.retry()
        while True:
            try:
                if self.driver:

                    while True:
                        data = self.driver.raw_receive()
                        if data:
                            pkt = BTLE(data)
                            self.receive_packet(pkt)

            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                exit(0)
            except SerialException:
                self.driver = None
                print(Fore.RED + 'Serial busy' + Fore.RESET)
            try:
                print(Fore.RED + 'Recovering' + Fore.RESET)
                self.disable_timeout('scan_timeout_timer')
                sleep(2)  # Sleep 1 second and retry
                self.driver = NRF52Dongle(self.dongle_serial_port, 1000000)
            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                exit(0)
            except SerialException:
                pass

    def receive_packet(self, pkt):
        self.update_timeout('conn_supervision_timer')
        print_lines = False
        append_current_pkt = True
        pkts_to_process = []

        # Decrypt packet if link is encrypted
        if self.conn_encryted:
            pkt = self.receive_encrypted(pkt)
            if pkt is None:
                # Integrity check fail. Drop packet to not cause validation confusion
                return

        # Add packet to session packets history
        if self.slave_crashed == False:
            self.machine.add_packets(
                NORDIC_BLE(board=75, protocol=2, flags=0x01, event_counter=self.driver.event_counter) / pkt)
        # Handle L2CAP fragment
        if (BTLE_DATA in pkt and pkt.len != 0) and (pkt.LLID == 0x02 or pkt.LLID == 0x01):
            if pkt.LLID == 0x01 or len(self.slave_l2cap_fragment) == 0:
                self.slave_l2cap_fragment.append(pkt)
                return
            append_current_pkt = False
            self.slave_l2cap_fragment.append(pkt)

        if len(self.slave_l2cap_fragment) > 0:
            p_full = raw(self.slave_l2cap_fragment[0])[:-3]  # Get first raw l2cap start frame
            self.slave_l2cap_fragment.pop(0)  # remove it from list
            idx = 0
            for frag in self.slave_l2cap_fragment:
                if frag.LLID == 0x02:
                    break
                p_full += raw(frag[BTLE_DATA].payload)  # Get fragment bytes
                idx += 1
                # print(Fore.YELLOW + 'fragment')

            del self.slave_l2cap_fragment[:idx]
            p = BTLE(p_full + '\x00\x00\x00')
            p.len = len(p[BTLE_DATA].payload)  # update ble header length
            pkts_to_process.append(p)  # joins all fragements

        # Add currently received packet
        if append_current_pkt:
            pkts_to_process.append(pkt)

        # Process packts in the packet list
        for pkt in pkts_to_process:
            # If packet is not an empty pdu or a termination indication
            if Raw in pkt:
                continue
            if (BTLE_EMPTY_PDU not in pkt) and (LL_TERMINATE_IND not in pkt) and (
                    L2CAP_Connection_Parameter_Update_Request not in pkt) and (
                    BTLE_DATA in pkt or (
                    (BTLE_ADV_IND in pkt or BTLE_SCAN_RSP in pkt) and pkt.AdvA == self.slave_address)):
                # Print packet and state
                print(Fore.BLUE + "State:" + Fore.LIGHTCYAN_EX + self.state + Fore.LIGHTCYAN_EX)
                print(Fore.CYAN + "RX <--- " + pkt.summary()[7:])
                print_lines = True
                # Validate received packet against state
                if fitness.Validate(pkt, self.state, states_fuzzer_config) == False:
                    self.machine.report_anomaly(pkt=pkt)

            self.pkt_received = True
            self.pkt = pkt
            self.update()
            self.pkt_received = False

            if LL_TERMINATE_IND in pkt:
                print(Fore.YELLOW + "[!] LL_TERMINATE_IND received. Disconnecting from the slave...")
                self.disable_timeout('conn_supervision_timer')
                self.disable_timeout('conn_general_timer')
                self.reset_vars()
                self.machine.save_packets()
                self.machine.reset_machine()

        if print_lines:
            print('----------------------------')

    def version_already_received(self):
        if self.slave_ble_version is not None:
            return True
        return False

    def send_scan_request(self):
        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.slave_address)
        # pkt.Length = 14
        # pkt.Length = 6
        # pkt.AdvA = '7f:4d:e5:00:00:00'
        # pkt.ScanA = '00:00:00:00:21:09'
        # pkt.PDU_type = 0x0d
        self.send(pkt)
        # self.driver.set_jamming(1)

    def receive_scan_response(self):
        if self.pkt_received:

            if (BTLE_ADV_NONCONN_IND in self.pkt or BTLE_ADV_IND in self.pkt or BTLE_SCAN_RSP in self.pkt) and \
                    self.pkt.AdvA == self.slave_address.lower():
                self.machine.reset_state_timeout()

                # self.disable_timeout('scan_timeout_timer')
                # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)

                if BTLE_ADV_IND in self.pkt and self.slave_address_type != self.pkt.TxAdd:
                    self.slave_address_type = self.pkt.TxAdd  # Get slave address type
                    self.send_scan_request()  # Send scan request again
                else:
                    self.slave_address_type = self.pkt.TxAdd
                    return True

                return True
        return False

    switch = 0

    def send_connection_request(self):

        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        self.master_address = str(RandMAC()).upper()
        self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540

        self.send(pkt)

    def send_gatt_response(self):
        if self.last_gatt_request is None:
            pkt = self.pkt
            self.last_gatt_request = pkt
        else:
            pkt = self.last_gatt_request

        self.att.marshall_request(None, pkt[ATT_Hdr], self.peer_address)
        # self.sent_packet.show()

    def receive_gatt_request(self):
        if ATT_Hdr in self.pkt:
            return True
        return False

    def handle_gatt_response(self):
        if ATT_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            self.last_gatt_request = self.pkt
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
            self.last_gatt_request = None
            if ATT_Error_Response in self.sent_packet:
                # self.last_gatt_request = None
                return False
        return False

    def receive_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            return True
        return False

    def receive_2_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            self.empty_pdu_count += 1
            if self.empty_pdu_count >= 3:
                self.empty_pdu_count = 0
                return True
        return False

    def send_feature_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
            feature_set=self.master_feature_set)
        # if self.v == 0:
        #     self.v = 1
        # else:
        #     pkt = BTLE('7083329a431908210000000000bfa11891a5'.decode('hex'))
        #     self.v = 0
        self.send(pkt)
        # self.send_encryption_request()
        # self.send_feature_request()

    def receive_feature_request(self):
        if self.pkt_received:
            if LL_SLAVE_FEATURE_REQ in self.pkt:
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_feature_response(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
            feature_set=self.master_feature_set)

        self.send(pkt)

    def receive_feature_response(self):
        if self.pkt_received:
            if LL_FEATURE_RSP in self.pkt:
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_length_request(self):
        # pkt = BTLE('7083329a040914fb00121178f048085987a2'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a030914fb00f9e354af480867ef65'.decode('hex'))
        # self.send(pkt)

        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=self.master_mtu + 4, max_rx_bytes=self.master_mtu + 4)
        # pkt[BTLE_DATA].LLID = 0
        self.send(pkt)
        # self.send_encryption_request()

    def receive_length_request(self):
        if self.pkt_received:
            if LL_LENGTH_REQ in self.pkt:
                return True
        return False

    def send_length_response(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=self.att.mtu + 4, max_rx_bytes=self.att.mtu + 4)
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        # self.send_encryption_request()
        self.send(pkt)

    def receive_length_response(self):
        if LL_UNKNOWN_RSP in self.pkt:
            return True
        if LL_LENGTH_RSP in self.pkt:
            return True

        return False

    def send_version_indication(self):
        # Using BLE version 4.2
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
        # pkt.LLID = 0
        # pkt.len = 240  # Crash fitbit/Cypress fastly
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        self.send(pkt)
        # self.send_encryption_request()

    def receive_version_indication(self):

        if self.pkt_received:
            if LL_SLAVE_FEATURE_REQ in self.pkt:
                self.send_feature_response()

            if LL_VERSION_IND in self.pkt:
                self.slave_ble_version = self.pkt[LL_VERSION_IND].version

                if BTLE_Versions.has_key(self.slave_ble_version):
                    print(Fore.GREEN + "[!] Slave BLE Version: " + str(
                        BTLE_Versions[self.slave_ble_version]) + " - " + hex(self.slave_ble_version))
                else:
                    print(Fore.RED + "[!] Unknown Slave BLE Version: " + hex(self.slave_ble_version))
                self.version_received = True
                return True
        return False

    def receive_security_request(self):
        if SM_Security_Request in self.pkt:
            # self.paring_auth_request = self.pkt[SM_Security_Request].authentication
            # self.pairing_iocap = 0x04  # Change device to Keyboard an Display
            # self.send_encryption_request()
            # self.send_feature_request()
            return True

    def send_security_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
              SM_Security_Request(authentication=self.paring_auth_request)
        self.send(pkt)

    def send_mtu_length_request(self):
        # self.raw_att(ATT_Exchange_MTU_Response(self.att.mtu), None, None)
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=self.att.mtu)
        # pkt.len = 186
        # pkt[BTLE_DATA].LLID = 0  # Fitbit deadlock

        self.send(pkt)
        # self.send(pkt)

    def receive_mtu_length_request(self):
        if self.pkt_received:
            if ATT_Exchange_MTU_Request in self.pkt:
                # self.att.set_mtu(self.pkt.mtu)
                return True
        return False

    def send_mtu_length_response(self):
        if ATT_Hdr in self.pkt:
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)

    def receive_mtu_length_response(self):
        if LL_LENGTH_REQ in self.pkt:
            # TODO: Handle 2cap fragmentation if length is less than mtu
            # By responding to length request from slave here, length will be registered by slave
            self.send_length_response()
        if ATT_Exchange_MTU_Response in self.pkt:
            # self.att.set_mtu(self.pkt.mtu)
            return True

    def send_pair_request(self):

        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                # pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                # pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                # pkt.LLID = 0
                # pkt.len = 186
                # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                # ------------
                # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                # self.send(pkt)
                # self.disable_timeout('conn_supervision_timer')
                # self.disable_timeout('conn_general_timer')
                # self.reset_vars()
                # self.machine.reset_machine()
                # ------------
                # pkt[BTLE_DATA].len = 2
                # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                # self.send(pkt)
                # pkt[SM_Pairing_Request].oob = 1
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)

    def finish_pair_response(self):

        # if SM_Public_Key in self.pkt:
        #     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm()
        #     self.send(pkt)
        #     pass

        if SM_Hdr in self.pkt:
            # self.pkt.show()
            self.machine.reset_state_timeout()
            #
            # if SM_Pairing_Response in self.pkt:  # Telink final crash step
            # self.send_encryption_request()
            # self.conn_ltk = '\xFF' * 16
            # self.conn_ltk = '35A54250A0FC76CDC2893054B4096009'.decode('hex')
            # return True

            # if SM_Confirm in self.pkt:
            #     # pkt = BTLE('7083329a0215110006000700000400000000000000000000000000e94bf0'.decode('hex'))
            #     # self.send(pkt)
            #     self.conn_ltk = '\x00' * 16
            #     # self.conn_ltk = 'F643BB7D84C1BD6255D485FB8DAAE51A'.decode('hex')
            #     return True

            # if SM_Random in self.pkt:
            # 	print(hexlify(BLESMPServer.get_ltk()))

            # if SM_Pairing_Response in self.pkt:

            # if SM_Pairing_Response in self.pkt:  # PSoC 6 crash
            #     pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))
            #     self.send(pkt)
            #     return False

            # if SM_Random in self.pkt:  # Telink final crash step
            #     self.conn_ltk = '\x00' * 16
            #     # self.send(BTLE('7083329a0215110006000700000000000000000000000000000000e94bf0'.decode('hex')))
            #     return True

            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    if SM_Hdr in res:
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        self.pairing_starting = True

                        # pkt = BTLE(
                        #     '7083329a0245410006000cd14b70d78dbf394c6b964a089d0656fa8a6eabc4cabadcbfc4c88e67d30ab2356d4ea71fe1899f4c4a74b864e7378b148efb5f121c177f2c8e356772f53629c0a03f55'.decode(
                        #         'hex'))
                        # self.send(pkt)
                        # pkt = BTLE('7083329a021511000600820330c727319c85926c23dc8285f7e4103117db'.decode('hex'))
                        # self.send(pkt)
                        # pkt = BTLE(
                        #     '7083329af145410006004ad14b70d78dbf394c6b964a089d0656fa8a6eabc4cabadcbfc4c88e67d30ab2356d4ea71fe1899f4c4a74b864e7378b148efb5f121c177f2c8e356772f53629c00e4c15'.decode(
                        #         'hex'))
                        # pkt = BTLE(
                        #     '7083329a0245410006000c54c5bb2ff050ee07ec4057d0df637d03895eea28be175615923ff0d1d915e33022e4c03b3497a9b8bdd2e87034f08f147d713a4000771169ebf2efeb38995f5d43f732'.decode(
                        #         'hex'))  # Public key for crashing texas instruments
                        #
                        # pkt = BTLE(
                        #     access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
                        #       SM_Public_Key()  # Public key for crashing texas instruments
                        #
                        #     self.send(pkt)

                        # if SM_Confirm in self.pkt:
                        #     # self.send(pkt)
                        #     # pkt = BTLE('7083329a031703000000000000000000009024de9e5d22f2b3ec44db32b3427a'.decode('hex'))
                        #     # self.send(pkt)
                        #     self.conn_ltk = '\x00' * 16
                        #     return True

                        # if SM_Random in self.pkt:  # Brutal attack against texas instruments
                        #     self.conn_ltk = BLESMPServer.get_ltk()
                        #     # self.conn_ltk = 'DB98EC7E029B088CC2339ED185380D90'.decode('hex')
                        #     # self.conn_ltk = '\x00' * 16
                        #     print hexlify(self.conn_ltk)
                        #     return True
                        # if SM_Failed in pkt:
                        #     print(hexlify(BLESMPServer.get_ltk()))
                        #     self.conn_ltk = '\x00' * 16
                        #     # self.conn_ltk = '2DBEED6EA163CD3A597DD3896A5C610B'.decode('hex')
                        #     return True

                        self.send(pkt)

                        # sleep(0.9)
                        # if SM_Public_Key in pkt:
                        #     self.send_encryption_request()

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False

    def send_encryption_request(self):
        # if self.conn_encryted is False:
        self.conn_ediv = '\x00'  # this is 0 on first time pairing
        self.conn_rand = '\x00'  # this is 0 on first time pairing
        self.conn_iv = '\x00' * 4  # set IVm (IV of master)
        self.conn_skd = '\x00' * 8
        # self.conn_iv = os.urandom(4)  # set IVm (IV of master)
        # self.conn_skd = os.urandom(8)
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
                                                                                                rand=self.conn_rand,
                                                                                                skdm=self.conn_skd,
                                                                                                ivm=self.conn_iv)
        # pkt[BTLE_DATA].LLID = 0
        # pkt = BTLE('7083329a0817032300000000000000000001e23444f17c9f6bb128c485c3ba21'.decode('hex')) # llid=0
        # pkt = BTLE('7083329a1717030000000000000000000096d20461af85f4ae6f09bcc0c2c239'.decode('hex'))  # md=1
        # pkt[BTLE_DATA].MD = 1
        self.send(pkt)

    def receive_encryption_response(self):

        # if LL_ENC_RSP in self.pkt:  # Telink final crash step
        #     self.send_version_indication()
        #     return True

        if LL_ENC_RSP in self.pkt:
            self.conn_skd += self.pkt.skds  # SKD = SKDm || SKDs
            self.conn_iv += self.pkt.ivs  # IV = IVm || IVs
            # e(key, plain text) - most significant octet first
            try:
                self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
            except:
                print('error')
                self.pkt.show()
            self.conn_master_packet_counter = 0
            # self.send_disconn_request()
            # self.disable_timeout('conn_supervision_timer')
            # self.disable_timeout('conn_general_timer')
            # self.reset_vars()
            # self.machine.save_packets()
            # self.machine.reset_machine()

        elif LL_START_ENC_REQ in self.pkt:
            self.conn_encryted = True  # Enable encryption for tx/rx
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
            # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
            self.send(pkt)
            # self.send(BTLE('d6be898e030c81d7f059970016554312cfa4199308'.decode('hex')))
            # self.send_encryption_request()
            # self.send(BTLE('7083329a86cf063288db'.decode('hex')))
            # self.send_encryption_request()
            # pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
            #                                                                                         rand=self.conn_rand,
            #                                                                                         skdm=self.conn_skd,
            #                                                                                         ivm=os.urandom(4))
            # self.send(pkt)

        elif LL_START_ENC_RSP in self.pkt:
            print(Fore.GREEN + "[!] !!! Link Encrypted direct in host !!!")
            # self.send_feature_response()
            return True

        # if Raw in self.pkt:
        #     print('oi')
        #     self.v += 1
        #     if self.v == 2:
        #         self.send_version_indication()
        #         self.send_encryption_request()

        # if LL_REJECT_IND in self.pkt:
        #     self.send_encryption_request()

        return False

    def finish_key_exchange(self):
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
                if smp_answer is not None and isinstance(smp_answer, list):
                    for res in smp_answer:
                        res = HCI_Hdr(res)  # type: HCI_Hdr
                        if SM_Hdr in res:
                            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                            self.sent_packet = pkt
                            # if SM_Identity_Address_Information in pkt:
                            #     pkt = BTLE('7083329a4315110006000a0000000000000000000000000000000080ce78'.decode('hex'))
                            #     self.send(pkt)
                            #     return False
                            self.send(pkt)
            except:
                pass

        return False

    def send_pri_services_request(self):

        if self.slave_next_start_handle is None:
            self.att.read_by_group_type(0x0001, 0xffff, 0x2800, None)
        else:
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2800, None)

    v = 0

    def receive_pri_services(self):
        # if LL_LENGTH_REQ in self.pkt:
        #     self.send_length_response()

        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            # if self.v >= 3:
            #     pkt = BTLE('7083329a020b070006000103d73710048c07709c'.decode('hex'))
            #     self.send(pkt)
            #     return False
            # self.v += 1

            if self.discover_gatt_services(pkt, 0x2800):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of primary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Primary service discovered")
            return True

    d = 0

    def send_sec_services_request(self):

        # pkt = BTLE('7083329a020804000400121100000d5b3a'.decode('hex'))  # Crash STM WB55
        # self.send(pkt)  # Crash STM WB55
        # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)  # required

        # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
        # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)

        if self.slave_next_start_handle is None:
            self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
        else:
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2801, None)
        # if self.d == 0:
        #     pkt = BTLE('7083329a020b07000400100100c45201281bb789'.decode('hex'))
        #     self.send(pkt)
        #     self.d = 1

    def receive_sec_services(self):
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            if self.discover_gatt_services(pkt, 0x2801):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of secondary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Secondary service discovered")
            return True

    def discover_gatt_services(self, pkt, request_uuid):

        length = pkt.length
        service_data = pkt.data
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')

        if length == 6:  # 4 byte uuid, 2 2-byte handles
            # print("We've got services with 16-bit UUIDs!")
            services = []
            i = 0
            end_loop = False
            while i < len(service_data):
                services.append(service_data[i:i + 6])
                i += 6
            # print "Services:", services
            for service in services:
                try:
                    start = struct.unpack("<h", service[:2])[0]
                    end = struct.unpack("<h", service[2:4])[0]
                    uuid_16 = struct.unpack("<h", service[4:])[0]
                    conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                    uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                           conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                    uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                    if end == -1:
                        end = 0xffff
                    if start == -1:
                        start = 0xffff
                    self.slave_device.add_service(start, end, uuid_128)
                    if end >= 0xFFFF or end < 0:
                        end_loop = True
                    if self.slave_next_start_handle is None or end >= self.slave_next_start_handle:
                        self.slave_next_start_handle = end + 1
                except:
                    continue
            if end_loop:
                return True
        elif length == 20:  # 16 byte uuid, 2 2-byte handles
            # print("We've got services with 128-bit UUIDs!")
            start = struct.unpack("<h", service_data[:2])[0]
            end = struct.unpack("<h", service_data[2:4])[0]
            return True
            uuid_128 = struct.unpack("<QQ", service_data[4:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if end == -1:
                end = 0xffff
            if start == -1:
                start = 0xffff
            self.slave_device.add_service(start, end, uuid_128)
            if end >= 0xFFFF or end < 0:
                return True
            self.slave_next_start_handle = end + 1
        else:
            print(Fore.RED + "[!] UNEXPECTED PRIMARY SERVICE DISCOVERY RESPONSE. BAILING")

            # Send next group type request (next services to discover)
        self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, request_uuid, None)
        return False

    def send_characteristics_request(self):
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2803, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)

    def receive_characteristics(self):
        # Note: This is not exactly the procedure described in the spec (BLUETOOTH SPECIFICATION Version 5.0 |
        # Vol 3, Part G page 2253-4), but it's independent of a service scan.

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Characteristics discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False
        # print('receive_characteristics')
        self.machine.reset_state_timeout()  # Clear timeout timer

        characteristic_data = raw(self.pkt[ATT_Read_By_Type_Response])
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')

        length = int(characteristic_data[0].encode('hex'), 16)
        characteristic_data = characteristic_data[1:]

        if length == 7:  # 4byte uuid, 2 2-byte handles, 1 byte permission
            # print("We've got services with 16-bit UUIDs!")
            characteristics = []
            i = 0
            end_loop = False
            while i < len(characteristic_data):
                characteristics.append(characteristic_data[i:i + 7])
                i += 7
            # print "Services:", services
            for characteristic in characteristics:
                handle = struct.unpack("<h", characteristic[:2])[0]
                perm = struct.unpack("<B", characteristic[2:3])[0]
                value_handle = struct.unpack("<h", characteristic[3:5])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                uuid_16 = struct.unpack("<h", characteristic[5:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if handle == -1:
                    handle = 0xffff
                if value_handle == -1:
                    value_handle = 0xffff
                self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 21:  # 16 byte uuid, 2 2-byte handles, 1 byte permission
            # print("We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<h", characteristic_data[:2])[0]
            perm = struct.unpack("<B", characteristic_data[2:3])[0]
            value_handle = struct.unpack("<h", characteristic_data[3:5])[0]
            print(Fore.GREEN + "[X] Characteristics skiped")
            return True
            uuid_128 = struct.unpack("<QQ", characteristic_data[5:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if handle == -1:
                handle = 0xffff
            if value_handle == -1:
                value_handle = 0xffff
            self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)
        return False

    def send_includes_request(self):
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2802, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)

    def receive_includes(self):

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Includes discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False

        self.machine.reset_state_timeout()  # Clear timeout timer

        include_data = raw(self.pkt[ATT_Read_By_Type_Response])
        length = int(include_data[0].encode('hex'), 16)
        include_data = include_data[1:]

        if length == 8:  # 2 byte handle of this attribute, 2 byte uuid, 2 end group handle, 2 byte handle of included service declaration
            # logger.debug("We've got includes with 16-bit UUIDs!")
            includes = []
            i = 0
            end_loop = False
            while i < len(include_data):
                includes.append(include_data[i:i + 7])
                i += 7
            # print "Services:", services
            for incl in includes:
                handle = struct.unpack("<H", incl[:2])[0]
                included_att_handle = struct.unpack("<H", incl[2:4])[0]
                end_group_handle = struct.unpack("<H", incl[4:6])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                try:
                    included_service_uuid_16 = struct.unpack("<H", incl[6:])[0]
                except:
                    return True
                if handle == -1:
                    handle = 0xffff
                self.slave_device.add_include(handle, included_att_handle, end_group_handle, included_service_uuid_16)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 6:  # 2 byte handle of this attribute, 2 end group handle, 2 byte handle of included service declaration
            # logger.debug("[!] We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<H", include_data[:2])[0]
            included_att_handle = struct.unpack("<H", include_data[2:4])[0]
            end_group_handle = struct.unpack("<H", include_data[4:6])[0]
            if handle == -1:
                handle = 0xffff
            self.slave_device.add_include(handle, included_att_handle, end_group_handle, None)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)
        return False

    def send_descriptors_request(self):

        if self.slave_next_start_handle is None:
            self.slave_service_idx = None
            self.slave_characteristic_idx = None
            service = None
            characteristic = None
            i = 0
            j = 0

            # Get the index of the first service and characteristic available
            for _i, _service in enumerate(self.slave_device.services):
                found = False
                for _j, _characteristic in enumerate(_service.characteristics):
                    service = self.slave_device.services[_i]
                    characteristic = _service.characteristics[_j]
                    i = _i
                    j = _j
                    found = True
                    break
                if found is True:
                    break

            if characteristic is None:
                self.att.find_information(None, 0x0001, 0xFFFF)
                return

            start = characteristic.handle + 1
            if (len(service.characteristics) - 1) is 0:
                if (len(self.slave_device.services) - 1) is 0:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            if end == -1 or end > 0xffff:
                end = 0xffff
            if start == -1:
                start = 0xffff

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
        else:
            start = self.slave_next_start_handle
            end = self.slave_next_end_handle
        self.att.find_information(None, start, end)

    cq = 0

    def receive_descriptors(self):

        # if ATT_Exchange_MTU_Response in self.pkt:
        #     self.send_encryption_request()
        # Compute information response and add to slave_device object
        if ATT_Find_Information_Response in self.pkt:
            # self.send_encryption_request()
            # if self.cq == 0:
            #     self.send_mtu_length_request()
            #     self.cq = 1

            bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
            data = raw(self.pkt[ATT_Find_Information_Response])[1:]
            uuid_format = self.pkt[ATT_Find_Information_Response].format
            if uuid_format == 1:  # 16 bit uuid
                mark = 0
                descriptors = []
                while mark < len(data):
                    descriptors.append(data[mark:mark + 4])  # 2 byte handle, 2 byte uuid
                    mark += 4
                for desc in descriptors:
                    try:
                        handle = struct.unpack("<h", desc[:2])[0]
                        uuid_16 = struct.unpack("<h", desc[2:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16],
                                             uuid_128[16:20], uuid_128[20:]))
                        if self.slave_characteristic is not None:
                            self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
                    except:
                        return False

            elif uuid_format == 2:  # 128-bit uuid
                handle = struct.unpack("<h", data[:2])[0]
                uuid_128 = struct.unpack("<QQ", data[2:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))

                self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)

        # Iterate over the characteristics of the slave_device and send accordingly
        if ATT_Find_Information_Response in self.pkt or ATT_Error_Response in self.pkt:
            self.machine.reset_state_timeout()  # Clear timeout timer
            # print('recebido 1')

            i = self.slave_service_idx
            j = self.slave_characteristic_idx

            if i is None or j is None:
                return False

            if self.slave_device.services is None or len(self.slave_device.services) is 0:
                print(Fore.YELLOW + '[!] No descriptors listed')
                self.update_slave_handles()
                self.slave_next_start_handle = None
                self.slave_next_end_handle = None
                return True

            if self.slave_device.services[i].characteristics is not None and j >= len(
                    self.slave_device.services[i].characteristics):
                # print('recebido 2')
                i += 1
                j = 0

                if i >= len(self.slave_device.services):
                    print(Fore.GREEN + '[!] Descriptors discovered')
                    # Proceed
                    self.update_slave_handles()
                    self.slave_next_start_handle = None
                    self.slave_next_end_handle = None

                    # pkt = BTLE('7083329a020703000400642d1451bf17'.decode('hex'))
                    # self.send(pkt)
                    return True

                elif self.slave_device.services[i].characteristics is None or len(
                        self.slave_device.services[i].characteristics) is 0:
                    self.slave_service_idx += 1
                    return False
            elif self.slave_device.services[i].characteristics is None:
                self.slave_service_idx += 1
                return False

            service = self.slave_device.services[i]
            characteristic = service.characteristics[j]

            start = characteristic.handle + 1
            if j >= len(service.characteristics) - 1:
                if i >= len(self.slave_device.services) - 1:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
            self.slave_next_start_handle = start
            self.slave_next_end_handle = end
            self.att.find_information(None, start, end)
            return False

        return False

    def send_read_request(self):
        if len(self.slave_handles) > 0:
            try:
                self.att.read(self.slave_handles[self.slave_handles_idx], None)
            except:
                pass
        self.slave_handles_idx += 1

    def finish_readings(self):

        if ATT_Read_Response in self.pkt:
            pkt = self.pkt[ATT_Read_Response]
            try:
                self.slave_handles_values.update({self.slave_handles[self.slave_handles_idx - 1]: pkt.value})
            except:
                pass

        if (ATT_Hdr in self.pkt and self.pkt[ATT_Hdr].opcode is 0x0B) or ATT_Error_Response in self.pkt:
            self.machine.reset_state_timeout()  # Clear timeout timer
            self.v += 1
            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                self.send_read_request()

                # if self.v == 3:
                #     pkt = BTLE('7083329a0207030004000aee7baf87d9'.decode('hex'))
                #     self.send(pkt)
                # if self.v == 8:
                #     pkt = BTLE('7083329a02070300040016258f549e09'.decode('hex'))
                #     self.send(pkt)
            else:
                print(Fore.GREEN + '[!] Readings finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.machine.reset_state_timeout()  # Clear timeout timer
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Readings finished')
            return True
        return False

    def send_write_request(self):

        try:
            if self.slave_handles[self.slave_handles_idx] in self.slave_handles_values:
                value = self.slave_handles_values[self.slave_handles[self.slave_handles_idx]]
            else:
                value = '\x00'
            self.att.write_req(self.slave_handles[self.slave_handles_idx], value, None)
        except:
            pass
        self.slave_handles_idx += 1

    def finish_writing(self):

        if (ATT_Write_Response in self.pkt) or ATT_Error_Response in self.pkt:
            self.machine.reset_state_timeout()  # Clear timeout timer

            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                # pkt = BTLE('7083329a0208040004003e0700003a7135'.decode('hex'))
                # self.send(pkt)
                self.send_write_request()
            else:
                print(Fore.GREEN + '[!] Writting finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.machine.reset_state_timeout()  # Clear timeout timer
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Writting finished')
            return True

    def send_disconn_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND(code=0x13)
        self.send(pkt)


# slave_target = 'd0:16:b4:e1:4b:aa'  # Smart Watch (4.2)
# slave_target = '15:4a:23:06:02:13'  # Wistiki Small Tracker (DA14580) (4.0)
# slave_target = '29:50:41:30:2a:13'  # Wistiki Big Tracker (DA14580) (4.0)
# slave_target = "c0:82:5b:c3:8c:be"  # Gablys Tracker (Nordic) (4.1)
# slave_target = '00:a0:50:00:00:01'  # Crypress PSoC 4 Dongle (4.2)
# slave_target = '00:a0:50:00:00:03'  # Crypress PSoC 6 (5.0)
# slave_target = '28:c6:3f:a8:af:c9'  # Intel (my computer)
# slave_target = 'b8:27:eb:c0:21:c1'  # Raspberry Pi
# slave_target = '80:ea:ca:00:00:03'  # Dialog DA14580-01 (4.2)
# slave_target = '80:ea:ca:80:00:01'  # Dialog DA14680-01 (4.2)
slave_target = 'a4:cf:12:43:55:16'  # ESP32
# slave_target = '00:60:37:88:16:0c'  # NXP-KW41Z
# slave_target = '40:06:a0:73:6d:a7'  # Kinsa Smart Ear thermometer - CC2341
# slave_target = 'a4:c1:38:e7:32:60'  # RENPHO Weight Scale - Telink Semiconductor
# slave_target = 'f7:b5:e6:89:1e:ae'  # SensorPush - Nordic
# slave_target = 'f0:f8:f2:da:09:63'  # Texas Instruments CC2640R2
# slave_target = '78:9c:85:09:50:e2'  # August Smart Lock - Dialog DA14680
# slave_target = 'f8:f0:05:f3:66:e0'  # Microship (Atmel) SAMB11
# slave_target = '80:e1:26:00:66:92'  # ST Microelectronics WB55
# slave_target = '80:e1:26:01:a5:9b'  # ST Microelectronics WB55 (Dongle)
# slave_target = '02:80:e1:94:12:a0'  # ST Microelectronics BlueNRG-2
# slave_target = 'a4:c1:38:d8:ad:a9'  # Telink TLSR8258 (ZERO LTK)
# slave_target = '38:81:d7:3d:45:a2'  # Texas Instruments CC2540
# slave_target = '00:02:5b:00:b9:1a'  # CSR1020
# slave_target = 'f5:9b:d4:48:6d:94'  # Zephyr NRF51422
# slave_target = 'FD:5A:AB:D4:D5:FC'  # NRF51422

# slave_target = 'c4:64:e3:a1:c9:15'  # CubiTag (public key)
# slave_target = 'F0:C7:7F:26:18:8C'  # GeeTouch (connection)
# slave_target = '59:29:bb:03:9f:c9'  # Fit bit
# slave_target = 'ee:20:52:7a:81:88'  # Mi Band 3 xiaomi
# slave_target = 'bc:23:4c:00:7f:05'  # Alarm (MEsh)
# slave_target = 'dc:a6:32:23:56:5a'  # Raspberry Pi 4
# slave_target = 'cb:bf:1b:b7:5e:33'  # Xiaomi Mi Band 4
# slave_target = '58:2d:34:51:1a:42'  # Xiaomi Qingping Smart Alarm Clock


model = BLECentralMethods(states, transitions,
                          master_mtu=247,  # 23 default, 247 max (mtu must be 4 less than max length)
                          slave_address=23,
                          master_address='c8:c9:a3:d3:65:1e',
                          dongle_serial_port='/dev/ttyACM2',
                          baudrate=115200,
                          monitor_magic_string='ESP-IDF v4.1')
                          enable_fuzzing=True,
                          enable_duplication=True)
model.get_graph().draw('bluetooth/ble_central.png', prog='dot')
model.sniff()

# try:
while True:
    sleep(1000)
