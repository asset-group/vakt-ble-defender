# Commom imports
import os
import sys
import datetime
import threading
import struct
from time import time
from time import sleep
from itertools import count
import logging
from colorama import Fore, Back, Style
from colorama import init as colorama_init
from binascii import hexlify
import random
import json
from subprocess import Popen
import signal
import curses

# Crypto libraries import
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from wifi.crypto import build_TKIP_payload, check_MIC_ICV, build_MIC_ICV, \
    customPRF512, ARC4_encrypt, gen_TKIP_RC4_key, ARC4_decrypt
# Scapy imports
from scapy.config import conf
from scapy.sendrecv import sendp, sniff
from scapy.base_classes import Net
from scapy.compat import raw, hex_bytes, chb, orb
from scapy.utils import mac2str, rdpcap
from scapy.packet import Raw, Packet
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Disas, Dot11AssoReq, Dot11ReassoResp, Dot11ReassoReq, \
    Dot11AssoResp, \
    Dot11Auth, Dot11Beacon, Dot11Elt, Dot11EltMicrosoftWPA, Dot11EltRates, Dot11EltCountry, \
    Dot11EltCountryConstraintTriplet, Dot11Deauth, Dot11EltRSN, \
    Dot11ProbeReq, Dot11ProbeResp, RSNCipherSuite, AKMSuite, Dot11TKIP, Dot11QoS, Dot11EltVendorSpecific, Dot11CCMP
from scapy.layers.eap import EAPOL, EAPOL_KEY, EAP, EAP_PWD, EAP_PEAP, EAP_TTLS
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
from scapy.layers.inet import IP
from scapy.layers.dhcp import DHCP_am, DHCP

# Pytransitions import
from transitions.extensions import HierarchicalGraphMachine as Machine
from transitions.extensions.states import add_state_features, Tags, Timeout

# Flask imports
from flask import Flask, request
from flask_socketio import SocketIO

# Project imports
from wifi.tint import TunInterface
import wifi.eap_freeradius_bridge as eap_freeradius_bridge
import greyhound.fitness as fitness
import greyhound.fuzzing as fuzzing
from greyhound.fuzzing import StateConfig, MutatorRandom, SelectorRandom, SelectorAll
from monitors.monitor_serial import Monitor
from wifi.rpyutils import set_monitor_mode
# Custom drivers import
from drivers.rt2800usb import RT2800USBNetlink
from greyhound.webserver import send_vulnerability, send_fitness, SetFuzzerConfig
from greyhound.machine import GreyhoundStateMachine
from greyhound import g_utils
import EAPModule

# --------------------- Machine state and transitions ------------------------------------------
states = [
    {'name': 'WAIT_BEACON', 'on_enter': 'iteration'},
    {'name': 'PROBE', 'on_enter': 'send_probe_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'AUTHENTICATION', 'on_enter': 'send_authentication_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'ASSOCIATION', 'on_enter': 'send_association_request', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'EAP_START', 'on_enter': 'send_eapol_start'},
    {'name': 'EAP_IDENTITY', 'on_enter': 'send_eap_response'},
    {'name': 'EAP_CHALLANGE', 'on_enter': 'send_eap_response'},
    {'name': 'EAP_SUCCESS'},
    {'name': 'WPA_MSG_1'},
    {'name': 'WPA_MSG_2', 'on_enter': 'send_wpa_handshake_2', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'WPA_MSG_4', 'on_enter': 'send_wpa_handshake_4', 'timeout': 0.5, 'on_timeout': 'retry'},
    {'name': 'CONNECTED', 'timeout': 0.5, 'on_timeout': 'max_timeout'}
]

transitions = [
    # WAIT_BEACON -> PROBE
    {'trigger': 'update', 'source': 'WAIT_BEACON', 'dest': 'PROBE',
     'conditions': 'receive_beacon'},
    # PROBE -> AUTHENTICATION
    {'trigger': 'update', 'source': 'PROBE', 'dest': 'AUTHENTICATION',
     'conditions': 'receive_probe_response'},
    {'trigger': 'skip', 'source': 'PROBE', 'dest': 'AUTHENTICATION'},
    {'trigger': 'retry', 'source': 'PROBE', 'dest': 'PROBE'},
    # AUTHENTICATION -> ASSOCIATION
    {'trigger': 'update', 'source': 'AUTHENTICATION', 'dest': 'ASSOCIATION',
     'conditions': 'receive_authentication_response'},
    {'trigger': 'retry', 'source': 'AUTHENTICATION', 'dest': 'AUTHENTICATION'},
    # ASSOCIATION -> WPA_MSG_1
    {'trigger': 'update', 'source': 'ASSOCIATION', 'dest': 'WPA_MSG_1',
     'conditions': 'receive_association_response'},
    {'trigger': 'retry', 'source': 'ASSOCIATION', 'dest': 'ASSOCIATION'},
    # WPA_MSG_1 -> WPA_MSG_2
    {'trigger': 'update', 'source': 'WPA_MSG_1', 'dest': 'WPA_MSG_2',
     'conditions': 'receive_wpa_handshake_1'},
    # WPA_MSG_2 -> WPA_MSG_4
    {'trigger': 'update', 'source': 'WPA_MSG_2', 'dest': 'WPA_MSG_4',
     'conditions': 'receive_wpa_handshake_3', 'after': 'update'},
    {'trigger': 'retry', 'source': 'WPA_MSG_2', 'dest': 'WPA_MSG_2'},
    # WPA_MSG_2 -> WPA_MSG_4
    {'trigger': 'update', 'source': 'WPA_MSG_4', 'dest': 'CONNECTED'},
    {'trigger': 'retry', 'source': 'WPA_MSG_4', 'dest': 'WPA_MSG_4'},
    # CONNECTED -> CONNECTED
    {'trigger': 'update', 'source': 'CONNECTED', 'dest': 'CONNECTED',
     'conditions': 'connected'},
    # CONNECTED -> WAIT_BEACON
    {'trigger': 'max_timeout', 'source': 'CONNECTED', 'dest': 'WAIT_BEACON',
     'before': 'send_disconnection'},
    # ---------------------------- EAP ------------------------------
    # ASSOCIATION -> EAP_START
    {'trigger': 'start_eap', 'source': 'ASSOCIATION', 'dest': 'EAP_START'},
    # EAP_START -> EAP_IDENTITY
    {'trigger': 'update', 'source': 'EAP_START', 'dest': 'EAP_IDENTITY',
     'conditions': 'receive_eap_identity_request'},
    # EAP_IDENTITY -> EAP_CHALLANGE
    {'trigger': 'update', 'source': 'EAP_IDENTITY', 'dest': 'EAP_CHALLANGE',
     'conditions': 'receive_eap_request'},
    # EAP_CHALLANGE -> EAP_SUCCESS
    {'trigger': 'update', 'source': 'EAP_CHALLANGE', 'dest': 'EAP_SUCCESS',
     'conditions': 'finish_eap_challange'},
    # EAP_SUCCESS -> WPA_MSG_1
    {'trigger': 'update', 'source': 'EAP_SUCCESS', 'dest': 'WPA_MSG_1',
     'conditions': 'receive_eap_success'},

]

states_fuzzer_config = {
    'WAIT_BEACON': StateConfig(
        states_expected=[Dot11Auth, Raw, Dot11Elt, Dot11EltRates, Dot11EltRSN, Dot11EltMicrosoftWPA,
                         Dot11EltVendorSpecific, Dot11Disas, Dot11ProbeReq, Dot11Deauth, DHCP, Dot11CCMP, Dot11TKIP],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[Dot11EltRates, Dot11ProbeResp, Dot11EltRSN],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom,
                                    SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[10, 15, 30, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], ['ID'], ['ID']],
        fuzzable_layers_mutators_lengths_chance=[20, 20, 20, 20],  # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),
    'PROBE': StateConfig(
        states_expected=[Dot11Auth, Dot11Elt, Dot11EltRates, Dot11EltRSN, Dot11EltMicrosoftWPA,
                         Dot11EltVendorSpecific, Dot11Disas, Dot11ProbeReq, Dot11Deauth, DHCP, Dot11CCMP, Dot11TKIP],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[Dot11EltRates, Dot11ProbeResp, Dot11Elt],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom,
                                    SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[10, 15, 30, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], ['ID'], ['ID']],
        fuzzable_layers_mutators_lengths_chance=[20, 20, 20, 20],  # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),
    'AUTHENTICATION': StateConfig(
        states_expected=[Dot11Auth, Dot11AssoReq, Dot11Elt, Dot11EltRates, Dot11EltRSN, Dot11EltMicrosoftWPA,
                         Dot11Deauth, DHCP],
        fuzzable_layers=[Dot11Auth],
        fuzzable_layers_mutators=[[MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],
        fuzzable_action_transition=None),
    'ASSOCIATION': StateConfig(
        states_expected=[Dot11AssoResp, Dot11AssoReq, Dot11Auth, Dot11ProbeResp],
        fuzzable_layers=[Dot11EltRates, Dot11AssoResp, Dot11Elt],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=20,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['ID'], ['ID'], ['ID']],
        fuzzable_layers_mutators_lengths_chance=[40, 40, 40],
        fuzzable_action_transition=None),
    'EAP_START': StateConfig(
        states_expected=[EAPOL, EAP, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoResp],
        fuzzable_layers=[EAP, EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100, 10],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['id'], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10],
        fuzzable_action_transition='WAIT_BEACON'),
    'EAP_IDENTITY': StateConfig(
        states_expected=[EAPOL, EAP, Dot11Deauth, Dot11Disas, Dot11AssoReq, DHCP, Dot11Auth, Dot11ProbeReq],
        fuzzable_layers=[EAP, EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100, 10],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['id'], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10],
        fuzzable_action_transition='EAP_START'),
    'EAP_CHALLANGE': StateConfig(
        states_expected=[EAPOL, EAP, EAP_PWD, Dot11Deauth, Dot11Disas, Dot11AssoReq, DHCP, Dot11Auth],
        fuzzable_layers=[EAP_PEAP, EAPOL, EAP_TTLS],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],  # Selection strategy
        # 30 for eap-peap  # 50  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_global_chance=50,  # 15 # 20
        fuzzable_layers_mutators_chance_per_layer=[50, 10, 20],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[30, 30, 30],  # Probability for each field to be fuzzed
        # fuzzable_layers_mutators_exclude_fields=[['code', 'id', 'type', 'len', 'message_len', 'pwd_exch', 'L', 'M'],
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20, 20],
        fuzzable_action_transition='EAP_START'),
    'EAP_SUCCESS': StateConfig(
        states_expected=[EAPOL, EAP, EAP_PWD, DHCP],
        fuzzable_layers=[EAP, EAPOL, EAP_PEAP, EAP_TTLS],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 10 # 50 # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 10, 20, 20],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 30, 30, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['id'], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20, 20, 20],
        fuzzable_action_transition=None),

    'WPA_MSG_1': StateConfig(
        states_expected=[Dot11ProbeReq, Dot11AssoResp, EAPOL, EAP, Raw, Dot11Deauth, Dot11Disas, DHCP, Dot11Auth],
        fuzzable_layers=[EAPOL, EAPOL_KEY],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 10 # 30  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[30, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10],
        fuzzable_action_transition=None),
    'WPA_MSG_2': StateConfig(
        states_expected=[EAPOL, EAP, Raw, Dot11Deauth, Dot11Disas, Dot11Auth, DHCP],
        fuzzable_layers=[EAPOL, EAPOL_KEY],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 30 # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10],
        fuzzable_action_transition=None),
    'WPA_MSG_4': StateConfig(
        states_expected=[EAPOL, EAP, Raw, Dot11Deauth, Dot11Disas, Dot11Auth, DHCP],
        fuzzable_layers=[EAPOL, EAPOL_KEY],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 30 # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10],
        fuzzable_action_transition=None),
    'CONNECTED': StateConfig(
        states_expected=[Dot11TKIP, SNAP, Dot11QoS, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11ProbeReq],
        fuzzable_layers=[Dot11ProbeResp, Dot11Elt, Dot11EltRSN, Dot11TKIP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 45 # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 10, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 30, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['ID'], ['ID'], ['ID']],
        fuzzable_layers_mutators_lengths_chance=[20, 20, 20],
        fuzzable_action_transition=None),
}


# --------------------- Model Implementation ------------------------------------------


class Dot11Methods(object):
    # Model configuration
    wifi_channel = 1
    wifi_ssid = "esp32"
    wifi_passphrase = "mypassword"
    wifi_interface = "wlan1mon"  # interface for packet transmission
    wifi_security = 'CCMP'
    eap_username = 'matheus_garbelini'
    mac = "28:c6:3f:a8:af:c5"  # type: str
    fuzzing_enable = True
    driver_custom_name = 'RT2800USB'
    driver_custom_enable = False
    driver_custom_instance = None  # type: RT2800USBNetlink
    monitor_serial_magic_string = 'WPA2 ENTERPRISE VERSION:'
    monitor_serial_port = '/dev/ttyUSB*'
    monitor_serial_baud = 115200
    enable_fuzzing = True

    # State machine variables
    config_file = 'wifi_client_config.json'  # File to store model configuration
    machine = None
    iterations = 0
    warnings = 0
    idle_state = None
    monitor = None

    # Timers
    timer_global = None  # type: threading.Timer
    timer_crash_detection = None  # type: threading.Timer

    # Model local variables
    pkt = None
    last_pkt = None
    pkt_received = False
    client = None
    seq_num = count(0)
    boot_time = time()

    base_pkt_dot11_wpa = Dot11(FCfield="from-DS+protected")  # Pre allocate Dot11 Packet
    base_pkt_radiotap = '\x00\x00\x08\x00\x00\x00\x00\x00'
    ap_connected = False
    ap_mac = None
    ap_RSN = None
    ap_group_cipher = 0x02  # Default to TKIP
    ap_ever_connected = False
    eap_pkt = None
    enable_eap = False

    # Key vars
    anonce = None
    snonce = None
    pmk = None
    ptk = None
    gtk = None
    kck = None
    kek = None
    tk = None
    last_iv = None
    group_iv = count(0)
    client_iv = None
    mic_ap_to_sta = None  # Used in mic ap -> sta
    mic_sta_to_ap = None  # used in mic sta -> ap
    mic_ap_to_group = None  # Used to send broadcast packets

    def __init__(self, machine_states, machine_transitions, driver_custom=None,
                 idle_state=None,
                 crash_magic_word=None,
                 serialport_name=None,
                 serialport_baudrate=None):

        self.load_config()

        if crash_magic_word is not None:
            self.monitor_serial_magic_string = crash_magic_word

        if serialport_name is not None:
            self.monitor_serial_port = serialport_name

        if serialport_baudrate is not None:
            self.monitor_serial_baud = serialport_baudrate

        if idle_state is not None:
            self.idle_state = idle_state

        if driver_custom is not None:
            self.driver_custom_name = driver_custom

        colorama_init(autoreset=True)  # Colors autoreset

        # TODO: Create virtual interface for wifi_client if necessary
        # Configure virtual interface
        # self.virtual_iface = TunInterface(self.send_ethernet_over_wifi, self.virtual_ip,
        #                                   name='WIFI_CLIENT', enable_dns=True)
        # self.virtual_iface.start()

        # Configure custom driver if enabled
        if self.driver_custom_name is not None:
            _driver = eval(self.driver_custom_name + 'Netlink()')
            self.driver_custom_instance = _driver
            self.driver_custom_enable = True
            print(Fore.CYAN + "Custom Wi-Fi driver selected: " + Fore.YELLOW + self.driver_custom_name)

        # Configure Master key if pre-shared authentication is used
        self.install_PMK()
        print(Fore.YELLOW + 'Pairwise Master Key (PMK) generated: ' + hexlify(self.pmk).upper())

        # Configure Wi-Fi interface and channel
        if 'mon' in self.wifi_interface:
            ifc = self.wifi_interface.split('mon')[0]
            set_monitor_mode(ifc)

        if self.wifi_channel > 0:
            os.system("iwconfig " + self.wifi_interface + " channel " + str(1 + ((self.wifi_channel + 1) % 14)))
            os.system("iwconfig " + self.wifi_interface + " channel " + str(self.wifi_channel))
            print(Fore.CYAN + 'Interface ' + str(self.wifi_interface) + ' set to channel ' + str(self.wifi_channel))

        EAPModule.configure_peer(self.eap_username, self.wifi_passphrase, '')  # Setup EAP credentials

        # Initialize state machine instance
        conf.verb = 0
        SetFuzzerConfig(states_fuzzer_config)
        self.machine = GreyhoundStateMachine(states=machine_states,
                                             transitions=machine_transitions,
                                             print_transitions=True,
                                             print_timeout=True,
                                             initial='WAIT_BEACON',
                                             idle_state='WAIT_BEACON',
                                             before_state_change='state_change',
                                             show_conditions=True,
                                             show_state_attributes=True,
                                             enable_webserver=True)

        # Used for any serial device
        if self.monitor_serial_port:
            self.monitor = Monitor(self.monitor_serial_port, self.monitor_serial_baud,
                                   magic_string=self.monitor_serial_magic_string,
                                   user_callback=self.monitor_crash_detected)

        print(Fore.GREEN + 'Fuzzer Access Point started. Waiting for SSID=' + self.wifi_ssid)

    # ----------------------------- Timers ----------------------------

    def timeout_global(self):
        print(Fore.YELLOW + "Global Timeout !!!")
        self.reset_vars()
        self.machine.reset_machine()

    def timeout_crash(self):
        self.reset_vars()
        self.machine.report_crash()
        self.machine.reset_machine()

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
        timer = threading.Timer(seconds, callback)
        setattr(self, timer_name, timer)
        timer.daemon = True
        timer.start()

    # ----------------------------- Config vars ----------------------------

    def get_config(self):
        obj = {'WifiSSID': self.wifi_ssid,
               'WifiPassword': self.wifi_passphrase,
               'WifiUsername': self.eap_username,
               'WifiChannel': self.wifi_channel,
               'WifiMAC': self.mac,
               'WifiSecurity': self.wifi_security,
               'WifiInterface': self.wifi_interface,
               'MonitorSerialPort': self.monitor_serial_port,
               'MonitorSerialBaud': str(self.monitor_serial_baud),
               'MonitorDetectionString': self.monitor_serial_magic_string,
               'EnableFuzzing': self.enable_fuzzing
               }
        return json.dumps(obj, indent=4)

    def set_config(self, data):
        self.wifi_ssid = data['WifiSSID']
        self.wifi_passphrase = data['WifiPassword']
        self.eap_username = data['WifiUsername']
        self.wifi_channel = int(data['WifiChannel'])
        self.mac = data['WifiMAC']
        self.wifi_security = data['WifiSecurity']
        self.wifi_interface = data['WifiInterface']
        self.monitor_serial_port = data['MonitorSerialPort']
        self.monitor_serial_baud = int(data['MonitorSerialBaud'])
        self.monitor_serial_magic_string = data['MonitorDetectionString']
        self.enable_fuzzing = data['EnableFuzzing']

    def save_config(self, obj):
        f = file(self.config_file, 'w')
        f.write(json.dumps(obj, indent=4))
        f.close()

    def load_config(self):
        try:
            f = file(self.config_file, 'r')
            obj = json.loads(f.read())
            f.close()
            self.set_config(obj)
            return True
        except:
            f = file(self.config_file, 'w')
            f.write(self.get_config())
            f.close()
            return False

    def reset_vars(self):
        self.machine.reset_state_timeout()
        self.disable_timeout('timer_global')
        self.disable_timeout('timer_crash_detection')

        self.ap_connected = False
        self.last_iv = None
        self.group_iv = count(0)
        self.client_iv = count(0)

    # ----------------------- Scapy send and sniff ---------------------------

    def send(self, pkt):
        # Increment sequence counter for each sent packet
        pkt.SC = (next(self.seq_num) << 4) % 4096

        print(Fore.CYAN + "TX ---> " + pkt.summary())
        self.machine.add_packets(RadioTap() / pkt)

        # Fuzz packets
        if self.enable_fuzzing:
            fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)

        # Encrypt packets
        if self.ap_connected and pkt.type == 2:
            pkt = self.encrypt_packet(pkt)

        # Send packets through custom Wi-Fi driver
        data = self.base_pkt_radiotap + raw(pkt)  # RadioTap + 802.11 frame
        self.driver_custom_instance.send_data(data)

    def sniff(self):
        conf.sniff_promisc = False
        self.driver_custom_instance.set_mac(self.mac)
        self.driver_custom_instance.set_flags_enable(1)
        self.driver_custom_instance.set_flags_retry(1)
        self.driver_custom_instance.set_filter_unicast()
        self.driver_custom_instance.set_interrupt_rx_enable()

        try:
            while True:
                self.receive_packet(Dot11(self.driver_custom_instance.raw_receive()))
        except KeyboardInterrupt:
            print(Fore.RED + 'Model process stopped' + Fore.RESET)
            exit(0)

    def receive_packet(self, pkt):
        print_lines = False

        if self.ap_mac is not None and pkt.addr2 != self.ap_mac:
            # Once AP is recognized, ignore packets from other APs
            return

        self.machine.add_packets(RadioTap() / pkt)

        if Dot11Deauth in pkt or Dot11Disas in pkt:
            self.reset_vars()
            self.machine.reset_machine()

        if self.ap_connected:
            pkt = self.decrypt_packet(pkt)

        # Validade packets against expected packets set
        if Dot11TKIP not in pkt or self.ap_connected == True:
            self.fitness(pkt)

        # Filter packets which summary will be printed
        if (self.ap_mac is None or Dot11Beacon not in pkt) and (pkt.type != 0x02 or pkt.subtype != 0x04):
            print_lines = True
            print(Fore.BLUE + "State:" + Fore.LIGHTCYAN_EX + self.state + Fore.LIGHTCYAN_EX)
            print(Fore.CYAN + "RX <--- " + pkt.summary())

        self.pkt = pkt
        self.update()

        if print_lines:
            print('----------------------------')

    # ------------------------ MONITOR Callback -----------------------------------------------

    def monitor_crash_detected(self):
        message = 'CRASH DETECTED in state ' + self.state
        print(Fore.RED + '[CRASH] !!!!!!!!!! ' + message + ' !!!!!!!!!!!!')
        if self.idle_state is not None and fuzzing.last_fuzzed_packet is not None:
            self.warnings += 1
            self.ap_connected = False
            self.machine.report_crash()
            self.machine.reset_machine()

    # ----------------------- MISC ------------------------------------------------------------

    def state_change(self):
        if self.machine.source == self.machine.destination:
            # Return if transition is equal
            return
        self.machine.reset_state_timeout()
        self.update_timeout('timer_global')
        fitness.Transition()

    def iteration(self):

        if self.machine.source == self.machine.destination:
            # Return if transition is equal
            return

        fitness.Transition(reset=True)
        state_transitions = fitness.TransitionLastCount
        iterationTime = fitness.Iteration()

        if fitness.IssuePeriod > 0:
            issuePeriod = fitness.IssuePeriod
        else:
            issuePeriod = float('inf')

        self.machine.save_packets()

        print(Back.WHITE + Fore.BLACK +
              "IssueCount:" + str(fitness.IssueCounter) + ' IssuePeriod:{0:.3f}'.format(issuePeriod)
              + ' Transitions:' + str(state_transitions) + ' IterTime:{0:.3f}'.format(
                    iterationTime) + ' TotalIssues: '
              + str(fitness.IssuesTotalCounter))

        send_fitness(fitness.IssueCounter, issuePeriod, state_transitions, iterationTime, self.iterations,
                     fitness.IssuesTotalCounter)

        self.iterations += 1

        # Setup crash timeout timer
        self.start_timeout('timer_crash_detection', 2.0, self.timeout_crash)

    def fitness(self, pkt):
        # Only calculate fitness of unicast packets
        if pkt.type == 2 and pkt.subtype == 0x04:
            return False  # discart Null Data frames

        if Dot11Beacon in pkt or Dot11ProbeReq in pkt:
            return False

        if EAP in pkt:
            if pkt[EAP].type == 0x03 or pkt[EAP].type == 0x01:
                return False  # discart Nack EAP frames

        if fitness.Validate(pkt, self.state, states_fuzzer_config):
            return True
        else:
            self.machine.report_anomaly(pkt=pkt)
            self.warnings += 1

            return True

    def current_timestamp_us(self):
        return (time() - self.boot_time) * 1000000

    def current_timestamp(self):
        return time() - self.boot_time

    # --------------- WPA cryptographic send functions (TKIP + RC4) ---------------------------
    def encrypt_packet(self, data):
        """Encrypt packet with content @data, using IV @iv,
        sequence number @seqnum, MIC key @mic_key
        """
        if data.addr1 == 'ff:ff:ff:ff:ff:ff':
            iv = next(self.group_iv)
            encrypt_key = self.gtk
            mic = self.mic_ap_to_group
        else:
            iv = next(self.client_iv)
            encrypt_key = self.tk
            mic = self.mic_ap_to_sta

        self.base_pkt_dot11_wpa.addr1 = data.addr1
        self.base_pkt_dot11_wpa.addr2 = data.addr2
        self.base_pkt_dot11_wpa.addr3 = data.addr3
        self.base_pkt_dot11_wpa.subtype = data.subtype
        self.base_pkt_dot11_wpa.type = data.type

        # Assume packet is send by our AP -> use self.mac as source
        # Encapsule in TKIP with MIC Michael and ICV
        data_to_enc = build_MIC_ICV(raw(data[Dot11].payload), mic, self.mac, data.addr1)
        # Header TKIP + payload
        return self.base_pkt_dot11_wpa / Raw(build_TKIP_payload(data_to_enc, iv, self.mac, encrypt_key))

    def decrypt_packet(self, pkt):
        """
        :type pkt: Packet
        """
        if pkt.type == 2 and pkt[Dot11].FCfield.protected and pkt.addr1 == self.mac:
            # Check IV
            iv = pkt.TSC0 | (pkt.TSC1 << 8) | (pkt.TSC2 << 16) | (pkt.TSC3 << 24) | \
                 (pkt.TSC4 << 32) | (pkt.TSC5 << 40)

            if self.last_iv is None:
                self.last_iv = iv
            else:
                if iv <= self.last_iv and pkt.FCfield.retry == 0:
                    print(Fore.RED + "IV re-use!! Client seems to be "
                                     "vulnerable to handshake 3/4 replay "
                                     "(CVE-2017-13077)")
                    # send_vulnerability(0, 'IV re-use (CVE-2017-13077) detected')
                    self.machine.report_anomaly(msg='IV re-use (CVE-2017-13077) detected', pkt=pkt)

            # Normal decoding
            TA = [orb(e) for e in mac2str(pkt.addr2)]
            TSC = [pkt.TSC0, pkt.TSC1, pkt.TSC2, pkt.TSC3, pkt.TSC4, pkt.TSC5]
            TK = [orb(x) for x in self.tk]
            rc4_key = gen_TKIP_RC4_key(TSC, TA, TK)
            # decrypt data
            data = ARC4_decrypt(rc4_key, pkt[Dot11TKIP].data)
            # check data integrity (exception may happen here)
            try:
                data_decrypted = check_MIC_ICV(data, self.mic_ap_to_sta, pkt.addr2,
                                               pkt.addr3)

                pkt[Dot11].remove_payload()
                pkt.FCfield.protected = 0
                return pkt / LLC(data_decrypted)
            except:
                # MIC error
                print(Fore.RED + "[!] MIC Error")
                return pkt
        else:
            return pkt

    def build_EAPOL_Key_8021X2004(self,
                                  replay_counter,
                                  nonce,
                                  data=None,
                                  key_mic=None,
                                  key_data_encrypt=None,
                                  key_rsc=0,
                                  key_id=0,
                                  key_descriptor_type=2,  # EAPOL RSN Key
                                  key_iv=None
                                  ):

        if key_iv is None:
            key_iv = os.urandom(16)

        if data is None:
            data = ''

        if self.wifi_security == 'TKIP':
            hash_method = hashlib.md5
            key_information = 0x0109
            key_length = 32
        else:  # CCMP
            hash_method = hashlib.sha1
            key_information = 0x010A
            key_length = 16

        pkt = EAPOL(version="802.1X-2004", type="EAPOL-Key")

        payload = b"".join([
            chb(key_descriptor_type),
            struct.pack(">H", key_information),
            struct.pack(">H", key_length),  # Key length
            struct.pack(">Q", replay_counter),
            nonce,
            key_iv,
            struct.pack(">Q", key_rsc),
            struct.pack(">Q", key_id),
        ])

        # MIC field is set to 0's during MIC computation
        offset_MIC = len(payload)
        payload += b'\x00' * 0x10

        if data is None and key_mic is None and key_data_encrypt is None:
            # If key is unknown and there is no data, no MIC is needed
            # Example: handshake 1/4
            payload += b'\x00' * 2  # Length
            return pkt / EAPOL_KEY(payload)

        payload += struct.pack(">H", len(data))
        # payload += enc_data
        payload += data

        # Compute MIC and set at the right place
        temp_mic = pkt.copy()
        temp_mic /= Raw(load=payload)
        to_mic = raw(temp_mic[EAPOL])
        mic = hmac.new(key_mic, to_mic, hash_method).digest()[:16]  # Truncate mic to 16 bytes (necessary for ccmp)
        final_payload = payload[:offset_MIC] + mic + payload[offset_MIC + len(mic):]  # noqa: E501

        return pkt / EAPOL_KEY(final_payload)

    def install_PMK(self):
        """Compute and install the PMK if using WPA2-PSK"""
        self.pmk = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,
            salt=self.wifi_ssid.encode(),
            iterations=4096,
            backend=default_backend(),
        ).derive(self.wifi_passphrase.encode())

    def install_unicast_keys(self, ap_nonce):
        """Use the client nonce @client_nonce to compute and install
        PTK, KCK, KEK, TK, MIC (AP -> STA), MIC (STA -> AP)
        """
        pmk = self.pmk
        snonce = self.snonce  # Supplicant nonce
        anonce = ap_nonce  # Authenticator nonce
        smac = hex_bytes(self.mac.replace(":", ""))
        amac = hex_bytes(self.ap_mac.replace(":", ""))

        # Compute PTK
        self.ptk = customPRF512(pmk, amac, smac, anonce, snonce)

        # Extract derivated keys
        self.kck = self.ptk[:16]
        self.kek = self.ptk[16:32]
        self.tk = self.ptk[32:48]
        self.mic_ap_to_sta = self.ptk[48:56]
        self.mic_sta_to_ap = self.ptk[56:64]

        # Reset IV
        self.client_iv = count(0)

    def install_GTK(self, gtk_full):
        """Compute a new GTK and install it alongs
        MIC (AP -> Group = broadcast + multicast)
        """

        self.gtk = gtk_full[:16]

        # Extract derivated keys
        self.mic_ap_to_group = gtk_full[16:24]

        # Reset IV
        self.group_iv = count(0)

    # -------------------------------- State machine functions ---------------------------

    def receive_beacon(self):
        if EAP_PEAP in self.pkt:
            self.eap_pkt = EAPModule.send_peer_request(raw(self.pkt[EAP]))
            self.send_eap_response()
            print(Fore.YELLOW + 'Rogue EAP response sent!!!!!')

        if Dot11Beacon in self.pkt and self.pkt[Dot11Elt].info == self.wifi_ssid:
            self.ap_mac = self.pkt.addr2
            print(Fore.GREEN + '[!] SSID=' + self.wifi_ssid + ' received from ' + self.ap_mac.upper())
            if Dot11EltRSN in self.pkt:
                self.disable_timeout('timer_crash_detection')
                self.enable_eap = (self.pkt[Dot11EltRSN].akm_suites[0].suite == 0x01)  # Check if eap is required
                self.ap_group_cipher = self.pkt[Dot11EltRSN].group_cipher_suite.cipher  # Get group cipher
                self.start_timeout('timer_global', 4, self.timeout_global)
            return True

    def build_RSN(self):

        if self.wifi_security == 'TKIP':
            cipher = 0x02
        elif self.wifi_security == 'CCMP':
            cipher = 0x04

        if self.enable_eap:
            suite_version = 0x01  # 802.1X
        else:
            suite_version = 0x02  # Pre shared key (PSK)

        return Dot11EltRSN(group_cipher_suite=RSNCipherSuite(cipher=self.ap_group_cipher),  # Group defaults TKIP
                           pairwise_cipher_suites=[RSNCipherSuite(cipher=cipher)],
                           akm_suites=[AKMSuite(suite=suite_version)])

    def send_probe_request(self):
        rep = Dot11(addr1=self.ap_mac, addr2=self.mac, addr3=self.ap_mac) / \
              Dot11ProbeReq() / \
              Dot11Elt(ID=0x00, info=self.wifi_ssid) / \
              Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36]) / \
              Dot11Elt(ID='ESRates', info='l\x12$H') / \
              Dot11Elt(ID=0x3B, info='\x51\x51\x53\x54\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81') / \
              Dot11Elt(ID='DSset', info='\x01') / \
              Dot11Elt(ID='Country', info='\x43\x4e\x00\x01\x0d\x14') / \
              self.build_RSN() / \
              Dot11EltVendorSpecific(oui=0x50f2, info="\x02\x01\x01\x04\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00")

        self.send(rep)

    def receive_probe_response(self):
        if Dot11ProbeResp in self.pkt:
            return True
        return False

    def send_authentication_request(self):
        rep = Dot11(addr1=self.ap_mac, addr2=self.mac, addr3=self.ap_mac) / \
              Dot11Auth(seqnum=1, algo=0)  # Open authentication (0)

        self.send(rep)

    def receive_authentication_response(self):

        if Dot11Auth in self.pkt:
            print(Fore.YELLOW + '[!] Authenticated to ' + self.pkt.addr2.upper())
            self.ap_ever_connected = True  # indicate that AP has interacted at least once
            return True

    def send_association_request(self):
        rep = Dot11(addr1=self.ap_mac, addr2=self.mac, addr3=self.ap_mac) / \
              Dot11AssoReq(cap=0x2104) / \
              Dot11Elt(ID=0x00, info=self.wifi_ssid) / \
              Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36]) / \
              Dot11Elt(ID='ESRates', info='l\x12$H') / \
              Dot11Elt(ID=0x3B, info='\x51\x51\x53\x54\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81') / \
              Dot11Elt(ID='DSset', info='\x01') / \
              Dot11Elt(ID='Country', info='\x43\x4e\x00\x01\x0d\x14') / \
              self.build_RSN() / \
              Dot11EltVendorSpecific(oui=0x50f2, info="\x02\x01\x01\x04\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00")

        self.send(rep)

    def receive_association_response(self):

        if Dot11AssoResp in self.pkt:
            print(Fore.YELLOW + '[!] Association')
            if self.enable_eap:
                print(Fore.YELLOW + '[!] EAP network detected!')
                self.start_eap()  # Transitions to EAP_START
                return False
            else:
                # Normal connection
                return True

        return False

    def send_eapol_start(self):
        EAPModule.restart_peer()

        rep = Dot11(
            type='Data',
            addr1=self.ap_mac,
            addr2=self.mac,
            addr3=self.ap_mac,
            FCfield='to-DS',
            subtype=8
        )
        rep /= Dot11QoS(TID=6)
        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= EAPOL(version="802.1X-2004", type="EAPOL-Start")
        self.send(rep)

    def receive_eap_identity_request(self):
        if EAP in self.pkt and self.pkt[EAP].type == 0x01:  # EAP identity
            self.eap_pkt = EAPModule.send_peer_request(raw(self.pkt[EAP]))
            return True

    def receive_eap_request(self):
        if EAP in self.pkt and self.pkt[EAP].code == 0x01:  # Request
            self.eap_pkt = EAPModule.send_peer_request(raw(self.pkt[EAP]))

            if self.pkt[EAP].type != 0x01:
                # Wait for eap Identity type
                return True

            self.send_eap_response()

    def send_eap_response(self):
        if self.eap_pkt is None:
            return
        rep = Dot11(
            type='Data',
            addr1=self.ap_mac,
            addr2=self.mac,
            addr3=self.ap_mac,
            FCfield='to-DS',
            subtype=8
        )
        rep /= Dot11QoS(TID=6)
        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= EAPOL(version="802.1X-2004", type=0x00)  # EAP Packet
        rep /= EAP(self.eap_pkt)
        self.send(rep)

    def finish_eap_challange(self):
        if EAP in self.pkt and self.pkt[EAP].code == 0x01:  # Request
            self.eap_pkt = EAPModule.send_peer_request(raw(self.pkt[EAP]))
            self.send_eap_response()

            # Check if EAP Key (PMK) was received
            eap_master_key = EAPModule.get_key_peer()
            if eap_master_key:
                # MSK = MasterReceiveKey + MasterSendKey + 32 bytes zeroes (padding)
                # PMK = First 32 bytes of MSK
                # MS-MPPE-Recv-Key      = MasterSendKey
                # MS-MPPE-Send-Key      = MasterReceiveKey
                self.pmk = eap_master_key[:32]
                print(Fore.GREEN + '[!] Receved PMK: ' + hexlify(self.pmk).upper())

                return True

        return False

    def receive_eap_success(self):

        if EAP in self.pkt:
            if self.pkt[EAP].code == 0x01:  # Request received
                self.eap_pkt = EAPModule.send_peer_request(raw(self.pkt[EAP]))
                self.send_eap_response()
            elif self.pkt[EAP].code == 0x03:  # Success received
                return True

    def receive_wpa_handshake_1(self):

        if EAPOL_KEY in self.pkt:
            print(Fore.YELLOW + '[!] Handshake 1/4')
            self.anonce = self.pkt[EAPOL_KEY].wpa_key_nonce
            # Generate supplicant nonce (client)
            self.snonce = os.urandom(32)
            # Generate unicast keys with ap nonce
            self.install_unicast_keys(self.anonce)
            return True
        return False

    def send_wpa_handshake_2(self):
        rep = Dot11(
            addr1=self.ap_mac,
            addr2=self.mac,
            addr3=self.ap_mac,
            FCfield='to-DS'
        ) / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0, code=0x888e)

        print(Fore.YELLOW + "[!] " + self.wifi_security + " selected")

        # 802.1X Authentication
        rep /= self.build_EAPOL_Key_8021X2004(
            # key_information=0x12C9,  # MIC flag not set
            replay_counter=1,
            nonce=self.snonce,
            data=raw(self.build_RSN()),
            key_mic=self.kck,
            key_iv='\x00' * 16,
        )
        self.send(rep)
        print(Fore.YELLOW + '[!] Handshake 2/4')

    def receive_wpa_handshake_3(self):
        if EAPOL_KEY in self.pkt and (self.pkt[EAPOL_KEY].key_mic != '\x00' * 16):
            ap_key_pkt = self.pkt[EAPOL_KEY]
            ap_wpa_key_mic = ap_key_pkt.key_mic  # get mic from eapol
            ap_raw_eapol = raw(self.pkt[EAPOL]).replace(ap_wpa_key_mic, '\x00' * 16)  # clear mic from payload

            if self.wifi_security == 'TKIP':
                calculated_mic = hmac.new(self.kck, ap_raw_eapol, hashlib.md5).digest()  # calculate mic from packet
            else:  # CCMP
                calculated_mic = hmac.new(self.kck, ap_raw_eapol, hashlib.sha1).digest()[:16]

            print(Fore.YELLOW + '[!] Handshake 3/4')

            if calculated_mic == ap_wpa_key_mic:
                print(Fore.GREEN + '[!] AP MIC accepted')
                # Decrypt key data
                if self.wifi_security == 'TKIP':
                    data_decrypted = ARC4_decrypt(ap_key_pkt.key_iv + self.kek,
                                                  ap_key_pkt.key_data,
                                                  skip=256)
                else:
                    # CCMP
                    data_decrypted = aes_key_unwrap(self.kek,
                                                    ap_key_pkt.key_data,
                                                    default_backend())

                # Process key data
                data_decoded = Dot11EltRSN(data_decrypted)

                if Dot11EltVendorSpecific in data_decoded:  # GTK element
                    # Install GTK key
                    self.install_GTK(raw(data_decoded[Dot11EltVendorSpecific])[8:])
                    print(Fore.GREEN + '[!] GTK received: ' + hexlify(self.gtk).upper())
                else:
                    print(Fore.RED + '[!] GTK not received')

                data_decoded.remove_payload()
                self.ap_RSN = data_decoded

                return True
            else:
                print(Fore.RED + 'AP MIC wrong')
                return False

        return False

    def send_wpa_handshake_4(self):
        rep = Dot11(
            addr1=self.ap_mac,
            addr2=self.mac,
            addr3=self.ap_mac,
            FCfield='to-DS'
        ) / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0, code=0x888e)

        # 802.1X Authentication
        rep /= self.build_EAPOL_Key_8021X2004(
            # key_information=0x12C9,  # MIC flag not set
            replay_counter=2,
            key_mic=self.kck,
            nonce='\x00' * 32,
            key_iv='\x00' * 16,
            data='',  # Message 4 data is empty,
        )
        self.send(rep)
        self.ap_connected = True
        print(Fore.YELLOW + '[!] Handshake 4/4')
        print(Fore.GREEN + '[!] Connected to AP')

    def connected(self):
        return False

    def send_disconnection(self):
        if self.ap_mac:
            print(Fore.YELLOW + 'Disconnecting from ' + self.ap_mac)
            rep = Dot11(addr1=self.ap_mac, addr2=self.mac, addr3=self.ap_mac) / Dot11Disas()
            self.send(rep)
            rep = Dot11(addr1=self.ap_mac, addr2=self.mac, addr3=self.ap_mac) / Dot11Deauth()
            self.send(rep)

            self.reset_vars()


wifi_machine = Dot11Methods(states, transitions)
wifi_machine.get_graph().draw('wifi/wifi_client_diagram.svg', prog='dot')  # Save the whole graph ...
wifi_machine.sniff()
