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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from wifi.crypto import build_TKIP_payload, check_MIC_ICV, build_MIC_ICV, \
    customPRF512, ARC4_encrypt, gen_TKIP_RC4_key, ARC4_decrypt

# Scapy imports
from scapy.config import conf
from scapy.sendrecv import sendp, sniff
from scapy.base_classes import Net
from scapy.compat import raw, hex_bytes, chb, orb
from scapy.utils import mac2str, rdpcap
from scapy.volatile import RandBin
from scapy.packet import Raw, Packet
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Disas, Dot11AssoReq, Dot11ReassoResp, Dot11ReassoReq, \
    Dot11AssoResp, \
    Dot11Auth, Dot11Beacon, Dot11Elt, Dot11EltMicrosoftWPA, Dot11EltRates, Dot11Deauth, Dot11EltRSN, \
    Dot11ProbeReq, Dot11ProbeResp, RSNCipherSuite, AKMSuite, Dot11TKIP, Dot11QoS, Dot11EltVendorSpecific, Dot11CCMP
from scapy.layers.eap import EAPOL, EAP, EAP_PWD, EAP_PEAP, EAP_TTLS, EAP_TLS, EAPOL_KEY
from scapy.layers.l2 import ARP, LLC, SNAP, Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6ExtHdrHopByHop, IPv6
from scapy.contrib.igmp import IGMP
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

# --------------------- Machine state and transitions ------------------------------------------
states = [
    {'name': 'INIT', 'on_enter': 'send_AP_beacon_continuous'},
    {'name': 'WAIT_AUTH_REQUEST', 'on_enter': 'iteration'},
    {'name': 'SUPPLICANT',
     'children': [
         {'name': 'AUTHENTICATION', 'on_enter': ['send_auth_response', 'transition'], 'timeout': 1,
          'on_timeout': 'retry'},
         {'name': 'ASSOCIATION', 'on_enter': ['send_assoc_response', 'transition']},
     ]},

    {'name': 'EAP', 'initial': 'IDENTITY', 'timeout': 8, 'on_timeout': 'timeout_max',
     'children': [
         {'name': 'IDENTITY', 'on_enter': ['send_eap_request_identity', 'transition'], 'timeout': 1,
          'on_timeout': 'retry'},
         {'name': 'CHALLANGE', 'on_enter': ['send_eap_request', 'transition']},  # Radius Request
         {'name': 'ACCEPT', 'on_enter': ['send_eap_accept', 'transition']},
     ]},
    {'name': 'WPA_HANDSHAKE', 'initial': 'MSG_1', 'timeout': 2.5, 'on_timeout': 'timeout_max',
     'children': [
         # {'name': 'MSG_1', 'on_enter': 'send_wpa_handshake_1', 'timeout': 0.3, 'on_timeout': 'retry'},
         {'name': 'MSG_1', 'on_enter': ['send_wpa_handshake_1', 'transition']},
         {'name': 'MSG_3', 'on_enter': ['send_wpa_handshake_3', 'transition']},
         {'name': 'COMPLETE', 'on_enter': ['transition']},
     ]},

    # {'name': 'ANALYZE_DATA'},  # Limitless connection
    {'name': 'ANALYZE_DATA', 'timeout': 3, 'on_timeout': 'timeout_max'},
    {'name': 'ARP', 'on_enter': ['send_arp_request', 'transition'], 'timeout': 1, 'on_timeout': 'timeout_max'},
]

transitions = [
    # Timeout
    {'trigger': 'timeout_max',
     'source': ['SUPPLICANT_AUTHENTICATION', 'SUPPLICANT_ASSOCIATION', 'EAP',
                'WPA_HANDSHAKE', 'ANALYZE_DATA'],
     'before': 'send_deauth',
     'dest': 'WAIT_AUTH_REQUEST'},
    # Deauths
    {'trigger': 'deauth_request', 'source': ['EAP_IDENTITY', 'WPA_HANDSHAKE_MSG_1', 'WPA_HANDSHAKE_MSG_3'],
     'dest': 'WAIT_AUTH_REQUEST'},
    # init
    {'trigger': 'init', 'source': 'INIT', 'dest': 'WAIT_AUTH_REQUEST',
     'before': 'send_AP_beacon_continuous'},

    # WAIT_AUTH_REQUEST -> SUPPLICANT_AUTHENTICATION
    # State transition
    {'trigger': 'update', 'source': 'WAIT_AUTH_REQUEST', 'dest': 'SUPPLICANT_AUTHENTICATION',
     'conditions': 'received_authentication'},  # Transition Action
    # Retry transition
    {'trigger': 'retry', 'source': 'WAIT_AUTH_REQUEST', 'dest': 'WAIT_AUTH_REQUEST'},

    # AUTH_RESPONSE_SENT -> ASSOC_RESPONSE_SENT
    # State transition
    {'trigger': 'update', 'source': 'SUPPLICANT_AUTHENTICATION', 'dest': 'SUPPLICANT_ASSOCIATION',
     'conditions': 'received_association', 'after': 'update'},  # Transition Action
    # Retry transition
    {'trigger': 'retry', 'source': 'SUPPLICANT_AUTHENTICATION', 'dest': 'SUPPLICANT_AUTHENTICATION',
     'conditions': 'limit_retries'},  # Max retry conditions

    # ASSOC_RESPONSE_SENT -> EAP_IDENTITY OR
    # State transition
    {'trigger': 'update', 'source': 'SUPPLICANT_ASSOCIATION', 'dest': 'EAP_IDENTITY'},  # Transition Action

    # EAP_IDENTITY -> EAP_CHALLANGE
    # State transition
    {'trigger': 'update', 'source': 'EAP_IDENTITY', 'dest': 'EAP_CHALLANGE',
     'conditions': 'received_eap_identity'},  # Transition Action
    # EAP Rejection transition
    {'trigger': 'eap_reject', 'source': 'EAP_IDENTITY', 'dest': 'WAIT_AUTH_REQUEST',
     'before': 'send_eap_reject'},
    # Retry transition
    {'trigger': 'retry', 'source': 'EAP_IDENTITY', 'dest': 'EAP_IDENTITY',
     'conditions': 'limit_retries'},  # Max retry conditions

    # EAP_CHALLANGE -> EAP_ACCEPT
    # State transition
    {'trigger': 'update', 'source': 'EAP_CHALLANGE', 'dest': 'EAP_ACCEPT',
     'conditions': 'received_eap_complete', 'after': 'update'},  # Transition Action
    # EAP Rejection transition
    {'trigger': 'eap_reject', 'source': 'EAP_CHALLANGE', 'dest': 'WAIT_AUTH_REQUEST',
     'before': 'send_eap_reject'},

    # EAP_ACCEPTED -> WPA_HANDSHAKE_MSG_1
    # State transition
    {'trigger': 'update', 'source': 'EAP_ACCEPT', 'dest': 'WPA_HANDSHAKE_MSG_1'},  # Transition Action

    # WPA_HANDSHAKE_MSG_1 -> WPA_HANDSHAKE_MSG_3
    {'trigger': 'update', 'source': 'WPA_HANDSHAKE_MSG_1', 'dest': 'WPA_HANDSHAKE_MSG_3',
     'conditions': 'received_wpa_handshake_2'},
    # deauth received
    {'trigger': 'deauth_request', 'source': 'WPA_HANDSHAKE_MSG_1', 'dest': 'WAIT_AUTH_REQUEST'},
    # Retry transition
    {'trigger': 'retry', 'source': 'WPA_HANDSHAKE_MSG_1', 'dest': 'WPA_HANDSHAKE_MSG_1',
     'conditions': 'limit_retries'},  # Max retry conditions

    # WPA_HANDSHAKE_MSG_3 -> WPA_HANDSHAKE_COMPLETE
    {'trigger': 'update', 'source': 'WPA_HANDSHAKE_MSG_3', 'dest': 'WPA_HANDSHAKE_COMPLETE',
     'conditions': 'received_wpa_handshake_4', 'after': 'update'},
    {'trigger': 'disconnect_client', 'source': 'WPA_HANDSHAKE_MSG_3', 'dest': 'WAIT_AUTH_REQUEST',
     'before': 'send_deauth'},

    # WPA_HANDSHAKE_COMPLETE -> ANALYZE_DATA
    {'trigger': 'update', 'source': 'WPA_HANDSHAKE_COMPLETE', 'dest': 'ANALYZE_DATA'},

    # ANALYZE_DATA -> ANALYZE_DATA
    {'trigger': 'update', 'source': 'ANALYZE_DATA', 'dest': 'ANALYZE_DATA',
     'conditions': 'connected'},
    {'trigger': 'disconnect_client', 'source': 'ANALYZE_DATA', 'dest': 'WAIT_AUTH_REQUEST',
     'before': 'send_deauth'},
    {'trigger': 'deauth_request', 'source': 'ANALYZE_DATA', 'dest': 'WAIT_AUTH_REQUEST'},
]

states_fuzzer_config = {
    'WAIT_AUTH_REQUEST': StateConfig(
        states_expected=[Dot11Auth, Dot11Elt, Dot11EltRates, Dot11EltRSN, Dot11EltMicrosoftWPA,
                         Dot11EltVendorSpecific, Dot11Disas, Dot11ProbeReq, Dot11Deauth, DHCP, Dot11CCMP, Dot11TKIP,
                         ARP],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[Dot11EltRates, Dot11ProbeResp, Dot11EltRSN],
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
    'SUPPLICANT_AUTHENTICATION': StateConfig(
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
    'SUPPLICANT_ASSOCIATION': StateConfig(
        states_expected=[Dot11AssoResp, Dot11AssoReq, Dot11Elt, Dot11EltRates, Dot11EltRSN,
                         Dot11EltMicrosoftWPA()],
        fuzzable_layers=[Dot11EltRates, Dot11AssoResp, Dot11EltRSN],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['ID'], ['ID'], ['ID']],
        fuzzable_layers_mutators_lengths_chance=[40, 40, 40],
        fuzzable_action_transition=None),
    'EAP_IDENTITY': StateConfig(
        states_expected=[EAPOL, EAP, Dot11Deauth, Dot11Disas, Dot11AssoReq, DHCP, Dot11Auth, Dot11ProbeReq],
        fuzzable_layers=[EAP, EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['id'], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10],
        fuzzable_action_transition=None),
    'EAP_CHALLANGE': StateConfig(
        states_expected=[EAP_PWD, Dot11Deauth, EAP_PEAP, EAP_TTLS, EAP_TLS, Dot11Disas, Dot11AssoReq, DHCP, Dot11Auth],
        fuzzable_layers=[EAP_PWD, EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        # 30 for eap-peap  # 50  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_global_chance=15,  # 15 # 20
        fuzzable_layers_mutators_chance_per_layer=[50, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[30, 30],  # Probability for each field to be fuzzed
        # fuzzable_layers_mutators_exclude_fields=[['code', 'id', 'type', 'len', 'message_len', 'pwd_exch', 'L', 'M'],
        fuzzable_layers_mutators_exclude_fields=[[None],
                                                 [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],
        fuzzable_action_transition='WAIT_AUTH_REQUEST'),
    'EAP_ACCEPT': StateConfig(
        states_expected=[EAPOL, EAP, EAP_PWD, DHCP],
        fuzzable_layers=[EAP, EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 10 # 50 # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[['id'], [None]],
        fuzzable_layers_mutators_lengths_chance=[20, 20],
        fuzzable_action_transition=None),

    'WPA_HANDSHAKE_MSG_1': StateConfig(
        states_expected=[Dot11ProbeReq, EAPOL, EAP, Raw, Dot11Deauth, Dot11Disas, DHCP, Dot11Auth],
        fuzzable_layers=[EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 10 # 30  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10],
        fuzzable_action_transition=None),
    'WPA_HANDSHAKE_MSG_3': StateConfig(
        states_expected=[EAPOL, EAP, Raw, Dot11Deauth, Dot11Disas, Dot11Auth, DHCP],
        fuzzable_layers=[EAPOL],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 30 # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10],
        fuzzable_action_transition=None),
    'ANALYZE_DATA': StateConfig(
        states_expected=[Dot11TKIP, ARP, IPv6, IGMP, DHCP, IP, UDP, IPv6ExtHdrHopByHop, TCP, Dot11QoS, Dot11Deauth,
                         Dot11Disas,
                         Dot11Auth,
                         Dot11ProbeReq],
        fuzzable_layers=[Dot11ProbeResp, Dot11Elt, Dot11EltRSN, Dot11TKIP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom,
                                    SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=0,  # 45 # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[
            50,
            10,
            30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[
            50,
            30,
            30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[
            [
                'ID'],
            [
                'ID'],
            [
                'ID']],
        fuzzable_layers_mutators_lengths_chance=[
            20,
            20,
            20],
        fuzzable_action_transition=None),
}


# --------------------- Model Implementation ------------------------------------------


class DHCPOverWPA(DHCP_am):
    """Wrapper over DHCP_am to send and recv inside a WPA channel"""

    def __init__(self, send_func, **kwargs):
        super(DHCPOverWPA, self).__init__(**kwargs)
        self.send_function = send_func

    def sniff(self, *args, **kwargs):
        # Do not sniff, use a direct call to 'replay(pkt)' instead
        return


class Dot11Methods(object):
    # State machine variables
    machine = None
    iterations = 0
    idle_state = None
    crash_magic_word = 'WPA2 ENTERPRISE VERSION:'
    serialport_name = '/dev/ttyUSB*'
    serialport_baudrate = 115200
    config_file = 'wifi_ap_config.json'  # File to store model configuration
    stop_request = False
    monitor = None

    @add_state_features(Tags, Timeout)
    class CustomStateMachine(Machine):
        pass

    # ----------------- Custom Model declarations --------------------
    # Model configuration
    channel = 9
    ssid = "TEST_KRA"
    eap_username = 'matheus_garbelini'
    passphrase = "testtest"
    mac = "28:c6:3f:a8:af:c5"  # type: str
    interface_tx = "wlan1mon"  # interface for packet transmission
    interface_rx = "wlan1mon"  # interface for packet reception/sniff
    virtual_enable = True
    # virtual_shared_iface = 'eth0'
    virtual_shared_iface = 'wlan0'
    virtual_ip = '192.168.42.1'
    enable_fuzzing = False
    # driver options (if not using esp8266 for not supported drivers)
    driver_custom_name = 'RT2800USB'
    driver_custom_enable = False
    driver_custom_instance = None

    # Model local variables
    pkt = None
    last_pkt = None
    pkt_received = False
    client = None
    seq_num = count()
    replay_counter = count(0)
    time_handshake_end = None
    debug_pkt = False
    pkt_retry_count = 0
    RSN = None
    last_deauth_time = 0
    deauth_time_interval = 10.0
    global_timer = None
    crash_detection_timer = None
    boot_time = time()
    aid = count(1)
    mutex = threading.Lock()
    arp_target_ip = None
    arp_source_ip = None
    virtual_iface = None
    client_connected = False
    base_pkt_dot11_wpa = Dot11(FCfield="from-DS+protected")  # Pre allocate Dot11 Packet
    base_pkt_radiotap = '\x00\x00\x08\x00\x00\x00\x00\x00'
    client_ever_connected = False

    # Key vars
    last_iv = None
    group_iv = count(0)
    client_iv = None
    pmk = None
    ptk = None
    anonce = None
    kck = None
    kek = None
    tk = None
    mic_ap_to_sta = None
    mic_sta_to_ap = None
    gtk_full = None
    gtk = None
    mic_ap_to_group = None
    client_mic = None
    client_data = None

    # Test Vulnaribility
    krack_enable = False
    krack_interval = 3.0
    krack_time = 0
    # ------------------
    # ARP Request and GTK rekeying
    gtk_rekeying_enable = False
    gtk_rekeying_request_interval = 1.0
    gtk_rekeying_interval = 10.0
    gtk_rekeying_request_time = 0
    gtk_rekeying_time = 0
    gtk_rekeying_renewed = False

    # Enable EAP WPA-802.1X authentication before 4 way handshake
    eap_enable = False
    eap_success = False
    eap_pkt = None

    def stop(self):
        self.stop_request = True  # Stop main sniff thread
        self.monitor.stop_request = True  # stop monitor thread
        if self.driver_custom_enable:
            self.driver_custom_instance.close()
        self.virtual_iface.close()  # Close virtual iface thread
        while self.virtual_iface.is_alive() is True:
            sleep(0.1)
        sleep(1)
        del self.virtual_iface
        del self.monitor

    def __init__(self, machine_states, machine_transitions, driver_custom=None,
                 machine_initial_state='INIT',
                 machine_show_all_transitions=False,
                 idle_state=None,
                 crash_magic_word=None,
                 serialport_name=None,
                 serialport_baudrate=None,
                 enable_fuzzing=None,
                 enable_duplication=None):

        self.load_config()

        if crash_magic_word is not None:
            self.crash_magic_word = crash_magic_word

        if serialport_name is not None:
            self.serialport_name = serialport_name

        if serialport_baudrate is not None:
            self.serialport_baudrate = serialport_baudrate

        if idle_state is not None:
            self.idle_state = idle_state

        if driver_custom is not None:
            self.driver_custom_name = driver_custom

        if enable_fuzzing is not None:
            self.enable_fuzzing = enable_fuzzing

        if enable_duplication is not None:
            self.enable_duplication = enable_duplication

        colorama_init(autoreset=True)  # Colors autoreset

        # Configure virtual interface
        self.virtual_iface = TunInterface(self.send_ethernet_over_wifi, self.virtual_ip,
                                          name=self.ssid, enable_dns=True)
        self.virtual_iface.start()
        if self.virtual_shared_iface:
            self.virtual_iface.share_internet(self.virtual_shared_iface)

        # Configure virtual DHCP server
        ip_array = self.virtual_ip.split('.')
        ip_array[3] = str(0)  # Clear the last ip part (192.168.42.1 -> 192.168.42.0)
        dhcp_ip_array = ".".join(ip_array)
        self.dhcp_server = DHCPOverWPA(self.send_ethernet_over_wifi,
                                       pool=Net(dhcp_ip_array + '/25'),
                                       network=dhcp_ip_array + '/24',
                                       gw=self.virtual_ip)
        self.arp_source_ip = self.virtual_ip
        print(Fore.CYAN + 'DHCP Server started for ' + Fore.YELLOW + self.arp_source_ip)

        # Configure RADIUS (freeradius) server
        eap_freeradius_bridge.setup(self.eap_username, self.passphrase)

        # Configure custom driver if enabled
        if self.driver_custom_name is not None:
            _driver = eval(self.driver_custom_name + 'Netlink()')
            self.driver_custom_instance = _driver
            self.driver_custom_enable = True
            print(Fore.CYAN + "Custom Wi-Fi driver selected: " + Fore.YELLOW + self.driver_custom_name)

        # Configure Master key if pre-shared authentication is used
        if self.eap_enable is False:
            self.install_PMK()
            print(Fore.YELLOW + 'Pairwise Master Key (PMK) generated: ' + hexlify(self.pmk).upper())
        else:
            print(Fore.YELLOW + 'Pairwise Master Key (PMK) will be generated after EAP exchange')

        # Configure Wi-Fi interface and channel
        if 'mon' in self.interface_tx:
            ifc = self.interface_tx.split('mon')[0]
            set_monitor_mode(ifc)
        os.system("iwconfig " + self.interface_tx + " channel " + str((self.channel + 1) % 14))
        os.system("iwconfig " + self.interface_rx + " channel " + str((self.channel + 1) % 14))
        os.system("iwconfig " + self.interface_tx + " channel " + str(self.channel))
        os.system("iwconfig " + self.interface_rx + " channel " + str(self.channel))
        print(Fore.CYAN + 'Interface ' + str(self.interface_tx) + ' set to channel ' + str(self.channel))

        # Initialize state machine instance
        conf.verb = 0
        SetFuzzerConfig(states_fuzzer_config)
        self.machine = GreyhoundStateMachine(states=machine_states,
                                             transitions=machine_transitions,
                                             print_transitions=True,
                                             print_timeout=True,
                                             initial='INIT',
                                             idle_state='WAIT_AUTH_REQUEST',
                                             show_conditions=False,
                                             show_state_attributes=False,
                                             enable_webserver=True)

        # Used for any serial device
        if self.serialport_name:
            self.monitor = Monitor(self.serialport_name, self.serialport_baudrate, magic_string=self.crash_magic_word,
                                   user_callback=self.monitor_crash_detected)

        print(Fore.GREEN + 'Fuzzer Access Point started. Waiting for client..')
        self.start_timeout('global_timer', 8, self.global_timeout)

    def get_config(self):
        obj = {'SSID': self.ssid,
               'Password': self.passphrase,
               'Username': self.eap_username,
               'EAP': self.eap_enable,
               'Channel': self.channel,
               'MAC': self.mac,
               'GatewayIP': self.virtual_ip,
               'CustomDriverName': self.driver_custom_name,
               'FuzzingInterface': self.interface_tx,
               'ShareInternet': self.virtual_enable,
               'ShareInterface': self.virtual_shared_iface,
               'SerialPortName': self.serialport_name,
               'SerialPortBaud': str(self.serialport_baudrate),
               'CrashDetectionWord': self.crash_magic_word,
               'EnableFuzzing': self.enable_fuzzing,
               'EnableDuplication': self.enable_duplication,
               }
        return json.dumps(obj, indent=4)

    def global_timeout(self):
        self.client_connected = False
        self.to_WAIT_AUTH_REQUEST()
        print(Fore.YELLOW + "Global Timeout !!!")
        self.start_timeout('global_timer', 8, self.global_timeout)

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

    def set_config(self, data):
        self.ssid = data['SSID']
        self.passphrase = data['Password']
        self.eap_username = data['Username']
        self.eap_enable = data['EAP']
        self.channel = int(data['Channel'])
        self.mac = data['MAC']
        self.virtual_ip = data['GatewayIP']
        self.driver_custom_name = data['CustomDriverName']
        self.interface_tx = data['FuzzingInterface']
        self.virtual_enable = bool(data['ShareInternet'])
        self.virtual_shared_iface = data['ShareInterface']
        self.serialport_name = data['SerialPortName']
        self.serialport_baudrate = int(data['SerialPortBaud'])
        self.crash_magic_word = data['CrashDetectionWord']
        self.enable_fuzzing = bool(data['EnableFuzzing'])
        self.enable_duplication = bool(data['EnableDuplication'])

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

    # --------------- Scapy send and sniff function wrappers ---------------------------
    @staticmethod
    def send_duplicated(cls, method, state):
        # Execute method to repeat state
        if method.co_argcount == 1:  # Only execute methods with 1 argument (cls)
            fuzzing.last_mirror_packet = method.co_name
            getattr(cls, method.co_name)()
            print(Fore.BLUE + 'Repeated State: ' + Fore.LIGHTYELLOW_EX + state + Fore.BLUE +
                  ', Method: ' + Fore.MAGENTA + method.co_name)

    def send(self, pkt):
        pkt.SC = (next(self.seq_num) << 4) % 4096

        beacon = False
        if pkt.addr1 == 'ff:ff:ff:ff:ff:ff':
            beacon = True
        if self.enable_fuzzing:
            if self.client is None:
                fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)
            elif beacon or pkt.addr1 == self.client:  # Reject frames not from the client
                fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)

        if pkt.type != 0 or pkt.subtype != 8 and ((self.client_connected is False) or (pkt.addr2 == self.client)):
            print(Fore.CYAN + "TX ---> " + pkt.summary())

        # Encrypt data packet if client is connect (after 4-Way Handshake)
        if self.client_connected and pkt.type == 2:
            pkt = self.encrypt_packet(pkt)

        if self.driver_custom_enable is False:
            sendp(RadioTap() / pkt, iface=self.interface_tx)
        else:  # use custom driver to send packets
            self.machine.add_packets(RadioTap() / Dot11(raw(pkt)))
            data = self.base_pkt_radiotap + raw(pkt)  # RadioTap + 802.11 frame
            self.driver_custom_instance.send_data(data)
            if not beacon and (Dot11Deauth not in pkt) and (Dot11Disas not in pkt) and self.enable_duplication:
                fuzzing.repeat_packet(self)

    def send_ethernet_over_wifi(self, pkt):
        """Send an Ethernet packet using the WPA channel
        Extra arguments will be ignored, and are just left for compatibility
        """

        if self.client_connected:
            payload = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac) / LLC() / SNAP() / pkt[IP]
            self.send(payload)

    def sniff(self):
        if not self.driver_custom_enable:
            try:
                sniff(iface=self.interface_rx, prn=self.receive_packet, filter="(wlan addr1 " + self.mac + ")")
            except KeyboardInterrupt:
                sys.exit()
        else:
            conf.sniff_promisc = False
            self.driver_custom_instance.set_mac(self.mac)
            self.driver_custom_instance.set_filter_unicast()
            # self.driver_custom_instance.set_filter_sniffer()
            self.driver_custom_instance.set_flags_enable(1)
            self.driver_custom_instance.set_flags_retry(1)
            self.driver_custom_instance.set_interrupt_rx_enable()
            try:
                while self.stop_request is False:
                    self.receive_packet(Dot11(self.driver_custom_instance.raw_receive()))
            except KeyboardInterrupt:
                sys.exit()
            print(Fore.RED + 'Model process stopped' + Fore.RESET)

    # ------------------------ MONITOR Callback -----------------------------------------------

    def monitor_crash_detected(self):
        message = 'CRASH DETECTED in state ' + self.state
        print(Fore.RED + '[CRASH] !!!!!!!!!! ' + message + ' !!!!!!!!!!!!')
        if self.idle_state != None and fuzzing.last_fuzzed_packet != None:
            # message = 'CRASH by ' + fuzzing.last_fuzzed_packet.summary()
            #
            # fitness.AnomalyDetected(self.state, None, message)  # Increment issue counter
            # print(Fore.RED + '[STATE] Reseting fuzzer to state ' + self.state + ' -> ' + self.idle_state)
            # getattr(self, 'to_' + self.idle_state)()  # Call transition to go to idle state after crash
            self.warnings += 1
            self.client_connected = False
            self.machine.report_crash()
            self.machine.reset_machine()

        # send_vulnerability(self.warnings, message, error=True)

    # ----------------------- MISC ------------------------------------------------------------

    def iteration(self):

        if self.iterations > 0:
            self.last_deauth_time = self.current_timestamp()
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

    def transition(self):
        self.update_timeout('global_timer')
        self.update_timeout('crash_detection_timer')
        fitness.Transition()

    def current_timestamp_us(self):
        return (time() - self.boot_time) * 1000000

    def current_timestamp(self):
        return time() - self.boot_time

    def setup_eap_transitions(self, eap_enable):
        if eap_enable is False:
            self.machine.remove_transition('update', source='SUPPLICANT_ASSOCIATION', dest='EAP_IDENTITY')
            self.machine.remove_transition('update', source='EAP_ACCEPT', dest='WPA_HANDSHAKE_MSG_1')
            self.machine.remove_transition('eap_reject', source='*', dest='*')
            self.machine.remove_transition('deauth_request', source='EAP', dest='*')
            self.machine.remove_transition('deauth_request', source='EAP_IDENTITY', dest='*')
            self.machine.remove_transition('disconnect_client', source='EAP_IDENTITY', dest='*')
            self.machine.remove_transition('timeout_max', source='EAP', dest='*')
            self.machine.add_transition('update', 'SUPPLICANT_ASSOCIATION', 'WPA_HANDSHAKE_MSG_1')

        else:
            self.machine.remove_transition('update', source='SUPPLICANT_ASSOCIATION', dest='WPA_HANDSHAKE_MSG_1')
            self.machine.add_transition('update', 'SUPPLICANT_ASSOCIATION', 'EAP_IDENTITY')
        self.eap_enable = eap_enable

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
            print('Received IV: ' + str(iv))
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
                data_decrypted = check_MIC_ICV(data, self.mic_sta_to_ap, pkt.addr2,
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

    # --------------- Packet receiving/sending functions ---------------------------

    def received_authentication(self):
        if not self.pkt_received:
            return False

        if EAPOL in self.pkt or ARP in self.pkt:
            self.send_deauth()
            Z

        if self.pkt[Dot11].FCfield.retry:
            return

        if Dot11Deauth in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac:
            return False

        if Dot11Auth in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac:
            print(Fore.YELLOW + '[!] Authentication from ' + self.pkt.addr2.upper())
            return True

    def send_auth_response(self):
        if self.pkt.haslayer(Dot11Auth):
            self.client = self.pkt.addr2

            rep = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac, SC=((next(self.seq_num) + 1) << 4) % 4096)
            rep /= Dot11Auth(seqnum=2, algo=self.pkt[Dot11Auth].algo,  # Open authentication (0)
                             status=self.pkt[Dot11Auth].status)

            self.send(rep)

    def received_association(self):
        if not self.pkt_received:
            return False

        if Dot11AssoReq in self.pkt or Dot11ReassoReq in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac and \
                self.pkt[Dot11Elt::{'ID': 0}].info == self.ssid:
            print(Fore.YELLOW + '[!] Association')

            try:
                temp_pkt = self.pkt[Dot11Elt::{"ID": 48}].copy()
                temp_pkt.remove_payload()
                self.RSN = raw(temp_pkt)
                # Avoid 802.11w, etc. (deactivate RSN capabilities)
                self.RSN = self.RSN[:-2] + "\x00\x00"
            except:
                pass

            return True

        return False

    def send_assoc_response(self):
        # Get RSN info

        rep = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac)
        rep /= Dot11AssoResp(cap=0x2104, AID=next(self.aid))
        rep /= Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36])

        self.send(rep)

    def send_eap_request_identity(self):
        print('EAP Request Identity sent')
        rep = Dot11(
            type='Data',
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS',
            subtype=8
        )
        rep /= Dot11QoS(TID=6)
        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= EAPOL(version="802.1X-2004", type="EAP-Packet")
        rep /= EAP(code='Request', id=1, type="Identity")

        self.send(rep)

    def received_eap_identity(self):
        if not self.pkt_received:
            return False

        if Dot11Deauth in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac:
            self.deauth_request()
            return False

        if EAP in self.pkt:
            try:
                eap_pkt = eap_freeradius_bridge.radius_send_eap_request(self.pkt[EAP])

                if EAP in eap_pkt:

                    if eap_pkt[EAP].code == EAP.REQUEST:
                        print('EAP Identity received as ' + self.pkt[EAP].identity)
                        self.eap_pkt = eap_pkt
                        return True
                    elif eap_pkt[EAP].code == EAP.FAILURE:
                        print('EAP Rejection ')
                        self.eap_pkt = eap_pkt
                        self.eap_reject()
                elif self.pkt[EAPOL].type == 0x01:  # EAPoL Start
                    pass
            except:
                pass

        return False

    def send_eap_request(self):
        self.send_eap_packet(self.eap_pkt)

    def received_eap_complete(self):
        if not self.pkt_received:
            return False

        if Dot11Deauth in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac:
            return False

        if EAP in self.pkt:
            print('EAP response received')
            eap_pkt = eap_freeradius_bridge.radius_send_eap_request(self.pkt[EAP])

            if EAP in eap_pkt:

                if eap_pkt[EAP].code == EAP.SUCCESS:
                    # MSK = MasterReceiveKey + MasterSendKey + 32 bytes zeroes (padding)
                    # PMK = First 32 bytes of MSK
                    # MS-MPPE-Recv-Key      = MasterSendKey
                    # MS-MPPE-Send-Key      = MasterReceiveKey
                    self.pmk = eap_freeradius_bridge.radius_mppe_msk()[:32]
                    self.eap_pkt = eap_pkt
                    # print('EAP client authorized')
                    print(Fore.GREEN + '[!] Received PMK from Radius: ' + hexlify(self.pmk).upper())
                    return True

                elif eap_pkt[EAP].code == EAP.FAILURE:
                    # print('EAP Rejection ')
                    self.eap_pkt = eap_pkt
                    self.eap_reject()
                    return False

                self.send_eap_packet(eap_pkt)
                # print('EAP Challange sent')

        return False

    def send_eap_accept(self):
        self.send_eap_packet(self.eap_pkt)

    def send_eap_reject(self):
        # self.send_eap_packet(self.eap_pkt)
        rep = Dot11(
            type='Data',
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS',
            subtype=8
        )
        rep /= Dot11QoS(TID=6)
        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= EAPOL(version="802.1X-2004", type="EAP-Packet")
        rep /= EAP(code='Failure', id=5)
        self.send(rep)

    def send_wpa_handshake_1(self):

        self.anonce = self.gen_nonce(32)
        self.replay_counter = count(0)
        print(Fore.YELLOW + '[!] Handshake 1')

        rep = Dot11(
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS',
        )
        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= self.build_EAPOL_Key_8021X2004(
            key_information=0x89,
            replay_counter=next(self.replay_counter),
            nonce=self.anonce,
        )
        self.send(rep)

    def received_wpa_handshake_2(self):
        if not self.pkt_received:
            return False

        if self.pkt[Dot11].FCfield.retry:
            return False

        if Dot11AssoReq in self.pkt:
            self.send_assoc_response()
            self.send_wpa_handshake_1()

        if Dot11ReassoReq in self.pkt:
            rep = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac)
            rep /= Dot11ReassoResp()
            rep /= Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36])
            self.send(rep)
            self.send_wpa_handshake_1()

        if Dot11Deauth in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac:
            print(Fore.YELLOW + "[!] Deauth received")
            self.deauth_request()
            return False

        if EAPOL_KEY in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac:
            # Key MIC: set, Secure / Error / Request / Encrypted / SMK
            print(Fore.YELLOW + '[!] Handshake 2')
            client_nonce = self.pkt[EAPOL_KEY].wpa_key_nonce
            self.install_unicast_keys(client_nonce)

            # Check client MIC
            # Data: full message with MIC place replaced by 0s
            client_mic = self.pkt[EAPOL_KEY].key_mic
            client_data = raw(self.pkt[EAPOL]).replace(client_mic, "\x00" * len(client_mic))  # noqa: E501

            if hmac.new(self.kck, client_data, hashlib.md5).digest() == client_mic:  # noqa: E501
                self.client_mic = client_mic
                self.client_data = client_data
                self.last_iv = None
                if self.pmk == '\x00' * 32:
                    print(Fore.RED + '[!] OOOPS, client installed zero Pairwise Master Key (PMK)')
                return True
            else:
                print(Fore.RED + '[!] Client MIC invalid')
                self.client_mic = client_mic
                self.client_data = client_data
                self.last_iv = None
                self.client_connected = False
                print(hexlify(client_mic))
                self.send_deauth()
                self.deauth_request()

            return False

    def send_wpa_handshake_3(self):
        rep = Dot11(
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS'
        )

        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication

        self.install_GTK()
        data = raw(self.build_RSN())
        data += self.build_GTK_KDE()
        eap = self.build_EAPOL_Key_8021X2004(
            key_information=0x13c9,  # MIC flag set
            # key_information=0x12C9,  # MIC flag not set
            replay_counter=next(self.replay_counter),
            nonce=self.anonce,
            data=data,
            key_mic=self.kck,
            key_data_encrypt=self.kek,
        )
        # Send copy of message 3
        rep = rep / eap
        self.send(rep)
        print(Fore.YELLOW + "[!] Message 3 sent")

    def received_wpa_handshake_4(self):

        if Dot11Disas in self.pkt:
            print(Fore.YELLOW + "[!] Disassociation received")
            self.client_connected = False
            self.deauth_request()
            return False
        try:
            if EAPOL_KEY in self.pkt and self.pkt.addr1 == self.pkt.addr3 == self.mac and \
                    self.pkt[EAPOL_KEY].key_iv == '\x00' * 16:
                print(Fore.GREEN + '[!] Message 4 received, encryption completed!!!')
                self.client_connected = True
                return True
        except:
            pass

        return False

    def connected(self):
        pkt = self.pkt
        if Dot11Deauth in pkt:
            print(Fore.YELLOW + "[!] Deauth received")
            self.client_connected = False
            self.deauth_request()

        if Dot11Auth in pkt or Dot11Disas in pkt:
            self.client_connected = False
            print(Fore.YELLOW + "[!] Disconnection identified")
            self.disconnect_client()

        # Skip retries
        if pkt[Dot11].FCfield.retry:
            return
        # LLC / SNAP to Ether
        if SNAP in pkt:
            ether_pkt = Ether(src=self.client, dst=self.mac) / pkt[SNAP].payload  # noqa: E501
            self.dhcp_server.reply(ether_pkt)

            if not self.client_connected:
                self.gtk_rekeying_request_time = self.current_timestamp()
                self.gtk_rekeying_time = self.current_timestamp()
                self.krack_time = self.current_timestamp()

            self.client_connected = True

            if IP in pkt:
                self.virtual_iface.write(pkt)

        # If an ARP request is made, extract client IP and answer

        if ARP in pkt:
            # op 1 is "who-has"
            if pkt[ARP].op == 1 and pkt[ARP].pdst == self.dhcp_server.gw:
                if self.arp_target_ip is None:
                    self.arp_target_ip = pkt[ARP].psrc
                    print(Fore.GREEN + "ARP - Detected IP: " + self.arp_target_ip)
                # Reply
                ARP_ans = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac) / LLC() / SNAP() / ARP(
                    op="is-at",
                    psrc=self.arp_source_ip,
                    pdst=self.arp_target_ip,
                    hwsrc=self.mac,
                    hwdst=self.client,
                )
                self.send(ARP_ans)
            # op 2 is "is-at"
            elif pkt[ARP].op == 2 and pkt[ARP].pdst == self.dhcp_server.gw:

                # Check ARP received from client
                # print("Received IV: " + str(
                #     self.pkt.TSC0 | (self.pkt.TSC1 << 8) | (self.pkt.TSC2 << 16) | (self.pkt.TSC3 << 24) |
                #     (self.pkt.TSC4 << 32) | (self.pkt.TSC5 << 40)))
                if self.gtk_rekeying_renewed:
                    print(Fore.RED + "GTK Reinstallation (CVE-2017-13080)")
                    self.send_vulnerability(1, 'GTK Reinstallation (CVE-2017-13080) detected')
                    self.gtk_rekeying_renewed = False

    def send_renew_gtk(self):
        # 802.1X Authentication
        rep_to_enc = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac) / \
                     LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
                     SNAP(OUI=0, code=0x888e)

        eap = self.build_EAPOL_Key_8021X2004(
            # Key information 0x1381:
            #   ARC4 HMAC-MD5, Group Key, KEY ACK, KEY MIC, Secure, Encrypted,
            #   SMK
            key_information=0x1381,
            # key_information=0x1281,
            replay_counter=next(self.replay_counter),
            nonce=self.anonce,
            data=self.build_GTK_KDE(),
            key_mic=self.kck,
            key_data_encrypt=self.kek,
        )

        self.send(rep_to_enc / eap)

    def send_arp_request(self):
        self.arp_target_ip = self.dhcp_server.leases.get(self.client,
                                                         self.arp_target_ip)  # noqa: E501
        if self.arp_target_ip is None:
            return

        # Send the first ARP requests, for control test
        rep = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=self.mac, addr3=self.mac) / \
              LLC() / SNAP() / ARP(op="who-has",
                                   psrc=self.arp_source_ip,
                                   pdst=self.arp_target_ip,
                                   hwsrc=self.mac)

        self.send(rep)

    def build_RSN(self):
        if self.eap_enable:
            suite_v = 0x01
        else:
            suite_v = 0x02
        return Dot11EltRSN(group_cipher_suite=RSNCipherSuite(cipher=0x2),
                           pairwise_cipher_suites=[RSNCipherSuite(cipher=0x2)],
                           akm_suites=[AKMSuite(suite=suite_v)])

    def build_ap_info_pkt(self, layer_cls, dest):
        """Build a packet with info describing the current AP
        For beacon / proberesp use
        """
        name = Dot11Elt(ID="SSID", info=self.ssid)

        return Dot11(addr1=dest, addr2=self.mac, addr3=self.mac, SC=0) \
               / layer_cls(timestamp=self.current_timestamp_us(), beacon_interval=100,
                           cap='ESS+privacy') \
               / name \
               / Dot11EltRates(rates=[130, 132, 139, 150, 12, 18, 24, 36]) \
               / Dot11Elt(ID="DSset", info=chb(self.channel)) \
               / self.build_RSN()
        # akm_suites=[AKMSuite(suite=0x2)])

        # / Dot11(addr1=dest, addr2=self.mac, addr3=self.mac, SC=(next(self.seq_num))) \

    # / layer_cls(timestamp=self.current_timestamp(), beacon_interval=100,

    @staticmethod
    def build_EAPOL_Key_8021X2004(
            key_information,
            replay_counter,
            nonce,
            data=None,
            key_mic=None,
            key_data_encrypt=None,
            key_rsc=0,
            key_id=0,
            key_descriptor_type=2,  # EAPOL RSN Key
    ):
        pkt = EAPOL(version="802.1X-2004", type="EAPOL-Key")

        key_iv = Dot11Methods.gen_nonce(16)

        payload = b"".join([
            chb(key_descriptor_type),
            struct.pack(">H", key_information),
            b'\x00\x20',  # Key length
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
            return pkt / Raw(load=payload)

        # Skip 256 first bytes
        # REF: 802.11i 8.5.2
        # Key Descriptor Version 1:
        # ...
        # No padding shall be used. The encryption key is generated by
        # concatenating the EAPOL-Key IV field and the KEK. The first 256 octets  # noqa: E501
        # of the RC4 key stream shall be discarded following RC4 stream cipher
        # initialization with the KEK, and encryption begins using the 257th key  # noqa: E501
        # stream octet.
        enc_data = ARC4_encrypt(key_iv + key_data_encrypt, data, skip=256)

        payload += struct.pack(">H", len(data))
        payload += enc_data

        # Compute MIC and set at the right place
        temp_mic = pkt.copy()
        temp_mic /= Raw(load=payload)
        to_mic = raw(temp_mic[EAPOL])
        mic = hmac.new(key_mic, to_mic, hashlib.md5).digest()
        final_payload = payload[:offset_MIC] + mic + payload[offset_MIC + len(mic):]  # noqa: E501
        assert len(final_payload) == len(payload)

        return pkt / Raw(load=final_payload)

    def install_PMK(self):
        """Compute and install the PMK"""
        self.pmk = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,
            salt=self.ssid.encode(),
            iterations=4096,
            backend=default_backend(),
        ).derive(self.passphrase.encode())

    def install_unicast_keys(self, client_nonce):
        """Use the client nonce @client_nonce to compute and install
        PTK, KCK, KEK, TK, MIC (AP -> STA), MIC (STA -> AP)
        """
        pmk = self.pmk
        anonce = self.anonce
        snonce = client_nonce
        amac = hex_bytes(self.mac.replace(":", ""))
        smac = hex_bytes(self.client.replace(":", ""))

        # Compute PTK
        self.ptk = customPRF512(pmk, amac, smac, anonce, snonce)

        # Extract derivated keys
        self.kck = self.ptk[:16]
        self.kek = self.ptk[16:32]
        self.tk = self.ptk[32:48]
        self.mic_ap_to_sta = self.ptk[48:56]
        self.mic_sta_to_ap = self.ptk[56:64]

        # Reset IV
        self.client_iv = count()

    def install_GTK(self):
        """Compute a new GTK and install it alongs
        MIC (AP -> Group = broadcast + multicast)
        """

        # Compute GTK
        self.gtk_full = self.gen_nonce(32)
        self.gtk = self.gtk_full[:16]

        # Extract derivated keys
        self.mic_ap_to_group = self.gtk_full[16:24]

        # Reset IV
        self.group_iv = count(0)

    def build_GTK_KDE(self):
        """Build the Key Data Encapsulation for GTK
        KeyID: 0
        Ref: 802.11i p81
        """
        return b''.join([
            b'\xdd',  # Type KDE
            chb(len(self.gtk_full) + 6),
            b'\x00\x0f\xac',  # OUI
            b'\x01',  # GTK KDE
            b'\x00\x00',  # KeyID - Tx - Reserved x2
            self.gtk_full,
        ])

    def send_AP_beacon_continuous(self):
        if self.stop_request is False:
            threading.Timer(0.1, self.send_AP_beacon_continuous).start()

        rep = self.build_ap_info_pkt(Dot11Beacon, dest="ff:ff:ff:ff:ff:ff")
        self.send(rep)

        c_time = self.current_timestamp()

        if self.client and self.state is 'WAIT_AUTH_REQUEST' and (
                c_time - self.last_deauth_time) >= self.deauth_time_interval:
            print(Fore.YELLOW + 'Forcing deauth on ' + self.client)
            self.last_deauth_time = c_time
            self.send_deauth()

        if self.client_connected and self.krack_enable and ((c_time - self.krack_time) > self.krack_interval):
            self.krack_time = c_time
            self.send_wpa_handshake_3()
            print('Message 3 replayed')

        if self.client_connected and self.gtk_rekeying_enable and (
                (c_time - self.gtk_rekeying_request_time) > self.gtk_rekeying_request_interval):

            self.gtk_rekeying_request_time = c_time
            print("> 1) ARP Request sent")
            self.send_arp_request()

            if (c_time - self.gtk_rekeying_time) > self.gtk_rekeying_interval:
                self.gtk_rekeying_time = c_time
                # reset group IV key (test for broadcast replies)
                if self.krack_enable is False:
                    self.send_renew_gtk()
                self.group_iv = count(0)
                self.gtk_rekeying_renewed = True
                self.gtk_rekeying_request_time += 3.0
                print(">> 2) Group IV reset")

        return

    @staticmethod
    def gen_nonce(size):
        """Return a nonce of @size element of random bytes as a string"""
        return raw(RandBin(size))

    warnings = 0

    def fitness(self, pkt):
        # Only calculate fitness of unicast functions
        if pkt.type == 2 and pkt.subtype == 0x04:
            return False  # discart Null Data frames

        if pkt.addr1 != 'ff:ff:ff:ff:ff:ff':

            if self.client and (pkt.addr2 != self.client):  # Reject frames not from the client
                return False
            elif pkt.addr1 != self.mac:
                return

            if EAP in pkt:
                if pkt[EAP].type == 0x03 or pkt[EAP].type == 0x01:
                    return False  # discart Nack EAP frames

            if fitness.Validate(pkt, self.state, states_fuzzer_config):
                return True
            else:
                # pkt_summary = pkt.summary()
                # message = '[TRIGGER] INCONSISTENCY DETECTED, Received ' + pkt_summary + \
                #           ' in state ' + self.state + '. Session saved!'
                # print(Fore.RED + message)
                # fitness.AnomalyDetected(self.state, pkt, pkt_summary)  # Increment issue counter
                # self.send_vulnerability(self.warnings, message)
                self.machine.report_anomaly(pkt=pkt)
                self.warnings += 1

                return True
        return False

    def receive_packet(self, pkt):
        print_lines = False
        self.machine.add_packets(RadioTap() / pkt)
        if self.client_connected:
            pkt = self.decrypt_packet(pkt)

        if self.state is 'WAIT_AUTH_REQUEST' and EAPOL in pkt and pkt[EAPOL].type == 0x1:
            pass
        elif pkt.subtype == 15 or pkt.subtype == 13:
            pass
        else:
            self.fitness(pkt)

        if ((self.client_connected is False) or (pkt.addr2 == self.client)) and (
                pkt.type != 0x02 or pkt.subtype != 0x04) and Dot11Beacon not in pkt and Dot11ProbeReq not in pkt:
            print_lines = True
            print(Fore.BLUE + "State:" + Fore.LIGHTCYAN_EX + self.state + Fore.LIGHTCYAN_EX)
            print(Fore.CYAN + "RX <--- " + pkt.summary())

        self.pkt_received = True
        self.pkt = pkt
        try:
            self.update()
        except:
            pass
        self.pkt_received = False
        # Handle probe requests
        if Dot11ProbeReq in pkt and (pkt[Dot11Elt].info == self.ssid or pkt[Dot11Elt].info == ''):
            rep = self.build_ap_info_pkt(Dot11ProbeResp, dest=pkt.addr2)
            self.send(rep)
            if print_lines:
                print(Fore.YELLOW + '[!] Probe sent to ' + str(pkt.addr2).upper())

        if print_lines:
            print('----------------------------')

    def limit_retries(self):
        # just 1 retry
        if self.pkt_retry_count >= 1:
            self.pkt_retry_count = 0
            print('timeout_max')
            self.timeout_max()

            return False
        print('retries count: ' + str(self.pkt_retry_count))
        self.pkt_retry_count += 1

        return True

    def send_deauth(self):
        self.client_connected = False
        self.last_iv = None
        self.group_iv = count(0)
        self.gtk_rekeying_renewed = False
        self.eap_success = False

        if self.client:
            rep = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac) / Dot11Disas()
            self.send(rep)
            rep = Dot11(addr1=self.client, addr2=self.mac, addr3=self.mac) / Dot11Deauth()
            self.send(rep)
            print(Fore.YELLOW + 'Deauth sent' + Fore.RESET)

    # Not used (hardware handles this)
    def send_ack(self, dest):
        rep = Dot11(type='Control', subtype=0x1D, addr1=dest)
        self.send(rep)

    # EAP Handling
    def send_eap_packet(self, data):
        rep = Dot11(
            addr1=self.client,
            addr2=self.mac,
            addr3=self.mac,
            FCfield='from-DS'
        )

        rep /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        rep /= SNAP(OUI=0, code=0x888e)  # 802.1X Authentication
        rep /= EAPOL(version="802.1X-2004", type="EAP-Packet")
        rep /= data[EAP]
        self.send(rep)


wifi_machine = Dot11Methods(states, transitions,
                            machine_show_all_transitions=False,
                            idle_state='WAIT_AUTH_REQUEST')
wifi_machine.setup_eap_transitions(wifi_machine.eap_enable)
wifi_machine.get_graph().draw('wifi/wifi_diagram.png', prog='dot')  # Save the whole graph ...
wifi_machine.init()
wifi_machine.sniff()
