import sys
import os, signal

# Add libs to python path
sys.path.insert(0, os.getcwd() + '/libs')

from binascii import hexlify, unhexlify
from wdissector import \
    Machine, wd_init, wd_field, wd_filter, wd_read_filter, wd_register_filter, packet_read_field_uint64, \
    wd_register_field, wd_packet_dissect, wd_packet_dissectors, wd_packet_layers_count, wd_read_field, \
    wd_packet_show, wd_packet_show_pdml, wd_info_profile, wd_packet_summary, packet_read_value_to_string, \
    wd_set_packet_direction, wd_set_dissection_mode, packet_read_field_string, packet_read_field_display_name, \
    WD_DIR_TX, WD_DIR_RX, WD_MODE_NORMAL, WD_MODE_FAST, WD_MODE_FULL, wd_set_log_level, WD_LOG_LEVEL_DEBUG
from scapy.utils import rdpcap
from scapy.packet import raw
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from colorama import Fore, Back, Style
import colorama

# from libs.NRF52_dongle import NRF52Dongle, NRF52_USB_VALID_PORTS_DESC
from NRF52_pcap2 import NRF52Pcap
from timeout_lib import start_timeout, disable_timeout, update_timeout
# from WDPacket import ValidatePacket

# ------------------ Sample Packets ------------------
pkts = rdpcap("Captures/capture_dialog_DA14680_truncated_l2cap_crash.pcap")

interesting_pkts = []
interesting_pkts.append((WD_DIR_TX, pkts[58]))
interesting_pkts.append((WD_DIR_RX, pkts[60]))
interesting_pkts.append((WD_DIR_TX, pkts[64]))
interesting_pkts.append((WD_DIR_RX, pkts[66]))
interesting_pkts.append((WD_DIR_TX, pkts[67]))

# ------------------ WDissector Initialization ------------------
print('\n---------------------- WDissector -----------------------')
# Initialize protocol
wd = wd_init("proto:nordic_ble")
# ------------------ State Machine Initialization ------------------
print('\n--------------------- State Machine ---------------------')
StateMachine = Machine()
# Load State Mapper configuration
ret = StateMachine.init("configs/ble_config.json")
if not ret:
    print("Error initializing state machine model")
    exit(1)
# Load State Machine model
ret = StateMachine.LoadModel("configs/models/sample_ble_model.json")
if not ret:
    print("Error loading state machine model")
    exit(1)

print(f'Total States Loaded: {StateMachine.TotalStates()}')
print(f'Total Transitions Loaded: {StateMachine.TotalTransitions()}')

for direction, pkt in interesting_pkts:
    print('---------------------------------------------------------')  
    # Convert to raw and then to bytearray the packet
    pkt = bytearray(raw(pkt))      
    print(f'{Fore.MAGENTA}1) BEFORE Transition:')
    print(f'{Fore.YELLOW}Previous State: {StateMachine.GetPreviousStateName()}')
    print(f'{Fore.CYAN}Current State: {StateMachine.GetCurrentStateName()}')
    next_states = StateMachine.GetNextStateNames()
    if len(next_states):
        print(f'Next Expected States:')
        for state in next_states:
            print(f' {state}')
    # 1) Prepare State Mapper
    StateMachine.PrepareStateMapper(wd)
    # 2) Set packet direction (WD_DIR_TX or WD_DIR_RX) and decode packet
    wd_set_packet_direction(wd, direction)
    wd_packet_dissect(wd, pkt, len(pkt))
    # 3) Run State Mapper
    # 2nd argument force transition to TX state, so we just need to validate RX
    transition_valid = StateMachine.RunStateMapper(wd, direction == WD_DIR_TX)
    # 4) Validate transition
    dir_str = "TX" if direction == WD_DIR_TX else "RX"
    print(f'\nReceived {dir_str}: {wd_packet_summary(wd)}\n')
    print(f'{Fore.MAGENTA}2) AFTER Transition ({dir_str}):')
    print(f'{Fore.YELLOW}Previous State: {StateMachine.GetPreviousStateName()}')
    print(f'{Fore.CYAN}Current State: {StateMachine.GetCurrentStateName()}')
    if direction == WD_DIR_RX:
        color = Fore.GREEN if transition_valid else Fore.RED
        print(f'{color}RX Transition Valid? {transition_valid}')