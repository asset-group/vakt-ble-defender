#!/usr/bin/env python3

import sys
import os

# Add libs to python path
sys.path.insert(0, os.getcwd() + '/src/libs')
#sys.path.insert(0, os.getcwd() + '/../src/libs')
import serial
import colorama
from scapy.all import sniff
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from scapy.packet import raw, Raw
from time import sleep, perf_counter, time
from threading import Thread, Lock
from binascii import hexlify, unhexlify
from colorama import Fore, Back
from libs.NRF52_dongle import NRF52Dongle, NRF52_USB_VALID_PORTS_DESC
from timeout_lib import start_timeout, disable_timeout, update_timeout
from wdissector import *
from libs.WDPacket import ValidatePacket, print_l, g_lock
from BLECrypto import BLEncryption
from smp_server import BLESMPServer
from NRF52_pcap2 import NRF52Pcap
from uhubctl_cycle import device_cycle_port
import platform 
## launch a connect requetst to a wrong 

# Peripheral side configs
central_address = '5d:36:ac:90:0b:22'
central_address_type = 0
central_access_address = 0x9a328370
#mdk_dongle = 'd9:45:70:85:7b:b4'
#peripheral_injectablepca59 = 'c4:d1:b7:fc:b7:f2'
#peripheral_address = '3c:61:05:4c:33:6e'
#peripheral_address ='59:af:1f:1f:b2:0d'
# peripheral_address = 'c8:c9:a3:d3:65:1e'
peripheral_address = os.environ.get("peripheral_address")
#if peripheral_address is None:
#    print("MAC address not provided. Please set the peripheral_address environment variable.")
#    sys.exit(1)
peripheral_addr_type = 1
peripheral_name = b'MyESP32'
peripheral_adv_flags = 'general_disc_mode+br_edr_not_supported'

# Internal bridge vars
bridge_enabled = True
mutex_peripheral = Lock()
mutex_central = Lock()
queue_central_to_peripheral = []
queue_peripheral_to_central = []
conn_req_sent = 0
conn_req_recv = 0
connected_central = 0
connected_peripheral = 0
disconnect_on_error = True
count_conn_req = 0
scan_req_recv  = False
# Internal constants
TIMEOUT_CONN = 0.5
anomaly = 0
packets = []
# Initialize the ValidatePacket class
verify_pkt = ValidatePacket()
verify_pkt.event_threshold = 4
n_event = 0
state_machine=True

# Encryption internal vars
encryptor = BLEncryption()

#hdr_ble_nordic_tx = NORDIC_BLE(board=75, protocol=2, flags=0x3)
#hdr_ble_nordic_rx = NORDIC_BLE(board=75, protocol=2, flags=0x1)

pkt_adv = BTLE() / BTLE_ADV(RxAdd=0, TxAdd=0) / \
    BTLE_ADV_IND(AdvA=peripheral_address, data=EIR_Hdr(len=2) /
                 EIR_Flags(flags=peripheral_adv_flags) /
                 EIR_Hdr(len=len(peripheral_name) + 1) /
                 EIR_CompleteLocalName(local_name=peripheral_name) /
                 EIR_Hdr(len=2) /
                 EIR_TX_Power_Level(level=-21) /
                 EIR_Hdr(len=2) /
                 EIR_Slave_Conn_Interval_Range(int_min=32, int_max=64))

pkt_conn_request = BTLE() / BTLE_ADV(RxAdd=peripheral_addr_type, TxAdd=central_address_type) / BTLE_CONNECT_REQ(
    InitA=central_address,
    AdvA=peripheral_address,
    AA=central_access_address,  # Access address (any)
    crc_init=0x179a9c,  # CRC init (any)
    win_size=2,  # 2.5 of windows size (anchor connection window size)
    win_offset=1,  # 1.25ms windows offset (anchor connection point)
    interval=16,  # 20ms connection interval
    latency=0,  # Slave latency (any)
    timeout=50,  # Supervision timeout, 500ms (any)
    chM=0x1FFFFFFFFF,  # Any
    hop=5,  # Hop increment (any)
    SCA=1, # Clock tolerance
)


def discover_bridge(dev_idx=0):
    ports = serial.tools.list_ports.comports()
    # Sort ports list
    ports.sort(key=lambda x: x.device)

    dev_peripheral = None
    dev_central = None
    idx_peripheral = 0
    idx_central = 0

    for port in ports:
        print(port.device + ' : ' + port.description)
        if 'BLEDefender Peripheral' in port.description:
            if idx_peripheral >= dev_idx:
                dev_peripheral = port.device
            idx_peripheral += 1
        elif 'BLEDefender Central' in port.description:
            if idx_central >= dev_idx:
                dev_central = port.device
            idx_central += 1

    return [dev_peripheral, dev_central, idx_peripheral - 1, idx_central - 1]


def addr_type_to_str(addr_type):
    return 'Public (0)' if addr_type == 0 else 'Random (1)'


def send_to_central(scapy_pkt, print_tx=True):
    mutex_central.acquire()
    driver_peripheral.raw_send(raw(scapy_pkt))
    mutex_central.release()
    if print_tx:
        print("           [" + Fore.CYAN + "C <--" + Fore.RESET + " P | C --- P] " +
              Fore.GREEN + "TX <--- " + scapy_pkt.summary()[7:])


def send_to_peripheral(scapy_pkt, print_tx=True):
    mutex_peripheral.acquire()
    driver_central.raw_send(raw(scapy_pkt))
    mutex_peripheral.release()
    if print_tx:
        print("           [C -->"+ Fore.RESET +" P | C " + Fore.YELLOW + "--> P" + Fore.RESET + "] " +
              Fore.BLUE + "TX ---> " + scapy_pkt.summary()[7:])


def send_conn_req():
    global connected_peripheral
    global pkt_conn_request

    if not connected_peripheral:
        send_to_peripheral(pkt_conn_request)
        start_timeout('timeout_central_conn',
                      TIMEOUT_CONN,
                      send_conn_req)

def reset_bridge_peripheral():
    print(Fore.YELLOW + '[!] reset_bridge_peripheral')
    global conn_req_recv
    global connected_central
    global queue_peripheral_to_central
    global scan_req_recv
    global driver_peripheral

    driver_peripheral.set_auto_disconnect(0)
    driver_peripheral.set_scanmode()
    driver_peripheral.set_ble_role('impersonator')
    conn_req_recv = 0
    queue_peripheral_to_central = []
    connected_central = 0
    scan_req_recv = False
    disable_timeout('supervision_timeout_peripheral')
    driver_peripheral.serial.flushInput()


def reset_bridge_central():
    print(Fore.YELLOW + '[!] reset_bridge_central')
    global connected_peripheral
    global queue_central_to_peripheral
    global conn_req_sent
    global scan_req_recv
    global driver_central

    disable_timeout('timeout_central_conn')
    queue_central_to_peripheral = []
    driver_central.set_scanmode()
    conn_req_sent = 0
    connected_peripheral = 0
    scan_req_recv = False
    driver_central.serial.flushInput()


def supervision_timeout():
    print(Fore.RED + "           Supervision Timeout ")
    reset_bridge()

def reset_bridge():
    encryptor.disable_encryption()
    reset_bridge_peripheral()
    reset_bridge_central()

def time_to_hijack_channel(pkt):
    start = perf_counter()
    if (LL_LENGTH_REQ in pkt or LL_FEATURE_RSP in pkt or LL_VERSION_IND in pkt):
        end = perf_counter()
        ms = abs((end-start) * 10**3)
        return ms


def bridge_peripheral_thread():
    global bridge_enabled
    global conn_req_recv
    global connected_central
    global connected_peripheral
    global queue_peripheral_to_central
    global queue_central_to_peripheral
    global pkt_conn_request
    global n_event
    global g_lock  # thread to avoid conflicts between changed variables of cetral and peripheral
    global encryption_enabled
    global conn_skd
    global conn_iv
    global conn_ltk
    global pairing_procedure
    global stime_periph_to_central, packets
    global state_machine
    global scan_req_recv

    # Start WDissector
    #wdissector_init("encap:NORDIC_BLE")
    #print("WDissector Version: " + wdissector_version_info().decode())
    #print("WDissector Loaded Profile: " + wdissector_profile_info().decode())
    #print("Python Version: " + sys.version.split('\n')[0])

    # Block initial connection, and connect to the 
    # BLE-Defender peripheral instead 
    print(Back.WHITE + Fore.BLACK + '|--> START TX/RX Peripheral Thread --|')

    # Initialize bridge vars
    reset_bridge()
    # Set Peripheral Advertisement address to follow
    driver_peripheral.set_bdaddr(peripheral_address)
    driver_peripheral.set_auto_disconnect(0)
    driver_central.set_bdaddr(peripheral_address) # used for assiting with the conn_ind jamming
    driver_central.set_jamm_conn_ind(1) # used for assiting with the conn_ind jamming

    print(Fore.YELLOW + '[!] Peripheral Address: %s, Type: %s' %
          (peripheral_address, addr_type_to_str(peripheral_addr_type)))

    while bridge_enabled:
        try:
            data = driver_peripheral.raw_receive()
            #data, pkt_number = driver_peripheral.raw_receive(True)
        except Exception as e:
            print(Fore.RED + str(e))
            sleep(1)
            continue

        if data:
            # Decode Bluetooth Low Energy Data
            pkt = encryptor.config_peripheral_encryption(data)
            if pkt is None:
                valid = False # wrong mic
            else:
                valid = True
            if pkt and valid:
                try:
                    pkt = BTLE(data)
                    if LL_LENGTH_REQ in pkt:
                        stime_periph_to_central = time()
                        packets.append((pkt,stime_periph_to_central))
                        #print(packets)
                    valid = verify_pkt.validate_pkt(pkt,WD_DIR_TX)
                    #print("Before check manually:", valid)
                    if conn_req_recv == 0 and BTLE_CONNECT_REQ in pkt:
                        #print(pkt.show())
                        if(pkt[BTLE_CONNECT_REQ].chM == 0):
                            #print("Entered condition, not filter")
                            valid = False
                        #print(valid)
                        if pkt[BTLE_CONNECT_REQ].interval <= 0:
                        #    print("Interval less or 0")
                            valid=False   
                        if(not valid):
                            disable_timeout('timeout_peripheral_conn')
                            #reset_bridge()
                    if valid == False:
                        #print(Fore.RED + '[Structure] malformed')
                        if BTLE_EMPTY_PDU not in pkt:
                            print(Fore.RED + "[Malformed]" + Fore.RESET + "[C " + Fore.YELLOW + "--> P" + Fore.RESET + " | C --- P] " +
                                Fore.LIGHTGREEN_EX + "RX ---> " + pkt.summary()[7:])
                        #valid = True
                        #disable_timeout('timeout_peripheral_conn')
                    else:
                        if BTLE_EMPTY_PDU not in pkt and (not scan_req_recv or BTLE_SCAN_REQ not in pkt):
                            print(Fore.GREEN + "[Valid]    " + Fore.RESET + "[C " + Fore.YELLOW + "--> P" + Fore.RESET + " | C --- P] " +
                            Fore.LIGHTGREEN_EX + "RX ---> " + pkt.summary()[7:])
                    
                    flood = verify_pkt.flooding_pkt(pkt, WD_DIR_TX, n_event)
                    #flood = True
                    if flood == False:
                        if BTLE_EMPTY_PDU not in pkt:
                            print(Fore.RED + "[Flooding] " + Fore.RESET + "[C " + Fore.YELLOW + "--> P" + Fore.RESET + " | C --- P] " +
                            Fore.LIGHTGREEN_EX + "RX ---> " + pkt.summary()[7:])
                        disable_timeout('timeout_peripheral_conn')
                        valid = False
                        #print(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
                        #valid = True
                    if SM_Hdr in pkt or LL_ENC_REQ in pkt or LL_START_ENC_RSP in pkt:
                        state_machine = verify_pkt.machine_pkt(pkt, WD_DIR_TX)
                    
                        if state_machine == False:
                            print(Fore.RED + "[Out Order]" + Fore.RESET + "[C " + Fore.YELLOW + "--> P" + Fore.RESET + " | C --- P] " +
                            Fore.LIGHTGREEN_EX + "RX ---> " + pkt.summary()[7:])
                            disable_timeout('timeout_peripheral_conn')
                            valid = False
                    
                    if not scan_req_recv and BTLE_SCAN_REQ in pkt:
                        scan_req_recv = True

                    #if state_machine == False:
                    #    valid = False
                    #    print(Fore.RED + "---------------------STATE MACHINE Detected Anomaly-------------")
                    n_event +=1
                except Exception as e:
                    print(e)
                    continue
            if not valid and disconnect_on_error:
                # TODO: indicate jamming for malformed advertisement channel packets
                disable_timeout('timeout_peripheral_conn')
                print(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
                reset_bridge()
                continue
                #exit(0)
                # break
            
            if BTLE_ADV in pkt:

                if conn_req_recv == 0 and BTLE_CONNECT_REQ in pkt:   
                    conn_req_recv = 1
                    pkt_conn_request = pkt
                    start_timeout('timeout_peripheral_conn',
                                  ((pkt[BTLE_CONNECT_REQ].win_offset * 0.00125) +
                                   pkt[BTLE_CONNECT_REQ].interval * 0.00125 * 10),
                                  reset_bridge)
                    start_timeout('supervision_timeout_peripheral',
                                  (int(pkt[BTLE_CONNECT_REQ].timeout) * 0.015),
                                  supervision_timeout)
                    #pkt.show()

            elif BTLE_DATA in pkt and (BTLE_EMPTY_PDU not in pkt) and pkt[BTLE_DATA].Length != 0:
                #pkt.show()

                if (LL_TERMINATE_IND in pkt):
                    reset_bridge()

                # TODO: Handle this on the firmware
                elif (LL_CONNECTION_UPDATE_REQ in pkt) or (LL_CHANNEL_MAP_REQ in pkt):
                    test_pkt = BTLE(access_addr=1) / \
                        BTLE_DATA() / CtrlPDU() / LL_UNKNOWN_RSP()
                    send_to_central(test_pkt)
                    test_pkt = BTLE(access_addr=1) / \
                        BTLE_DATA() / CtrlPDU() / LL_REJECT_IND()
                    send_to_central(test_pkt)
                    continue
                #elif (LL_VERSION_IND in pkt):
                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / \
                #        CtrlPDU() / LL_VERSION_IND(version='4.2')
                #    send_to_central(test_pkt)

                #elif LL_LENGTH_REQ in pkt:
                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                #        max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
                #    send_to_central(test_pkt)

                #elif (LL_FEATURE_REQ in pkt):
                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / \
                #        LL_FEATURE_RSP(
                #            feature_set="le_encryption+le_data_len_ext")
                #    send_to_central(test_pkt)

                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / \
                #        LL_SLAVE_FEATURE_REQ(
                #            feature_set="le_encryption+le_data_len_ext")
                #    send_to_central(test_pkt)

                #elif ATT_Exchange_MTU_Request in pkt:
                #    test_pkt = BTLE(access_addr=1) / \
                #        BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Response(mtu=247)
                #    send_to_central(test_pkt)
                #print(Fore.LIGHTCYAN_EX + "Time elapsed to hijack the channel:" + 
                #Fore.LIGHTBLUE_EX + str("%.4f" % time_to_hijack_channel(pkt)) +  "ms")
                if valid:
                    queue_central_to_peripheral.append(pkt)

            # Start Bridge Central thread
            #print(f'conn_req_recv={conn_req_recv}, connected_central={connected_central}, BTLE_DATA in pkt={BTLE_DATA in pkt}')
            if not connected_central and conn_req_recv and BTLE_DATA in pkt:
            # if not connected_central and conn_req_recv:
                disable_timeout('timeout_peripheral_conn')
                connected_central = 1
                t = Thread(target=bridge_central_thread)
                t.daemon = True
                t.start()
            if BTLE_DATA in pkt and not BTLE_EMPTY_PDU in pkt:
                update_timeout('supervision_timeout_peripheral')
        while connected_central and len(queue_peripheral_to_central):
            p_pkt = queue_peripheral_to_central.pop()
            p_pkt[BTLE].AA = 1
            send_to_central(p_pkt)
            etime_periph_to_central = time()
            #print(f"Elapsed time [ P ----> C] :{abs(etime_periph_to_central - stime_periph_to_central)*1000}"+ "ms")


    print(Back.WHITE + Fore.BLACK + '|<-- EXIT TX/RX Peripheral Thread --|')
    exit(0)


def bridge_central_thread():
    global connected_central
    global connected_peripheral
    global queue_peripheral_to_central
    global queue_central_to_peripheral
    global pkt_conn_request
    global stime_periph_to_central
    global scan_req_recv

    print(Back.WHITE + Fore.BLACK + '|--> START TX/RX Central Thread --|')
    # sleep(1)  # Comment to spped up connection start
    send_conn_req()

    # Minimum data count to identify successul link layer connection with peripheral
    data_req = 0###

    while connected_central:
 
        data = driver_central.raw_receive()
        if data:
            # Decode Bluetooth Low Energy Data
            try:
                pkt = encryptor.config_central_encryption(data)
                pkt = BTLE(data)

            except Exception as e:
                print("Decoding Error")
                print(pkt.show())
                continue
            if BTLE_DATA in pkt:

                if not data_req and not connected_peripheral:
                    connected_peripheral = 1
                    disable_timeout('timeout_central_conn')
                elif data_req:
                    data_req -= 1

                if BTLE_EMPTY_PDU not in pkt:

                    verify_pkt.validate_pkt(pkt,WD_DIR_RX)
                    verify_pkt.flooding_pkt(pkt, WD_DIR_RX, n_event)
                    print("           [C --- P | " + Fore.CYAN + "C <--" + Fore.RESET +
                          " P] " + Fore.LIGHTBLUE_EX + "RX <--- " + pkt.summary()[7:])
                    # DESCOMENTAR AQUI DEPOIS DE TESTAR
                    # verify_pkt.flooding_pkt(pkt, WD_DIR_RX, n_event)
                    if LL_START_ENC_REQ in pkt or LL_ENC_RSP in pkt or SM_Hdr in pkt:
                        verify_pkt.machine_pkt(pkt, WD_DIR_RX)
                    #if valid:
                    queue_peripheral_to_central.append(pkt)

        while connected_peripheral and len(queue_central_to_peripheral):
            p_pkt = queue_central_to_peripheral.pop()
            if LL_LENGTH_REQ in p_pkt:
                etime_periph_to_central = time()
                print(f"Elapsed time (Forwarding LL_LENGTH_REQ)\n[P ----> C] :{abs(etime_periph_to_central - stime_periph_to_central)*1000}"+ " ms")
            p_pkt[BTLE].AA = central_access_address
            send_to_peripheral(p_pkt)

    print(Back.WHITE + Fore.BLACK + '|<-- EXIT TX/RX Central Thread --|')
    reset_bridge()


colorama.init(autoreset=True)

# Reset bridges via uhubctrl if available (for evaluation only)
device_cycle_port('BLEDefender Central')
device_cycle_port('BLEDefender Peripheral')
sleep(2)
# Discover and connect to BLE dongles
try:
    tty_dongles = discover_bridge()
    #tty_dongles = ["/dev/ttyACM2", "/dev/ttyACM1", 0, 1]
    # print(Fore.GREEN + "Dongles discovered: " + str(tty_dongles))
    # driver_peripheral = NRF52Dongle(tty_dongles[0], '115200')
    if None not in tty_dongles:
        print(Fore.GREEN + "Dongles discovered: " + str(tty_dongles))
        driver_peripheral = NRF52Dongle(tty_dongles[0], '115200', logs=True)
        driver_central = NRF52Dongle(tty_dongles[1], '115200', logs=True)

        #driver_peripheral = NRF52Pcap(tty_dongles[0], '115200', logs=True, capture="/home/asset/blecopy/ble-defender/bridge/src/Captures/test.pcapng", direction=1)
        #driver_central = NRF52Pcap(tty_dongles[1], '115200', logs=True, capture="/home/asset/blecopy/ble-defender/bridge/src/Captures/test.pcapng", direction=0)
    else:
        print(Fore.RED + "Dongles cannot be discovered. Got only " + str(tty_dongles))
        exit(1)
except Exception as e:
    print(e)
    print(Fore.RED + "Failed to open serial port")
    exit(1)

t = Thread(target=bridge_peripheral_thread)
t.daemon = True
t.start()


try:
    while True:
        # if conn_req_recv == 0 and connected_central == 0:
        #     send_to_central(pkt_adv)
        # if connected_central:
        #     sleep(0.5)
        #     test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / \
        #         LL_SLAVE_FEATURE_REQ(
        #             feature_set="le_encryption+le_data_len_ext")
        #     send_to_central(test_pkt)
        sleep(0.5)
except KeyboardInterrupt as e:
    pass

print(Fore.YELLOW + '[!] Waiting bridge to stop...')

bridge_enabled = False
reset_bridge()
while t.is_alive():
    sleep(0.1)

# Disable bridge
driver_peripheral.set_bdaddr('00:00:00:00:00:00') # Clear bdaddress tracking
driver_central.set_bdaddr('00:00:00:00:00:00') # Clear bdaddress tracking
driver_central.set_jamm_conn_ind(0) # Disable auxiliary central jamming

print(Fore.RED + "VaktBLE Bridge Stopped Tracking Target \"" + peripheral_address + "\"")
exit(0)
