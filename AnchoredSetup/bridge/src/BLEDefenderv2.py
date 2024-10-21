#!/usr/bin/env python3

import sys
import os

# Add libs to python path
sys.path.insert(0, os.getcwd() + '/src/libs')

import serial
import colorama
from scapy.all import sniff
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from scapy.packet import raw, Raw
from time import sleep, perf_counter
from threading import Thread, Lock
from binascii import hexlify, unhexlify
from colorama import Fore, Back
from libs.NRF52_dongle import NRF52Dongle, NRF52_USB_VALID_PORTS_DESC
from libs.NRF52_pcap import NRF52Pcap
from timeout_lib import start_timeout, disable_timeout, update_timeout
from wdissector import *


## launch a connect requetst to a wrong 

# Attribute PDU table: name and opcode
# Request
request_attribute = {
    "att":['ATT_FIND_INFORMATION_REQ','ATT_EXCHANGE_MTU_REQ','ATT_READ_REQ','ATT_FIND_BY_TYPE_VALUE_REQ','ATT_READ_BY_TYPE_REQ',\
        'ATT_READ_MULTIPLE_REQ','ATT_READ_BY_GROUP_TYPE_REQ','ATT_BLOB_READ_REQ',\
        'ATT_READ_MULTIPLE_VARIABLE_REQ', 'ATT_EXECUTE_WRITE_REQ','ATT_PREPARE_WRITE_REQ',\
        'ATT_WRITE_REQ'],
    "code":[0X04,0x02,0x0A,0x06,0x08,0x0E,0x10,0x0C,0x20,0x18,0x16,0x12]
}
# Response
response_attribute = {
    "att":['ATT_FIND_INFORMATION_RSP','ATT_EXCHANGE_MTU_RSP','ATT_READ_RSP','ATT_FIND_BY_TYPE_VALUE_RSP','ATT_READ_BY_TYPE_RSP',\
        'ATT_READ_MULTIPLE_RSP','ATT_READ_BY_GROUP_TYPE_RSP','ATT_BLOB_READ_RSP',\
        'ATT_READ_MULTIPLE_VARIABLE_RSP', 'ATT_EXECUTE_WRITE_RSP','ATT_PREPARE_WRITE_RSP',\
        'ATT_WRITE_RSP'],
    "code":[0x05,0x03,0x0B,0x07,0x09,0x0F,0x11,0x0D,0x21,0x19,0x17,0x13]
}

# Peripheral side configs
central_address = '5d:36:ac:90:0b:22'
central_address_type = 0
central_access_address = 0x9a328370
peripheral_address = '3c:61:05:4c:33:6e'.lower()
peripheral_addr_type = 0
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
# Internal constants
TIMEOUT_CONN = 0.5
anomaly = 0

hdr_ble_nordic_tx = NORDIC_BLE(board=75, protocol=2, flags=0x3)
hdr_ble_nordic_rx = NORDIC_BLE(board=75, protocol=2, flags=0x1)

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
    interval=6,  # 20ms connection interval
    latency=0,  # Slave latency (any)
    timeout=50,  # Supervision timeout, 500ms (any)
    chM=0x1FFFFFFFFF,  # Any
    hop=5,  # Hop increment (any)
    SCA=0,  # Clock tolerance
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
        if port.description == NRF52_USB_VALID_PORTS_DESC[0]:
            if idx_peripheral == dev_idx:
                dev_peripheral = port.device
            idx_peripheral += 1
        elif port.description in NRF52_USB_VALID_PORTS_DESC:
            if idx_central == dev_idx:
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
        print("        [" + Fore.CYAN + "C <--" + Fore.RESET + " P | C --- P] " +
              Fore.GREEN + "TX <--- " + scapy_pkt.summary()[7:])


def send_to_peripheral(scapy_pkt, print_tx=True):
    mutex_peripheral.acquire()
    driver_central.raw_send(raw(scapy_pkt))
    mutex_peripheral.release()
    if print_tx:
        print("        [C --- P | C " + Fore.YELLOW + "--> P" + Fore.RESET + "] " +
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
    global conn_req_recv
    global connected_central
    global queue_peripheral_to_central

    driver_peripheral.set_scanmode()
    driver_peripheral.set_ble_role('impersonator')
    conn_req_recv = 0
    queue_peripheral_to_central = []
    connected_central = 0

    print(Fore.YELLOW + '[!] reset_bridge_peripheral')


def reset_bridge_central():
    global connected_peripheral
    global queue_central_to_peripheral
    global conn_req_sent

    disable_timeout('timeout_central_conn')
    queue_central_to_peripheral = []
    driver_central.set_scanmode()
    conn_req_sent = 0
    connected_peripheral = 0

    print(Fore.YELLOW + '[!] reset_bridge_central')


def reset_bridge():
    reset_bridge_peripheral()
    reset_bridge_central()

def time_to_hijack_channel(pkt):
    start = time.perf_counter()
    if (LL_LENGTH_REQ in pkt or LL_FEATURE_RSP in pkt or LL_VERSION_IND in pkt):
        end = time.perf_counter()
        ms = (end-start) * 10**3
        return ms


def validate_packet(pkt):
    # return True
    # Prepare wireshark packet for dissection
    w_pkt = hdr_ble_nordic_rx / pkt
    w_pkt = (ctypes.c_ubyte * len(w_pkt)
             ).from_buffer_copy(raw(w_pkt))
    # Set direction (required for sequence analyser)
    packet_set_direction(0)
    # Dissect packet
    packet_dissect(w_pkt, len(w_pkt))
    summary = packet_summary()
    print(summary)
    if summary is None:
        return 
    # Validate Packet
    # TODO: Add improvements here
    if summary and b'Malformed' not in summary and b'Unkown' not in summary:
    # and Raw not in pkt:
        # print(Fore.GREEN + '[Valid] ' + Fore.RESET +
        #       summary.decode() + ' ', end='')

        # if L2CAP_Hdr in pkt:
        #     pkt.show()

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
            if summary and b'AUX_CONNECT_REQ' in summary and \
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

            elif summary and b'AUX_CONNECT_REQ' in summary:
                print(Fore.RED + '[Error] ', end='')
                return False
            
            else:
                print(Fore.GREEN + '[Valid] ', end='')
                return True

    else:
        # print(Fore.RED + '[Error] ')
        # pkt.show()
        print(Fore.RED + '[Error] ', end='')
        return False


def bridge_peripheral_thread():
    global bridge_enabled
    global conn_req_recv
    global connected_central
    global connected_peripheral
    global queue_peripheral_to_central
    global queue_central_to_peripheral
    global pkt_conn_request

    # Start WDissector
    wdissector_init("encap:NORDIC_BLE")
    print("WDissector Version: " + wdissector_version_info().decode())
    print("WDissector Loaded Profile: " + wdissector_profile_info().decode())
    print("Python Version: " + sys.version.split('\n')[0])

    # Block initial connection, and connect to the 
    # BLE-Defender peripheral instead 
    print(Back.WHITE + Fore.BLACK + '|--> START TX/RX Peripheral Thread --|')

    # Initialize bridge vars
    reset_bridge()
    # Set Peripheral Advertisement address to follow
    driver_peripheral.set_bdaddr(peripheral_address)
    driver_peripheral.set_auto_disconnect(0)

    print(Fore.YELLOW + '[!] Peripheral Address: %s, Type: %s' %
          (peripheral_address, addr_type_to_str(peripheral_addr_type)))

    while bridge_enabled:
        try:
            data = driver_peripheral.raw_receive()
        except Exception as e:
            print(Fore.RED + str(e))
            sleep(1)
            continue

        if data:
            # Decode Bluetooth Low Energy Data
            valid = False
            # try:
            pkt = BTLE(data)

            valid = validate_packet(pkt)
                
            print("[C " + Fore.YELLOW + "--> P" + Fore.RESET + " | C --- P] " +
                    Fore.LIGHTGREEN_EX + "RX ---> " + pkt.summary()[7:])

            # except:
            #     pass

            if not valid and disconnect_on_error:
                # TODO: indicate jamming for malformed advertisement channel packets
                disable_timeout('timeout_peripheral_conn')
                print(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
                print(pkt)
                #reset_bridge()
                #continue
                reset_bridge()
                # exit(0)
                #break
                

            if BTLE_ADV in pkt:

                if conn_req_recv == 0 and BTLE_CONNECT_REQ in pkt:   
                    if((pkt[BTLE_CONNECT_REQ].win_offset <= 0) or (pkt[BTLE_CONNECT_REQ].chM <= 0) or
                        (pkt[BTLE_CONNECT_REQ].interval == 21)): ## Just 21 for testing connect request crash
                        disable_timeout('timeout_peripheral_conn')
                        # print(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
                        reset_bridge()
                        #print(pkt)
                        continue
#                if(conn_req_recv == 0 and BTLE_CONNECT_REQ in pkt):
#                    global count_conn_req
#                    count_conn_req+=1
#                    print(Fore.RED + "value of connect req"+ str(count_conn_req))
#                    while count_conn_req < 5:
#                        if(count_conn_req == 5 or count_conn_req == 6):
#                            # We've seen 5 or 6 consecutive CONNECT_IND packets, print a warning
#                            print(f"WARNING: {count_conn_req} consecutive CONNECT_IND packets received without a CONNECT_RSP")
#                            print("No CONNECT_RSP received")
#                            disable_timeout('timeout_peripheral_conn')
#                            print(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
#                            print(pkt)
#                        # Check if the next packet is a CONNECT_RSP
#                        elif(LL_LENGTH_REQ in pkt or LL_FEATURE_RSP in pkt or LL_VERSION_IND in pkt or BTLE_EMPTY_PDU in pkt):
#                            # Timeout occurred, no CONNECT_RSP received
#                            print("Connection established!")
#                            disable_timeout('timeout_peripheral_conn')
#                            print(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
#                            print(pkt)
#                            continue
#
#                        else:
#                            continue

                    conn_req_recv = 1
                    pkt_conn_request = pkt
                    #pkt_conn_request.interval = 10
                    # pkt_conn_request.TxAdd = pkt.TxAdd
                    # pkt_conn_request[BTLE_CONNECT_REQ].InitA = pkt[BTLE_CONNECT_REQ].InitA

                    # Wait connection win_offset + interval*5 to consider lost connection (TODO: Improve this)
                    start_timeout('timeout_peripheral_conn',
                                  ((pkt[BTLE_CONNECT_REQ].win_offset * 0.00125) +
                                   pkt[BTLE_CONNECT_REQ].interval * 0.00125 * 10),
                                  reset_bridge)
                    pkt.show()

            elif BTLE_DATA in pkt and (BTLE_EMPTY_PDU not in pkt):

                if (LL_TERMINATE_IND in pkt):
                    reset_bridge_peripheral()

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
                #  Fore.LIGHTBLUE_EX + str("%.4f" % time_to_hijack_channel(pkt)) +  "ms")
                queue_central_to_peripheral.append(pkt)

            # Start Bridge Central thread
            if not connected_central and conn_req_recv and BTLE_DATA in pkt:
                disable_timeout('timeout_peripheral_conn')
                connected_central = 1
                t = Thread(target=bridge_central_thread)
                t.daemon = True
                t.start()

        while connected_central and len(queue_peripheral_to_central):
            p_pkt = queue_peripheral_to_central.pop()
            p_pkt[BTLE].AA = 1
            send_to_central(p_pkt)

    print(Back.WHITE + Fore.BLACK + '|<-- EXIT TX/RX Peripheral Thread --|')
    exit(0)


def bridge_central_thread():
    global connected_central
    global connected_peripheral
    global queue_peripheral_to_central
    global queue_central_to_peripheral
    global pkt_conn_request

    print(Back.WHITE + Fore.BLACK + '|--> START TX/RX Central Thread --|')
    sleep(1)  # Comment to spped up connection start
    send_conn_req()

    # Minimum data count to identify successul link layer connection with peripheral
    data_req = 0###

    while connected_central:
        data = driver_central.raw_receive()
        if data:
            # Decode Bluetooth Low Energy Data
            pkt = BTLE(data)

            if BTLE_DATA in pkt:

                if not data_req and not connected_peripheral:
                    connected_peripheral = 1
                    disable_timeout('timeout_central_conn')
                elif data_req:
                    data_req -= 1

                if BTLE_EMPTY_PDU not in pkt:
                    ## validate periph 
                    #valid = validate_packet(pkt)

                    print("[C --- P | " + Fore.CYAN + "C <--" + Fore.RESET +
                          " P] " + Fore.LIGHTBLUE_EX + "RX <--- " + pkt.summary()[7:])
                    #if valid:
                    queue_peripheral_to_central.append(pkt)

        while connected_peripheral and len(queue_central_to_peripheral):
            p_pkt = queue_central_to_peripheral.pop()
            p_pkt[BTLE].AA = central_access_address
            send_to_peripheral(p_pkt)

    print(Back.WHITE + Fore.BLACK + '|<-- EXIT TX/RX Central Thread --|')
    reset_bridge()


colorama.init(autoreset=True)

# Discover and connect to BLE dongles
try:
    # tty_dongles = discover_bridge() # ****************
    tty_dongles = ["/dev/ttyACM0","/dev/ttyACM1",0,1]
    # print(Fore.GREEN + "Dongles discovered: " + str(tty_dongles))
    # driver_peripheral = NRF52Dongle(tty_dongles[0], '115200')
    if None not in tty_dongles:
        print(Fore.GREEN + "Dongles discovered: " + str(tty_dongles))
        driver_peripheral = NRF52Pcap(tty_dongles[0], '115200', logs=True, capture="./src/Captures/capture_microchip_ATSAMB11_invalid_fragment_2.pcap", direction=1)
        driver_central = NRF52Pcap(tty_dongles[1], '115200', logs=True)
        # , capture="./src/Captures/Teste-21-03-2023.pcap", direction=0)
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

print(Fore.YELLOW + '\n[!] Waiting bridge to stop...')

bridge_enabled = False
reset_bridge()
while t.is_alive():
    sleep(0.1)
print(Fore.YELLOW + "Bridge closed")
exit(0)
