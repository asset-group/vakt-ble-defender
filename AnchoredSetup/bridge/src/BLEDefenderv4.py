#!/usr/bin/env python3
# Add libs to python path
import sys
import os
sys.path.insert(0, os.getcwd() + '/src/libs')


from WDPacket import ValidatePacket, print_l, g_lock
from timeout_lib import start_timeout, disable_timeout, update_timeout
from NRF52_pcap2 import NRF52Pcap
from NRF52_dongle import NRF52Dongle, NRF52_USB_VALID_PORTS_DESC
from colorama import Fore, Back
from binascii import hexlify, unhexlify
from threading import Thread, Lock
from time import sleep, perf_counter
from scapy.packet import raw, Raw
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.all import sniff
from wdissector import WD_DIR_TX, WD_DIR_RX
from BLECrypto import BLEncryption
from smp_server import BLESMPServer
import colorama
import serial
import signal


# launch a connect request to a wrong

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

# Initialize the ValidatePacket class
verify_pkt = ValidatePacket()
verify_pkt.event_threshold = 4
n_event = 0

# Encryption internal vars
encryptor = BLEncryption()


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
    # driver_peripheral.raw_send(raw(scapy_pkt))
    mutex_central.release()
    # if print_tx:
    #     print_l("        [" + Fore.CYAN + "C <--" + Fore.RESET + " P | C --- P] " +
    #           Fore.GREEN + "TX <--- " + scapy_pkt.summary()[7:])


def send_to_peripheral(scapy_pkt, print_tx=True):
    mutex_peripheral.acquire()
    # driver_central.raw_send(raw(scapy_pkt))
    mutex_peripheral.release()
    # if print_tx:
    #     print_l("        [C --- P | C " + Fore.YELLOW + "--> P" + Fore.RESET + "] " +
    #           Fore.BLUE + "TX ---> " + scapy_pkt.summary()[7:])


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

    print_l(Fore.YELLOW + '[!] reset_bridge_peripheral')


def reset_bridge_central():
    global connected_peripheral
    global queue_central_to_peripheral
    global conn_req_sent

    disable_timeout('timeout_central_conn')
    queue_central_to_peripheral = []
    driver_central.set_scanmode()
    conn_req_sent = 0
    connected_peripheral = 0

    print_l(Fore.YELLOW + '[!] reset_bridge_central')


def reset_bridge():
    reset_bridge_peripheral()
    reset_bridge_central()


def time_to_hijack_channel(pkt):
    start = time.perf_counter()
    if (LL_LENGTH_REQ in pkt or LL_FEATURE_RSP in pkt or LL_VERSION_IND in pkt):
        end = time.perf_counter()
        ms = (end-start) * 10**3
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

    # Start WDissector
    # wdissector_init("encap:NORDIC_BLE")
    # print_l("WDissector Version: " + wdissector_version_info().decode())
    # print_l("WDissector Loaded Profile: " + wdissector_profile_info().decode())
    # print_l("Python Version: " + sys.version.split('\n')[0])

    # Block initial connection, and connect to the
    # BLE-Defender peripheral instead
    print_l(Back.WHITE + Fore.BLACK + '|--> START TX/RX Peripheral Thread --|')

    # Initialize bridge vars
    reset_bridge()
    # Set Peripheral Advertisement address to follow
    driver_peripheral.set_bdaddr(peripheral_address)
    driver_peripheral.set_auto_disconnect(0)

    print_l(Fore.YELLOW + '[!] Peripheral Address: %s, Type: %s' %
            (peripheral_address, addr_type_to_str(peripheral_addr_type)))

    cont_pkt = 0

    while bridge_enabled:
        try:
            try:
                # Release the lock
                g_lock.release()
            except:
                pass
            data, pkt_number = driver_peripheral.raw_receive(True)
            # Start to lock
            g_lock.acquire()
        except Exception as e:
            print_l(Fore.RED + str(e))
            sleep(1)
            continue

        if data:
            # Decode Bluetooth Low Energy Data
            pkt = encryptor.config_peripheral_encryption(data)

            # ---- VALIDATION SECTION ----
            valid = False
            # valid = True # APAGAR DEPOIS DE TESTAR
            # try:
            # pkt = BTLE(data)
            print_l(f"[{pkt_number}][C " + Fore.YELLOW + "--> P" + Fore.RESET + " | C --- P] " +
                    Fore.LIGHTGREEN_EX + "TX ---> " + pkt.summary()[7:])
            # DESCOMENTAR AQUI DEPOIS DE TESTAR
            valid = verify_pkt.validate_pkt(pkt, WD_DIR_TX)
            # if not valid:
            #     cont_pkt += 1
            # print_l("Falso positivo: ", cont_pkt)
            # print_l('---------------------------------------------------------')
            flood = verify_pkt.flooding_pkt(pkt, WD_DIR_TX, n_event)
            # flood = True
            if flood == True:
                print_l(Fore.GREEN + "Flooding OK!!!")
            else:
                print_l(Fore.RED + "Flooding packet detected!!!")
            n_event += 1
            print_l('---------------------------------------------------------')
            #verify_pkt.machine_pkt( pkt, WD_DIR_TX)
            print_l(f'{Fore.CYAN}Packet Number: {pkt_number}')
            # except:
            #     pass

            if not valid and disconnect_on_error:
                # TODO: indicate jamming for malformed advertisement channel packets
                disable_timeout('timeout_peripheral_conn')
                print_l(
                    Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
                print_l(pkt)
                # reset_bridge()
                # continue
                reset_bridge()
                # exit(0)
                # break

            if BTLE_ADV in pkt:

                if conn_req_recv == 0 and BTLE_CONNECT_REQ in pkt:
                    if ((pkt[BTLE_CONNECT_REQ].win_offset <= 0) or (pkt[BTLE_CONNECT_REQ].chM <= 0) or
                            (pkt[BTLE_CONNECT_REQ].interval == 21)):  # Just 21 for testing connect request crash
                        disable_timeout('timeout_peripheral_conn')
                        # print_l(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
                        reset_bridge()
                        # print_l(pkt)
                        continue
#                if(conn_req_recv == 0 and BTLE_CONNECT_REQ in pkt):
#                    global count_conn_req
#                    count_conn_req+=1
#                    print_l(Fore.RED + "value of connect req"+ str(count_conn_req))
#                    while count_conn_req < 5:
#                        if(count_conn_req == 5 or count_conn_req == 6):
#                            # We've seen 5 or 6 consecutive CONNECT_IND packets, print a warning
#                            print_l(f"WARNING: {count_conn_req} consecutive CONNECT_IND packets received without a CONNECT_RSP")
#                            print_l("No CONNECT_RSP received")
#                            disable_timeout('timeout_peripheral_conn')
#                            print_l(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
#                            print_l(pkt)
#                        # Check if the next packet is a CONNECT_RSP
#                        elif(LL_LENGTH_REQ in pkt or LL_FEATURE_RSP in pkt or LL_VERSION_IND in pkt or BTLE_EMPTY_PDU in pkt):
#                            # Timeout occurred, no CONNECT_RSP received
#                            print_l("Connection established!")
#                            disable_timeout('timeout_peripheral_conn')
#                            print_l(Fore.RED + 'Anomaly Detected by BLEDefender. Terminating connection!')
#                            print_l(pkt)
#                            continue
#
#                        else:
#                            continue

                    conn_req_recv = 1
                    pkt_conn_request = pkt
                    # pkt_conn_request.interval = 10
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
                # elif (LL_VERSION_IND in pkt):
                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / \
                #        CtrlPDU() / LL_VERSION_IND(version='4.2')
                #    send_to_central(test_pkt)

                # elif LL_LENGTH_REQ in pkt:
                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                #        max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
                #    send_to_central(test_pkt)

                # elif (LL_FEATURE_REQ in pkt):
                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / \
                #        LL_FEATURE_RSP(
                #            feature_set="le_encryption+le_data_len_ext")
                #    send_to_central(test_pkt)

                #    test_pkt = BTLE(access_addr=1) / BTLE_DATA() / CtrlPDU() / \
                #        LL_SLAVE_FEATURE_REQ(
                #            feature_set="le_encryption+le_data_len_ext")
                #    send_to_central(test_pkt)

                # elif ATT_Exchange_MTU_Request in pkt:
                #    test_pkt = BTLE(access_addr=1) / \
                #        BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Response(mtu=247)
                #    send_to_central(test_pkt)
                # print_l(Fore.LIGHTCYAN_EX + "Time elapsed to hijack the channel:" +
                #  Fore.LIGHTBLUE_EX + str("%.4f" % time_to_hijack_channel(pkt)) +  "ms")
                queue_central_to_peripheral.append(pkt)

            # Start Bridge Central thread
            if not connected_central and conn_req_recv:
                #  and BTLE_DATA in pkt:
                disable_timeout('timeout_peripheral_conn')
                connected_central = 1
                t = Thread(target=bridge_central_thread)
                t.daemon = True
                t.start()

        while connected_central and len(queue_peripheral_to_central):
            p_pkt = queue_peripheral_to_central.pop()
            p_pkt[BTLE].AA = 1
            send_to_central(p_pkt)

    print_l(Back.WHITE + Fore.BLACK + '|<-- EXIT TX/RX Peripheral Thread --|')
    exit(0)


def bridge_central_thread():
    global connected_central
    global connected_peripheral
    global queue_peripheral_to_central
    global queue_central_to_peripheral
    global pkt_conn_request
    global g_lock  # thread to avoid conflicts between changed variables of cetral and peripheral

    print_l(Back.WHITE + Fore.BLACK + '|--> START TX/RX Central Thread --|')
    sleep(1)  # Comment to spped up connection start
    send_conn_req()

    # Minimum data count to identify successul link layer connection with peripheral
    data_req = 0

    while connected_central:
        try:
            # Release the lock
            g_lock.release()
        except:
            pass
        time.sleep(0.01)
        data = driver_central.raw_receive()
        # Start to lock
        g_lock.acquire()
        if data:
            # Decode Bluetooth Low Energy Data
            # pkt = BTLE(data)
            # time.sleep(0.2)
            # n_event += 1

            # Decode Bluetooth Low Energy Data
            pkt = encryptor.config_central_encryption(data)

            if BTLE_DATA in pkt:

                if not data_req and not connected_peripheral:
                    connected_peripheral = 1
                    disable_timeout('timeout_central_conn')
                elif data_req:
                    data_req -= 1

                if BTLE_EMPTY_PDU not in pkt:
                    # validate periph
                    valid = verify_pkt.validate_pkt(pkt, WD_DIR_RX)
                    print_l("[C --- P | " + Fore.CYAN + "C <--" + Fore.RESET +
                            " P] " + Fore.LIGHTBLUE_EX + "RX <--- " + pkt.summary()[7:])
                    # DESCOMENTAR AQUI DEPOIS DE TESTAR
                    flood = verify_pkt.flooding_pkt(pkt, WD_DIR_RX, n_event)
                    #verify_pkt.machine_pkt(pkt, WD_DIR_RX)
                    # if valid:
                    queue_peripheral_to_central.append(pkt)

        while connected_peripheral and len(queue_central_to_peripheral):
            p_pkt = queue_central_to_peripheral.pop()
            p_pkt[BTLE].AA = central_access_address
            send_to_peripheral(p_pkt)

    print_l(Back.WHITE + Fore.BLACK + '|<-- EXIT TX/RX Central Thread --|')
    sleep(1)
    os.kill(0, signal.SIGQUIT)
    reset_bridge()


colorama.init(autoreset=True)

# Discover and connect to BLE dongles
try:
    # tty_dongles = discover_bridge() # ****************
    tty_dongles = ["/dev/ttyACM0", "/dev/ttyACM1", 0, 1]
    # print_l(Fore.GREEN + "Dongles discovered: " + str(tty_dongles))
    # driver_peripheral = NRF52Dongle(tty_dongles[0], '115200')
    if None not in tty_dongles:
        print_l(Fore.GREEN + "Dongles discovered: " + str(tty_dongles))
        driver_peripheral = NRF52Pcap(
            tty_dongles[0], '115200', logs=True, capture="./src/Captures/capture_zephyr_invalid_channel_map.pcap", direction=1)
        sleep(1)
        driver_central = NRF52Pcap(
            tty_dongles[1], '115200', logs=True, capture="./src/Captures/capture_zephyr_invalid_channel_map.pcap", direction=0)
    else:
        print_l(Fore.RED + "Dongles cannot be discovered. Got only " +
                str(tty_dongles))
        exit(1)
except Exception as e:
    print_l(e)
    print_l(Fore.RED + "Failed to open serial port")
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

print_l(Fore.YELLOW + '\n[!] Waiting bridge to stop...')

bridge_enabled = False
reset_bridge()
while t.is_alive():
    sleep(0.1)
print_l(Fore.YELLOW + "Bridge closed")
exit(0)
