from time import time
import csv
from binascii import hexlify
from datetime import datetime

import numpy
from colorama import Fore
from scapy.utils import raw, wrpcap
from scapy.layers.dot11 import RadioTap

from fuzzing import field_length
import fuzzing

# Saving options
SaveToPCAP = True
SaveCSVStruct = True

GlobalConfig = None
IssuesByState = {}  # Countain found vulnerabilities
IssueCounter = 0
IssuesTotalCounter = 0
IssueLastTime = time()
IssuePeriod = float('inf')
TransitionCount = 0
TransitionLastCount = 0
IterationLastTime = time()
IterationTime = float('inf')

STATE = 'STATE'
REASON = 'REASON'
FUZZED_PKT = 'FUZZED_PKT'
RECEIVED_PKT = 'RECEIVED_PKT'
TIME = 'TIME'
FUZZED_FIELDS_NAME = 'FUZZED_FIELDS_NAME'
FUZZED_FIELDS_VALUE = 'FUZZED_FIELDS_VALUE'
DUPLICATED_PACKET = 'DUPLICATED_PKT'
ITERATION_NUMBER = 'ITERATION_NUMBER'

model_name = ''
iterationCount = 0


def ConfigureFitness(config):
    global GlobalConfig
    GlobalConfig = config


def Iteration():
    global IterationLastTime
    global IterationTime
    global iterationCount
    t = time()
    ret = t - IterationLastTime
    IterationLastTime = t
    IterationTime = ret
    iterationCount += 1
    return ret


def Transition(reset=False):
    global TransitionCount
    global TransitionLastCount

    TransitionCount += 1

    if reset:
        TransitionLastCount = TransitionCount
        TransitionCount = 0

    return TransitionLastCount


# Issue rate
def AnomalyDetected(state, pkt, summary_text):
    global IssueCounter
    global IssueLastTime
    global IssuePeriod
    global IssuesTotalCounter
    global model_name
    global iterationCount

    issue_time = time()
    fuzzed_pkt = None
    pkts_to_save = []

    IssuesTotalCounter += 1

    if fuzzing.last_fuzzed_packet is not None:
        fuzzed_pkt = fuzzing.last_fuzzed_packet
        print(Fore.YELLOW + "Last fuzzed packet: " + fuzzed_pkt.summary())
    # If state of the issue is not found in the issues dictionary
    if state not in IssuesByState:
        # Initialize the entry by the state name
        IssuesByState[state] = {
            REASON: [],
            FUZZED_PKT: [],
            RECEIVED_PKT: [],
            TIME: [],
            FUZZED_FIELDS_NAME: [],
            FUZZED_FIELDS_VALUE: [],
            DUPLICATED_PACKET: [],
            ITERATION_NUMBER: []
        }

    # Gets the time between any issue
    IssuePeriod = issue_time - IssueLastTime
    IssueLastTime = issue_time

    issues = IssuesByState[state]
    reasons = issues[REASON]
    packet_description = issues[RECEIVED_PKT]
    # if summary of the invalid packet is not already in the reason array
    if summary_text not in reasons or (pkt is not None and pkt.summary() not in packet_description):
        IssueCounter = IssueCounter + 1
        if pkt is not None:
            print(Fore.RED + 'Pkt received: ' + pkt.summary())
        # Append it to the array as a unique issue
        reasons.append(summary_text)
        # Append the last fuzzed packet (None for non fuzzing related)
        if fuzzed_pkt is not None:
            fuzzing.last_fuzzed_packet = None
            issues[FUZZED_PKT].append(fuzzed_pkt.summary())
            pkts_to_save.append(fuzzed_pkt.copy())
            issues[FUZZED_FIELDS_NAME].append(list(fuzzing.last_fuzzed_packet_fields[fuzzing.NAME]))
            issues[FUZZED_FIELDS_VALUE].append(list(fuzzing.last_fuzzed_packet_fields[fuzzing.VALUE]))
        else:
            issues[FUZZED_PKT].append('None')
            issues[FUZZED_FIELDS_NAME].append('None')
            issues[FUZZED_FIELDS_VALUE].append('None')
        # Append the received packet (None for crash)
        if pkt is not None:
            pcap_pkt = pkt
            issues[RECEIVED_PKT].append(pcap_pkt.summary())
            pkts_to_save.append(pkt.copy())
        else:
            issues[RECEIVED_PKT].append(None)

        if fuzzing.last_mirror_packet is not None:
            # pkts_to_save.append(fuzzing.last_mirror_packet)
            issues[DUPLICATED_PACKET].append(fuzzing.last_mirror_packet)
        else:
            issues[DUPLICATED_PACKET].append('None')
        fuzzing.last_mirror_packet = None
        # Timestamp of the issue
        issue_time_formatted = str(datetime.fromtimestamp(issue_time)).replace(':', '_')
        issues[TIME].append(issue_time_formatted)
        issues[ITERATION_NUMBER].append(iterationCount)

        if SaveToPCAP:
            if len(pkts_to_save) > 0:
                # for o in pkts_to_save:
                #     print(Fore.RED + o.summary())
                try:
                    wrpcap('logs/' + model_name + '/pcap/' + issue_time_formatted + '_' + summary_text + '.pcap',
                           pkts_to_save)
                except:
                    pass

        if SaveCSVStruct:
            with open('logs/' + model_name + '/csv/' + issue_time_formatted + '.csv', 'w') as csvfile:
                columns = [TIME, STATE, RECEIVED_PKT, REASON, FUZZED_PKT, FUZZED_FIELDS_NAME, FUZZED_FIELDS_VALUE,
                           DUPLICATED_PACKET, ITERATION_NUMBER]
                # Create CSV columns
                # columns = [STATE]
                # for column in IssuesByState[IssuesByState.keys()[0]]:
                #     columns.append(column)

                writer = csv.DictWriter(csvfile, fieldnames=columns)
                writer.writeheader()
                for state_key in IssuesByState:
                    state_issue = IssuesByState[state_key]
                    for idx, issue_summary in enumerate(state_issue[REASON]):
                        value = 'None'
                        if fuzzed_pkt is not None:
                            value = state_issue[FUZZED_FIELDS_VALUE]
                            if isinstance(value, list):
                                value = str(value)
                            else:
                                value = '0x' + hexlify(value)

                        writer.writerow({
                            TIME: state_issue[TIME][idx],
                            STATE: state_key,
                            RECEIVED_PKT: state_issue[RECEIVED_PKT][idx],
                            REASON: issue_summary,
                            FUZZED_PKT: state_issue[FUZZED_PKT][idx],
                            FUZZED_FIELDS_NAME: state_issue[FUZZED_FIELDS_NAME][idx],
                            FUZZED_FIELDS_VALUE: value,
                            DUPLICATED_PACKET: state_issue[DUPLICATED_PACKET][idx],
                            ITERATION_NUMBER: state_issue[ITERATION_NUMBER][idx]
                        })

                        idx += 1

    return IssueCounter


def Validate(packet, state, expected_layers):
    pkt_layers = get_packet_expected_layers_from_state(packet, state, expected_layers)
    if pkt_layers and len(pkt_layers) > 0:
        fields_cost = 0
        for pkt_layer in pkt_layers:
            # fields_name = [field.name for field in pkt_layer.fields_desc]
            # fields_size = [field_length(getattr(pkt_layer, field_name)) for field_name in fields_name]
            # fields_size = fields_size
            # fields_cost += numpy.prod(  # multiply everything
            #     numpy.multiply(fields_size, 2))  # multiply size by 2
            fields_cost = fields_cost + 1

        return fields_cost
    else:
        return 0


def get_packet_expected_layers_from_state(packet, state, expected_layers):
    counter = 0  # start after Dot11
    layers = []
    if state in expected_layers:
        while True:
            layer = packet.getlayer(counter)
            counter += 1
            if layer is None:
                break

            for layerClass in expected_layers[state].states_expected:
                if layerClass == type(layer):
                    layers.append(layer)

        return layers

    else:
        return None
