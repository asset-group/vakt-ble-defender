import numpy
from math import log
from pyrecord import Record
import random
from binascii import hexlify
from colorama import Fore, Back, Style
from scapy.layers.dot11 import Dot11Beacon
import threading
import sys
from scapy.utils import mac2str
import os
import g_utils

StateConfig = Record.create_type('StateConfig',
                                 'states_expected',
                                 'fuzzable_layers',
                                 'fuzzable_layers_mutators',
                                 'fuzzable_layers_selections',
                                 'fuzzable_layers_mutators_global_chance',
                                 'fuzzable_layers_mutators_chance_per_layer',
                                 'fuzzable_layers_mutators_chance_per_field',
                                 'fuzzable_layers_mutators_lengths_chance',
                                 'fuzzable_layers_mutators_exclude_fields',
                                 'fuzzable_action_transition')

# random.seed(1)  # Fix the seed to 0
NAME = 'name'
VALUE = 'val'
last_mirror_packet = None
last_fuzzed_packet = None
last_fuzzed_packet_fields = {
    NAME: [],
    VALUE: []
}


def save_last_fuzzed_fields(names, values):
    global last_fuzzed_packet_fields

    del last_fuzzed_packet_fields[NAME][:]
    del last_fuzzed_packet_fields[VALUE][:]

    for (idx, name) in enumerate(names):
        last_fuzzed_packet_fields[NAME].append(name)
        last_fuzzed_packet_fields[VALUE].append(values[idx])


def field_length(field_val):
    # print(name + ' ' + str(type(field_val)) + ' value: ' + str(field_val))
    # check for int
    if type(field_val) is int:
        if field_val == 0:
            return 1
        return int(log(field_val, 256)) + 1
    # check for none, as in len fields
    elif field_val is None:
        return 1
    else:
        return len(field_val)


def get_packet_fuzzable_layers_from_state(packet, state, expected_layers):
    if state in expected_layers:
        counter = 0
        layers = []
        options = expected_layers[state]

        FilteredConfig = options.copy()
        for parameters_name in FilteredConfig.field_names:
            if isinstance(getattr(FilteredConfig, parameters_name), list):  # For all lists in parameters
                setattr(FilteredConfig, parameters_name, [])  # Clear it

        while True:
            layer = packet.getlayer(counter)
            counter += 1
            if layer is None:
                break

            total_idx = 0
            for layerClass in options.fuzzable_layers:  # for all fuzzible layers
                if layerClass == type(layer):  # if layer in packet exists in fuzzable layers
                    layers.append(layer)  # Add layer to the layers list
                    for parameter_name in StateConfig.field_names:  # for each parameter in StateConfig
                        if parameter_name is 'states_expected':
                            continue
                        parameter_val = getattr(options, parameter_name)  # get its values
                        if isinstance(parameter_val, list):  # Check if the value is a list
                            # Insert the configurations for that layer in the FilteredConfig in sequencial order
                            getattr(FilteredConfig, parameter_name).append(parameter_val[total_idx])

                total_idx += 1

        return layers, FilteredConfig

    else:
        return None, None


def fuzz_packet_by_layers(packet, state, states_layers, cls):
    pkt_layers, Config = get_packet_fuzzable_layers_from_state(packet, state, states_layers)
    global last_fuzzed_packet
    fuzzed_fields = 0
    fuzzed_fields_name = []
    fuzzed_fields_value = []
    if pkt_layers:

        # [GLOBAL CHANCE] - global probability of fuzzing the current state
        if random.randint(1, 101) > Config.fuzzable_layers_mutators_global_chance:
            return
        # [GLOBAL CHANCE]

        for idx, pkt_layer in enumerate(pkt_layers):
            # [LAYER CHANCE] - global probability of fuzzing the current state
            if random.randint(1, 101) > Config.fuzzable_layers_mutators_chance_per_layer[idx]:
                continue
            # [LAYER CHANCE]

            for field_desc in pkt_layer.fields_desc:
                # if field_desc.name == 'pwd_data':
                #     print(field_desc.name)
                # [FIELD_IGNORE] Do not fuzz specified fields
                if field_desc.name in Config.fuzzable_layers_mutators_exclude_fields[idx]:
                    # print('ignore ' + field_desc.name)
                    continue
                # [FIELD_IGNORE]

                # [FIELD CHANCE] - global probability of fuzzing the current state
                if random.randint(1, 101) > Config.fuzzable_layers_mutators_chance_per_field[idx]:
                    continue
                # [FIELD CHANCE]

                val = pkt_layer.getfieldval(field_desc.name)

                # [SIZES] post build packet to recalculate sizes, so they can also be fuzzed
                if val is None:
                    if random.randint(1, 101) > Config.fuzzable_layers_mutators_lengths_chance[idx]:
                        continue
                # [SIZES]

                # [Mutate] ---- Based on MutatorSelection, mutate value
                val = Config.fuzzable_layers_selections[idx](val, field_desc.sz, Config, idx)
                pkt_layer.setfieldval(field_desc.name, val)
                # [Mutate]
                fuzzed_fields += 1
                fuzzed_fields_name.append(field_desc.name)
                fuzzed_fields_value.append(val)

        if fuzzed_fields:
            last_fuzzed_packet = packet
            packet.fuzzed = True
        if fuzzed_fields and Dot11Beacon not in packet:
            save_last_fuzzed_fields(fuzzed_fields_name, fuzzed_fields_value)

            print(Fore.MAGENTA + '[FUZZED ' + str(fuzzed_fields) + ' fields] ' + packet.summary())
            print(Fore.MAGENTA + str(fuzzed_fields_name))
            if Config.fuzzable_action_transition is not None:
                last_state = cls.state
                print(Fore.YELLOW + '[FORCED TRANSITION] ' + last_state + ' -> ' +
                      Config.fuzzable_action_transition)
                getattr(cls, 'to_' + Config.fuzzable_action_transition)()  # Force the transition


def send_repeated_packet(cls, method):
    global last_mirror_packet
    # Execute method to repeat packet
    if method.co_argcount == 1:  # Only execute methods with 1 argument (cls)
        print(Fore.BLUE + 'Repeated State: ' + Fore.LIGHTYELLOW_EX + cls.state + Fore.BLUE +
              ', Method: ' + Fore.MAGENTA + method.co_name)
        last_mirror_packet = method.co_name
        getattr(cls, method.co_name)()


def repeat_packet(cls):
    # History pkt buffer (TODO: Integrate in probabilities and states array)
    mirror_chance = random.randint(1, 100)
    if mirror_chance > 80:
        threading.Timer(random.randint(0, 6), send_repeated_packet,
                        (cls, sys._getframe(1).f_back.f_code)).start()


# ----------------------- Selectors --------------
# Randomly select a mutator
def SelectorRandom(value, value_size, Config, idx):
    random_mutator = random.choice(Config.fuzzable_layers_mutators[idx])
    return random_mutator(value, value_size)


# Iterate over mutators
def SelectorAll(value, value_size, Config, idx):
    for mutator in Config.fuzzable_layers_mutators[idx]:
        value = mutator(value, value_size)
    return value


# ----------------------- Mutators --------------
def MutatorRandom(field, type_sz):
    mac_address = False
    if type(field) is int or field is None:
        if type_sz > 6:
            type_sz = 6
        return random.randint(1, numpy.power(2, type_sz * 8) - 1)
    elif isinstance(field, str):
        if ':' in field and g_utils.is_mac(field):  # Check if value is a mac addr string
            mac_address = True
            field = mac2str(field)  # convert mac string to bytes
        data = bytearray(field)
        cast = str
    elif isinstance(field, list):
        data = field
        cast = list
    else:
        return field
    if len(data):
        for _ in range(random.randint(1, len(data))):  # Random iterations up until max data lenght size
            ran_pos = random.randint(0, len(data) - 1)  # Random index
            data[ran_pos] = random.randint(0, 0xFF)
    data = cast(data)
    if mac_address:
        data = ("%02x:" * len(data))[:-1] % tuple(map(ord, data))  # Convert bytes back to mac string
    return data


def MutatorHighBit(field, type_sz):
    if type(field) is int or field is None:
        return numpy.power(2, type_sz * 8) - 1
    elif isinstance(field, str):
        data = bytearray(field)
    elif isinstance(field, list):
        data = field
    else:
        return field
    if len(data):
        for _ in range(random.randint(1, len(data))):  # Random iterations up until max data lenght size
            ran_pos = len(data) - 1  # Random index
            data[ran_pos] = random.randint(0, 0xFF)
    return data


# TODO: MutatorBit
def MutatorBit(field, type_sz):
    bit_index = 0
    if type(field) is int or field is None:

        return random.randint(1, numpy.power(2, type_sz * 8) - 1)
    elif isinstance(field, str):
        data = bytearray(field)
    elif isinstance(field, list):
        data = field
    else:
        return field
    if len(data):
        for _ in range(random.randint(1, len(data))):  # Random iterations up until max data lenght size
            ran_pos = random.randint(0, len(data) - 1)  # Random index
            data[ran_pos] = random.randint(0, 0xFF)
    return data


def MutatorZeroFill(field, type_sz):
    bit_index = 0
    if type(field) is int or field is None:

        return 0
    elif isinstance(field, str):
        data = bytearray(field)
    elif isinstance(field, list):
        data = field
    else:
        return field
    if len(data):
        for _ in range(random.randint(1, len(data))):  # Random iterations up until max data lenght size
            ran_pos = random.randint(0, len(data) - 1)  # Random index
            data[ran_pos] = 0
    return data


def MutatorFullFill(field, type_sz):
    bit_index = 0
    if type(field) is int or field is None:

        return numpy.power(2, type_sz * 8) - 1
    elif isinstance(field, str):
        data = bytearray(field)
    elif isinstance(field, list):
        data = field
    else:
        return field
    if len(data):
        for _ in range(random.randint(1, len(data))):  # Random iterations up until max data lenght size
            ran_pos = random.randint(0, len(data) - 1)  # Random index
            data[ran_pos] = 0xFF
    return data
