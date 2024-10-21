import re
import os

regex_is_mac_str = re.compile("[A-Fa-f0-9]{2}:")


def is_mac(s):
    return regex_is_mac_str.match(s) is not None


def gen_nonce(size):
    """Return a nonce of @size element of random bytes as a string"""
    return raw(os.urandom(size))
