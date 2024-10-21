"""
Copyright (c) 2012 Maciej Wasilak <http://sixpinetrees.blogspot.com/>
              2017 Nordic Semiconductor ASA

CoAP message implementation.
"""
import struct
from piccata import option
import os

from piccata.constants import EMPTY, MAX_TRANSMIT_WAIT, ACK, RST, MAX_TOKEN_LENGTH
    
class Message(object):
    """A CoAP Message."""

    def __init__(self, mtype=None, mid=None, code=EMPTY, payload=b'', token=b''):

        if payload is None:
            raise TypeError("Payload must not be None. Use empty string instead.")

        self.version = 1
        self.mtype = mtype
        self.code = code
        self.mid = mid
        self.token = token
        self.opt = option.Options()
        self.payload = payload

        self.remote = None
        self.timeout = MAX_TRANSMIT_WAIT

    @classmethod
    def decode(cls, rawdata, remote=None):
        """Create Message object from binary representation of message."""
        (vttkl, code, mid) = struct.unpack('!BBH', rawdata[:4])
        version = (vttkl & 0xC0) >> 6
        if version is not 1:
            raise ValueError("Fatal Error: Protocol Version must be 1")
        mtype = (vttkl & 0x30) >> 4
        token_length = (vttkl & 0x0F)
        msg = Message(mtype=mtype, mid=mid, code=code)
        msg.token = rawdata[4:4 + token_length]
        msg.payload = msg.opt.decode(rawdata[4 + token_length:])
        msg.remote = remote
        return msg

    def encode(self):
        """Create binary representation of message from Message object."""
        if self.mtype is None or self.mid is None:
            raise TypeError("Fatal Error: Message Type and Message ID must not be None.")
        rawdata = bytes([(self.version << 6) + ((self.mtype & 0x03) << 4) + (len(self.token) & 0x0F)])
        rawdata += struct.pack('!BH', self.code, self.mid)
        rawdata += self.token
        rawdata += self.opt.encode()
        if len(self.payload) > 0:
            rawdata += bytes([0xFF])
            rawdata += self.payload
        return rawdata

    def is_request(self):
        return (self.code >= 1 and self.code < 32)

    def is_response(self):
        return (self.code >= 64 and self.code < 192)

    def is_successfull(self):
        return (self.code >= 64 and self.code < 96)
    
    @classmethod
    def _empty_message(cls, request, mtype):
        response = cls(mtype=mtype, mid=request.mid, code=EMPTY)
        response.remote = request.remote
        return response

    @classmethod
    def AckMessage(cls, request, code, payload=b''):
        ack = cls(mtype=ACK, mid=request.mid, code=code, payload=payload, token=request.token)
        ack.remote = request.remote
        return ack

    @classmethod
    def EmptyAckMessage(cls, request):
        return cls._empty_message(request, ACK)

    @classmethod
    def EmptyRstMessage(cls, request):
        return cls._empty_message(request, RST)

def random_token(length = MAX_TOKEN_LENGTH):
    """Generate a new random token.

    Args:
        length (int): A length of a token. Shall not be greater than MAX_TOKEN_LENGTH.

    Returns:
        A random token byte string of specified length.
    """
    assert length <= MAX_TOKEN_LENGTH
    return os.urandom(length)