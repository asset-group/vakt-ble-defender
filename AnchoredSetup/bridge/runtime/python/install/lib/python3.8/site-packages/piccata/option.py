"""
Copyright (c) 2012 Maciej Wasilak <http://sixpinetrees.blogspot.com/>
              2017 Nordic Semiconductor ASA

CoAP option processing.
"""
import collections
import struct
from itertools import chain
from abc import ABC, abstractmethod

from piccata.constants import *

class Options(object):
    """Represent CoAP Header Options."""

    def __init__(self):
        self._options = {}

    def decode(self, rawdata):
        """Decode all options in message from raw binary data."""
        option_number = 0
        while len(rawdata) > 0:
            if rawdata[0] == 0xFF:
                return rawdata[1:]
            dllen = rawdata[0]
            delta = (dllen & 0xF0) >> 4
            length = (dllen & 0x0F)
            rawdata = rawdata[1:]
            (delta, rawdata) = self.read_extended_field_value(delta, rawdata)
            (length, rawdata) = self.read_extended_field_value(length, rawdata)
            option_number += delta
            option = option_formats.get(option_number, OpaqueOption)(option_number)
            option.decode(rawdata[:length])
            self.add_option(option)
            rawdata = rawdata[length:]
        return b''

    def encode(self):
        """Encode all options in option header into string of bytes."""
        data = []
        current_opt_num = 0
        option_list = self.option_list()
        for option in option_list:
            delta, extended_delta = self.write_extended_field_value(int(option.number - current_opt_num))
            length, extended_length = self.write_extended_field_value(int(option.length))
            data.append(bytes([((delta & 0x0F) << 4) + (length & 0x0F)]))
            data.append(extended_delta)
            data.append(extended_length)
            data.append(option.encode())
            current_opt_num = option.number
        return (b''.join(data))

    def add_option(self, option):
        """Add option into option header."""
        self._options.setdefault(option.number, []).append(option)

    def delete_option(self, number):
        """Delete option from option header."""
        if number in self._options:
            self._options.pop(number)

    def get_option(self, number):
        """Get option with specified number."""
        return self._options.get(number)

    def option_list(self):
        return chain.from_iterable(sorted(self._options.values(), key=lambda x: x[0].number))

    def get_uri_path_as_string(self):
        return '/' + '/'.join(self.uri_path)

    def _set_uri_path(self, segments):
        """Convenience setter: Uri-Path option"""
        if isinstance(segments, (str, bytes)):
            raise ValueError("URI Path should be passed as a list or tuple of segments")
        self.delete_option(number=URI_PATH)
        for segment in segments:
            self.add_option(StringOption(number=URI_PATH, value=segment))

    def _get_uri_path(self):
        """Convenience getter: Uri-Path option"""
        segment_list = []
        uri_path = self.get_option(number=URI_PATH)
        if uri_path is not None:
            for segment in uri_path:
                segment_list.append(segment.value)
        return segment_list

    uri_path = property(_get_uri_path, _set_uri_path)

    def _set_uri_query(self, segments):
        """Convenience setter: Uri-Query option"""
        if isinstance(segments, (str, bytes)):
            raise ValueError("URI Query should be passed as a list or tuple of segments")
        self.delete_option(number=URI_QUERY)
        for segment in segments:
            self.add_option(StringOption(number=URI_QUERY, value=segment))

    def _get_uri_query(self):
        """Convenience getter: Uri-Query option"""
        segment_list = []
        uri_query = self.get_option(number=URI_QUERY)
        if uri_query is not None:
            for segment in uri_query:
                segment_list.append(segment.value)
        return segment_list

    uri_query = property(_get_uri_query, _set_uri_query)

    def _set_block_2(self, block_tuple):
        """Convenience setter: Block2 option"""
        self.delete_option(number=BLOCK2)
        self.add_option(BlockOption(number=BLOCK2, value=block_tuple))

    def _get_block_2(self):
        """Convenience getter: Block2 option"""
        block2 = self.get_option(number=BLOCK2)
        if block2 is not None:
            return block2[0].value
        else:
            return None

    block2 = property(_get_block_2, _set_block_2)

    def _set_block_1(self, block_tuple):
        """Convenience setter: Block1 option"""
        self.delete_option(number=BLOCK1)
        self.add_option(BlockOption(number=BLOCK1, value=block_tuple))

    def _get_block_1(self):
        """Convenience getter: Block1 option"""
        block1 = self.get_option(number=BLOCK1)
        if block1 is not None:
            return block1[0].value
        else:
            return None

    block1 = property(_get_block_1, _set_block_1)

    def _set_content_format(self, content_format):
        """Convenience setter: Content-Format option"""
        self.delete_option(number=CONTENT_FORMAT)
        self.add_option(UintOption(number=CONTENT_FORMAT, value=content_format))

    def _get_content_format(self):
        """Convenience getter: Content-Format option"""
        content_format = self.get_option(number=CONTENT_FORMAT)
        if content_format is not None:
            return content_format[0].value
        else:
            return None

    content_format = property(_get_content_format, _set_content_format)

    def _set_etag(self, etag):
        """Convenience setter: ETag option"""
        self.delete_option(number=ETAG)
        if etag is not None:
            self.add_option(OpaqueOption(number=ETAG, value=etag))

    def _get_etag(self):
        """Convenience getter: ETag option"""
        etag = self.get_option(number=ETAG)
        if etag is not None:
            return etag[0].value
        else:
            return None

    etag = property(_get_etag, _set_etag, None, "Access to a single ETag on the message (as used in responses)")

    def _set_etags(self, etags):
        self.delete_option(number=ETAG)
        for tag in etags:
            self.add_option(OpaqueOption(number=ETAG, value=tag))

    def _get_etags(self):
        etag = self.get_option(number=ETAG)
        return [] if etag is None else [tag.value for tag in etag]

    etags = property(_get_etags, _set_etags, None, "Access to a list of ETags on the message (as used in requests)")

    def _set_observe(self, observe):
        self.delete_option(number=OBSERVE)
        if observe is not None:
            self.add_option(UintOption(number=OBSERVE, value=observe))

    def _get_observe(self):
        observe = self.get_option(number=OBSERVE)
        if observe is not None:
            return observe[0].value
        else:
            return None

    observe = property(_get_observe, _set_observe)

    def _set_accept(self, accept):
        self.delete_option(number=ACCEPT)
        if accept is not None:
            self.add_option(UintOption(number=ACCEPT, value=accept))

    def _get_accept(self):
        accept = self.get_option(number=ACCEPT)
        if accept is not None:
            return accept[0].value
        else:
            return None

    accept = property(_get_accept, _set_accept)

    def _set_location_path(self, segments):
        """Convenience setter: Location-Path option"""
        if isinstance(segments, (str, bytes)):
            raise ValueError("Location Path should be passed as a list or tuple of segments")
        self.delete_option(number=LOCATION_PATH)
        for segment in segments:
            self.add_option(StringOption(number=LOCATION_PATH, value=segment))

    def _get_location_path(self):
        """Convenience getter: Location-Path option"""
        segment_list = []
        location_path = self.get_option(number=LOCATION_PATH)
        if location_path is not None:
            for segment in location_path:
                segment_list.append(segment.value)
        return segment_list

    location_path = property(_get_location_path, _set_location_path)

    @staticmethod
    def read_extended_field_value(value, rawdata):
        """Used to decode large values of option delta and option length
        from raw binary form."""
        if value >= 0 and value < 13:
            return (value, rawdata)
        elif value == 13:
            return (rawdata[0] + 13, rawdata[1:])
        elif value == 14:
            return (struct.unpack('!H', rawdata[:2])[0] + 269, rawdata[2:])
        else:
            raise ValueError("Value out of range.")

    @staticmethod
    def write_extended_field_value(value):
        """Used to encode large values of option delta and option length
        into raw binary form.
        In CoAP option delta and length can be represented by a variable
        number of bytes depending on the value."""
        if value >= 0 and value < 13:
            return (value, b'')
        elif value >= 13 and value < 269:
            return (13, struct.pack('!B', value - 13))
        elif value >= 269 and value < 65804:
            return (14, struct.pack('!H', value - 269))
        else:
            raise ValueError("Value out of range.")


class Option(ABC):
    @abstractmethod
    def encode(self):
        pass

    @abstractmethod
    def decode(self):
        pass

    @abstractmethod
    def _length(self):
        pass


class OpaqueOption(Option):
    """Opaque CoAP option - used to represent opaque options.
       This is a default option type."""

    def __init__(self, number, value=""):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = self.value
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata  # if rawdata is not None else ""

    def _length(self):
        return len(self.value)
    length = property(_length)


class StringOption(Option):
    """String CoAP option - used to represent string options."""

    def __init__(self, number, value=""):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = self.value
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata  # if rawdata is not None else ""

    def _length(self):
        return len(self.value)
    length = property(_length)


class UintOption(Option):
    """Uint CoAP option - used to represent uint options."""

    def __init__(self, number, value=0):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = struct.pack("!L", self.value)  # For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(bytes([0]))

    def decode(self, rawdata):  # For Python >3.1 replace with int.from_bytes()
        value = 0
        for byte in rawdata:
            value = (value * 256) + byte
        self.value = value
        return self

    def _length(self):
        if self.value > 0:
            return (self.value.bit_length() - 1) // 8 + 1
        else:
            return 0
    length = property(_length)


class BlockOption(Option):
    """Block CoAP option - special option used only for Block1 and Block2 options.
       Currently it is the only type of CoAP options that has
       internal structure."""
    BlockwiseTuple = collections.namedtuple('BlockwiseTuple', ['num', 'm', 'szx'])

    def __init__(self, number, value=(0, None, 0)):
        self.value = self.BlockwiseTuple._make(value)
        self.number = number

    def encode(self):
        as_integer = (self.value[0] << 4) + (self.value[1] * 0x08) + self.value[2]
        rawdata = struct.pack("!L", as_integer)  # For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(bytes([0]))

    def decode(self, rawdata):
        as_integer = 0
        for byte in rawdata:
            as_integer = (as_integer * 256) + byte
        self.value = self.BlockwiseTuple(num=(as_integer >> 4), m=bool(as_integer & 0x08), szx=(as_integer & 0x07))

    def _length(self):
        return ((self.value[0].bit_length() + 3) / 8 + 1)
    length = property(_length)

option_formats = {3:  StringOption,     # If-Match
                  6:  UintOption,       # Observe
                  7:  UintOption,       # Uri-Port
                  8:  StringOption,     # Location-Path
                  11: StringOption,     # Uri-Path
                  12: UintOption,       # Content-Format
                  14: UintOption,       # Max-Age
                  15: StringOption,     # Uri-Query
                  17: UintOption,       # Accept
                  20: StringOption,     # Location-Query
                  23: BlockOption,      # Block2
                  27: BlockOption,      # Block1
                  28: UintOption,       # Size2
                  35: StringOption,     # Proxy-Uri
                  39: StringOption,     # Proxy-Scheme
                  60: UintOption}       # Size1
"""Dictionary used to assign option type to option numbers."""
