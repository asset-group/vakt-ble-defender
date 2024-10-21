"""
Copyright (c) 2012 Maciej Wasilak <http://sixpinetrees.blogspot.com/>
              2017 Nordic Semiconductor ASA

CoAP protocol constants.
"""

COAP_PORT = 5683
"""The IANA-assigned standard port for COAP services."""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | ACK_TIMEOUT       | 2 seconds     |
#   | ACK_RANDOM_FACTOR | 1.5           |
#   | MAX_RETRANSMIT    | 4             |
#   | NSTART            | 1             |
#   | DEFAULT_LEISURE   | 5 seconds     |
#   | PROBING_RATE      | 1 Byte/second |
#   +-------------------+---------------+

ACK_TIMEOUT = 2.0
"""The time, in seconds, to wait for an acknowledgement of a
confirmable message. The inter-transmission time doubles
for each retransmission."""

ACK_RANDOM_FACTOR = 1.5
"""Timeout multiplier for anti-synchronization."""

MAX_RETRANSMIT = 4
"""The number of retransmissions of confirmable messages to
non-multicast endpoints before the infrastructure assumes no
acknowledgement will be received."""

NSTART = 1
"""Maximum number of simultaneous outstanding interactions
   that endpoint maintains to a given server (including proxies)"""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | MAX_TRANSMIT_SPAN |          45 s |
#   | MAX_TRANSMIT_WAIT |          93 s |
#   | MAX_LATENCY       |         100 s |
#   | PROCESSING_DELAY  |           2 s |
#   | MAX_RTT           |         202 s |
#   | EXCHANGE_LIFETIME |         247 s |
#   | NON_LIFETIME      |         145 s |
#   +-------------------+---------------+

MAX_TRANSMIT_SPAN = ACK_TIMEOUT * (2 ** MAX_RETRANSMIT - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to its last retransmission."""

MAX_TRANSMIT_WAIT = ACK_TIMEOUT * (2 ** (MAX_RETRANSMIT + 1) - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to the time when the sender gives up on
receiving an acknowledgement or reset."""

MAX_LATENCY = 100.0
"""Maximum time a datagram is expected to take from the start
of its transmission to the completion of its reception."""

PROCESSING_DELAY = ACK_TIMEOUT
""""Time a node takes to turn around a
confirmable message into an acknowledgement."""

MAX_RTT = 2 * MAX_LATENCY + PROCESSING_DELAY
"""Maximum round-trip time."""

EXCHANGE_LIFETIME = MAX_TRANSMIT_SPAN + MAX_RTT
"""time from starting to send a confirmable
 message to the time when an acknowledgement is no longer expected,
i.e. message layer information about the message exchange can be purged"""

DEFAULT_BLOCK_SIZE_EXP = 2  # Block size 64
"""Default size exponent for blockwise transfers."""

EMPTY_ACK_DELAY = 0.1
"""After this time protocol sends empty ACK, and separate response"""

MAX_TOKEN_LENGTH = 8
"""Maximum length of a token"""

REQUEST_TIMEOUT = MAX_TRANSMIT_WAIT
"""Time after which server assumes it won't receive any answer.
   It is not defined by IETF documents.
   For human-operated devices it might be preferable to set some small value
   (for example 10 seconds)
   For M2M it's application dependent."""

CON = 0
"""Confirmable message type."""

NON = 1
"""Non-confirmable message type."""

ACK = 2
"""Acknowledgement message type."""

RST = 3
"""Reset message type"""

types = {0: 'CON',
         1: 'NON',
         2: 'ACK',
         3: 'RST'}


EMPTY = 0
GET = 1
POST = 2
PUT = 3
DELETE = 4
CREATED = 65
DELETED = 66
VALID = 67
CHANGED = 68
CONTENT = 69
CONTINUE = 95
BAD_REQUEST = 128
UNAUTHORIZED = 129
BAD_OPTION = 130
FORBIDDEN = 131
NOT_FOUND = 132
METHOD_NOT_ALLOWED = 133
NOT_ACCEPTABLE = 134
REQUEST_ENTITY_INCOMPLETE = 136
PRECONDITION_FAILED = 140
REQUEST_ENTITY_TOO_LARGE = 141
UNSUPPORTED_CONTENT_FORMAT = 143
INTERNAL_SERVER_ERROR = 160
NOT_IMPLEMENTED = 161
BAD_GATEWAY = 162
SERVICE_UNAVAILABLE = 163
GATEWAY_TIMEOUT = 164
PROXYING_NOT_SUPPORTED = 165

requests = {1: 'GET',
            2: 'POST',
            3: 'PUT',
            4: 'DELETE'}

requests_rev = {v:k for k, v in requests.items()}

responses = {65: '2.01 Created',
             66: '2.02 Deleted',
             67: '2.03 Valid',
             68: '2.04 Changed',
             69: '2.05 Content',
             95: '2.31 Continue',
             128: '4.00 Bad Request',
             129: '4.01 Unauthorized',
             130: '4.02 Bad Option',
             131: '4.03 Forbidden',
             132: '4.04 Not Found',
             133: '4.05 Method Not Allowed',
             134: '4.06 Not Acceptable',
             136: '4.08 Request Entity Incomplete',
             140: '4.12 Precondition Failed',
             141: '4.13 Request Entity Too Large',
             143: '4.15 Unsupported Content-Format',
             160: '5.00 Internal Server Error',
             161: '5.01 Not Implemented',
             162: '5.02 Bad Gateway',
             163: '5.03 Service Unavailable',
             164: '5.04 Gateway Timeout',
             165: '5.05 Proxying Not Supported'}

responses_rev = {v:k for k, v in responses.items()}

#=============================================================================
# RFC7252, block-14, observe-11
#=============================================================================
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# | No. | C | U | N | R | Name           | Format     | Length | Default     |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# |   1 | x |   |   | x | If-Match       | opaque     | 0-8    | (none)      |
# |   3 | x | x | - |   | Uri-Host       | string     | 1-255  | (see below) |
# |   4 |   |   |   | x | ETag           | opaque     | 1-8    | (none)      |
# |   5 | x |   |   |   | If-None-Match  | empty      | 0      | (none)      |
# |   6 |   | x |   |   | Observe        | empty/uint | ?      | (none)      |
# |   7 | x | x | - |   | Uri-Port       | uint       | 0-2    | (see below) |
# |   8 |   |   |   | x | Location-Path  | string     | 0-255  | (none)      |
# |  11 | x | x | - | x | Uri-Path       | string     | 0-255  | (none)      |
# |  12 |   |   |   |   | Content-Format | uint       | 0-2    | (none)      |
# |  14 |   | x |   |   | Max-Age        | uint       | 0-4    | 60          |
# |  15 | x | x | - | x | Uri-Query      | string     | 0-255  | (none)      |
# |  17 | x |   |   |   | Accept         | uint       | 0-2    | (none)      |
# |  20 |   |   |   | x | Location-Query | string     | 0-255  | (none)      |
# |  23 | x | x | - | - | Block2         | uint       | 0-3    | (see below) |
# |  27 | x | x | - | - | Block1         | uint       | 0-3    | (see below) |
# |  28 |   |   | x |   | Size2          | uint       | 0-4    | (none)      |
# |  35 | x | x | - |   | Proxy-Uri      | string     | 1-1034 | (none)      |
# |  39 | x | x | - |   | Proxy-Scheme   | string     | 1-255  | (none)      |
# |  60 |   |   | x |   | Size1          | uint       | 0-4    | (none)      |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
#=============================================================================
#
# This table should serve as a reference only. It does not confirm that
# txThings conforms to the documents above
#

IF_MATCH = 1
URI_HOST = 3
ETAG = 4
IF_NONE_MATCH = 5
OBSERVE = 6
URI_PORT = 7
LOCATION_PATH = 8
URI_PATH = 11
CONTENT_FORMAT = 12
MAX_AGE = 14
URI_QUERY = 15
ACCEPT = 17
LOCATION_QUERY = 20
BLOCK2 = 23
BLOCK1 = 27
SIZE2 = 28
PROXY_URI = 35
PROXY_SCHEME = 39
SIZE1 = 60

options = {1: 'If-Match',
           3: 'Uri-Host',
           4: 'ETag',
           5: 'If-None-Match',
           6: 'Observe',
           7: 'Uri-Port',
           8: 'Location-Path',
           11: 'Uri-Path',
           12: 'Content-Format',
           14: 'Max-Age',
           15: 'Uri-Query',
           17: 'Accept',
           20: 'Location-Query',
           23: 'Block2',
           27: 'Block1',
           28: 'Size2',
           35: 'Proxy-Uri',
           39: 'Proxy-Scheme',
           60: 'Size1'}

options_rev = {v:k for k, v in options.items()}

media_types = {0: 'text/plain',
               40: 'application/link-format',
               41: 'application/xml',
               42: 'application/octet-stream',
               47: 'application/exi',
               50: 'application/json',
               60: 'application/cbor'}
"""A map from CoAP-assigned integral codes to Internet media type descriptions."""

media_types_rev = {v:k for k, v in media_types.items()}

RESULT_SUCCESS = 0
RESULT_RESET = 1
RESULT_TIMEOUT = 2
RESULT_CANCELLED = 3