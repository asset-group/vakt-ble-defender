# import time
# from scapy.layers.bluetooth import *
# from scapy.utils import raw
#
# s = HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request()
#
# data = bytearray(raw(s))
#
# c_array = ''
#
# c_array = 'uint8_t packet[] = { '
# for idx, b in enumerate(data):
#     c_array += hex(b)
#     if idx is not len(data) - 1:
#         c_array += ', '
#         if idx != 0 and idx % 8 == 0:
#             c_array += '\n'
# c_array += ' };'
#
# print(c_array)
#
# x = '0001020304'.decode('hex')
#
# x = HCI_Hdr(x)
# x.show()


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from scapy.layers.bluetooth4LE import *
from scapy.utils import raw, wrpcap, rdpcap
from binascii import hexlify

read_pkts = rdpcap('test.pcap')
pkts = []

# for pkt in read_pkts:
#     pkts.append(BTLE(pkt.load))

# wrpcap('pairing.pcap', pkts)
print(read_pkts[0].summary())
read_pkts[0].show()

print('finished')
