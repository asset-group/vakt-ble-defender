#!runtime/python/install/bin/python3


import pygatt
import binascii

adapter = pygatt.GATTToolBackend()

try:
    adapter.start()
    device = adapter.connect('3c:61:05:4c:33:6e')
    for uuid in device.discover_characteristics().keys():
        print("Read UUID %s: %s" % (uuid, binascii.hexlify(device.char_read(uuid))))
finally:
    adapter.stop()