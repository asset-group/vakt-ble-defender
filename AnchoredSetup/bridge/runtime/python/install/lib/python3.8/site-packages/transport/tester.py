"""
Copyright (c) 2017 Nordic Semiconductor ASA

CoAP transport class for tests.
"""
from transport.base import TransportBase


class TesterTransport(TransportBase):

    def __init__(self, port=None):
        TransportBase.__init__(self, port)

        self.tester_opened = False
        self.tester_data = None
        self.tester_remote = None
        self.output_count = 0

    def open(self):
        self.tester_opened = True

    def close(self):
        self.tester_opened = False

    def send(self, data, dest):
        self.tester_data = data
        self.tester_remote = dest
        self.output_count += 1
