"""
Copyright (c) 2017 Nordic Semiconductor ASA

CoAP transport implmentation based on sockets.
"""
import socket
import time
import errno

from threading import Thread
from ipaddress import ip_address
from transport.base import TransportBase

MTU = 1500

class ListenerThread(Thread):

    def __init__(self, sock, receive_callback):
        Thread.__init__(self)

        self.daemon = True

        self._sock = sock
        self._receive_callback = receive_callback
        self._terminate = False

    def run(self):
        while not self._terminate:
            try:
                data, addr = self._sock.recvfrom(MTU)
                addr = (ip_address(addr[0]), addr[1])
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # If no data is available, one of the following will be raised.
                    time.sleep(0.001)
                    continue
                else:
                    # Other exception raised
                    print(e)
                    break
            else:
                if len(data) == 0:
                    print("shutdown!")
                    break
                else:
                    own_addr = self._sock.getsockname()
                    own_addr = (ip_address(own_addr[0]), own_addr[1])
                    self._receive_callback(data, addr, own_addr)

    def stop(self):
        self._terminate = True

class SocketTransport(TransportBase):

    def __init__(self, port=0):
        TransportBase.__init__(self, port)

        self._sock = None
        self._listener_thread = None

    def _close_listener(self):
        self._listener_thread.stop()
        self._listener_thread.join()
        self._listener_thread = None

    def open(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(0)
        self._sock.bind(('', self._port))

        # Start the listener thread.
        if self._listener_thread != None:
            self._close_listener()

        self._listener_thread = ListenerThread(self._sock, self._receive)
        self._listener_thread.start()

    def close(self):
        # Wait for the listener thread to finish
        if self._listener_thread != None:
            self._close_listener()

        if self._sock != None:
            self._sock.close()
            self._sock = None

    def send(self, data, dest):
        self._sock.sendto(data, (str(dest[0]), dest[1]))
