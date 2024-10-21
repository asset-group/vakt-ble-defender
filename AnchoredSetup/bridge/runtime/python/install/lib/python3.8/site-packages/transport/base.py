"""
Copyright (c) 2017 Nordic Semiconductor ASA

An abstract base class for specific transport classes.
"""

from abc import ABC, abstractmethod

class TransportBase(ABC):
    @abstractmethod
    def __init__(self, port):
        """Initializes transport.

        Args:
            port (int): A port number that transport shall use.
        """
        self._port = port
        self._receivers = []

    @abstractmethod
    def open(self):
        """Opens transport for communication."""
        pass

    @abstractmethod
    def close(self):
        """Closes transport for communication."""
        pass

    @abstractmethod
    def send(self, data, dest):
        """Sends data to the specified destination.

        Args:
            data (bytes): A data to send.
            dest (piccata.types.Endpoint): A tuple of destination IP address an UDP port.
        """
        pass

    def register_receiver(self, receiver):
        """Registers a reciever, that will get all the data received from the transport.

        Args:
            receiver (obj): A receiver object, that contains receive function.
                The callback function shall be in format:
                receive(payload, remote, local)
        """
        if receiver not in self._receivers:
            self._receivers.append(receiver)

    def remove_receiver(self, receiver):
        """Remove a receiver.

        Args:
            receiver (obj): A receiver object was previously registered.
        """
        if receiver in self._receivers:
            self._receivers.remove(receiver)

    def _receive(self, data, remote, local):
        """This method shall be called whenever transport recevied data.

        Calls callback functions of all registered receivers

        Args:
            type (bytes): A data received through the transport.
            remote (piccata.types.Endpoint): A tuple of source IP address an UDP port.
            local (piccata.types.Endpoint): A tuple of destination IP address an UDP port.
        """
        for rcvr in self._receivers:
            rcvr.receive(data, remote, local)
