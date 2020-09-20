import io
import pathlib
import socket


# TODO Add async support as well
# TODO Add support for context management protocol
# TODO Add method to scan filepath, or IO object

class IcapClient:
    DEFAULT_PORT = 1344
    END_LINE_DELIMETER = "\r\n"

    def __init__(self, address, port=DEFAULT_PORT):
        self._address = address
        self._port = port
        self._started = False
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @property
    def host(self):
        return self._address

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, p: int):
        if not isinstance(p, int):
            raise TypeError("Port is not valid type. Please enter an int value.")
        self._port = p

    def connect(self):
        self._socket.bind((self.host, self.port))
        self._socket.setblocking(True)

    def icap_request_header(self):
        pass

    def perform_adaptation(self):
        return

    def send(self):
        pass
