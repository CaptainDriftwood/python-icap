import io
import pathlib
import socket


class IcapClient:
    DEFAULT_PORT = 1344
    END_LINE_DELIMETER = "\r\n"

    def __init__(self, address, port=DEFAULT_PORT):
        self.address = address
        self.port = port
        self._started = False
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @property
    def host(self):
        return self.address

    @property
    def port(self):
        return self.port

    def connect(self):
        self.__socket.bind((self.host, self.port))
        self.__socket.setblocking(True)

    def icap_request_header(self):

        pass

    def perform_adaptation(self):
        return

    def send(self):
        pass

    @port.setter
    def port(self, value):
        self._port = value


