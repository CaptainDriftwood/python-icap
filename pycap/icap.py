import socket


class ICAP(object):
    DEFAULT_PORT = 1344

    def __init__(self, address, port=None):
        self.address = address
        self.port = port
        self._started = False
        self.socket = None

    def connect(self, host: str, port: int = DEFAULT_PORT):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pass
