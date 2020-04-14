from . import request


class ICAP(object):
    DEFAULT_PORT = 1344

    def __init__(self, address, port=None):
        self.address = address
        self.port = port
        self._started = False
        self.socket = None

    @property
    def started(self):
        return self._started

    def start(self):
        if self.started:
            raise IOError("ICAP session already opened")

        pass
