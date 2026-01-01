import logging

from .icap import IcapClient
from .response import IcapResponse
from .exception import (
    IcapException,
    IcapConnectionError,
    IcapProtocolError,
    IcapTimeoutError
)

# Set up logging with NullHandler to avoid "No handler found" warnings
logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"

__all__ = [
    "IcapClient",
    "IcapResponse",
    "IcapException",
    "IcapConnectionError",
    "IcapProtocolError",
    "IcapTimeoutError",
]
