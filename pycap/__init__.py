import logging

from .async_icap import AsyncIcapClient
from .exception import (
    IcapConnectionError,
    IcapException,
    IcapProtocolError,
    IcapServerError,
    IcapTimeoutError,
)
from .icap import IcapClient
from .response import IcapResponse

# Set up logging with NullHandler to avoid "No handler found" warnings
logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"

__all__ = [
    "AsyncIcapClient",
    "IcapClient",
    "IcapResponse",
    "IcapException",
    "IcapConnectionError",
    "IcapProtocolError",
    "IcapServerError",
    "IcapTimeoutError",
]
