"""Pure-Python ICAP (Internet Content Adaptation Protocol) client library.

python-icap implements RFC 3507 for talking to ICAP servers such as c-icap and
SquidClamav, typically for virus scanning, content filtering, or data loss
prevention. It has no external dependencies and ships both a synchronous client
(``IcapClient``) and an asyncio client (``AsyncIcapClient``) that share the same
API.

Public API:
    Clients:
        - ``IcapClient`` - Synchronous client.
        - ``AsyncIcapClient`` - Asyncio client with the same methods (awaited).
    Responses:
        - ``IcapResponse`` - Result of any OPTIONS/REQMOD/RESPMOD request.
        - ``EncapsulatedParts`` - Parsed offsets from the Encapsulated header.
        - ``CaseInsensitiveDict`` - Case-insensitive mapping used for headers.
    Exceptions (all inherit from ``IcapException``):
        - ``IcapConnectionError`` - Network/connection failures.
        - ``IcapTimeoutError`` - Operation timeouts.
        - ``IcapProtocolError`` - Malformed or unparseable responses.
        - ``IcapServerError`` - Server-side 5xx errors.

Example:
    >>> from icap import IcapClient
    >>>
    >>> with IcapClient("localhost", port=1344) as client:
    ...     response = client.scan_file("/path/to/file.pdf")
    ...     if response.is_no_modification:
    ...         print("File is clean")
    ...     else:
    ...         print(f"Threat: {response.headers.get('X-Virus-ID')}")

The async client mirrors this API; use ``async with AsyncIcapClient(...)`` and
``await`` each request. The installed version is available as ``icap.__version__``.
"""

import logging
from importlib.metadata import version

from .async_icap import AsyncIcapClient
from .exception import (
    IcapConnectionError,
    IcapException,
    IcapProtocolError,
    IcapServerError,
    IcapTimeoutError,
)
from .icap import IcapClient
from .response import CaseInsensitiveDict, EncapsulatedParts, IcapResponse

# Set up logging with NullHandler to avoid "No handler found" warnings
logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = version("python-icap")

__all__ = [
    "AsyncIcapClient",
    "CaseInsensitiveDict",
    "EncapsulatedParts",
    "IcapClient",
    "IcapResponse",
    "IcapException",
    "IcapConnectionError",
    "IcapProtocolError",
    "IcapServerError",
    "IcapTimeoutError",
]
