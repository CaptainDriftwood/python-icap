"""
ICAP client exceptions.

This module defines the exception hierarchy for the ICAP client. All exceptions
inherit from IcapException, allowing you to catch all ICAP-related errors with
a single except clause, or handle specific error types individually.

Exception Hierarchy:
    IcapException (base)
    ├── IcapConnectionError - Network/connection failures
    ├── IcapTimeoutError - Operation timeouts
    ├── IcapProtocolError - Malformed responses
    └── IcapServerError - Server-side errors (5xx)

Example:
    >>> from pycap import IcapClient
    >>> from pycap.exception import IcapConnectionError, IcapTimeoutError
    >>>
    >>> try:
    ...     with IcapClient("localhost") as client:
    ...         response = client.scan_file("/path/to/file.pdf")
    ... except IcapConnectionError:
    ...     print("Could not connect to ICAP server")
    ... except IcapTimeoutError:
    ...     print("Request timed out")
"""


class IcapException(Exception):
    """
    Base exception for all ICAP-related errors.

    Catch this to handle any ICAP error regardless of specific type.

    Example:
        >>> try:
        ...     response = client.scan_file(path)
        ... except IcapException as e:
        ...     logger.error(f"ICAP operation failed: {e}")
    """

    pass


class IcapConnectionError(IcapException):
    """
    Raised when connection to the ICAP server fails.

    This includes:
    - Unable to establish TCP connection (server down, wrong host/port)
    - SSL/TLS handshake failures
    - Connection reset or broken pipe during communication
    - DNS resolution failures

    Example:
        >>> try:
        ...     client.connect()
        ... except IcapConnectionError as e:
        ...     print(f"Connection failed: {e}")
        ...     # Retry with fallback server, alert ops, etc.
    """

    pass


class IcapProtocolError(IcapException):
    """
    Raised when the ICAP server returns a malformed or unparseable response.

    This indicates the server sent data that doesn't conform to RFC 3507,
    such as an invalid status line or malformed headers. This typically
    indicates a server bug or network corruption.

    Example:
        >>> try:
        ...     response = client.scan_bytes(data)
        ... except IcapProtocolError as e:
        ...     print(f"Server sent invalid response: {e}")
        ...     # Log for debugging, possibly try different server
    """

    pass


class IcapTimeoutError(IcapException):
    """
    Raised when an ICAP operation times out.

    This can occur during:
    - Initial connection attempt
    - Sending request data
    - Waiting for server response

    The timeout duration is configured when creating the client.

    Example:
        >>> client = IcapClient("localhost", timeout=30)  # 30 second timeout
        >>> try:
        ...     response = client.scan_file(large_file)
        ... except IcapTimeoutError:
        ...     print("Scan took too long, consider increasing timeout")
    """

    pass


class IcapServerError(IcapException):
    """
    Raised when the ICAP server returns a 5xx error response.

    This indicates a server-side problem such as:
    - 500 Internal Server Error
    - 502 Bad Gateway
    - 503 Service Unavailable (e.g., antivirus engine not ready)
    - 505 ICAP Version Not Supported

    Unlike other exceptions, this means the connection succeeded but the
    server could not process the request.

    Example:
        >>> try:
        ...     response = client.scan_bytes(data)
        ... except IcapServerError as e:
        ...     print(f"Server error: {e}")
        ...     # Server might be overloaded, retry after delay
    """

    pass
