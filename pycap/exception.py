class IcapException(Exception):
    """Base exception for ICAP errors."""

    pass


class IcapConnectionError(IcapException):
    """Raised when connection to ICAP server fails."""

    pass


class IcapProtocolError(IcapException):
    """Raised when ICAP protocol error occurs."""

    pass


class IcapTimeoutError(IcapException):
    """Raised when ICAP request times out."""

    pass


class IcapServerError(IcapException):
    """Raised when ICAP server returns a 5xx error response."""

    pass
