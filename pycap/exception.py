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
