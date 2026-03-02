"""
Call recording for mock ICAP clients.

This module provides the MockCall dataclass for recording method invocations
and the MockResponseExhaustedError for queue exhaustion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from icap import IcapResponse


class MockResponseExhaustedError(Exception):
    """
    Raised when all queued mock responses have been consumed.

    This error indicates that more method calls were made than responses
    were configured. Configure additional responses or use a callback
    for dynamic response generation.

    Example:
        >>> client = MockIcapClient()
        >>> client.on_respmod(
        ...     IcapResponseBuilder().clean().build(),
        ...     IcapResponseBuilder().virus().build(),
        ... )
        >>> client.scan_bytes(b"file1")  # Returns clean
        >>> client.scan_bytes(b"file2")  # Returns virus
        >>> client.scan_bytes(b"file3")  # Raises MockResponseExhaustedError
    """

    pass


@dataclass
class MockCall:
    """
    Record of a single method call on a MockIcapClient.

    MockCall instances are created automatically when methods are called on
    the mock client and stored in the `calls` list for later inspection.

    Attributes:
        method: Name of the method that was called (e.g., "scan_bytes", "options").
        timestamp: Unix timestamp when the call was made (from time.time()).
        kwargs: Dictionary of keyword arguments passed to the method. The keys
            depend on the method called:
            - options: {"service": str}
            - respmod: {"service": str, "http_request": bytes, "http_response": bytes,
                        "headers": dict|None, "preview": int|None}
            - reqmod: {"service": str, "http_request": bytes, "http_body": bytes|None,
                       "headers": dict|None}
            - scan_bytes: {"data": bytes, "service": str, "filename": str|None}
            - scan_file: {"filepath": str, "service": str, "data": bytes}
            - scan_stream (sync): {"data": bytes, "service": str, "filename": str|None,
                                   "chunk_size": int}
            - scan_stream (async): {"data": bytes, "service": str, "filename": str|None}
              Note: async scan_stream doesn't have chunk_size (matches AsyncIcapClient API)
        response: The IcapResponse returned by the call (None if exception raised).
        exception: The exception raised by the call (None if successful).
        matched_by: How the response was determined: "matcher", "callback", "queue",
            or "default". Useful for debugging which configuration produced the response.
        call_index: Position in the call history (0-based).

    Properties:
        data: Shorthand for kwargs.get("data") - the scanned content.
        filename: Shorthand for kwargs.get("filename") - the filename if provided.
        service: Shorthand for kwargs.get("service") - the service name.
        succeeded: True if the call completed without raising an exception.
        was_clean: True if the response indicates no modification (clean scan).
        was_virus: True if the response indicates virus detection.

    Example - Basic inspection:
        >>> client = MockIcapClient()
        >>> client.scan_bytes(b"test", filename="test.txt")
        >>> call = client.calls[0]
        >>> call.method
        'scan_bytes'
        >>> call.data
        b'test'
        >>> call.filename
        'test.txt'
        >>> call.was_clean
        True
        >>> call.matched_by
        'default'

    Example - Checking virus detection:
        >>> client.on_respmod(IcapResponseBuilder().virus("Trojan").build())
        >>> client.scan_bytes(b"malware")
        >>> call = client.last_call
        >>> call.was_virus
        True
        >>> call.response.headers["X-Virus-ID"]
        'Trojan'

    Example - Exception tracking:
        >>> client.on_respmod(raises=IcapTimeoutError("Timeout"))
        >>> try:
        ...     client.scan_bytes(b"data")
        ... except IcapTimeoutError:
        ...     pass
        >>> call = client.calls[-1]
        >>> call.succeeded
        False
        >>> type(call.exception).__name__
        'IcapTimeoutError'
    """

    method: str
    timestamp: float
    kwargs: dict[str, Any] = field(default_factory=dict)

    # Track response/exception and how it was determined
    response: IcapResponse | None = None
    exception: Exception | None = None
    matched_by: str | None = None  # "matcher", "callback", "queue", or "default"
    call_index: int = 0

    # === Convenience Properties ===

    @property
    def data(self) -> bytes | None:
        """
        Get the scanned data if this was a scan call.

        Returns:
            The bytes that were scanned, or None if not a scan call.
        """
        return self.kwargs.get("data")

    @property
    def filename(self) -> str | None:
        """
        Get the filename if provided to the call.

        Returns:
            The filename argument, or None if not provided.
        """
        return self.kwargs.get("filename")

    @property
    def service(self) -> str | None:
        """
        Get the service name used in the call.

        Returns:
            The service name (e.g., "avscan"), or None if not provided.
        """
        return self.kwargs.get("service")

    @property
    def succeeded(self) -> bool:
        """
        Check if the call completed successfully (didn't raise an exception).

        Returns:
            True if the call returned a response, False if it raised an exception.
        """
        return self.exception is None

    @property
    def was_clean(self) -> bool:
        """
        Check if the call resulted in a clean (no modification) response.

        Returns:
            True if the call succeeded and returned a 204 No Modification response.
            False if an exception was raised or the response indicates modification.
        """
        return (
            self.exception is None
            and self.response is not None
            and self.response.is_no_modification
        )

    @property
    def was_virus(self) -> bool:
        """
        Check if the call resulted in a virus detection.

        Returns:
            True if the call succeeded and the response contains an X-Virus-ID header.
            False if an exception was raised, response is clean, or no virus header present.
        """
        return (
            self.exception is None
            and self.response is not None
            and not self.response.is_no_modification
            and "X-Virus-ID" in self.response.headers
        )

    def __repr__(self) -> str:
        """
        Return a rich string representation for debugging.

        Format: method(data=..., filename=...) -> result
        Where result is one of: clean, virus(name), raised ExceptionType
        """
        parts = [f"{self.method}("]

        # Show truncated data if present
        if self.data is not None:
            if len(self.data) > 20:
                parts.append(f"data={self.data[:20]!r}...")
            else:
                parts.append(f"data={self.data!r}")

        # Show filename if present
        if self.filename:
            if self.data is not None:
                parts.append(f", filename={self.filename!r}")
            else:
                parts.append(f"filename={self.filename!r}")

        # Show service if different from default
        if self.service and self.service != "avscan":
            if self.data is not None or self.filename:
                parts.append(f", service={self.service!r}")
            else:
                parts.append(f"service={self.service!r}")

        parts.append(")")

        # Show result
        if self.was_clean:
            parts.append(" -> clean")
        elif self.was_virus:
            # was_virus property guarantees self.response is not None
            assert self.response is not None
            virus_id = self.response.headers.get("X-Virus-ID", "unknown")
            parts.append(f" -> virus({virus_id})")
        elif self.exception:
            parts.append(f" -> raised {type(self.exception).__name__}")
        elif self.response:
            parts.append(f" -> {self.response.status_code}")

        return "".join(parts)


__all__ = ["MockCall", "MockResponseExhaustedError"]
