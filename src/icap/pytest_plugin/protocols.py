"""
Protocol definitions for mock response callbacks.

This module defines the callback protocols used for dynamic response generation
in MockIcapClient and MockAsyncIcapClient.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from icap import IcapResponse


class ResponseCallback(Protocol):
    """
    Protocol for synchronous response callbacks.

    Callbacks receive the request context and return an IcapResponse.
    Use this for dynamic response generation based on content, filename,
    or service name.

    The callback signature is flexible:
        - Required: `data` (bytes) - the content being scanned
        - Optional keyword arguments: `service`, `filename`, and others

    Example signatures (all valid):
        >>> def simple_callback(data: bytes, **kwargs) -> IcapResponse: ...
        >>> def detailed_callback(
        ...     data: bytes,
        ...     *,
        ...     service: str,
        ...     filename: str | None,
        ...     **kwargs
        ... ) -> IcapResponse: ...

    Example:
        >>> def eicar_detector(data: bytes, **kwargs) -> IcapResponse:
        ...     if b"EICAR" in data:
        ...         return IcapResponseBuilder().virus("EICAR-Test").build()
        ...     return IcapResponseBuilder().clean().build()
        >>>
        >>> client = MockIcapClient()
        >>> client.on_respmod(callback=eicar_detector)

    See Also:
        AsyncResponseCallback: Async version for MockAsyncIcapClient.
        MockIcapClient.on_respmod: Configure callbacks for scan methods.
    """

    def __call__(
        self,
        data: bytes,
        *,
        service: str,
        filename: str | None = None,
        **kwargs: Any,
    ) -> IcapResponse: ...


class AsyncResponseCallback(Protocol):
    """
    Protocol for asynchronous response callbacks.

    Async version of ResponseCallback for use with MockAsyncIcapClient.
    Callbacks receive the request context and return an IcapResponse.

    Note: MockAsyncIcapClient also accepts synchronous callbacks for
    convenience - they will be called directly without awaiting.

    Example:
        >>> async def async_scanner(data: bytes, **kwargs) -> IcapResponse:
        ...     # Can perform async operations if needed
        ...     if b"EICAR" in data:
        ...         return IcapResponseBuilder().virus("EICAR-Test").build()
        ...     return IcapResponseBuilder().clean().build()
        >>>
        >>> client = MockAsyncIcapClient()
        >>> client.on_respmod(callback=async_scanner)

    See Also:
        ResponseCallback: Sync version for MockIcapClient.
        MockAsyncIcapClient.on_respmod: Configure callbacks for scan methods.
    """

    async def __call__(
        self,
        data: bytes,
        *,
        service: str,
        filename: str | None = None,
        **kwargs: Any,
    ) -> IcapResponse: ...


__all__ = ["ResponseCallback", "AsyncResponseCallback"]
