"""
Asynchronous mock ICAP client for testing.

This module provides MockAsyncIcapClient, an async mock implementation
of AsyncIcapClient that can be used in tests without requiring a real ICAP server.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from .call_record import MockCall, MockResponseExhaustedError
from .mock_client import MockIcapClient
from .protocols import AsyncResponseCallback, ResponseCallback

if TYPE_CHECKING:
    from icap import IcapResponse


class MockAsyncIcapClient(MockIcapClient):
    """
    Async mock ICAP client for testing without network I/O.

    Inherits from MockIcapClient and provides the same functionality with
    async/await syntax. All ICAP methods (options, respmod, reqmod, scan_*)
    are coroutines that must be awaited.

    The configuration API (on_options, on_respmod, on_reqmod, on_any) and
    assertion API (assert_called, assert_not_called, assert_scanned, reset_calls)
    are synchronous and inherited directly from MockIcapClient.

    Attributes:
        host: Mock server hostname (inherited from MockIcapClient).
        port: Mock server port (inherited from MockIcapClient).
        is_connected: Whether connect() has been called.
        calls: List of MockCall objects recording all method invocations.

    Example - Basic async usage:
        >>> async def test_scan(mock_async_icap_client):
        ...     async with mock_async_icap_client as client:
        ...         response = await client.scan_bytes(b"content")
        ...         assert response.is_no_modification
        ...         client.assert_called("scan_bytes", times=1)

    Example - Configure virus detection:
        >>> async def test_virus(mock_async_icap_client):
        ...     mock_async_icap_client.on_respmod(
        ...         IcapResponseBuilder().virus("Trojan.Gen").build()
        ...     )
        ...     async with mock_async_icap_client as client:
        ...         response = await client.scan_file("/path/to/file.txt")
        ...         assert not response.is_no_modification

    Example - Error handling:
        >>> async def test_timeout(mock_async_icap_client):
        ...     mock_async_icap_client.on_any(raises=IcapTimeoutError("Timeout"))
        ...     async with mock_async_icap_client as client:
        ...         with pytest.raises(IcapTimeoutError):
        ...             await client.scan_bytes(b"content")

    See Also:
        MockIcapClient: Synchronous version with full API documentation.
        IcapResponseBuilder: Fluent builder for creating test responses.
    """

    async def _get_response_with_metadata_async(
        self, method: str, call_kwargs: dict[str, Any]
    ) -> tuple[IcapResponse | Exception, str]:
        """
        Get the next response and metadata for the given method (async version).

        This method determines the response and tracks how it was resolved
        (matcher, callback, queue, or default). Supports both sync and async callbacks.

        Args:
            method: The ICAP method name ("options", "respmod", "reqmod").
            call_kwargs: The arguments passed to the method call.

        Returns:
            A tuple of (response_or_exception, matched_by) where:
            - response_or_exception: The IcapResponse or Exception to return/raise
            - matched_by: String indicating resolution source: "matcher", "callback",
              "queue", or "default"

        Raises:
            MockResponseExhaustedError: When queue is exhausted and queue_active is True.
        """
        # Check matchers first (highest priority)
        for matcher in self._matchers:
            if not matcher.is_exhausted() and matcher.matches(**call_kwargs):
                return matcher.consume(), "matcher"

        callback = self._callbacks.get(method)
        if callback is not None:
            self._callback_used[method] = True
            # Check if callback is async and await if needed
            if inspect.iscoroutinefunction(callback):
                async_callback = cast(AsyncResponseCallback, callback)
                result = await async_callback(**call_kwargs)
            else:
                sync_callback = cast(ResponseCallback, callback)
                result = sync_callback(**call_kwargs)
            return result, "callback"

        queue = self._response_queues[method]

        if queue:
            response_or_exception = queue.popleft()
            return response_or_exception, "queue"

        if self._queue_active[method]:
            raise MockResponseExhaustedError(
                f"All queued {method} responses have been consumed. "
                f"Configure more responses with on_{method}() or use reset_responses()."
            )

        default_responses: dict[str, IcapResponse | Exception] = {
            "options": self._options_response,
            "respmod": self._respmod_response,
            "reqmod": self._reqmod_response,
        }
        return default_responses[method], "default"

    async def _execute_call_async(self, call: MockCall, response_method: str) -> IcapResponse:
        """
        Execute a recorded call and update it with response metadata (async version).

        This method:
        1. Resolves the response using _get_response_with_metadata_async
        2. Updates the MockCall with response/exception/matched_by
        3. Returns the response or raises the exception

        Args:
            call: The MockCall object to update.
            response_method: The method key for response lookup ("options", "respmod", "reqmod").

        Returns:
            The IcapResponse.

        Raises:
            Exception: If the response was configured as an exception.
        """
        try:
            response_or_exception, matched_by = await self._get_response_with_metadata_async(
                response_method, call.kwargs
            )
            call.matched_by = matched_by

            if isinstance(response_or_exception, Exception):
                call.exception = response_or_exception
                raise response_or_exception

            call.response = response_or_exception
            return response_or_exception

        except MockResponseExhaustedError:
            # MockResponseExhaustedError is a configuration error, not a mock response
            # Still record that it happened
            call.matched_by = "queue"
            raise

    async def connect(self) -> None:  # type: ignore[override]
        """Simulate async connection (no-op)."""
        self._connected = True

    async def disconnect(self) -> None:  # type: ignore[override]
        """Simulate async disconnection (no-op)."""
        self._connected = False

    async def __aenter__(self) -> MockAsyncIcapClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        await self.disconnect()
        return False

    async def options(self, service: str) -> IcapResponse:  # type: ignore[override]
        """Send OPTIONS request (mocked)."""
        call = self._record_call("options", service=service)
        return await self._execute_call_async(call, "options")

    async def respmod(  # type: ignore[override]
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: dict[str, str] | None = None,
        preview: int | None = None,
    ) -> IcapResponse:
        """Send RESPMOD request (mocked)."""
        call = self._record_call(
            "respmod",
            service=service,
            http_request=http_request,
            http_response=http_response,
            headers=headers,
            preview=preview,
        )
        return await self._execute_call_async(call, "respmod")

    async def reqmod(  # type: ignore[override]
        self,
        service: str,
        http_request: bytes,
        http_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> IcapResponse:
        """Send REQMOD request (mocked)."""
        call = self._record_call(
            "reqmod",
            service=service,
            http_request=http_request,
            http_body=http_body,
            headers=headers,
        )
        return await self._execute_call_async(call, "reqmod")

    async def scan_bytes(  # type: ignore[override]
        self,
        data: bytes,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan bytes content (mocked)."""
        call = self._record_call(
            "scan_bytes",
            data=data,
            service=service,
            filename=filename,
        )
        return await self._execute_call_async(call, "respmod")

    async def scan_file(  # type: ignore[override]
        self,
        filepath: str | Path,
        service: str = "avscan",
    ) -> IcapResponse:
        """Scan a file (mocked)."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        data = filepath.read_bytes()
        call = self._record_call(
            "scan_file",
            filepath=str(filepath),
            service=service,
            data=data,
        )
        return await self._execute_call_async(call, "respmod")

    async def scan_stream(  # type: ignore[override]
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan a stream (mocked)."""
        data = stream.read()
        call = self._record_call(
            "scan_stream",
            data=data,
            service=service,
            filename=filename,
        )
        return await self._execute_call_async(call, "respmod")


__all__ = ["MockAsyncIcapClient"]
