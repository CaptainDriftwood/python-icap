"""
Mock ICAP clients for testing without network I/O.

This module provides mock implementations of IcapClient and AsyncIcapClient
that can be used in tests without requiring a real ICAP server. The mocks
support configurable responses and call recording for assertions.

Classes:
    MockCall: Dataclass recording details of a single method call.
    MockIcapClient: Synchronous mock implementing the full IcapClient interface.
    MockAsyncIcapClient: Asynchronous mock implementing the AsyncIcapClient interface.

Example:
    >>> from pytest_pycap import MockIcapClient, IcapResponseBuilder
    >>>
    >>> # Create mock with default clean responses
    >>> client = MockIcapClient()
    >>> response = client.scan_bytes(b"content")
    >>> assert response.is_no_modification
    >>>
    >>> # Configure to return virus detection
    >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
    >>> response = client.scan_bytes(b"malware")
    >>> assert not response.is_no_modification
    >>>
    >>> # Verify calls were made
    >>> client.assert_called("scan_bytes", times=2)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from .builder import IcapResponseBuilder

if TYPE_CHECKING:
    from pycap import IcapResponse


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

    Example:
        >>> client = MockIcapClient()
        >>> client.scan_bytes(b"test", filename="test.txt")
        >>> call = client.calls[0]
        >>> call.method
        'scan_bytes'
        >>> call.kwargs["data"]
        b'test'
        >>> call.kwargs["filename"]
        'test.txt'
    """

    method: str
    timestamp: float
    kwargs: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        args_str = ", ".join(f"{k}={v!r}" for k, v in self.kwargs.items())
        return f"MockCall({self.method}({args_str}))"


class MockIcapClient:
    """
    Mock ICAP client for testing without network I/O.

    Implements the full IcapClient interface with configurable responses
    and call recording for assertions. By default, all methods return clean/success
    responses (204 No Modification for scans, 200 OK for OPTIONS).

    The mock provides three main capabilities:
        1. **Response Configuration**: Set what responses methods should return
        2. **Exception Injection**: Make methods raise specific exceptions
        3. **Call Recording**: Track all method calls for assertions

    Attributes:
        host: Mock server hostname (default: "mock-icap-server").
        port: Mock server port (default: 1344).
        is_connected: Whether connect() has been called.
        calls: List of MockCall objects recording all method invocations.

    Configuration Methods:
        on_options(response, raises): Configure OPTIONS method behavior.
        on_respmod(response, raises): Configure RESPMOD and scan_* methods.
        on_reqmod(response, raises): Configure REQMOD method behavior.
        on_any(response, raises): Configure all methods at once.

    Assertion Methods:
        assert_called(method, times): Assert a method was called.
        assert_not_called(method): Assert a method was not called.
        assert_scanned(data): Assert specific bytes were scanned.
        reset_calls(): Clear call history for fresh assertions.

    IcapClient Interface:
        connect(): Simulates connection (sets is_connected=True).
        disconnect(): Simulates disconnection (sets is_connected=False).
        options(service): Returns configured OPTIONS response.
        respmod(service, http_request, http_response, ...): Returns RESPMOD response.
        reqmod(service, http_request, ...): Returns REQMOD response.
        scan_bytes(data, service, filename): High-level scan, uses RESPMOD response.
        scan_file(filepath, service): Reads file and scans, uses RESPMOD response.
        scan_stream(stream, service, filename): Reads stream and scans.

    Example - Basic usage:
        >>> client = MockIcapClient()
        >>> response = client.scan_bytes(b"safe content")
        >>> assert response.is_no_modification  # Default is clean
        >>> client.assert_called("scan_bytes", times=1)

    Example - Configure virus detection:
        >>> client = MockIcapClient()
        >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
        >>> response = client.scan_bytes(b"malware")
        >>> assert not response.is_no_modification
        >>> assert response.headers["X-Virus-ID"] == "Trojan.Gen"

    Example - Simulate timeout error:
        >>> from pycap.exception import IcapTimeoutError
        >>> client = MockIcapClient()
        >>> client.on_any(raises=IcapTimeoutError("Connection timed out"))
        >>> client.scan_bytes(b"content")  # Raises IcapTimeoutError

    Example - Different responses per method:
        >>> client = MockIcapClient()
        >>> client.on_options(IcapResponseBuilder().options().build())
        >>> client.on_respmod(IcapResponseBuilder().virus().build())
        >>> client.options("avscan").is_success  # True
        >>> client.scan_bytes(b"data").is_no_modification  # False (virus)

    Example - Context manager:
        >>> with MockIcapClient() as client:
        ...     response = client.scan_file("/path/to/file.txt")
        ...     assert response.is_no_modification

    Example - Inspect call history:
        >>> client = MockIcapClient()
        >>> client.scan_bytes(b"test", filename="test.txt", service="avscan")
        >>> call = client.calls[0]
        >>> call.method  # "scan_bytes"
        >>> call.kwargs["data"]  # b"test"
        >>> call.kwargs["filename"]  # "test.txt"

    See Also:
        MockAsyncIcapClient: Async version with same API but awaitable methods.
        IcapResponseBuilder: Fluent builder for creating test responses.
        MockCall: Dataclass representing a recorded method call.
    """

    def __init__(
        self,
        host: str = "mock-icap-server",
        port: int = 1344,
    ) -> None:
        """
        Initialize the mock ICAP client.

        Args:
            host: Mock server hostname (default: "mock-icap-server").
                  This value is stored but not used for actual connections.
            port: Mock server port (default: 1344).
                  This value is stored but not used for actual connections.
        """
        self._host = host
        self._port = port
        self._connected = False
        self._calls: list[MockCall] = []

        # Default responses (clean/success)
        self._options_response: IcapResponse | Exception = IcapResponseBuilder().options().build()
        self._respmod_response: IcapResponse | Exception = IcapResponseBuilder().clean().build()
        self._reqmod_response: IcapResponse | Exception = IcapResponseBuilder().clean().build()

    # === Configuration API ===

    def on_options(
        self,
        response: IcapResponse | None = None,
        *,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure what the OPTIONS method returns.

        Args:
            response: IcapResponse to return when options() is called.
            raises: Exception to raise when options() is called.
                    If both response and raises are provided, raises takes precedence.

        Returns:
            Self for method chaining.

        Example:
            >>> client = MockIcapClient()
            >>> client.on_options(IcapResponseBuilder().options(methods=["RESPMOD"]).build())
            >>> response = client.options("avscan")
            >>> response.headers["Methods"]
            'RESPMOD'

        Example - Raise exception:
            >>> client.on_options(raises=IcapConnectionError("Server unavailable"))
        """
        if raises is not None:
            self._options_response = raises
        elif response is not None:
            self._options_response = response
        return self

    def on_respmod(
        self,
        response: IcapResponse | None = None,
        *,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure what RESPMOD and scan methods return.

        This affects respmod(), scan_bytes(), scan_file(), and scan_stream()
        since the scan_* methods use RESPMOD internally.

        Args:
            response: IcapResponse to return.
            raises: Exception to raise. Takes precedence over response.

        Returns:
            Self for method chaining.

        Example - Virus detection:
            >>> client = MockIcapClient()
            >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
            >>> response = client.scan_bytes(b"content")
            >>> assert not response.is_no_modification

        Example - Timeout:
            >>> client.on_respmod(raises=IcapTimeoutError("Scan timed out"))
        """
        if raises is not None:
            self._respmod_response = raises
        elif response is not None:
            self._respmod_response = response
        return self

    def on_reqmod(
        self,
        response: IcapResponse | None = None,
        *,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure what the REQMOD method returns.

        Args:
            response: IcapResponse to return when reqmod() is called.
            raises: Exception to raise. Takes precedence over response.

        Returns:
            Self for method chaining.

        Example:
            >>> client = MockIcapClient()
            >>> client.on_reqmod(IcapResponseBuilder().clean().build())
            >>> http_req = b"POST /upload HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
            >>> response = client.reqmod("avscan", http_req, b"file content")
            >>> assert response.is_no_modification
        """
        if raises is not None:
            self._reqmod_response = raises
        elif response is not None:
            self._reqmod_response = response
        return self

    def on_any(
        self,
        response: IcapResponse | None = None,
        *,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure all methods (OPTIONS, RESPMOD, REQMOD) at once.

        Convenience method to set the same response or exception for all methods.

        Args:
            response: IcapResponse to return from all methods.
            raises: Exception to raise from all methods. Takes precedence.

        Returns:
            Self for method chaining.

        Example - All methods return clean:
            >>> client = MockIcapClient()
            >>> client.on_any(IcapResponseBuilder().clean().build())

        Example - All methods fail:
            >>> client.on_any(raises=IcapConnectionError("Server down"))
        """
        self.on_options(response, raises=raises)
        self.on_respmod(response, raises=raises)
        self.on_reqmod(response, raises=raises)
        return self

    # === Assertion API ===

    @property
    def calls(self) -> list[MockCall]:
        """
        Get a copy of all recorded method calls.

        Returns a copy to prevent accidental modification. Each MockCall
        contains the method name, timestamp, and keyword arguments.

        Returns:
            List of MockCall objects in chronological order.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"test1")
            >>> client.scan_bytes(b"test2")
            >>> len(client.calls)
            2
            >>> client.calls[0].kwargs["data"]
            b'test1'
        """
        return self._calls.copy()

    def assert_called(self, method: str, *, times: int | None = None) -> None:
        """
        Assert that a method was called.

        Args:
            method: Method name to check (e.g., "scan_bytes", "options", "respmod").
            times: If provided, assert the method was called exactly this many times.

        Raises:
            AssertionError: If the method was never called, or was called a
                different number of times than expected.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"content")
            >>> client.assert_called("scan_bytes")  # Passes
            >>> client.assert_called("scan_bytes", times=1)  # Passes
            >>> client.assert_called("scan_bytes", times=2)  # Raises AssertionError
            >>> client.assert_called("options")  # Raises AssertionError
        """
        matching = [c for c in self._calls if c.method == method]
        if not matching:
            raise AssertionError(f"Method '{method}' was never called")
        if times is not None and len(matching) != times:
            raise AssertionError(
                f"Method '{method}' was called {len(matching)} times, expected {times}"
            )

    def assert_not_called(self, method: str | None = None) -> None:
        """
        Assert that a method (or any method) was not called.

        Args:
            method: Specific method name to check. If None, asserts no methods
                    were called at all.

        Raises:
            AssertionError: If the method (or any method) was called.

        Example:
            >>> client = MockIcapClient()
            >>> client.assert_not_called()  # Passes - nothing called yet
            >>> client.assert_not_called("options")  # Passes
            >>> client.scan_bytes(b"test")
            >>> client.assert_not_called("options")  # Still passes
            >>> client.assert_not_called("scan_bytes")  # Raises AssertionError
            >>> client.assert_not_called()  # Raises AssertionError
        """
        if method is None:
            if self._calls:
                raise AssertionError(f"Expected no calls, got: {self._calls}")
        else:
            matching = [c for c in self._calls if c.method == method]
            if matching:
                raise AssertionError(f"Method '{method}' was called {len(matching)} times")

    def assert_scanned(self, data: bytes) -> None:
        """
        Assert that specific content was scanned.

        Checks if the given bytes were passed to scan_bytes() or respmod().
        For respmod(), checks if the http_response ends with the given data.

        Args:
            data: The exact bytes that should have been scanned.

        Raises:
            AssertionError: If the data was not found in any scan call.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"test content")
            >>> client.assert_scanned(b"test content")  # Passes
            >>> client.assert_scanned(b"other")  # Raises AssertionError
        """
        for call in self._calls:
            if call.method in ("scan_bytes", "respmod"):
                if call.kwargs.get("data") == data:
                    return
                if call.kwargs.get("http_response", b"").endswith(data):
                    return
        raise AssertionError(f"Content {data!r} was not scanned")

    def reset_calls(self) -> None:
        """
        Clear the call history.

        Use this between test phases to reset assertions.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"test1")
            >>> client.assert_called("scan_bytes", times=1)
            >>> client.reset_calls()
            >>> client.assert_not_called()  # Passes - history cleared
            >>> client.scan_bytes(b"test2")
            >>> client.assert_called("scan_bytes", times=1)  # Only counts new call
        """
        self._calls.clear()

    # === IcapClient Interface ===

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("Port is not a valid type. Please enter an int value.")
        self._port = value

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        """Simulate connection (no-op)."""
        self._connected = True

    def disconnect(self) -> None:
        """Simulate disconnection (no-op)."""
        self._connected = False

    def __enter__(self) -> MockIcapClient:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        self.disconnect()
        return False

    def _record_call(self, method: str, **kwargs: Any) -> None:
        """Record a method call."""
        self._calls.append(
            MockCall(
                method=method,
                timestamp=time.time(),
                kwargs=kwargs,
            )
        )

    def _get_response(self, response_or_exception: IcapResponse | Exception) -> IcapResponse:
        """Return response or raise exception."""
        if isinstance(response_or_exception, Exception):
            raise response_or_exception
        return response_or_exception

    def options(self, service: str) -> IcapResponse:
        """Send OPTIONS request (mocked)."""
        self._record_call("options", service=service)
        return self._get_response(self._options_response)

    def respmod(
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: dict[str, str] | None = None,
        preview: int | None = None,
    ) -> IcapResponse:
        """Send RESPMOD request (mocked)."""
        self._record_call(
            "respmod",
            service=service,
            http_request=http_request,
            http_response=http_response,
            headers=headers,
            preview=preview,
        )
        return self._get_response(self._respmod_response)

    def reqmod(
        self,
        service: str,
        http_request: bytes,
        http_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> IcapResponse:
        """Send REQMOD request (mocked)."""
        self._record_call(
            "reqmod",
            service=service,
            http_request=http_request,
            http_body=http_body,
            headers=headers,
        )
        return self._get_response(self._reqmod_response)

    def scan_bytes(
        self,
        data: bytes,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan bytes content (mocked)."""
        self._record_call(
            "scan_bytes",
            data=data,
            service=service,
            filename=filename,
        )
        return self._get_response(self._respmod_response)

    def scan_file(
        self,
        filepath: str | Path,
        service: str = "avscan",
    ) -> IcapResponse:
        """Scan a file (mocked - actually reads the file)."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        data = filepath.read_bytes()
        self._record_call(
            "scan_file",
            filepath=str(filepath),
            service=service,
            data=data,
        )
        return self._get_response(self._respmod_response)

    def scan_stream(
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: str | None = None,
        chunk_size: int = 0,
    ) -> IcapResponse:
        """Scan a stream (mocked - actually reads the stream)."""
        data = stream.read()
        self._record_call(
            "scan_stream",
            data=data,
            service=service,
            filename=filename,
            chunk_size=chunk_size,
        )
        return self._get_response(self._respmod_response)


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
        self._record_call("options", service=service)
        return self._get_response(self._options_response)

    async def respmod(  # type: ignore[override]
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: dict[str, str] | None = None,
        preview: int | None = None,
    ) -> IcapResponse:
        """Send RESPMOD request (mocked)."""
        self._record_call(
            "respmod",
            service=service,
            http_request=http_request,
            http_response=http_response,
            headers=headers,
            preview=preview,
        )
        return self._get_response(self._respmod_response)

    async def reqmod(  # type: ignore[override]
        self,
        service: str,
        http_request: bytes,
        http_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> IcapResponse:
        """Send REQMOD request (mocked)."""
        self._record_call(
            "reqmod",
            service=service,
            http_request=http_request,
            http_body=http_body,
            headers=headers,
        )
        return self._get_response(self._reqmod_response)

    async def scan_bytes(  # type: ignore[override]
        self,
        data: bytes,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan bytes content (mocked)."""
        self._record_call(
            "scan_bytes",
            data=data,
            service=service,
            filename=filename,
        )
        return self._get_response(self._respmod_response)

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
        self._record_call(
            "scan_file",
            filepath=str(filepath),
            service=service,
            data=data,
        )
        return self._get_response(self._respmod_response)

    async def scan_stream(  # type: ignore[override]
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan a stream (mocked)."""
        data = stream.read()
        self._record_call(
            "scan_stream",
            data=data,
            service=service,
            filename=filename,
        )
        return self._get_response(self._respmod_response)
