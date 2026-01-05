"""Mock ICAP clients for testing without network I/O."""

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
    """Record of a method call on the mock client."""

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
    and call recording for assertions.

    Example:
        def test_scan_clean(mock_icap_client):
            response = mock_icap_client.scan_bytes(b"content")
            assert response.is_no_modification
            mock_icap_client.assert_called("scan_bytes", times=1)

        def test_virus_detected(mock_icap_client):
            mock_icap_client.on_respmod(
                IcapResponseBuilder().virus("Trojan.Gen").build()
            )
            response = mock_icap_client.scan_bytes(EICAR)
            assert not response.is_no_modification
    """

    def __init__(
        self,
        host: str = "mock-icap-server",
        port: int = 1344,
    ) -> None:
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
        """Configure OPTIONS method behavior."""
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
        """Configure RESPMOD method behavior (also affects scan_* methods)."""
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
        """Configure REQMOD method behavior."""
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
        """Configure all methods at once."""
        self.on_options(response, raises=raises)
        self.on_respmod(response, raises=raises)
        self.on_reqmod(response, raises=raises)
        return self

    # === Assertion API ===

    @property
    def calls(self) -> list[MockCall]:
        """Get all recorded method calls."""
        return self._calls.copy()

    def assert_called(self, method: str, *, times: int | None = None) -> None:
        """Assert a method was called, optionally a specific number of times."""
        matching = [c for c in self._calls if c.method == method]
        if not matching:
            raise AssertionError(f"Method '{method}' was never called")
        if times is not None and len(matching) != times:
            raise AssertionError(
                f"Method '{method}' was called {len(matching)} times, expected {times}"
            )

    def assert_not_called(self, method: str | None = None) -> None:
        """Assert a method (or any method) was not called."""
        if method is None:
            if self._calls:
                raise AssertionError(f"Expected no calls, got: {self._calls}")
        else:
            matching = [c for c in self._calls if c.method == method]
            if matching:
                raise AssertionError(f"Method '{method}' was called {len(matching)} times")

    def assert_scanned(self, data: bytes) -> None:
        """Assert specific content was scanned."""
        for call in self._calls:
            if call.method in ("scan_bytes", "respmod"):
                if call.kwargs.get("data") == data:
                    return
                if call.kwargs.get("http_response", b"").endswith(data):
                    return
        raise AssertionError(f"Content {data!r} was not scanned")

    def reset_calls(self) -> None:
        """Clear call history."""
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

    Same API as MockIcapClient but with async methods.

    Example:
        async def test_async_scan(mock_async_icap_client):
            async with mock_async_icap_client as client:
                response = await client.scan_bytes(b"content")
                assert response.is_no_modification
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
