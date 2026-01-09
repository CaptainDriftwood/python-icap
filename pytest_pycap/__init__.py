"""
Pytest plugin for testing code that uses the PyCap ICAP client.

This plugin provides fixtures, mocks, and builders for testing ICAP integrations
without requiring a live ICAP server. It supports both synchronous and asynchronous
testing patterns.

Fixture Categories:
    **Live Client Fixtures** (require running ICAP server):
        - `icap_client` - Pre-connected synchronous IcapClient
        - `async_icap_client` - Pre-connected asynchronous AsyncIcapClient
        - `icap_service_config` - Default connection configuration dict

    **Mock Client Fixtures** (no server required):
        - `mock_icap_client` - MockIcapClient with default clean responses
        - `mock_async_icap_client` - Async mock with default clean responses
        - `mock_icap_client_virus` - Mock configured to detect viruses
        - `mock_icap_client_timeout` - Mock that raises IcapTimeoutError
        - `mock_icap_client_connection_error` - Mock that raises IcapConnectionError

    **Response Fixtures** (pre-built IcapResponse objects):
        - `icap_response_builder` - Factory for building custom responses
        - `icap_response_clean` - 204 No Modification response
        - `icap_response_virus` - Virus detection response
        - `icap_response_options` - OPTIONS response with server capabilities
        - `icap_response_error` - 500 Internal Server Error response

    **Marker-Based Fixtures**:
        - `icap_mock` - Configurable mock via @pytest.mark.icap_mock decorator

    **Helper Fixtures**:
        - `sample_clean_content` - Sample bytes for testing
        - `sample_file` - Temporary file Path for testing

When to Use Each Fixture Type:
    Use **live client fixtures** when:
        - Running integration tests against a real ICAP server
        - Testing actual network behavior and server responses
        - Validating end-to-end scanning functionality

    Use **mock client fixtures** when:
        - Writing unit tests that don't need network I/O
        - Testing error handling (timeouts, connection failures)
        - Testing application logic that depends on scan results
        - Running tests in CI/CD without an ICAP server

    Use **response fixtures** when:
        - Building custom mock responses for specific test scenarios
        - Testing code that processes IcapResponse objects directly

Markers:
    @pytest.mark.icap(host, port, timeout, ssl_context)
        Configure live client connection parameters.

    @pytest.mark.icap_mock(response, virus_name, raises, options, respmod, reqmod)
        Configure mock client behavior declaratively.

Example - Unit test with mock:
    >>> def test_scan_returns_clean(mock_icap_client):
    ...     response = mock_icap_client.scan_bytes(b"safe content")
    ...     assert response.is_no_modification
    ...     mock_icap_client.assert_called("scan_bytes", times=1)

Example - Integration test with live server:
    >>> @pytest.mark.icap(host="localhost", port=1344)
    ... def test_live_scan(icap_client, sample_file):
    ...     response = icap_client.scan_file(sample_file)
    ...     assert response.is_no_modification

Example - Testing error handling:
    >>> def test_timeout_handling(mock_icap_client_timeout):
    ...     with pytest.raises(IcapTimeoutError):
    ...         mock_icap_client_timeout.scan_bytes(b"content")

Example - Custom mock configuration:
    >>> @pytest.mark.icap_mock(response="virus", virus_name="Trojan.Test")
    ... def test_virus_detection(icap_mock):
    ...     response = icap_mock.scan_bytes(b"malware")
    ...     assert not response.is_no_modification
    ...     assert response.headers["X-Virus-ID"] == "Trojan.Test"

See Also:
    - IcapResponseBuilder: Fluent builder for custom test responses
    - MockIcapClient: Full mock implementation with call recording
    - MockAsyncIcapClient: Async version of the mock client
"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any, AsyncGenerator, Generator

import pytest

from pycap import AsyncIcapClient, IcapClient, IcapResponse
from pycap.exception import IcapConnectionError, IcapTimeoutError

from .builder import IcapResponseBuilder
from .mock import MockAsyncIcapClient, MockCall, MockIcapClient

__all__ = [
    # Plugin hooks
    "pytest_configure",
    # Live client fixtures
    "async_icap_client",
    "icap_client",
    "icap_service_config",
    "sample_clean_content",
    "sample_file",
    # Response fixtures
    "icap_response_builder",
    "icap_response_clean",
    "icap_response_virus",
    "icap_response_options",
    "icap_response_error",
    # Mock client fixtures
    "mock_icap_client",
    "mock_async_icap_client",
    "mock_icap_client_virus",
    "mock_icap_client_timeout",
    "mock_icap_client_connection_error",
    # Marker-based fixtures
    "icap_mock",
    # Builders
    "IcapResponseBuilder",
    # Mock clients
    "MockAsyncIcapClient",
    "MockCall",
    "MockIcapClient",
]


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "icap(host, port, timeout, ssl_context): configure ICAP client for testing",
    )
    config.addinivalue_line(
        "markers",
        "icap_mock(response, virus_name, raises, options, respmod, reqmod): "
        "configure mock ICAP client",
    )


@pytest.fixture
def icap_client(request) -> Generator[IcapClient, None, None]:
    """
    Provide an ICAP client for testing.

    The client configuration can be customized using pytest markers:

    Example - Basic usage:
        @pytest.mark.icap(host='localhost', port=1344)
        def test_something(icap_client):
            response = icap_client.options('avscan')
            assert response.is_success

    Example - With SSL/TLS:
        @pytest.mark.icap(host='icap.example.com', ssl_context=ssl.create_default_context())
        def test_secure_scan(icap_client):
            response = icap_client.scan_bytes(b"content")
            assert response.is_success

    Supported marker kwargs:
        - host: ICAP server hostname (default: 'localhost')
        - port: ICAP server port (default: 1344)
        - timeout: Connection timeout in seconds (default: 10)
        - ssl_context: Optional ssl.SSLContext for TLS connections (default: None)
    """
    marker = request.node.get_closest_marker("icap")

    # Default configuration
    config: dict[str, Any] = {
        "host": "localhost",
        "port": 1344,
        "timeout": 10,
        "ssl_context": None,
    }

    # Override with marker kwargs if provided
    if marker and marker.kwargs:
        config.update(marker.kwargs)

    ssl_context: ssl.SSLContext | None = config.get("ssl_context")

    client = IcapClient(
        config["host"],
        port=config["port"],
        timeout=config["timeout"],
        ssl_context=ssl_context,
    )

    try:
        client.connect()
        yield client
    finally:
        if client.is_connected:
            client.disconnect()


@pytest.fixture
async def async_icap_client(request) -> AsyncGenerator[AsyncIcapClient, None]:
    """
    Provide an async ICAP client for testing.

    The client configuration can be customized using pytest markers:

    Example - Basic usage:
        @pytest.mark.icap(host='localhost', port=1344)
        async def test_something(async_icap_client):
            response = await async_icap_client.options('avscan')
            assert response.is_success

    Example - With SSL/TLS:
        @pytest.mark.icap(host='icap.example.com', ssl_context=ssl.create_default_context())
        async def test_secure_scan(async_icap_client):
            response = await async_icap_client.scan_bytes(b"content")
            assert response.is_success

    Supported marker kwargs:
        - host: ICAP server hostname (default: 'localhost')
        - port: ICAP server port (default: 1344)
        - timeout: Connection timeout in seconds (default: 10.0)
        - ssl_context: Optional ssl.SSLContext for TLS connections (default: None)
    """
    marker = request.node.get_closest_marker("icap")

    # Default configuration
    config: dict[str, Any] = {
        "host": "localhost",
        "port": 1344,
        "timeout": 10.0,
        "ssl_context": None,
    }

    # Override with marker kwargs if provided
    if marker and marker.kwargs:
        config.update(marker.kwargs)

    ssl_context: ssl.SSLContext | None = config.get("ssl_context")

    # Use async context manager for proper cleanup
    async with AsyncIcapClient(
        config["host"],
        port=config["port"],
        timeout=config["timeout"],
        ssl_context=ssl_context,
    ) as client:
        yield client


@pytest.fixture
def icap_service_config() -> dict[str, Any]:
    """
    Provide default ICAP service configuration.

    This can be overridden in conftest.py for different environments.
    """
    return {
        "host": "localhost",
        "port": 1344,
        "service": "avscan",
    }


@pytest.fixture
def sample_clean_content() -> bytes:
    """Provide sample clean content for testing."""
    return b"This is clean test content for ICAP scanning."


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a temporary sample file for testing."""
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"Sample file content for ICAP testing.")
    return test_file


# === Response Fixtures ===


@pytest.fixture
def icap_response_builder() -> IcapResponseBuilder:
    """Factory for building custom IcapResponse objects."""
    return IcapResponseBuilder()


@pytest.fixture
def icap_response_clean() -> IcapResponse:
    """Pre-built 204 No Modification response."""
    return IcapResponseBuilder().clean().build()


@pytest.fixture
def icap_response_virus() -> IcapResponse:
    """Pre-built virus detection response."""
    return IcapResponseBuilder().virus().build()


@pytest.fixture
def icap_response_options() -> IcapResponse:
    """Pre-built OPTIONS response with typical server capabilities."""
    return IcapResponseBuilder().options().build()


@pytest.fixture
def icap_response_error() -> IcapResponse:
    """Pre-built 500 Internal Server Error response."""
    return IcapResponseBuilder().error().build()


# === Mock Client Fixtures ===


@pytest.fixture
def mock_icap_client() -> MockIcapClient:
    """
    Mock ICAP client with default clean responses.

    Example:
        def test_scan(mock_icap_client):
            response = mock_icap_client.scan_bytes(b"content")
            assert response.is_no_modification
    """
    return MockIcapClient()


@pytest.fixture
def mock_async_icap_client() -> MockAsyncIcapClient:
    """
    Async mock ICAP client with default clean responses.

    Example:
        async def test_async_scan(mock_async_icap_client):
            async with mock_async_icap_client as client:
                response = await client.scan_bytes(b"content")
                assert response.is_no_modification
    """
    return MockAsyncIcapClient()


# === Pre-configured Mock Fixtures ===


@pytest.fixture
def mock_icap_client_virus() -> MockIcapClient:
    """Mock client configured to detect viruses."""
    client = MockIcapClient()
    client.on_respmod(IcapResponseBuilder().virus().build())
    return client


@pytest.fixture
def mock_icap_client_timeout() -> MockIcapClient:
    """Mock client that simulates timeouts."""
    client = MockIcapClient()
    client.on_any(raises=IcapTimeoutError("Connection timed out"))
    return client


@pytest.fixture
def mock_icap_client_connection_error() -> MockIcapClient:
    """Mock client that simulates connection failures."""
    client = MockIcapClient()
    client.on_any(raises=IcapConnectionError("Connection refused"))
    return client


# === Marker-Based Configuration ===


@pytest.fixture
def icap_mock(request) -> MockIcapClient:
    """
    Configurable mock via @pytest.mark.icap_mock marker.

    Marker options:
        - response: "clean", "virus", "error", or IcapResponse instance
        - virus_name: str (when response="virus")
        - raises: Exception class or instance
        - options: dict for OPTIONS method config
        - respmod: dict for RESPMOD method config
        - reqmod: dict for REQMOD method config

    Examples:
        @pytest.mark.icap_mock(response="clean")
        def test_clean(icap_mock):
            ...

        @pytest.mark.icap_mock(response="virus", virus_name="Trojan.Gen")
        def test_virus(icap_mock):
            ...

        @pytest.mark.icap_mock(raises=IcapTimeoutError)
        def test_timeout(icap_mock):
            ...

        @pytest.mark.icap_mock(
            options={"response": "success"},
            respmod={"response": "virus"},
        )
        def test_mixed(icap_mock):
            ...
    """
    client = MockIcapClient()
    marker = request.node.get_closest_marker("icap_mock")

    if marker is None:
        return client

    # Handle simple response configuration
    response_type = marker.kwargs.get("response")
    virus_name = marker.kwargs.get("virus_name", "EICAR-Test-Signature")
    raises = marker.kwargs.get("raises")

    if raises is not None:
        if isinstance(raises, type) and issubclass(raises, Exception):
            raises = raises("Mock exception")
        client.on_any(raises=raises)
    elif response_type == "clean":
        client.on_any(IcapResponseBuilder().clean().build())
    elif response_type == "virus":
        client.on_any(IcapResponseBuilder().virus(virus_name).build())
    elif response_type == "error":
        client.on_any(IcapResponseBuilder().error().build())
    elif isinstance(response_type, IcapResponse):
        client.on_any(response_type)

    # Handle per-method configuration
    for method in ("options", "respmod", "reqmod"):
        method_config = marker.kwargs.get(method)
        if method_config:
            configure_method = getattr(client, f"on_{method}")
            if "raises" in method_config:
                exc = method_config["raises"]
                if isinstance(exc, type) and issubclass(exc, Exception):
                    exc = exc("Mock exception")
                configure_method(raises=exc)
            elif "response" in method_config:
                resp = method_config["response"]
                if resp == "clean":
                    configure_method(IcapResponseBuilder().clean().build())
                elif resp == "virus":
                    configure_method(IcapResponseBuilder().virus().build())
                elif resp == "error":
                    configure_method(IcapResponseBuilder().error().build())
                elif isinstance(resp, IcapResponse):
                    configure_method(resp)

    return client
