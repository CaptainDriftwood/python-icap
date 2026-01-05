"""
Pytest plugin for PyCap ICAP client testing.

This plugin provides fixtures and helpers for testing ICAP clients.
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
