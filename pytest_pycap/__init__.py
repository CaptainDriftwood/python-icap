"""
Pytest plugin for PyCap ICAP client testing.

This plugin provides fixtures and helpers for testing ICAP clients.
"""

from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator

import pytest

from pycap import AsyncIcapClient, IcapClient

__all__ = [
    "pytest_configure",
    "async_icap_client",
    "icap_client",
    "icap_service_config",
    "sample_clean_content",
    "sample_file",
]


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "icap: mark test as requiring an ICAP server")


@pytest.fixture
def icap_client(request) -> Generator[IcapClient, None, None]:
    """
    Provide an ICAP client for testing.

    The client configuration can be customized using pytest markers:

    @pytest.mark.icap(host='localhost', port=1344)
    def test_something(icap_client):
        response = icap_client.options('avscan')
        assert response.is_success
    """
    marker = request.node.get_closest_marker("icap")

    # Default configuration
    config = {
        "host": "localhost",
        "port": 1344,
        "timeout": 10,
    }

    # Override with marker kwargs if provided
    if marker and marker.kwargs:
        config.update(marker.kwargs)

    client = IcapClient(config["host"], port=config["port"], timeout=config["timeout"])

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

    @pytest.mark.icap(host='localhost', port=1344)
    async def test_something(async_icap_client):
        response = await async_icap_client.options('avscan')
        assert response.is_success
    """
    marker = request.node.get_closest_marker("icap")

    # Default configuration
    config = {
        "host": "localhost",
        "port": 1344,
        "timeout": 10.0,
    }

    # Override with marker kwargs if provided
    if marker and marker.kwargs:
        config.update(marker.kwargs)

    # Use async context manager for proper cleanup
    async with AsyncIcapClient(
        config["host"],
        port=config["port"],
        timeout=config["timeout"],
    ) as client:
        yield client


@pytest.fixture
def icap_service_config() -> Dict[str, Any]:
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
