"""Connection robustness integration tests.

These tests verify the ICAP client handles connection edge cases correctly,
including reconnection, persistence, and recovery from errors.

All tests require Docker (c-icap + ClamAV) to be running.
"""

from __future__ import annotations

import os
import time

import pytest

# TODO: These tests are flaky in CI due to the Docker-based ICAP server returning
# unexpected 307 redirects. The tests pass locally but fail intermittently in GitHub
# Actions. Investigation needed into the CI Docker environment configuration.
# See: https://github.com/CaptainDriftwood/python-icap/pull/42
CI = os.environ.get("CI", "false").lower() == "true"

from icap import AsyncIcapClient, IcapClient
from tests.conftest import wait_for_icap_service

# EICAR test string for virus detection
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.mark.integration
@pytest.mark.docker
def test_multiple_sequential_requests(icap_service):
    """Test 50 sequential scans on the same connection.

    Verifies connection persistence and reuse across many requests.
    """
    content = b"Sequential request test content"
    num_requests = 50

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        for i in range(num_requests):
            response = client.scan_bytes(
                content,
                service=icap_service["service"],
                filename=f"sequential_{i}.txt",
            )
            assert response.is_no_modification or response.is_success, (
                f"Request {i} failed with status {response.status_code}"
            )

        # Connection should still be active
        assert client.is_connected


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.skipif(CI, reason="Flaky in CI: receives 307 redirects from Docker ICAP server")
def test_connection_reuse_after_virus(icap_service):
    """Test connection remains usable after virus detection.

    Scans EICAR (detected as virus), then clean content on same connection.
    """
    clean_content = b"Clean content after virus scan"

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # First scan: EICAR virus
        virus_response = client.scan_bytes(
            EICAR,
            service=icap_service["service"],
            filename="eicar.com",
        )
        # Should be detected (not 204 No Modification)
        assert not virus_response.is_no_modification, "EICAR should be detected as virus"

        # Second scan: clean content on same connection
        clean_response = client.scan_bytes(
            clean_content,
            service=icap_service["service"],
            filename="clean.txt",
        )
        assert clean_response.is_no_modification, "Clean content should pass after virus scan"

        # Connection should still be active
        assert client.is_connected


@pytest.mark.integration
@pytest.mark.docker
def test_reconnect_after_disconnect(icap_service):
    """Test manual disconnect and reconnect cycle."""
    content = b"Reconnect test content"

    client = IcapClient(icap_service["host"], icap_service["port"])

    # First connection
    client.connect()
    assert client.is_connected

    response1 = client.scan_bytes(
        content,
        service=icap_service["service"],
        filename="reconnect1.txt",
    )
    assert response1.is_no_modification or response1.is_success

    # Disconnect
    client.disconnect()
    assert not client.is_connected

    # Reconnect
    client.connect()
    assert client.is_connected

    response2 = client.scan_bytes(
        content,
        service=icap_service["service"],
        filename="reconnect2.txt",
    )
    assert response2.is_no_modification or response2.is_success

    # Cleanup
    client.disconnect()


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
def test_reconnect_after_server_restart(icap_service, docker_controller):
    """Test recovery after server restart.

    Performs scan, restarts Docker container, then scans again.
    Requires new connection after restart.
    """
    content = b"Server restart test content"

    # First scan
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response1 = client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="before_restart.txt",
        )
        assert response1.is_no_modification or response1.is_success

    # Restart the ICAP server container
    docker_controller.restart()

    # Wait for service to be ready again
    wait_for_icap_service(
        icap_service["host"],
        icap_service["port"],
        icap_service["service"],
        timeout=120,
    )

    # Second scan with new connection
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response2 = client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="after_restart.txt",
        )
        assert response2.is_no_modification or response2.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
def test_idle_connection_30s(icap_service):
    """Test connection remains usable after 30 seconds idle.

    Note: Server KeepAliveTimeout is 30s, so this tests the boundary.
    """
    content = b"Idle connection test content"

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # First scan
        response1 = client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="before_idle.txt",
        )
        assert response1.is_no_modification or response1.is_success

        # Wait 30 seconds
        time.sleep(30)

        # Try another scan - may need reconnect if server closed connection
        try:
            response2 = client.scan_bytes(
                content,
                service=icap_service["service"],
                filename="after_idle.txt",
            )
            assert response2.is_no_modification or response2.is_success
        except Exception:
            # If connection was dropped, reconnect should work
            client.disconnect()
            client.connect()
            response2 = client.scan_bytes(
                content,
                service=icap_service["service"],
                filename="after_idle_reconnect.txt",
            )
            assert response2.is_no_modification or response2.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_connection_state_consistency(icap_service):
    """Test is_connected property accuracy through lifecycle."""
    client = IcapClient(icap_service["host"], icap_service["port"])

    # Initially not connected
    assert not client.is_connected

    # After connect
    client.connect()
    assert client.is_connected

    # After successful operation
    response = client.options(icap_service["service"])
    assert response.is_success
    assert client.is_connected

    # After disconnect
    client.disconnect()
    assert not client.is_connected

    # Reconnect via context manager
    with client:
        assert client.is_connected

    # After context manager exit
    assert not client.is_connected


@pytest.mark.integration
@pytest.mark.docker
async def test_async_connection_persistence(icap_service):
    """Test async client handles 20 sequential requests correctly."""
    content = b"Async persistence test content"
    num_requests = 20

    async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
        for i in range(num_requests):
            response = await client.scan_bytes(
                content,
                service=icap_service["service"],
                filename=f"async_seq_{i}.txt",
            )
            assert response.is_no_modification or response.is_success, (
                f"Async request {i} failed with status {response.status_code}"
            )

        # Connection should still be active
        assert client.is_connected


@pytest.mark.integration
@pytest.mark.docker
async def test_async_reconnect_after_error(icap_service):
    """Test async client recovery after connection issues."""
    content = b"Async recovery test content"

    # First connection
    async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
        response1 = await client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="async_before.txt",
        )
        assert response1.is_no_modification or response1.is_success

    # Second connection (simulates recovery after context exit)
    async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
        response2 = await client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="async_after.txt",
        )
        assert response2.is_no_modification or response2.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_options_then_scan_same_connection(icap_service):
    """Test OPTIONS followed by scan on same connection."""
    content = b"Options then scan test"

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # First: OPTIONS request
        options_response = client.options(icap_service["service"])
        assert options_response.is_success
        assert "Methods" in options_response.headers

        # Then: scan request
        scan_response = client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="after_options.txt",
        )
        assert scan_response.is_no_modification or scan_response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.skipif(CI, reason="Flaky in CI: receives 307 redirects from Docker ICAP server")
def test_alternating_clean_and_virus(icap_service):
    """Test alternating between clean content and virus detection."""
    clean_content = b"This is clean content"

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        for i in range(5):
            # Clean scan
            clean_response = client.scan_bytes(
                clean_content,
                service=icap_service["service"],
                filename=f"clean_{i}.txt",
            )
            assert clean_response.is_no_modification, f"Clean scan {i} should pass"

            # Virus scan
            virus_response = client.scan_bytes(
                EICAR,
                service=icap_service["service"],
                filename=f"virus_{i}.com",
            )
            assert not virus_response.is_no_modification, f"Virus {i} should be detected"

        # Connection should still be healthy
        assert client.is_connected
        final_response = client.options(icap_service["service"])
        assert final_response.is_success
