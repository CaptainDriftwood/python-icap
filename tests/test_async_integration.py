"""Async ICAP client integration tests.

These tests use the same testcontainers-based Docker setup as the sync tests.
The icap_service fixture is defined in conftest.py and auto-discovered.
"""

import asyncio
import time

import pytest

from pycap import AsyncIcapClient
from pycap.exception import IcapConnectionError

# EICAR test virus signature
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.mark.integration
async def test_async_options(icap_service):
    """Test async OPTIONS request."""
    async with AsyncIcapClient(icap_service["host"], port=icap_service["port"]) as client:
        response = await client.options(icap_service["service"])
        assert response.is_success
        assert response.status_code == 200


@pytest.mark.integration
async def test_async_scan_clean(icap_service):
    """Test scanning clean content."""
    async with AsyncIcapClient(icap_service["host"], port=icap_service["port"]) as client:
        response = await client.scan_bytes(
            b"Clean content here", service=icap_service["service"], filename="clean.txt"
        )
        assert response.is_no_modification


@pytest.mark.integration
async def test_async_scan_eicar(icap_service):
    """Test EICAR virus detection."""
    async with AsyncIcapClient(icap_service["host"], port=icap_service["port"]) as client:
        response = await client.scan_bytes(
            EICAR, service=icap_service["service"], filename="eicar.com"
        )
        # EICAR should be detected as a threat
        assert not response.is_no_modification


@pytest.mark.integration
async def test_concurrent_scans_mixed_content(icap_service):
    """Test multiple concurrent scans with mixed clean/infected content."""
    host = icap_service["host"]
    port = icap_service["port"]
    service = icap_service["service"]

    test_cases = [
        (b"Clean content 1", "clean1.txt", True),
        (b"Clean content 2", "clean2.txt", True),
        (EICAR, "eicar.com", False),
        (b"Another clean file", "clean3.txt", True),
        (EICAR, "virus.exe", False),
        (b"Hello World", "hello.txt", True),
    ]

    async def scan_one(content: bytes, filename: str):
        async with AsyncIcapClient(host, port=port) as client:
            response = await client.scan_bytes(content, service=service, filename=filename)
            return filename, response.is_no_modification

    # Run all scans concurrently
    tasks = [scan_one(content, filename) for content, filename, _ in test_cases]
    results = await asyncio.gather(*tasks)

    # Verify results
    results_dict = dict(results)
    for _content, filename, expected_clean in test_cases:
        actual_clean = results_dict[filename]
        assert actual_clean == expected_clean, (
            f"{filename}: expected {expected_clean}, got {actual_clean}"
        )


@pytest.mark.integration
async def test_concurrent_many_connections(icap_service):
    """Test many concurrent connections."""
    host = icap_service["host"]
    port = icap_service["port"]
    service = icap_service["service"]

    async def scan_clean(index: int) -> bool:
        async with AsyncIcapClient(host, port=port) as client:
            response = await client.scan_bytes(
                f"Content {index}".encode(), service=service, filename=f"file_{index}.txt"
            )
            return response.is_no_modification

    # Launch 20 concurrent scans
    tasks = [scan_clean(i) for i in range(20)]
    results = await asyncio.gather(*tasks)

    # All should be clean
    assert all(results)


@pytest.mark.integration
async def test_async_throughput_comparison(icap_service):
    """Compare async concurrent vs sequential performance."""
    host = icap_service["host"]
    port = icap_service["port"]
    service = icap_service["service"]

    test_files = [(f"file_{i}.txt", b"Content " * 100) for i in range(10)]

    # Sequential
    start = time.perf_counter()
    for filename, content in test_files:
        async with AsyncIcapClient(host, port=port) as client:
            await client.scan_bytes(content, service=service, filename=filename)
    sequential_time = time.perf_counter() - start

    # Concurrent
    async def scan_one(filename: str, content: bytes):
        async with AsyncIcapClient(host, port=port) as client:
            return await client.scan_bytes(content, service=service, filename=filename)

    start = time.perf_counter()
    tasks = [scan_one(fn, c) for fn, c in test_files]
    await asyncio.gather(*tasks)
    concurrent_time = time.perf_counter() - start

    print(f"\nSequential: {sequential_time:.2f}s")
    print(f"Concurrent: {concurrent_time:.2f}s")
    print(f"Speedup: {sequential_time / concurrent_time:.1f}x")

    # Concurrent should be faster (allow some margin for CI variability)
    assert concurrent_time < sequential_time


@pytest.mark.integration
async def test_async_scan_file(icap_service, tmp_path):
    """Test scanning an actual file."""
    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean file content for testing")

    async with AsyncIcapClient(icap_service["host"], port=icap_service["port"]) as client:
        response = await client.scan_file(test_file, service=icap_service["service"])
        assert response.is_no_modification


@pytest.mark.integration
async def test_async_scan_file_eicar(icap_service, tmp_path):
    """Test scanning an EICAR file."""
    # Create test file with EICAR
    test_file = tmp_path / "eicar.com"
    test_file.write_bytes(EICAR)

    async with AsyncIcapClient(icap_service["host"], port=icap_service["port"]) as client:
        response = await client.scan_file(test_file, service=icap_service["service"])
        assert not response.is_no_modification


async def test_async_error_handling_wrong_port(mocker):
    """Test error handling for connection failures (wrong port)."""
    mocker.patch(
        "asyncio.open_connection",
        side_effect=ConnectionRefusedError("Connection refused"),
    )

    with pytest.raises(IcapConnectionError):
        async with AsyncIcapClient("localhost", port=9999) as client:
            await client.options("avscan")


async def test_async_error_handling_wrong_host(mocker):
    """Test error handling for connection failures (wrong host)."""
    import asyncio

    mocker.patch(
        "asyncio.open_connection",
        side_effect=asyncio.TimeoutError("Connection timed out"),
    )

    from pycap.exception import IcapTimeoutError

    with pytest.raises(IcapTimeoutError):
        client = AsyncIcapClient("192.0.2.1", port=1344, timeout=2.0)
        await client.connect()


@pytest.mark.integration
async def test_async_respmod_direct(icap_service):
    """Test direct RESPMOD call."""
    async with AsyncIcapClient(icap_service["host"], port=icap_service["port"]) as client:
        http_request = b"GET /test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello World!"
        )
        response = await client.respmod(icap_service["service"], http_request, http_response)
        assert response.is_no_modification


@pytest.mark.integration
async def test_async_context_manager_cleanup(icap_service):
    """Test that context manager properly cleans up on exception."""
    client = AsyncIcapClient(icap_service["host"], port=icap_service["port"])

    try:
        async with client:
            # Verify we're connected
            response = await client.options(icap_service["service"])
            assert response.is_success
            # Simulate an error
            raise ValueError("Test error")
    except ValueError:
        pass

    # Client should be disconnected after context manager exit
    assert not client.is_connected
