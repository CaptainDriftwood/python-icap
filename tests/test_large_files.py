"""Large file handling integration tests.

These tests verify that the ICAP client correctly handles large files
without memory issues and with proper streaming behavior.

All tests require Docker (c-icap + ClamAV) to be running.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from icap import AsyncIcapClient, IcapClient
from tests.helpers import KB, MB


@pytest.mark.integration
@pytest.mark.docker
def test_scan_10mb_file(icap_service, large_file_10mb: Path):
    """Test scanning a 10MB file completes successfully."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_file(large_file_10mb, service=icap_service["service"])

        assert response.is_success or response.is_no_modification
        # Clean random data should return 204 No Modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
def test_scan_100mb_file(icap_service, large_file_100mb: Path):
    """Test scanning a 100MB file completes without OOM."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_file(large_file_100mb, service=icap_service["service"])

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
def test_stream_large_file_memory_stable(icap_service, large_file_100mb: Path, memory_tracker):
    """Test that streaming a 100MB file doesn't consume proportional memory.

    When using scan_stream with chunked transfer, memory usage should stay
    well below the file size since data is streamed, not loaded entirely.
    """
    with memory_tracker() as stats:
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            with open(large_file_100mb, "rb") as f:
                response = client.scan_stream(
                    f,
                    service=icap_service["service"],
                    filename="test_100mb.bin",
                    chunk_size=64 * KB,  # Stream in 64KB chunks
                )

        assert response.is_success or response.is_no_modification

    # Memory growth should be much less than 100MB
    # Allow up to 50MB for buffers, protocol overhead, etc.
    assert stats.growth_mb < 50, (
        f"Memory grew by {stats.growth_mb:.1f}MB while streaming 100MB file. "
        f"Expected <50MB growth for streaming."
    )


@pytest.mark.integration
@pytest.mark.docker
def test_chunked_stream_512b_chunks(icap_service, large_file_10mb: Path):
    """Test streaming with very small (512 byte) chunks."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        with open(large_file_10mb, "rb") as f:
            response = client.scan_stream(
                f,
                service=icap_service["service"],
                filename="test_small_chunks.bin",
                chunk_size=512,
            )

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
def test_chunked_stream_64kb_chunks(icap_service, large_file_10mb: Path):
    """Test streaming with medium (64KB) chunks."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        with open(large_file_10mb, "rb") as f:
            response = client.scan_stream(
                f,
                service=icap_service["service"],
                filename="test_64kb_chunks.bin",
                chunk_size=64 * KB,
            )

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
def test_chunked_stream_1mb_chunks(icap_service, large_file_10mb: Path):
    """Test streaming with large (1MB) chunks."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        with open(large_file_10mb, "rb") as f:
            response = client.scan_stream(
                f,
                service=icap_service["service"],
                filename="test_1mb_chunks.bin",
                chunk_size=1 * MB,
            )

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
def test_large_file_with_preview(icap_service, large_file_100mb: Path):
    """Test scanning a large file with preview mode enabled.

    First queries OPTIONS to get preview size, then uses respmod with preview.
    Note: scan_file() doesn't support preview, so we use the lower-level respmod().
    """
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # Get preview size from server
        options_response = client.options(icap_service["service"])
        assert options_response.is_success

        preview_size_str = options_response.headers.get("Preview")
        if preview_size_str is None:
            pytest.skip("Server does not support preview mode")

        preview_size = int(preview_size_str)

        # Read file and build HTTP response for respmod
        content = large_file_100mb.read_bytes()
        http_request = b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n"
        ) + content

        # Scan with preview using respmod
        response = client.respmod(
            icap_service["service"],
            http_request,
            http_response,
            preview=preview_size,
        )

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
async def test_async_large_file_scan(icap_service, large_file_10mb: Path):
    """Test async scanning of a 10MB file."""
    async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
        response = await client.scan_file(large_file_10mb, service=icap_service["service"])

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
async def test_async_concurrent_large_files(icap_service, large_file_factory):
    """Test scanning 3 large files concurrently with async client.

    Creates 3 separate 10MB files and scans them concurrently.
    """
    # Create 3 separate 10MB files
    files = [large_file_factory(10 * MB, f"concurrent_{i}.bin") for i in range(3)]

    async def scan_file(file_path: Path) -> bool:
        """Scan a single file and return success status."""
        async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
            response = await client.scan_file(file_path, service=icap_service["service"])
            return response.is_no_modification or response.is_success

    # Scan all files concurrently
    results = await asyncio.gather(*[scan_file(f) for f in files])

    # All scans should succeed
    assert all(results), f"Some scans failed: {results}"


@pytest.mark.integration
@pytest.mark.docker
async def test_async_stream_large_file(icap_service, large_file_10mb: Path):
    """Test async streaming of a large file."""
    async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
        with open(large_file_10mb, "rb") as f:
            response = await client.scan_stream(
                f,
                service=icap_service["service"],
                filename="async_stream_test.bin",
                chunk_size=64 * KB,
            )

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
def test_scan_bytes_large_content(icap_service, large_file_factory):
    """Test scan_bytes with large (5MB) content."""
    # Create a 5MB file and read its contents
    file_path = large_file_factory(5 * MB)
    content = file_path.read_bytes()

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_bytes(
            content,
            service=icap_service["service"],
            filename="large_bytes.bin",
        )

        assert response.is_success or response.is_no_modification
        assert response.status_code == 204


@pytest.mark.integration
@pytest.mark.docker
def test_multiple_large_scans_same_connection(icap_service, large_file_factory):
    """Test scanning multiple large files on the same connection."""
    # Create 5 files of 2MB each
    files = [large_file_factory(2 * MB, f"multi_{i}.bin") for i in range(5)]

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        for file_path in files:
            response = client.scan_file(file_path, service=icap_service["service"])
            assert response.is_success or response.is_no_modification
            assert response.status_code == 204
