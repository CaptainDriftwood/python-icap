"""
Performance benchmarks for ICAP client operations.

These tests measure throughput and latency of ICAP operations against a real
c-icap/ClamAV server running in Docker. They use pytest-benchmark for
consistent measurement and reporting.

Run benchmarks with: just benchmark
Or directly: pytest -m benchmark --benchmark-only

Note: These benchmarks measure end-to-end performance including network I/O
and server processing time. The ICAP server (ClamAV) dominates the time for
actual virus scanning - client overhead is typically negligible.
"""

import asyncio
import io
import os
import tempfile

import pytest

from icap import AsyncIcapClient, IcapClient

# Standard EICAR test string for triggering virus detection
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


# =============================================================================
# Sync Client Benchmarks
# =============================================================================


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_options_request(benchmark, icap_service):
    """Benchmark OPTIONS request latency (includes connection overhead)."""

    def run_options():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.options(icap_service["service"])

    result = benchmark(run_options)
    assert result.is_success


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_small_clean(benchmark, icap_service):
    """Benchmark scanning small clean content (1 KB)."""
    content = b"Clean content " * 73  # ~1 KB

    def run_scan():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_bytes(content, service=icap_service["service"])

    result = benchmark(run_scan)
    assert result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_medium_clean(benchmark, icap_service):
    """Benchmark scanning medium clean content (100 KB)."""
    content = b"Clean content " * 7300  # ~100 KB

    def run_scan():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_bytes(content, service=icap_service["service"])

    result = benchmark(run_scan)
    assert result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_large_clean(benchmark, icap_service):
    """Benchmark scanning large clean content (1 MB)."""
    content = b"Clean content " * 73000  # ~1 MB

    def run_scan():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_bytes(content, service=icap_service["service"])

    result = benchmark(run_scan)
    assert result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_very_large_clean(benchmark, icap_service):
    """Benchmark scanning very large clean content (10 MB)."""
    content = b"Clean content " * 730000  # ~10 MB

    def run_scan():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_bytes(content, service=icap_service["service"])

    result = benchmark(run_scan)
    assert result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_virus_detection(benchmark, icap_service):
    """Benchmark virus detection latency."""

    def run_scan():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_bytes(EICAR, service=icap_service["service"])

    result = benchmark(run_scan)
    # EICAR should be detected - not a 204 response
    assert not result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_file(benchmark, icap_service):
    """Benchmark file scanning (1 MB file)."""
    content = b"Clean file content " * 55000  # ~1 MB
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        filepath = f.name

    def run_scan():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_file(filepath, service=icap_service["service"])

    try:
        result = benchmark(run_scan)
        assert result.is_no_modification
    finally:
        os.unlink(filepath)


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_scan_stream(benchmark, icap_service):
    """Benchmark stream scanning (1 MB stream)."""
    content = b"Clean stream content " * 50000  # ~1 MB

    def run_scan():
        stream = io.BytesIO(content)
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            return client.scan_stream(stream, service=icap_service["service"])

    result = benchmark(run_scan)
    assert result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_connection_reuse(benchmark, icap_service):
    """Benchmark multiple scans on a single connection (amortized connection cost)."""
    content = b"Clean content " * 73  # ~1 KB

    def scan_multiple():
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            for _ in range(5):
                client.scan_bytes(content, service=icap_service["service"])

    benchmark(scan_multiple)


# =============================================================================
# Async Client Benchmarks
# =============================================================================


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_async_options_request(benchmark, icap_service):
    """Benchmark async OPTIONS request latency (includes connection overhead)."""

    async def run_options():
        async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
            return await client.options(icap_service["service"])

    result = benchmark(lambda: asyncio.run(run_options()))
    assert result.is_success


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_async_scan_medium_clean(benchmark, icap_service):
    """Benchmark async scanning medium clean content (100 KB)."""
    content = b"Clean content " * 7300  # ~100 KB

    async def run_scan():
        async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
            return await client.scan_bytes(content, service=icap_service["service"])

    result = benchmark(lambda: asyncio.run(run_scan()))
    assert result.is_no_modification


@pytest.mark.benchmark
@pytest.mark.slow
@pytest.mark.docker
def test_benchmark_async_scan_large_clean(benchmark, icap_service):
    """Benchmark async scanning large clean content (1 MB)."""
    content = b"Clean content " * 73000  # ~1 MB

    async def run_scan():
        async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
            return await client.scan_bytes(content, service=icap_service["service"])

    result = benchmark(lambda: asyncio.run(run_scan()))
    assert result.is_no_modification
