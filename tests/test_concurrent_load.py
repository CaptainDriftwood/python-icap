"""Concurrent load testing for ICAP client.

These tests verify the client handles high concurrency correctly,
including resource management and graceful error handling.

All tests require Docker (c-icap + ClamAV) to be running.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from icap import AsyncIcapClient, IcapClient
from icap.exception import IcapConnectionError, IcapException
from tests.helpers import KB, MB, LoadTestMetrics, get_open_fd_count


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
async def test_50_concurrent_scans(icap_service, load_metrics: LoadTestMetrics):
    """Test 50 simultaneous async scans.

    All scans should complete successfully with >95% success rate.
    """
    content = b"Clean test content for concurrent scanning"
    num_scans = 50

    async def scan_one(scan_id: int) -> None:
        """Perform a single scan and record metrics."""
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
                response = await client.scan_bytes(
                    content,
                    service=icap_service["service"],
                    filename=f"concurrent_{scan_id}.txt",
                )
                if response.is_no_modification or response.is_success:
                    latency_ms = (time.perf_counter() - start) * 1000
                    load_metrics.record_success(latency_ms)
                else:
                    load_metrics.record_failure(f"Unexpected status: {response.status_code}")
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            load_metrics.record_failure(e, latency_ms)

    # Launch all scans concurrently
    await asyncio.gather(*[scan_one(i) for i in range(num_scans)])

    # Verify results
    assert load_metrics.success_rate >= 0.95, (
        f"Success rate {load_metrics.success_rate_percent:.1f}% below 95% threshold.\n"
        f"{load_metrics.summary()}"
    )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
async def test_100_concurrent_scans(icap_service, load_metrics: LoadTestMetrics):
    """Test 100 simultaneous scans with graceful error handling.

    Some failures are expected due to server limits (MaxServers=10).
    Test verifies graceful handling rather than 100% success.
    """
    content = b"Clean test content"
    num_scans = 100

    async def scan_one(scan_id: int) -> None:
        """Perform a single scan and record metrics."""
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(
                icap_service["host"],
                icap_service["port"],
                timeout=30,
            ) as client:
                response = await client.scan_bytes(
                    content,
                    service=icap_service["service"],
                    filename=f"load_{scan_id}.txt",
                )
                if response.is_no_modification or response.is_success:
                    latency_ms = (time.perf_counter() - start) * 1000
                    load_metrics.record_success(latency_ms)
                else:
                    load_metrics.record_failure(f"Status: {response.status_code}")
        except (IcapConnectionError, IcapException, asyncio.TimeoutError) as e:
            # Expected failures under load
            latency_ms = (time.perf_counter() - start) * 1000
            load_metrics.record_failure(e, latency_ms)
        except Exception as e:
            # Unexpected failures
            latency_ms = (time.perf_counter() - start) * 1000
            load_metrics.record_failure(f"Unexpected: {type(e).__name__}: {e}", latency_ms)

    # Launch all scans concurrently
    await asyncio.gather(*[scan_one(i) for i in range(num_scans)])

    # At least some should succeed, and no crashes
    assert load_metrics.success_count > 0, "No scans succeeded"
    # With 100 concurrent and MaxServers=10, expect at least 50% success
    assert load_metrics.success_rate >= 0.50, (
        f"Success rate {load_metrics.success_rate_percent:.1f}% unexpectedly low.\n"
        f"{load_metrics.summary()}"
    )


@pytest.mark.integration
@pytest.mark.docker
async def test_mixed_workload(icap_service, load_metrics: LoadTestMetrics):
    """Test concurrent mixed workload: OPTIONS + scans + REQMOD.

    Verifies different ICAP methods work correctly under concurrent load.
    """
    content = b"Test content for mixed workload"

    async def do_options(task_id: int) -> None:
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
                response = await client.options(icap_service["service"])
                if response.is_success:
                    load_metrics.record_success((time.perf_counter() - start) * 1000)
                else:
                    load_metrics.record_failure(f"OPTIONS failed: {response.status_code}")
        except Exception as e:
            load_metrics.record_failure(e)

    async def do_scan(task_id: int) -> None:
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
                response = await client.scan_bytes(
                    content,
                    service=icap_service["service"],
                    filename=f"mixed_{task_id}.txt",
                )
                if response.is_no_modification or response.is_success:
                    load_metrics.record_success((time.perf_counter() - start) * 1000)
                else:
                    load_metrics.record_failure(f"Scan failed: {response.status_code}")
        except Exception as e:
            load_metrics.record_failure(e)

    async def do_reqmod(task_id: int) -> None:
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
                http_request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n"
                response = await client.reqmod(
                    icap_service["service"],
                    http_request,
                    request_body=content,
                )
                if response.is_no_modification or response.is_success:
                    load_metrics.record_success((time.perf_counter() - start) * 1000)
                else:
                    load_metrics.record_failure(f"REQMOD failed: {response.status_code}")
        except Exception as e:
            load_metrics.record_failure(e)

    # Create mixed workload: 10 OPTIONS + 20 scans + 5 REQMOD
    tasks = []
    tasks.extend([do_options(i) for i in range(10)])
    tasks.extend([do_scan(i) for i in range(20)])
    tasks.extend([do_reqmod(i) for i in range(5)])

    # Shuffle and run concurrently
    import random

    random.shuffle(tasks)
    await asyncio.gather(*tasks)

    # All operations should succeed
    assert load_metrics.success_rate >= 0.90, (
        f"Mixed workload success rate {load_metrics.success_rate_percent:.1f}% below 90%.\n"
        f"{load_metrics.summary()}"
    )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
async def test_sustained_load_30s(icap_service, load_metrics: LoadTestMetrics):
    """Test sustained load for 30 seconds.

    Continuously sends scans for 30 seconds to verify no resource growth.
    """
    content = b"Sustained load test content"
    duration_seconds = 30
    max_concurrent = 5

    async def scan_worker(worker_id: int, stop_event: asyncio.Event) -> None:
        """Worker that continuously scans until stopped."""
        while not stop_event.is_set():
            start = time.perf_counter()
            try:
                async with AsyncIcapClient(
                    icap_service["host"], icap_service["port"], timeout=10
                ) as client:
                    response = await client.scan_bytes(
                        content,
                        service=icap_service["service"],
                        filename=f"sustained_{worker_id}.txt",
                    )
                    if response.is_no_modification or response.is_success:
                        load_metrics.record_success((time.perf_counter() - start) * 1000)
                    else:
                        load_metrics.record_failure(f"Status: {response.status_code}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                load_metrics.record_failure(e)
                await asyncio.sleep(0.1)  # Brief pause on error

    stop_event = asyncio.Event()
    workers = [scan_worker(i, stop_event) for i in range(max_concurrent)]

    # Run workers for specified duration
    worker_tasks = [asyncio.create_task(w) for w in workers]
    await asyncio.sleep(duration_seconds)
    stop_event.set()

    # Wait for workers to finish
    await asyncio.gather(*worker_tasks, return_exceptions=True)

    # Verify reasonable throughput and success rate
    assert load_metrics.total_count > 10, "Too few operations completed"
    assert load_metrics.success_rate >= 0.90, (
        f"Sustained load success rate {load_metrics.success_rate_percent:.1f}% below 90%.\n"
        f"{load_metrics.summary()}"
    )


@pytest.mark.integration
@pytest.mark.docker
async def test_concurrent_varied_sizes(icap_service, large_file_factory, load_metrics):
    """Test concurrent scans with varied file sizes (1KB to 1MB)."""

    async def scan_file(file_path: Path) -> None:
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(icap_service["host"], icap_service["port"]) as client:
                response = await client.scan_file(file_path, service=icap_service["service"])
                if response.is_no_modification or response.is_success:
                    load_metrics.record_success((time.perf_counter() - start) * 1000)
                else:
                    load_metrics.record_failure(f"Status: {response.status_code}")
        except Exception as e:
            load_metrics.record_failure(e)

    # Create files of varied sizes
    sizes = [1 * KB, 10 * KB, 100 * KB, 500 * KB, 1 * MB]
    files = [large_file_factory(size, f"varied_{size}.bin") for size in sizes]

    # Scan each file twice concurrently (10 total scans)
    tasks = [scan_file(f) for f in files * 2]
    await asyncio.gather(*tasks)

    assert load_metrics.success_rate >= 0.90, (
        f"Varied sizes success rate {load_metrics.success_rate_percent:.1f}% below 90%.\n"
        f"{load_metrics.summary()}"
    )


@pytest.mark.integration
@pytest.mark.docker
async def test_server_limit_graceful(icap_service, load_metrics: LoadTestMetrics):
    """Test behavior when exceeding server connection limit (MaxServers=10).

    Opens more connections than the server allows and verifies
    graceful error handling rather than crashes.
    """
    content = b"Connection limit test"
    num_connections = 20  # More than MaxServers=10

    async def hold_connection(conn_id: int, hold_time: float = 2.0) -> None:
        """Open connection, do a scan, hold briefly."""
        start = time.perf_counter()
        try:
            async with AsyncIcapClient(
                icap_service["host"], icap_service["port"], timeout=10
            ) as client:
                response = await client.scan_bytes(
                    content,
                    service=icap_service["service"],
                    filename=f"limit_{conn_id}.txt",
                )
                # Hold the connection open briefly
                await asyncio.sleep(hold_time)

                if response.is_no_modification or response.is_success:
                    load_metrics.record_success((time.perf_counter() - start) * 1000)
                else:
                    load_metrics.record_failure(f"Status: {response.status_code}")
        except (IcapConnectionError, asyncio.TimeoutError, ConnectionRefusedError) as e:
            # Expected when exceeding limits
            load_metrics.record_failure(e)
        except Exception as e:
            load_metrics.record_failure(f"Unexpected: {type(e).__name__}: {e}")

    # Try to open all connections simultaneously
    await asyncio.gather(*[hold_connection(i) for i in range(num_connections)])

    # Some should succeed, some may fail - but no crashes
    assert load_metrics.success_count > 0, "No connections succeeded"
    # Verify we recorded all attempts (success + failure = total)
    assert load_metrics.total_count == num_connections


@pytest.mark.integration
@pytest.mark.docker
def test_no_fd_leak(icap_service):
    """Test that file descriptors are properly cleaned up after scans.

    Performs many scans and verifies FD count returns to baseline.
    """
    initial_fds = get_open_fd_count()
    if initial_fds == -1:
        pytest.skip("Cannot measure FD count on this platform")

    content = b"FD leak test content"
    num_scans = 50

    # Perform many scans
    for i in range(num_scans):
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            response = client.scan_bytes(
                content,
                service=icap_service["service"],
                filename=f"fdtest_{i}.txt",
            )
            assert response.is_no_modification or response.is_success

    # Check FD count returned to near baseline
    # Allow small tolerance for pytest/logging/etc
    final_fds = get_open_fd_count()
    fd_growth = final_fds - initial_fds

    assert fd_growth < 10, (
        f"FD count grew by {fd_growth} after {num_scans} scans. "
        f"Initial: {initial_fds}, Final: {final_fds}"
    )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
def test_no_memory_leak_sustained(icap_service, memory_tracker):
    """Test memory stability over many sequential scans.

    Performs 100 sequential scans and verifies memory doesn't grow significantly.
    """
    content = b"Memory leak test content " * 100  # ~2.5KB per scan
    num_scans = 100

    with memory_tracker() as stats:
        with IcapClient(icap_service["host"], icap_service["port"]) as client:
            for i in range(num_scans):
                response = client.scan_bytes(
                    content,
                    service=icap_service["service"],
                    filename=f"memtest_{i}.txt",
                )
                assert response.is_no_modification or response.is_success

    # Memory growth should be minimal for sequential scans
    # Allow up to 10MB for buffers, protocol overhead
    assert stats.growth_mb < 10, (
        f"Memory grew by {stats.growth_mb:.1f}MB over {num_scans} scans. "
        f"Peak: {stats.peak_mb:.1f}MB"
    )
