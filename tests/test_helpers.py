"""Tests for test helper utilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import (
    KB,
    MB,
    LoadTestMetrics,
    MemoryStats,
    generate_random_bytes,
    generate_random_file,
    get_open_fd_count,
    track_memory,
)


def test_generate_random_bytes_size():
    """Test that generate_random_bytes returns correct size."""
    data = generate_random_bytes(1000)
    assert len(data) == 1000


def test_generate_random_bytes_is_random():
    """Test that generate_random_bytes returns different data each call."""
    data1 = generate_random_bytes(100)
    data2 = generate_random_bytes(100)
    assert data1 != data2


def test_generate_random_file(tmp_path: Path):
    """Test that generate_random_file creates file of correct size."""
    file_path = tmp_path / "test.bin"
    result = generate_random_file(1 * KB, file_path)

    assert result == file_path
    assert file_path.exists()
    assert file_path.stat().st_size == 1 * KB


def test_generate_random_file_large(tmp_path: Path):
    """Test generating a larger file (1MB)."""
    file_path = tmp_path / "test_1mb.bin"
    generate_random_file(1 * MB, file_path)

    assert file_path.exists()
    assert file_path.stat().st_size == 1 * MB


def test_memory_stats_growth():
    """Test MemoryStats growth calculation."""
    stats = MemoryStats(peak_mb=50.0, start_mb=10.0, end_mb=30.0)
    assert stats.growth_mb == 20.0


def test_track_memory_captures_peak():
    """Test that track_memory captures peak memory usage."""
    with track_memory() as stats:
        # Allocate some memory
        data = [b"x" * (1 * MB) for _ in range(5)]
        # Keep reference to prevent GC
        assert len(data) == 5

    # Should have captured some memory usage
    assert stats.peak_mb > 0
    assert stats.start_mb >= 0
    assert stats.end_mb >= 0


def test_load_metrics_success():
    """Test LoadTestMetrics success tracking."""
    metrics = LoadTestMetrics()
    metrics.record_success(10.0)
    metrics.record_success(20.0)
    metrics.record_success(30.0)

    assert metrics.success_count == 3
    assert metrics.failure_count == 0
    assert metrics.total_count == 3
    assert metrics.success_rate == 1.0
    assert metrics.success_rate_percent == 100.0
    assert metrics.avg_latency_ms == 20.0


def test_load_metrics_failure():
    """Test LoadTestMetrics failure tracking."""
    metrics = LoadTestMetrics()
    metrics.record_success(10.0)
    metrics.record_failure("Connection error")
    metrics.record_failure(ValueError("Bad value"), latency_ms=5.0)

    assert metrics.success_count == 1
    assert metrics.failure_count == 2
    assert metrics.success_rate == pytest.approx(1 / 3)
    assert len(metrics.errors) == 2
    assert "Connection error" in metrics.errors
    assert "Bad value" in metrics.errors


def test_load_metrics_percentiles():
    """Test LoadTestMetrics percentile calculations."""
    metrics = LoadTestMetrics()
    # Add 100 latencies from 1 to 100
    for i in range(1, 101):
        metrics.record_success(float(i))

    assert metrics.min_latency_ms == 1.0
    assert metrics.max_latency_ms == 100.0
    # Percentile implementation uses floor index, so p50 of 1-100 is index 50 = value 51
    assert 50 <= metrics.p50_latency_ms <= 51
    assert 95 <= metrics.p95_latency_ms <= 96
    assert 99 <= metrics.p99_latency_ms <= 100


def test_load_metrics_empty():
    """Test LoadTestMetrics with no data."""
    metrics = LoadTestMetrics()

    assert metrics.total_count == 0
    assert metrics.success_rate == 0.0
    assert metrics.avg_latency_ms == 0.0
    assert metrics.p99_latency_ms == 0.0


def test_load_metrics_summary():
    """Test LoadTestMetrics summary output."""
    metrics = LoadTestMetrics()
    metrics.record_success(10.0)
    metrics.record_success(20.0)
    metrics.record_failure("Error")

    summary = metrics.summary()

    assert "Total: 3 operations" in summary
    assert "Success: 2" in summary
    assert "Failures: 1" in summary
    assert "Latency avg:" in summary


def test_get_open_fd_count():
    """Test that get_open_fd_count returns a reasonable value."""
    count = get_open_fd_count()
    # Should return a positive number or -1 on unsupported platforms
    assert count == -1 or count > 0


# =============================================================================
# Fixture Tests
# =============================================================================


def test_large_file_10mb_fixture(large_file_10mb: Path):
    """Test that large_file_10mb fixture creates correct file."""
    assert large_file_10mb.exists()
    assert large_file_10mb.stat().st_size == 10 * MB


def test_large_file_factory_fixture(large_file_factory):
    """Test that large_file_factory creates files of specified size."""
    file_5mb = large_file_factory(5 * MB)
    assert file_5mb.exists()
    assert file_5mb.stat().st_size == 5 * MB

    file_2mb = large_file_factory(2 * MB, name="custom.bin")
    assert file_2mb.exists()
    assert file_2mb.name == "custom.bin"
    assert file_2mb.stat().st_size == 2 * MB


def test_memory_tracker_fixture(memory_tracker):
    """Test that memory_tracker fixture provides track_memory."""
    with memory_tracker() as stats:
        data = b"x" * (1 * MB)
        assert len(data) == 1 * MB

    assert stats.peak_mb > 0


def test_load_metrics_fixture(load_metrics: LoadTestMetrics):
    """Test that load_metrics fixture provides fresh instance."""
    assert load_metrics.total_count == 0
    load_metrics.record_success(10.0)
    assert load_metrics.success_count == 1
