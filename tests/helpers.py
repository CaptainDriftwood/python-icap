"""Test helper utilities for integration tests.

This module provides utilities for:
- Large file generation
- Memory tracking
- Docker container control
- Load test metrics collection
"""

from __future__ import annotations

import os
import subprocess
import sys
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

# Size constants
KB = 1024
MB = 1024 * KB
GB = 1024 * MB


def generate_random_bytes(size_bytes: int) -> bytes:
    """Generate random bytes of specified size.

    Uses os.urandom for cryptographically random data that won't compress.

    Args:
        size_bytes: Number of bytes to generate

    Returns:
        Random bytes
    """
    return os.urandom(size_bytes)


def generate_random_file(size_bytes: int, path: Path) -> Path:
    """Generate a file with random binary data.

    Creates a file with non-compressible random data to stress test
    file handling and streaming.

    Args:
        size_bytes: Size of file to generate
        path: Path where file should be created

    Returns:
        Path to the created file
    """
    # Write in chunks to avoid memory issues with very large files
    chunk_size = min(size_bytes, 8 * MB)
    remaining = size_bytes

    with open(path, "wb") as f:
        while remaining > 0:
            write_size = min(chunk_size, remaining)
            f.write(os.urandom(write_size))
            remaining -= write_size

    return path


@dataclass
class MemoryStats:
    """Memory usage statistics from tracking."""

    peak_mb: float
    """Peak memory usage in megabytes."""

    start_mb: float
    """Memory usage at start of tracking in megabytes."""

    end_mb: float
    """Memory usage at end of tracking in megabytes."""

    @property
    def growth_mb(self) -> float:
        """Memory growth during tracking period."""
        return self.end_mb - self.start_mb


@contextmanager
def track_memory() -> Generator[MemoryStats, None, None]:
    """Track memory usage within a context.

    Uses tracemalloc to measure peak memory allocation.

    Yields:
        MemoryStats object (populated after context exits)

    Example:
        with track_memory() as stats:
            # do memory-intensive work
            pass
        print(f"Peak memory: {stats.peak_mb:.1f} MB")
    """
    # Create stats object that will be populated
    stats = MemoryStats(peak_mb=0.0, start_mb=0.0, end_mb=0.0)

    # Start tracking
    tracemalloc.start()
    current, _ = tracemalloc.get_traced_memory()
    stats.start_mb = current / MB

    try:
        yield stats
    finally:
        # Capture final stats
        current, peak = tracemalloc.get_traced_memory()
        stats.end_mb = current / MB
        stats.peak_mb = peak / MB
        tracemalloc.stop()


def restart_icap_container(container_name: str = "python-icap-server") -> None:
    """Restart the ICAP Docker container.

    Args:
        container_name: Name of the container to restart

    Raises:
        subprocess.CalledProcessError: If restart fails
    """
    subprocess.run(
        ["docker", "restart", container_name],
        check=True,
        capture_output=True,
        timeout=60,
    )


def stop_icap_container(container_name: str = "python-icap-server") -> None:
    """Stop the ICAP Docker container.

    Args:
        container_name: Name of the container to stop

    Raises:
        subprocess.CalledProcessError: If stop fails
    """
    subprocess.run(
        ["docker", "stop", container_name],
        check=True,
        capture_output=True,
        timeout=30,
    )


def start_icap_container(container_name: str = "python-icap-server") -> None:
    """Start the ICAP Docker container.

    Args:
        container_name: Name of the container to start

    Raises:
        subprocess.CalledProcessError: If start fails
    """
    subprocess.run(
        ["docker", "start", container_name],
        check=True,
        capture_output=True,
        timeout=60,
    )


def get_open_fd_count() -> int:
    """Return count of open file descriptors for current process.

    Works on Linux and macOS. Returns -1 on unsupported platforms.

    Returns:
        Number of open file descriptors, or -1 if unable to determine
    """
    if sys.platform == "linux":
        fd_path = Path(f"/proc/{os.getpid()}/fd")
        if fd_path.exists():
            return len(list(fd_path.iterdir()))
    elif sys.platform == "darwin":
        # macOS: use lsof
        try:
            result = subprocess.run(
                ["lsof", "-p", str(os.getpid())],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Count lines (minus header)
            lines = result.stdout.strip().split("\n")
            return max(0, len(lines) - 1)
        except Exception:
            pass

    return -1


@dataclass
class LoadTestMetrics:
    """Metrics collected during load tests."""

    success_count: int = 0
    """Number of successful operations."""

    failure_count: int = 0
    """Number of failed operations."""

    latencies_ms: list[float] = field(default_factory=list)
    """List of operation latencies in milliseconds."""

    errors: list[str] = field(default_factory=list)
    """List of error messages from failures."""

    @property
    def total_count(self) -> int:
        """Total number of operations attempted."""
        return self.success_count + self.failure_count

    @property
    def success_rate(self) -> float:
        """Success rate as a fraction (0.0 to 1.0)."""
        if self.total_count == 0:
            return 0.0
        return self.success_count / self.total_count

    @property
    def success_rate_percent(self) -> float:
        """Success rate as a percentage (0 to 100)."""
        return self.success_rate * 100

    @property
    def avg_latency_ms(self) -> float:
        """Average latency in milliseconds."""
        if not self.latencies_ms:
            return 0.0
        return sum(self.latencies_ms) / len(self.latencies_ms)

    @property
    def min_latency_ms(self) -> float:
        """Minimum latency in milliseconds."""
        if not self.latencies_ms:
            return 0.0
        return min(self.latencies_ms)

    @property
    def max_latency_ms(self) -> float:
        """Maximum latency in milliseconds."""
        if not self.latencies_ms:
            return 0.0
        return max(self.latencies_ms)

    @property
    def p50_latency_ms(self) -> float:
        """50th percentile (median) latency in milliseconds."""
        return self._percentile(50)

    @property
    def p95_latency_ms(self) -> float:
        """95th percentile latency in milliseconds."""
        return self._percentile(95)

    @property
    def p99_latency_ms(self) -> float:
        """99th percentile latency in milliseconds."""
        return self._percentile(99)

    def _percentile(self, p: float) -> float:
        """Calculate percentile of latencies."""
        if not self.latencies_ms:
            return 0.0
        sorted_latencies = sorted(self.latencies_ms)
        index = int(len(sorted_latencies) * p / 100)
        index = min(index, len(sorted_latencies) - 1)
        return sorted_latencies[index]

    def record_success(self, latency_ms: float) -> None:
        """Record a successful operation.

        Args:
            latency_ms: Operation latency in milliseconds
        """
        self.success_count += 1
        self.latencies_ms.append(latency_ms)

    def record_failure(self, error: Exception | str, latency_ms: float = 0.0) -> None:
        """Record a failed operation.

        Args:
            error: Exception or error message
            latency_ms: Operation latency in milliseconds (if available)
        """
        self.failure_count += 1
        if latency_ms > 0:
            self.latencies_ms.append(latency_ms)
        error_msg = str(error) if isinstance(error, Exception) else error
        self.errors.append(error_msg)

    def summary(self) -> str:
        """Return a human-readable summary of metrics."""
        lines = [
            f"Total: {self.total_count} operations",
            f"Success: {self.success_count} ({self.success_rate_percent:.1f}%)",
            f"Failures: {self.failure_count}",
        ]
        if self.latencies_ms:
            lines.extend(
                [
                    f"Latency avg: {self.avg_latency_ms:.1f}ms",
                    f"Latency p50: {self.p50_latency_ms:.1f}ms",
                    f"Latency p99: {self.p99_latency_ms:.1f}ms",
                    f"Latency min/max: {self.min_latency_ms:.1f}ms / {self.max_latency_ms:.1f}ms",
                ]
            )
        return "\n".join(lines)
