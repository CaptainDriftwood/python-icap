"""Pytest configuration for python-icap tests."""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path
from typing import Generator

import pytest

from tests.helpers import (
    MB,
    LoadTestMetrics,
    generate_random_file,
    restart_icap_container,
    start_icap_container,
    stop_icap_container,
    track_memory,
)

try:
    from testcontainers.compose import DockerCompose

    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False
    DockerCompose = None  # type: ignore[misc, assignment]


def is_docker_available() -> tuple[bool, str]:
    """
    Check if Docker is installed and running.

    Returns:
        Tuple of (is_available, message) where message explains any issues.
    """
    # Check if docker command exists
    if not shutil.which("docker"):
        return False, "Docker is not installed or not in PATH"

    # Check if docker daemon is running
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False, "Docker daemon is not running. Please start Docker."
    except subprocess.TimeoutExpired:
        return False, "Docker daemon not responding (timeout)"
    except Exception as e:
        return False, f"Failed to check Docker status: {e}"

    return True, "Docker is available"


def is_icap_service_running(host: str, port: int) -> bool:
    """Check if ICAP service is already running by attempting a TCP connection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply timeout to integration tests to allow for Docker startup."""
    for item in items:
        if "integration" in item.keywords:
            # Allow 300s for integration tests (Docker build/startup can be slow)
            item.add_marker(pytest.mark.timeout(300))


def wait_for_icap_service(
    host: str, port: int, service: str, timeout: int = 60, interval: float = 2.0
) -> None:
    """
    Wait for ICAP service to be ready by polling with OPTIONS requests.

    Args:
        host: ICAP server host
        port: ICAP server port
        service: ICAP service name
        timeout: Maximum time to wait in seconds
        interval: Time between retries in seconds

    Raises:
        TimeoutError: If service doesn't become ready within timeout
    """
    from icap import IcapClient

    start_time = time.time()
    last_error = None

    while time.time() - start_time < timeout:
        try:
            with IcapClient(host, port, timeout=5) as client:
                response = client.options(service)
                if response.is_success:
                    return  # Service is ready
        except Exception as e:
            last_error = e

        time.sleep(interval)

    raise TimeoutError(
        f"ICAP service at {host}:{port}/{service} not ready after {timeout}s. "
        f"Last error: {last_error}"
    )


@pytest.fixture(scope="session")
def icap_service():
    """Start ICAP service using docker-compose.

    If the service is already running (e.g., started by CI), uses the existing
    containers. Otherwise, starts containers using testcontainers.
    """
    config = {"host": "localhost", "port": 1344, "service": "avscan"}

    # Check if ICAP service is already running (e.g., started by CI)
    if is_icap_service_running(config["host"], config["port"]):
        # Service is already running, just wait for it to be fully ready
        wait_for_icap_service(config["host"], config["port"], config["service"])
        yield config
        return

    # Check if Docker is available before attempting to start containers
    docker_available, message = is_docker_available()
    if not docker_available:
        pytest.skip(f"Skipping Docker-based tests: {message}")

    # Check if testcontainers is available (requires Python 3.9+)
    if not HAS_TESTCONTAINERS:
        pytest.skip("Skipping Docker-based tests: testcontainers requires Python 3.9+")

    docker_path = Path(__file__).parent.parent / "docker"

    with DockerCompose(str(docker_path), compose_file_name="docker-compose.yml"):
        # Wait for ICAP service to be ready (polls until OPTIONS succeeds)
        wait_for_icap_service(config["host"], config["port"], config["service"])
        yield config


@pytest.fixture(scope="session")
def icap_service_ssl(icap_service):
    """
    Provide SSL-enabled ICAP service configuration.

    This fixture depends on icap_service to ensure Docker is running.
    It skips tests if SSL certificates haven't been generated.

    Returns:
        dict with host, port, ssl_port, service, ssl_context
    """
    ca_cert_path = Path(__file__).parent.parent / "docker/certs/ca.pem"

    if not ca_cert_path.exists():
        pytest.skip("SSL certificates not generated. Run: just generate-certs")

    # Create SSL context with CA certificate
    ssl_context = ssl.create_default_context(cafile=str(ca_cert_path))

    return {
        "host": icap_service["host"],
        "port": icap_service["port"],
        "ssl_port": 11344,
        "service": icap_service["service"],
        "ssl_context": ssl_context,
        "ca_cert": str(ca_cert_path),
    }


# =============================================================================
# Large File Fixtures
# =============================================================================


@pytest.fixture
def large_file_10mb(tmp_path: Path) -> Generator[Path, None, None]:
    """Generate a 10MB file with random data for testing.

    The file is automatically cleaned up after the test.

    Yields:
        Path to the 10MB test file
    """
    file_path = tmp_path / "test_10mb.bin"
    generate_random_file(10 * MB, file_path)
    yield file_path
    # Cleanup handled by tmp_path fixture


@pytest.fixture
def large_file_100mb(tmp_path: Path) -> Generator[Path, None, None]:
    """Generate a 100MB file with random data for testing.

    The file is automatically cleaned up after the test.
    This fixture is slow - tests using it should be marked with @pytest.mark.slow.

    Yields:
        Path to the 100MB test file
    """
    file_path = tmp_path / "test_100mb.bin"
    generate_random_file(100 * MB, file_path)
    yield file_path
    # Cleanup handled by tmp_path fixture


@pytest.fixture
def large_file_factory(tmp_path: Path):
    """Factory fixture for generating files of arbitrary size.

    Returns a callable that creates files of specified size.

    Example:
        def test_custom_size(large_file_factory):
            file_25mb = large_file_factory(25 * MB)
            # use file_25mb
    """
    created_files: list[Path] = []

    def _create_file(size_bytes: int, name: str | None = None) -> Path:
        if name is None:
            name = f"test_{size_bytes // MB}mb.bin"
        file_path = tmp_path / name
        generate_random_file(size_bytes, file_path)
        created_files.append(file_path)
        return file_path

    yield _create_file
    # Cleanup handled by tmp_path fixture


# =============================================================================
# Memory Tracking Fixtures
# =============================================================================


@pytest.fixture
def memory_tracker():
    """Provide memory tracking context manager.

    Returns the track_memory context manager for use in tests.

    Example:
        def test_memory_usage(memory_tracker):
            with memory_tracker() as stats:
                # do work
                pass
            assert stats.peak_mb < 50
    """
    return track_memory


# =============================================================================
# Load Test Fixtures
# =============================================================================


@pytest.fixture
def load_metrics() -> LoadTestMetrics:
    """Provide a fresh LoadTestMetrics instance for collecting test metrics.

    Example:
        def test_load(load_metrics):
            for i in range(100):
                start = time.time()
                try:
                    do_operation()
                    load_metrics.record_success((time.time() - start) * 1000)
                except Exception as e:
                    load_metrics.record_failure(e)
            assert load_metrics.success_rate > 0.95
    """
    return LoadTestMetrics()


# =============================================================================
# Docker Control Fixtures
# =============================================================================


@pytest.fixture
def docker_controller():
    """Provide Docker container control functions.

    Returns a namespace with start, stop, and restart functions.

    Example:
        def test_reconnect(docker_controller, icap_service):
            # Do initial scan
            docker_controller.restart()
            wait_for_icap_service(...)
            # Do another scan
    """

    class DockerController:
        """Docker container controller for tests."""

        container_name = "python-icap-server"

        def restart(self) -> None:
            """Restart the ICAP container."""
            restart_icap_container(self.container_name)

        def stop(self) -> None:
            """Stop the ICAP container."""
            stop_icap_container(self.container_name)

        def start(self) -> None:
            """Start the ICAP container."""
            start_icap_container(self.container_name)

    return DockerController()
