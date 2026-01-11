"""Pytest configuration for pycap tests."""

from __future__ import annotations

import shutil
import ssl
import subprocess
import time
from pathlib import Path

import pytest
from testcontainers.compose import DockerCompose


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
    from pycap import IcapClient

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
    """Start ICAP service using docker-compose."""
    # Check if Docker is available before attempting to start containers
    docker_available, message = is_docker_available()
    if not docker_available:
        pytest.skip(f"Skipping Docker-based tests: {message}")

    docker_path = Path(__file__).parent.parent / "docker"
    config = {"host": "localhost", "port": 1344, "service": "avscan"}

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
