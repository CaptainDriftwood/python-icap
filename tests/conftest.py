"""Pytest configuration for pycap tests."""

import time
from pathlib import Path

import pytest
from testcontainers.compose import DockerCompose


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


@pytest.fixture(scope="module")
def icap_service():
    """Start ICAP service using docker-compose."""
    docker_path = Path(__file__).parent.parent / "docker"
    config = {"host": "localhost", "port": 1344, "service": "avscan"}

    with DockerCompose(str(docker_path), compose_file_name="docker-compose.yml"):
        # Wait for ICAP service to be ready (polls until OPTIONS succeeds)
        wait_for_icap_service(config["host"], config["port"], config["service"])
        yield config
