"""
Integration tests for PyCap using testcontainers.
"""

import time
from pathlib import Path

import pytest
from testcontainers.compose import DockerCompose

from examples.test_utils import EICAR_TEST_STRING
from pycap import IcapClient


@pytest.fixture(scope="module")
def icap_service():
    """Start ICAP service using docker-compose."""
    # Get the path to the docker directory
    docker_path = Path(__file__).parent.parent / "docker"

    with DockerCompose(str(docker_path), compose_file_name="docker-compose.yml"):
        # Wait for services to be ready
        time.sleep(30)  # Give services time to initialize

        yield {"host": "localhost", "port": 1344, "service": "avscan"}


@pytest.mark.integration
def test_options_request(icap_service):
    """Test OPTIONS request against real ICAP server."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.options(icap_service["service"])
        assert response.is_success
        assert response.status_code == 200


@pytest.mark.integration
def test_scan_clean_content(icap_service):
    """Test scanning clean content."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        clean_content = b"This is clean text content"
        response = client.scan_bytes(clean_content, service=icap_service["service"])
        # Should return 204 (no modification) for clean content
        assert response.is_success


@pytest.mark.integration
def test_scan_eicar_virus(icap_service):
    """Test detection of EICAR test virus."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_bytes(EICAR_TEST_STRING, service=icap_service["service"])
        # Virus should be detected (not 204)
        # The exact response depends on the ICAP server configuration
        assert response.status_code in (200, 403, 500)  # Various ways servers report threats


@pytest.mark.integration
def test_scan_file_path_str(icap_service, tmp_path):
    """Test scanning a file using string path."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean test content")

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_file(str(test_file), service=icap_service["service"])
        assert response.is_success


@pytest.mark.integration
def test_scan_file_path_object(icap_service, tmp_path):
    """Test scanning a file using Path object."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean test content")

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_file(test_file, service=icap_service["service"])
        assert response.is_success


@pytest.mark.integration
def test_scan_stream(icap_service, tmp_path):
    """Test scanning a file-like object."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean test content")

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        with open(test_file, "rb") as f:
            response = client.scan_stream(f, service=icap_service["service"])
            assert response.is_success
