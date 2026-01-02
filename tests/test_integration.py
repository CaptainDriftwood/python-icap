"""
Integration tests for PyCap using testcontainers.

Wait Strategy Note:
    testcontainers emits a DeprecationWarning recommending migration from
    @wait_container_is_ready to structured wait strategies like
    HealthcheckWaitStrategy. However, these new strategies have a bug with
    DockerCompose containers:

    - HealthcheckWaitStrategy accesses `wrapped.attrs.get("State", {}).get("Health", {})`
    - This assumes a Docker SDK container object with an `attrs` attribute
    - ComposeContainer.get_wrapped_container() returns a ComposeContainer, not a
      Docker SDK container, causing: AttributeError: 'ComposeContainer' object
      has no attribute 'attrs'

    Relevant GitHub issues:
    - https://github.com/testcontainers/testcontainers-python/issues/241
      (Open since 2022: "Add wait_for_healthcheck method to DockerCompose")
    - https://github.com/testcontainers/testcontainers-python/issues/144
      (Similar pattern: wait_for_logs failed with DockerCompose)

    Workaround:
    We filter the deprecation warning in pyproject.toml and use our own
    ICAP-level polling via wait_for_icap_service() for reliable service
    readiness detection. This approach is actually more robust as it verifies
    the ICAP protocol is responding, not just that the container is healthy.
"""

import pytest

from examples.test_utils import EICAR_TEST_STRING
from pycap import IcapClient


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
        # TODO: Use the syrupy snapshot extension to assert against the response txt


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
