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
@pytest.mark.docker
def test_options_request(icap_service):
    """Test OPTIONS request against real ICAP server."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.options(icap_service["service"])
        assert response.is_success
        assert response.status_code == 200


@pytest.mark.integration
@pytest.mark.docker
def test_scan_clean_content(icap_service):
    """Test scanning clean content."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        clean_content = b"This is clean text content"
        response = client.scan_bytes(clean_content, service=icap_service["service"])
        # Should return 204 (no modification) for clean content
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_scan_eicar_virus(icap_service):
    """Test detection of EICAR test virus."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_bytes(EICAR_TEST_STRING, service=icap_service["service"])
        # Virus should be detected (not 204)
        # The exact response depends on the ICAP server configuration
        assert response.status_code in (200, 403, 500)  # Various ways servers report threats
        # TODO: Use the syrupy snapshot extension to assert against the response txt


@pytest.mark.integration
@pytest.mark.docker
def test_scan_file_path_str(icap_service, tmp_path):
    """Test scanning a file using string path."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean test content")

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_file(str(test_file), service=icap_service["service"])
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_scan_file_path_object(icap_service, tmp_path):
    """Test scanning a file using Path object."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean test content")

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        response = client.scan_file(test_file, service=icap_service["service"])
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_scan_stream(icap_service, tmp_path):
    """Test scanning a file-like object."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean test content")

    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        with open(test_file, "rb") as f:
            response = client.scan_stream(f, service=icap_service["service"])
            assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_respmod_with_preview_small_content(icap_service):
    """Test RESPMOD with preview mode where content fits in preview (ieof case)."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # Small content that fits entirely in preview
        content = b"Small clean content"
        http_request = b"GET /test.txt HTTP/1.1\r\nHost: test\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content
        )

        # Preview size larger than content - should use ieof
        response = client.respmod(
            icap_service["service"],
            http_request,
            http_response,
            preview=1024,
        )
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_respmod_with_preview_large_content(icap_service):
    """Test RESPMOD with preview mode where content exceeds preview size."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # Content larger than preview size
        content = b"A" * 2048  # 2KB of content
        http_request = b"GET /test.bin HTTP/1.1\r\nHost: test\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content
        )

        # Preview size smaller than content - should trigger 100 Continue
        response = client.respmod(
            icap_service["service"],
            http_request,
            http_response,
            preview=512,
        )
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_respmod_with_preview_eicar(icap_service):
    """Test that preview mode correctly detects EICAR virus."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        content = EICAR_TEST_STRING
        http_request = b"GET /eicar.com HTTP/1.1\r\nHost: test\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content
        )

        # EICAR is small enough to fit in preview, server should detect it
        response = client.respmod(
            icap_service["service"],
            http_request,
            http_response,
            preview=1024,
        )
        # Virus should be detected
        assert response.status_code in (200, 403, 500)


@pytest.mark.integration
@pytest.mark.docker
def test_reqmod_basic(icap_service):
    """Test basic REQMOD request without body."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        http_request = b"GET /clean.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"

        response = client.reqmod(icap_service["service"], http_request)
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_reqmod_with_body(icap_service):
    """Test REQMOD with HTTP request body."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        http_request = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 18\r\n"
            b"\r\n"
        )
        http_body = b"Clean file content"

        response = client.reqmod(icap_service["service"], http_request, http_body=http_body)
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
def test_reqmod_with_eicar(icap_service):
    """Test REQMOD detects EICAR in request body."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        http_request = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(EICAR_TEST_STRING)).encode() + b"\r\n"
            b"\r\n"
        )

        response = client.reqmod(icap_service["service"], http_request, http_body=EICAR_TEST_STRING)
        # Virus should be detected
        assert response.status_code in (200, 403, 500)


@pytest.mark.integration
@pytest.mark.docker
def test_connection_reuse(icap_service):
    """Test that a single client can handle multiple sequential requests."""
    with IcapClient(icap_service["host"], icap_service["port"]) as client:
        # First request - OPTIONS
        response1 = client.options(icap_service["service"])
        assert response1.is_success

        # Second request - scan clean content
        response2 = client.scan_bytes(b"Clean content", service=icap_service["service"])
        assert response2.is_success

        # Third request - scan EICAR
        response3 = client.scan_bytes(EICAR_TEST_STRING, service=icap_service["service"])
        assert response3.status_code in (200, 403, 500)

        # Fourth request - another OPTIONS
        response4 = client.options(icap_service["service"])
        assert response4.is_success

        # Verify client stayed connected throughout
        assert client.is_connected
