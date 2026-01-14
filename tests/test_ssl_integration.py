"""SSL/TLS integration tests for the ICAP client."""

import pytest

from icap import AsyncIcapClient, IcapClient

# EICAR test string for virus detection
EICAR_TEST_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
def test_ssl_options_request(icap_service_ssl):
    """Test OPTIONS request over TLS connection."""
    with IcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = client.options(icap_service_ssl["service"])
        assert response.is_success
        assert response.status_code == 200
        assert "Methods" in response.headers


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
def test_ssl_scan_clean_content(icap_service_ssl):
    """Test scanning clean content over TLS."""
    with IcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = client.scan_bytes(b"This is clean test content")
        assert response.is_success
        assert response.status_code in (200, 204)


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
def test_ssl_scan_eicar_virus(icap_service_ssl):
    """Test that EICAR virus is detected over TLS."""
    with IcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = client.scan_bytes(EICAR_TEST_STRING)
        # EICAR should trigger virus detection
        assert response.status_code in (200, 403, 500)
        # Check for virus indicator in response
        assert not response.is_success or "X-Virus-ID" in response.headers


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
def test_ssl_respmod_clean(icap_service_ssl):
    """Test RESPMOD with clean content over TLS."""
    with IcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        content = b"Clean file content for testing"
        http_request = b"GET /test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content
        )

        response = client.respmod(
            icap_service_ssl["service"],
            http_request,
            http_response,
        )
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
@pytest.mark.asyncio
async def test_ssl_async_options(icap_service_ssl):
    """Test async OPTIONS request over TLS."""
    async with AsyncIcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = await client.options(icap_service_ssl["service"])
        assert response.is_success
        assert response.status_code == 200


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
@pytest.mark.asyncio
async def test_ssl_async_scan_clean(icap_service_ssl):
    """Test async scanning clean content over TLS."""
    async with AsyncIcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = await client.scan_bytes(b"Clean async test content")
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
@pytest.mark.asyncio
async def test_ssl_async_scan_eicar(icap_service_ssl):
    """Test async EICAR detection over TLS."""
    async with AsyncIcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = await client.scan_bytes(EICAR_TEST_STRING)
        # EICAR should trigger virus detection
        assert response.status_code in (200, 403, 500)


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
def test_ssl_scan_file(icap_service_ssl, tmp_path):
    """Test scanning a file over TLS."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean file content for SSL testing")

    with IcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = client.scan_file(test_file, service=icap_service_ssl["service"])
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
def test_ssl_scan_stream(icap_service_ssl, tmp_path):
    """Test scanning a stream over TLS."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean stream content for SSL testing")

    with IcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        with open(test_file, "rb") as f:
            response = client.scan_stream(f, service=icap_service_ssl["service"])
            assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
@pytest.mark.asyncio
async def test_ssl_async_scan_file(icap_service_ssl, tmp_path):
    """Test async scanning a file over TLS."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean file content for async SSL testing")

    async with AsyncIcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        response = await client.scan_file(test_file, service=icap_service_ssl["service"])
        assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
@pytest.mark.asyncio
async def test_ssl_async_scan_stream(icap_service_ssl, tmp_path):
    """Test async scanning a stream over TLS."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"Clean stream content for async SSL testing")

    async with AsyncIcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        with open(test_file, "rb") as f:
            response = await client.scan_stream(f, service=icap_service_ssl["service"])
            assert response.is_success


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.ssl
@pytest.mark.asyncio
async def test_ssl_async_respmod(icap_service_ssl):
    """Test async RESPMOD over TLS."""
    async with AsyncIcapClient(
        icap_service_ssl["host"],
        port=icap_service_ssl["ssl_port"],
        ssl_context=icap_service_ssl["ssl_context"],
    ) as client:
        content = b"Clean content for async respmod"
        http_request = b"GET /test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(content)).encode() + b"\r\n"
            b"\r\n" + content
        )

        response = await client.respmod(icap_service_ssl["service"], http_request, http_response)
        assert response.is_success
