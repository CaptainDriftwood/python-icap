"""Tests for pytest_pycap mock functionality."""

from __future__ import annotations

import io

import pytest

from pycap import IcapResponse
from pycap.exception import IcapConnectionError, IcapTimeoutError
from pytest_pycap import (
    IcapResponseBuilder,
    MockAsyncIcapClient,
    MockCall,
    MockIcapClient,
)

# === IcapResponseBuilder Tests ===


def test_builder_default_is_clean():
    """Default builder creates 204 No Modification response."""
    response = IcapResponseBuilder().build()
    assert response.status_code == 204
    assert response.status_message == "No Modification"


def test_builder_clean():
    """clean() creates 204 No Modification response."""
    response = IcapResponseBuilder().clean().build()
    assert response.status_code == 204
    assert response.is_no_modification


def test_builder_virus():
    """virus() creates virus detection response."""
    response = IcapResponseBuilder().virus().build()
    assert response.status_code == 200
    assert response.headers["X-Virus-ID"] == "EICAR-Test-Signature"


def test_builder_virus_custom_name():
    """virus() accepts custom virus name."""
    response = IcapResponseBuilder().virus("Trojan.Generic").build()
    assert response.headers["X-Virus-ID"] == "Trojan.Generic"


def test_builder_options():
    """options() creates OPTIONS response with methods and preview."""
    response = IcapResponseBuilder().options().build()
    assert response.status_code == 200
    assert "Methods" in response.headers
    assert "Preview" in response.headers


def test_builder_options_custom_methods():
    """options() accepts custom methods list."""
    response = IcapResponseBuilder().options(methods=["RESPMOD"]).build()
    assert response.headers["Methods"] == "RESPMOD"


def test_builder_error():
    """error() creates 500 error response."""
    response = IcapResponseBuilder().error().build()
    assert response.status_code == 500
    assert response.status_message == "Internal Server Error"


def test_builder_error_custom_code():
    """error() accepts custom error code and message."""
    response = IcapResponseBuilder().error(503, "Service Unavailable").build()
    assert response.status_code == 503
    assert response.status_message == "Service Unavailable"


def test_builder_continue_response():
    """continue_response() creates 100 Continue."""
    response = IcapResponseBuilder().continue_response().build()
    assert response.status_code == 100
    assert response.status_message == "Continue"


def test_builder_with_status():
    """with_status() sets custom status code and message."""
    response = IcapResponseBuilder().with_status(201, "Created").build()
    assert response.status_code == 201
    assert response.status_message == "Created"


def test_builder_with_header():
    """with_header() adds a custom header."""
    response = IcapResponseBuilder().with_header("X-Custom", "value").build()
    assert response.headers["X-Custom"] == "value"


def test_builder_with_headers():
    """with_headers() adds multiple headers."""
    response = IcapResponseBuilder().with_headers({"X-One": "1", "X-Two": "2"}).build()
    assert response.headers["X-One"] == "1"
    assert response.headers["X-Two"] == "2"


def test_builder_with_body():
    """with_body() sets response body."""
    response = IcapResponseBuilder().with_body(b"test body").build()
    assert response.body == b"test body"


def test_builder_fluent_chaining():
    """Builder supports method chaining."""
    response = (
        IcapResponseBuilder()
        .with_status(200, "OK")
        .with_header("X-Test", "value")
        .with_body(b"body")
        .build()
    )
    assert response.status_code == 200
    assert response.headers["X-Test"] == "value"
    assert response.body == b"body"


# === MockCall Tests ===


def test_mock_call_repr():
    """MockCall has useful repr."""
    call = MockCall(method="scan_bytes", timestamp=0, kwargs={"data": b"test"})
    assert "scan_bytes" in repr(call)
    assert "data" in repr(call)


# === MockIcapClient Tests ===


def test_mock_client_default_clean_response():
    """Default mock returns clean responses."""
    client = MockIcapClient()
    response = client.scan_bytes(b"content")
    assert response.is_no_modification


def test_mock_client_records_calls():
    """Mock records method calls."""
    client = MockIcapClient()
    client.scan_bytes(b"test")
    assert len(client.calls) == 1
    assert client.calls[0].method == "scan_bytes"
    assert client.calls[0].kwargs["data"] == b"test"


def test_mock_client_assert_called():
    """assert_called() validates method was called."""
    client = MockIcapClient()
    client.scan_bytes(b"test")
    client.assert_called("scan_bytes")
    client.assert_called("scan_bytes", times=1)


def test_mock_client_assert_called_fails_if_not_called():
    """assert_called() fails if method wasn't called."""
    client = MockIcapClient()
    with pytest.raises(AssertionError, match="never called"):
        client.assert_called("scan_bytes")


def test_mock_client_assert_called_fails_wrong_times():
    """assert_called() fails if called wrong number of times."""
    client = MockIcapClient()
    client.scan_bytes(b"test")
    with pytest.raises(AssertionError, match="1 times, expected 2"):
        client.assert_called("scan_bytes", times=2)


def test_mock_client_assert_not_called():
    """assert_not_called() validates method wasn't called."""
    client = MockIcapClient()
    client.assert_not_called("scan_bytes")
    client.assert_not_called()


def test_mock_client_assert_not_called_fails():
    """assert_not_called() fails if method was called."""
    client = MockIcapClient()
    client.scan_bytes(b"test")
    with pytest.raises(AssertionError):
        client.assert_not_called("scan_bytes")


def test_mock_client_assert_scanned():
    """assert_scanned() validates content was scanned."""
    client = MockIcapClient()
    client.scan_bytes(b"test content")
    client.assert_scanned(b"test content")


def test_mock_client_assert_scanned_fails():
    """assert_scanned() fails if content wasn't scanned."""
    client = MockIcapClient()
    client.scan_bytes(b"test content")
    with pytest.raises(AssertionError):
        client.assert_scanned(b"other content")


def test_mock_client_reset_calls():
    """reset_calls() clears call history."""
    client = MockIcapClient()
    client.scan_bytes(b"test")
    assert len(client.calls) == 1
    client.reset_calls()
    assert len(client.calls) == 0


def test_mock_client_on_respmod():
    """on_respmod() configures RESPMOD response."""
    client = MockIcapClient()
    client.on_respmod(IcapResponseBuilder().virus().build())
    response = client.scan_bytes(b"test")
    assert not response.is_no_modification
    assert "X-Virus-ID" in response.headers


def test_mock_client_on_options():
    """on_options() configures OPTIONS response."""
    client = MockIcapClient()
    client.on_options(IcapResponseBuilder().options(preview=2048).build())
    response = client.options("avscan")
    assert response.headers["Preview"] == "2048"


def test_mock_client_on_reqmod():
    """on_reqmod() configures REQMOD response."""
    client = MockIcapClient()
    client.on_reqmod(IcapResponseBuilder().error().build())
    response = client.reqmod("avscan", b"GET / HTTP/1.1\r\n")
    assert response.status_code == 500


def test_mock_client_on_any():
    """on_any() configures all methods."""
    client = MockIcapClient()
    client.on_any(IcapResponseBuilder().virus().build())
    assert not client.scan_bytes(b"test").is_no_modification
    assert not client.options("avscan").is_no_modification


def test_mock_client_exception_injection():
    """Mock can raise exceptions."""
    client = MockIcapClient()
    client.on_any(raises=IcapTimeoutError("Timeout"))
    with pytest.raises(IcapTimeoutError):
        client.scan_bytes(b"test")


def test_mock_client_context_manager():
    """Mock supports context manager."""
    with MockIcapClient() as client:
        assert client.is_connected
        response = client.scan_bytes(b"test")
        assert response.is_no_modification
    assert not client.is_connected


def test_mock_client_host_port_properties():
    """Mock has host and port properties."""
    client = MockIcapClient("test-host", 1234)
    assert client.host == "test-host"
    assert client.port == 1234


def test_mock_client_scan_file(tmp_path):
    """scan_file() reads and records file content."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"file content")

    client = MockIcapClient()
    response = client.scan_file(test_file)
    assert response.is_no_modification
    client.assert_called("scan_file", times=1)
    assert client.calls[0].kwargs["data"] == b"file content"


def test_mock_client_scan_file_not_found():
    """scan_file() raises FileNotFoundError for missing files."""
    client = MockIcapClient()
    with pytest.raises(FileNotFoundError):
        client.scan_file("/nonexistent/file.txt")


def test_mock_client_scan_stream():
    """scan_stream() reads stream content."""
    stream = io.BytesIO(b"stream content")
    client = MockIcapClient()
    response = client.scan_stream(stream)
    assert response.is_no_modification
    assert client.calls[0].kwargs["data"] == b"stream content"


# === MockAsyncIcapClient Tests ===


@pytest.mark.asyncio
async def test_async_mock_client_scan_bytes():
    """Async mock returns clean responses."""
    client = MockAsyncIcapClient()
    response = await client.scan_bytes(b"content")
    assert response.is_no_modification


@pytest.mark.asyncio
async def test_async_mock_client_context_manager():
    """Async mock supports async context manager."""
    async with MockAsyncIcapClient() as client:
        assert client.is_connected
        response = await client.scan_bytes(b"test")
        assert response.is_no_modification
    assert not client.is_connected


@pytest.mark.asyncio
async def test_async_mock_client_records_calls():
    """Async mock records method calls."""
    client = MockAsyncIcapClient()
    await client.scan_bytes(b"test")
    assert len(client.calls) == 1
    client.assert_called("scan_bytes")


@pytest.mark.asyncio
async def test_async_mock_client_exception_injection():
    """Async mock can raise exceptions."""
    client = MockAsyncIcapClient()
    client.on_any(raises=IcapConnectionError("Connection failed"))
    with pytest.raises(IcapConnectionError):
        await client.scan_bytes(b"test")


# === Mock Fixture Tests ===


def test_mock_icap_client_fixture(mock_icap_client):
    """mock_icap_client fixture returns clean responses."""
    response = mock_icap_client.scan_bytes(b"test")
    assert response.is_no_modification


@pytest.mark.asyncio
async def test_mock_async_icap_client_fixture(mock_async_icap_client):
    """mock_async_icap_client fixture works with async."""
    response = await mock_async_icap_client.scan_bytes(b"test")
    assert response.is_no_modification


def test_mock_icap_client_virus_fixture(mock_icap_client_virus):
    """mock_icap_client_virus fixture detects viruses."""
    response = mock_icap_client_virus.scan_bytes(b"test")
    assert not response.is_no_modification
    assert "X-Virus-ID" in response.headers


def test_mock_icap_client_timeout_fixture(mock_icap_client_timeout):
    """mock_icap_client_timeout fixture raises timeout."""
    with pytest.raises(IcapTimeoutError):
        mock_icap_client_timeout.scan_bytes(b"test")


def test_mock_icap_client_connection_error_fixture(mock_icap_client_connection_error):
    """mock_icap_client_connection_error fixture raises connection error."""
    with pytest.raises(IcapConnectionError):
        mock_icap_client_connection_error.scan_bytes(b"test")


# === Response Fixture Tests ===


def test_icap_response_builder_fixture(icap_response_builder):
    """icap_response_builder fixture returns builder instance."""
    assert isinstance(icap_response_builder, IcapResponseBuilder)
    response = icap_response_builder.clean().build()
    assert response.is_no_modification


def test_icap_response_clean_fixture(icap_response_clean):
    """icap_response_clean fixture returns clean response."""
    assert isinstance(icap_response_clean, IcapResponse)
    assert icap_response_clean.is_no_modification


def test_icap_response_virus_fixture(icap_response_virus):
    """icap_response_virus fixture returns virus response."""
    assert isinstance(icap_response_virus, IcapResponse)
    assert "X-Virus-ID" in icap_response_virus.headers


def test_icap_response_options_fixture(icap_response_options):
    """icap_response_options fixture returns OPTIONS response."""
    assert isinstance(icap_response_options, IcapResponse)
    assert "Methods" in icap_response_options.headers


def test_icap_response_error_fixture(icap_response_error):
    """icap_response_error fixture returns error response."""
    assert isinstance(icap_response_error, IcapResponse)
    assert icap_response_error.status_code == 500


# === icap_mock Marker Tests ===


@pytest.mark.icap_mock(response="clean")
def test_marker_clean_response(icap_mock):
    """icap_mock marker with response='clean'."""
    response = icap_mock.scan_bytes(b"test")
    assert response.is_no_modification


@pytest.mark.icap_mock(response="virus")
def test_marker_virus_response(icap_mock):
    """icap_mock marker with response='virus'."""
    response = icap_mock.scan_bytes(b"test")
    assert not response.is_no_modification
    assert "X-Virus-ID" in response.headers


@pytest.mark.icap_mock(response="virus", virus_name="Trojan.Custom")
def test_marker_custom_virus_name(icap_mock):
    """icap_mock marker with custom virus_name."""
    response = icap_mock.scan_bytes(b"test")
    assert response.headers["X-Virus-ID"] == "Trojan.Custom"


@pytest.mark.icap_mock(response="error")
def test_marker_error_response(icap_mock):
    """icap_mock marker with response='error'."""
    response = icap_mock.scan_bytes(b"test")
    assert response.status_code == 500


@pytest.mark.icap_mock(raises=IcapTimeoutError)
def test_marker_raises_exception_class(icap_mock):
    """icap_mock marker with raises=ExceptionClass."""
    with pytest.raises(IcapTimeoutError):
        icap_mock.scan_bytes(b"test")


@pytest.mark.icap_mock(raises=IcapConnectionError("Custom message"))
def test_marker_raises_exception_instance(icap_mock):
    """icap_mock marker with raises=exception_instance."""
    with pytest.raises(IcapConnectionError, match="Custom message"):
        icap_mock.scan_bytes(b"test")


def test_marker_default_clean(icap_mock):
    """icap_mock fixture without marker returns clean responses."""
    response = icap_mock.scan_bytes(b"test")
    assert response.is_no_modification


@pytest.mark.icap_mock(respmod={"response": "virus"})
def test_marker_per_method_config(icap_mock):
    """icap_mock marker with per-method configuration."""
    # RESPMOD/scan_bytes should return virus
    response = icap_mock.scan_bytes(b"test")
    assert not response.is_no_modification
    # OPTIONS should still return default
    response = icap_mock.options("avscan")
    assert response.status_code == 200
