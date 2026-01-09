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
    MockResponseExhaustedError,
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


# === Response Sequence Tests ===


def test_response_sequence_respmod():
    """on_respmod() with multiple responses returns them in order."""
    client = MockIcapClient()
    clean = IcapResponseBuilder().clean().build()
    virus = IcapResponseBuilder().virus("Trojan.Test").build()

    client.on_respmod(clean, virus)

    # First call returns clean
    response1 = client.scan_bytes(b"file1")
    assert response1.is_no_modification

    # Second call returns virus
    response2 = client.scan_bytes(b"file2")
    assert not response2.is_no_modification
    assert response2.headers["X-Virus-ID"] == "Trojan.Test"


def test_response_sequence_exhausted():
    """MockResponseExhaustedError raised when queue is empty."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
    )

    # Wait, single response goes to default, not queue
    # Let's use two responses
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    client.scan_bytes(b"file1")  # clean
    client.scan_bytes(b"file2")  # virus

    # Third call should raise
    with pytest.raises(MockResponseExhaustedError):
        client.scan_bytes(b"file3")


def test_response_sequence_options():
    """on_options() with multiple responses returns them in order."""
    client = MockIcapClient()
    client.on_options(
        IcapResponseBuilder().options(methods=["RESPMOD"]).build(),
        IcapResponseBuilder().error(503, "Unavailable").build(),
    )

    response1 = client.options("avscan")
    assert response1.is_success
    assert response1.headers["Methods"] == "RESPMOD"

    response2 = client.options("avscan")
    assert response2.status_code == 503


def test_response_sequence_reqmod():
    """on_reqmod() with multiple responses returns them in order."""
    client = MockIcapClient()
    client.on_reqmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().error(500).build(),
    )

    response1 = client.reqmod("avscan", b"GET / HTTP/1.1\r\n")
    assert response1.is_no_modification

    response2 = client.reqmod("avscan", b"POST /upload HTTP/1.1\r\n")
    assert response2.status_code == 500


def test_response_sequence_mixed_with_exceptions():
    """Response queues can include exceptions."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapTimeoutError("Timeout on second call"),
        IcapResponseBuilder().virus().build(),
    )

    # First call returns clean
    response1 = client.scan_bytes(b"file1")
    assert response1.is_no_modification

    # Second call raises timeout
    with pytest.raises(IcapTimeoutError, match="Timeout on second call"):
        client.scan_bytes(b"file2")

    # Third call returns virus
    response3 = client.scan_bytes(b"file3")
    assert not response3.is_no_modification


def test_single_response_no_exhaustion():
    """Single response mode (not sequence) doesn't exhaust."""
    client = MockIcapClient()
    client.on_respmod(IcapResponseBuilder().virus().build())

    # Can call multiple times - single response repeats
    for _ in range(5):
        response = client.scan_bytes(b"test")
        assert not response.is_no_modification


def test_reset_responses_clears_queue():
    """reset_responses() clears queued responses and resets to defaults."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().virus().build(),
        IcapResponseBuilder().virus().build(),
    )

    # Use one response
    client.scan_bytes(b"file1")

    # Reset - should clear queue and restore defaults
    client.reset_responses()

    # Now should return default clean response (not exhaust)
    response = client.scan_bytes(b"file2")
    assert response.is_no_modification


def test_sequence_across_different_methods():
    """Each method has independent queue."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )
    client.on_options(
        IcapResponseBuilder().options(methods=["RESPMOD"]).build(),
        IcapResponseBuilder().options(methods=["REQMOD"]).build(),
    )

    # OPTIONS and RESPMOD queues are independent
    assert client.options("avscan").headers["Methods"] == "RESPMOD"
    assert client.scan_bytes(b"file1").is_no_modification
    assert client.options("avscan").headers["Methods"] == "REQMOD"
    assert not client.scan_bytes(b"file2").is_no_modification


def test_scan_methods_share_respmod_queue():
    """scan_bytes, scan_file, scan_stream all consume from respmod queue."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus("First").build(),
        IcapResponseBuilder().virus("Second").build(),
    )

    # Each scan method consumes from the same queue
    assert client.scan_bytes(b"data").is_no_modification

    stream = io.BytesIO(b"stream")
    assert client.scan_stream(stream).headers["X-Virus-ID"] == "First"

    # respmod directly also uses the queue
    assert client.respmod("avscan", b"req", b"resp").headers["X-Virus-ID"] == "Second"


@pytest.mark.asyncio
async def test_async_response_sequence():
    """Async mock also supports response sequences."""
    client = MockAsyncIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    response1 = await client.scan_bytes(b"file1")
    assert response1.is_no_modification

    response2 = await client.scan_bytes(b"file2")
    assert not response2.is_no_modification


@pytest.mark.asyncio
async def test_async_response_sequence_exhausted():
    """Async mock raises MockResponseExhaustedError when queue empty."""
    client = MockAsyncIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    await client.scan_bytes(b"file1")
    await client.scan_bytes(b"file2")

    with pytest.raises(MockResponseExhaustedError):
        await client.scan_bytes(b"file3")


# === Phase 2: Callback Tests ===


def test_callback_basic():
    """Callback is invoked instead of returning default response."""

    def always_virus(data: bytes, **kwargs) -> IcapResponse:
        return IcapResponseBuilder().virus("Callback.Virus").build()

    client = MockIcapClient()
    client.on_respmod(callback=always_virus)

    response = client.scan_bytes(b"any content")
    assert not response.is_no_modification
    assert response.headers["X-Virus-ID"] == "Callback.Virus"


def test_callback_receives_kwargs():
    """Callback receives data, service, and filename from the call."""
    received_kwargs = {}

    def capture_kwargs(data: bytes, **kwargs) -> IcapResponse:
        received_kwargs.update(kwargs)
        received_kwargs["data"] = data
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    client.on_respmod(callback=capture_kwargs)

    client.scan_bytes(b"test content", service="custom_service", filename="test.pdf")

    assert received_kwargs["data"] == b"test content"
    assert received_kwargs["service"] == "custom_service"
    assert received_kwargs["filename"] == "test.pdf"


def test_callback_dynamic_response():
    """Callback can return different responses based on content."""

    def eicar_detector(data: bytes, **kwargs) -> IcapResponse:
        if b"EICAR" in data:
            return IcapResponseBuilder().virus("EICAR-Test").build()
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    client.on_respmod(callback=eicar_detector)

    # Safe content
    response1 = client.scan_bytes(b"safe content")
    assert response1.is_no_modification

    # Content with EICAR
    response2 = client.scan_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    assert not response2.is_no_modification
    assert response2.headers["X-Virus-ID"] == "EICAR-Test"

    # Safe again
    response3 = client.scan_bytes(b"another safe file")
    assert response3.is_no_modification


def test_callback_overrides_queued_responses():
    """Callback takes precedence over queued responses."""

    def always_clean(data: bytes, **kwargs) -> IcapResponse:
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    # First configure a response queue
    client.on_respmod(
        IcapResponseBuilder().virus().build(),
        IcapResponseBuilder().virus().build(),
    )
    # Then set callback (should clear queue)
    client.on_respmod(callback=always_clean)

    # All calls should use callback (clean), not the queued virus responses
    response1 = client.scan_bytes(b"file1")
    assert response1.is_no_modification
    response2 = client.scan_bytes(b"file2")
    assert response2.is_no_modification
    response3 = client.scan_bytes(b"file3")
    assert response3.is_no_modification


def test_callback_cleared_by_reset_responses():
    """reset_responses() clears callback configuration."""

    def always_virus(data: bytes, **kwargs) -> IcapResponse:
        return IcapResponseBuilder().virus().build()

    client = MockIcapClient()
    client.on_respmod(callback=always_virus)

    response1 = client.scan_bytes(b"before reset")
    assert not response1.is_no_modification

    client.reset_responses()

    # After reset, should use default (clean)
    response2 = client.scan_bytes(b"after reset")
    assert response2.is_no_modification


def test_callback_cleared_by_new_response_config():
    """Setting a new response clears the callback."""

    def always_virus(data: bytes, **kwargs) -> IcapResponse:
        return IcapResponseBuilder().virus().build()

    client = MockIcapClient()
    client.on_respmod(callback=always_virus)

    response1 = client.scan_bytes(b"with callback")
    assert not response1.is_no_modification

    # Set a new static response
    client.on_respmod(IcapResponseBuilder().clean().build())

    response2 = client.scan_bytes(b"after static config")
    assert response2.is_no_modification


def test_callback_works_with_scan_file(tmp_path):
    """Callback works with scan_file method."""

    def file_size_detector(data: bytes, **kwargs) -> IcapResponse:
        if len(data) > 100:
            return IcapResponseBuilder().virus("LargeFile").build()
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    client.on_respmod(callback=file_size_detector)

    # Small file
    small_file = tmp_path / "small.txt"
    small_file.write_bytes(b"x" * 50)
    response1 = client.scan_file(small_file)
    assert response1.is_no_modification

    # Large file
    large_file = tmp_path / "large.txt"
    large_file.write_bytes(b"x" * 200)
    response2 = client.scan_file(large_file)
    assert not response2.is_no_modification


def test_callback_works_with_scan_stream():
    """Callback works with scan_stream method."""
    call_count = [0]

    def counting_callback(data: bytes, **kwargs) -> IcapResponse:
        call_count[0] += 1
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    client.on_respmod(callback=counting_callback)

    stream = io.BytesIO(b"stream content")
    client.scan_stream(stream, filename="stream.bin")

    assert call_count[0] == 1


@pytest.mark.asyncio
async def test_async_callback_sync():
    """Async client works with sync callback."""

    def sync_callback(data: bytes, **kwargs) -> IcapResponse:
        if b"virus" in data:
            return IcapResponseBuilder().virus().build()
        return IcapResponseBuilder().clean().build()

    client = MockAsyncIcapClient()
    client.on_respmod(callback=sync_callback)

    response1 = await client.scan_bytes(b"safe content")
    assert response1.is_no_modification

    response2 = await client.scan_bytes(b"this has virus in it")
    assert not response2.is_no_modification


@pytest.mark.asyncio
async def test_async_callback_async():
    """Async client works with async callback."""

    async def async_callback(data: bytes, **kwargs) -> IcapResponse:
        # Simulates async operation (could be async I/O in real code)
        if b"malware" in data:
            return IcapResponseBuilder().virus("Async.Malware").build()
        return IcapResponseBuilder().clean().build()

    client = MockAsyncIcapClient()
    client.on_respmod(callback=async_callback)

    response1 = await client.scan_bytes(b"safe content")
    assert response1.is_no_modification

    response2 = await client.scan_bytes(b"this is malware!")
    assert not response2.is_no_modification
    assert response2.headers["X-Virus-ID"] == "Async.Malware"


@pytest.mark.asyncio
async def test_async_callback_receives_kwargs():
    """Async callback receives proper kwargs."""
    received = {}

    async def capture_async(data: bytes, **kwargs) -> IcapResponse:
        received["data"] = data
        received["service"] = kwargs.get("service")
        received["filename"] = kwargs.get("filename")
        return IcapResponseBuilder().clean().build()

    client = MockAsyncIcapClient()
    client.on_respmod(callback=capture_async)

    await client.scan_bytes(b"async data", service="async_scan", filename="async.txt")

    assert received["data"] == b"async data"
    assert received["service"] == "async_scan"
    assert received["filename"] == "async.txt"
