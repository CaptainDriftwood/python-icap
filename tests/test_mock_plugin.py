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
    response2 = client.scan_bytes(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    )
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


# === Phase 3: Content Matcher Tests ===


def test_matcher_filename_exact():
    """when(filename=) matches exact filename."""
    client = MockIcapClient()
    client.when(filename="malware.exe").respond(IcapResponseBuilder().virus("Exact.Match").build())

    # Exact match should trigger virus response
    response1 = client.scan_bytes(b"content", filename="malware.exe")
    assert not response1.is_no_modification
    assert response1.headers["X-Virus-ID"] == "Exact.Match"

    # Different filename should fall through to default
    response2 = client.scan_bytes(b"content", filename="safe.txt")
    assert response2.is_no_modification

    # No filename should fall through to default
    response3 = client.scan_bytes(b"content")
    assert response3.is_no_modification


def test_matcher_filename_pattern():
    """when(filename_matches=) matches regex pattern."""
    client = MockIcapClient()
    client.when(filename_matches=r".*\.exe$").respond(
        IcapResponseBuilder().virus("Policy.BlockedExecutable").build()
    )

    # .exe files match
    response1 = client.scan_bytes(b"content", filename="program.exe")
    assert not response1.is_no_modification

    response2 = client.scan_bytes(b"content", filename="installer.EXE")
    assert response2.is_no_modification  # Case-sensitive by default

    # Non-.exe files don't match
    response3 = client.scan_bytes(b"content", filename="document.pdf")
    assert response3.is_no_modification


def test_matcher_data_contains():
    """when(data_contains=) matches content containing bytes."""
    client = MockIcapClient()
    client.when(data_contains=b"EICAR").respond(IcapResponseBuilder().virus("EICAR-Test").build())

    # Content with EICAR triggers
    response1 = client.scan_bytes(b"X5O!P%@AP...EICAR...test")
    assert not response1.is_no_modification

    # Content without EICAR is clean
    response2 = client.scan_bytes(b"safe content here")
    assert response2.is_no_modification


def test_matcher_service():
    """when(service=) matches specific service name."""
    client = MockIcapClient()
    client.when(service="avscan").respond(IcapResponseBuilder().virus("Service.Match").build())

    # Default service is "avscan"
    response1 = client.scan_bytes(b"content")
    assert not response1.is_no_modification

    # Different service doesn't match
    response2 = client.scan_bytes(b"content", service="dlp")
    assert response2.is_no_modification


def test_matcher_combined_criteria():
    """when() with multiple criteria uses AND logic."""
    client = MockIcapClient()
    client.when(
        service="avscan",
        filename_matches=r".*\.docx$",
        data_contains=b"PK\x03\x04",  # ZIP header
    ).respond(IcapResponseBuilder().virus("Macro.Suspicious").build())

    # All criteria match
    response1 = client.scan_bytes(b"PK\x03\x04content", service="avscan", filename="doc.docx")
    assert not response1.is_no_modification

    # Missing data_contains
    response2 = client.scan_bytes(b"plain text", service="avscan", filename="doc.docx")
    assert response2.is_no_modification

    # Wrong service
    response3 = client.scan_bytes(b"PK\x03\x04content", service="dlp", filename="doc.docx")
    assert response3.is_no_modification


def test_matcher_chaining():
    """Multiple matchers can be chained with method chaining."""
    client = MockIcapClient()
    client.when(filename="virus.exe").respond(
        IcapResponseBuilder().virus("Known.Virus").build()
    ).when(filename="suspicious.bat").respond(
        IcapResponseBuilder().virus("Suspicious.Script").build()
    )

    response1 = client.scan_bytes(b"content", filename="virus.exe")
    assert response1.headers["X-Virus-ID"] == "Known.Virus"

    response2 = client.scan_bytes(b"content", filename="suspicious.bat")
    assert response2.headers["X-Virus-ID"] == "Suspicious.Script"

    response3 = client.scan_bytes(b"content", filename="safe.txt")
    assert response3.is_no_modification


def test_matcher_first_match_wins():
    """First matching matcher wins when multiple could match."""
    client = MockIcapClient()
    # More specific matcher first
    client.when(filename="specific.exe").respond(
        IcapResponseBuilder().virus("Specific.Match").build()
    )
    # General matcher second
    client.when(filename_matches=r".*\.exe$").respond(
        IcapResponseBuilder().virus("General.Match").build()
    )

    # Specific match takes precedence
    response1 = client.scan_bytes(b"content", filename="specific.exe")
    assert response1.headers["X-Virus-ID"] == "Specific.Match"

    # General match for other .exe files
    response2 = client.scan_bytes(b"content", filename="other.exe")
    assert response2.headers["X-Virus-ID"] == "General.Match"


def test_matcher_times_limit():
    """times= parameter limits how many times matcher can be used."""
    client = MockIcapClient()
    client.when(data_contains=b"bad").respond(
        IcapResponseBuilder().virus("Limited").build(),
        times=2,
    )

    # First two matches work
    response1 = client.scan_bytes(b"bad content")
    assert not response1.is_no_modification

    response2 = client.scan_bytes(b"more bad stuff")
    assert not response2.is_no_modification

    # Third time falls through (matcher exhausted)
    response3 = client.scan_bytes(b"bad again")
    assert response3.is_no_modification


def test_matcher_priority_over_callback():
    """Matchers take priority over callbacks."""

    def always_clean(data: bytes, **kwargs) -> IcapResponse:
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    client.on_respmod(callback=always_clean)
    client.when(data_contains=b"virus").respond(
        IcapResponseBuilder().virus("Matcher.Priority").build()
    )

    # Content with "virus" uses matcher, not callback
    response1 = client.scan_bytes(b"this has virus in it")
    assert not response1.is_no_modification

    # Content without "virus" falls through to callback
    response2 = client.scan_bytes(b"safe content")
    assert response2.is_no_modification


def test_matcher_priority_over_queue():
    """Matchers take priority over response queue."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().virus("Queue.Virus1").build(),
        IcapResponseBuilder().virus("Queue.Virus2").build(),
    )
    client.when(filename="safe.txt").respond(IcapResponseBuilder().clean().build())

    # Matcher matches - clean response, queue not consumed
    response1 = client.scan_bytes(b"content", filename="safe.txt")
    assert response1.is_no_modification

    # No matcher - queue is consumed
    response2 = client.scan_bytes(b"content", filename="other.txt")
    assert response2.headers["X-Virus-ID"] == "Queue.Virus1"

    # Matcher again
    response3 = client.scan_bytes(b"content", filename="safe.txt")
    assert response3.is_no_modification

    # Queue continues
    response4 = client.scan_bytes(b"content", filename="other.txt")
    assert response4.headers["X-Virus-ID"] == "Queue.Virus2"


def test_matcher_cleared_by_reset_responses():
    """reset_responses() clears all matchers."""
    client = MockIcapClient()
    client.when(filename="malware.exe").respond(IcapResponseBuilder().virus().build())

    response1 = client.scan_bytes(b"content", filename="malware.exe")
    assert not response1.is_no_modification

    client.reset_responses()

    # Matcher cleared, falls through to default
    response2 = client.scan_bytes(b"content", filename="malware.exe")
    assert response2.is_no_modification


@pytest.mark.asyncio
async def test_async_matcher_filename():
    """Async client supports when() matchers."""
    client = MockAsyncIcapClient()
    client.when(filename="malware.exe").respond(
        IcapResponseBuilder().virus("Async.Matcher").build()
    )

    response1 = await client.scan_bytes(b"content", filename="malware.exe")
    assert not response1.is_no_modification

    response2 = await client.scan_bytes(b"content", filename="safe.txt")
    assert response2.is_no_modification


@pytest.mark.asyncio
async def test_async_matcher_data_contains():
    """Async client when(data_contains=) works."""
    client = MockAsyncIcapClient()
    client.when(data_contains=b"EICAR").respond(IcapResponseBuilder().virus("Async.EICAR").build())

    response1 = await client.scan_bytes(b"content with EICAR signature")
    assert not response1.is_no_modification

    response2 = await client.scan_bytes(b"clean content")
    assert response2.is_no_modification


@pytest.mark.asyncio
async def test_async_matcher_priority_over_callback():
    """Async matchers take priority over async callbacks."""

    async def async_callback(data: bytes, **kwargs) -> IcapResponse:
        return IcapResponseBuilder().clean().build()

    client = MockAsyncIcapClient()
    client.on_respmod(callback=async_callback)
    client.when(filename="virus.exe").respond(IcapResponseBuilder().virus().build())

    response1 = await client.scan_bytes(b"content", filename="virus.exe")
    assert not response1.is_no_modification

    response2 = await client.scan_bytes(b"content", filename="safe.txt")
    assert response2.is_no_modification


@pytest.mark.asyncio
async def test_async_matcher_times_limit():
    """Async client respects times= limit on matchers."""
    client = MockAsyncIcapClient()
    client.when(data_contains=b"bad").respond(
        IcapResponseBuilder().virus().build(),
        times=1,
    )

    response1 = await client.scan_bytes(b"bad content")
    assert not response1.is_no_modification

    response2 = await client.scan_bytes(b"bad again")
    assert response2.is_no_modification  # Matcher exhausted


# === Phase 4: Enhanced Call History Tests ===


# --- MockCall Enhanced Fields Tests ---


def test_mock_call_response_field():
    """MockCall.response is populated after successful call."""
    client = MockIcapClient()
    response = client.scan_bytes(b"test")

    call = client.last_call
    assert call.response is response
    assert call.exception is None


def test_mock_call_exception_field():
    """MockCall.exception is populated when call raises."""
    client = MockIcapClient()
    client.on_respmod(raises=IcapTimeoutError("Timeout"))

    with pytest.raises(IcapTimeoutError):
        client.scan_bytes(b"test")

    call = client.last_call
    assert call.response is None
    assert isinstance(call.exception, IcapTimeoutError)


def test_mock_call_matched_by_default():
    """MockCall.matched_by is 'default' for unconfigured responses."""
    client = MockIcapClient()
    client.scan_bytes(b"test")

    assert client.last_call.matched_by == "default"


def test_mock_call_matched_by_matcher():
    """MockCall.matched_by is 'matcher' when matcher triggers."""
    client = MockIcapClient()
    client.when(filename="virus.exe").respond(IcapResponseBuilder().virus().build())

    client.scan_bytes(b"test", filename="virus.exe")
    assert client.last_call.matched_by == "matcher"

    # Non-matching call falls to default
    client.scan_bytes(b"test", filename="safe.txt")
    assert client.last_call.matched_by == "default"


def test_mock_call_matched_by_callback():
    """MockCall.matched_by is 'callback' when callback is used."""

    def my_callback(data: bytes, **kwargs):
        return IcapResponseBuilder().clean().build()

    client = MockIcapClient()
    client.on_respmod(callback=my_callback)
    client.scan_bytes(b"test")

    assert client.last_call.matched_by == "callback"


def test_mock_call_matched_by_queue():
    """MockCall.matched_by is 'queue' when response comes from queue."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    client.scan_bytes(b"file1")
    assert client.last_call.matched_by == "queue"

    client.scan_bytes(b"file2")
    assert client.last_call.matched_by == "queue"


def test_mock_call_call_index():
    """MockCall.call_index reflects position in call history."""
    client = MockIcapClient()

    client.scan_bytes(b"first")
    client.options("avscan")
    client.scan_bytes(b"second")

    assert client.calls[0].call_index == 0
    assert client.calls[1].call_index == 1
    assert client.calls[2].call_index == 2


# --- MockCall Convenience Properties Tests ---


def test_mock_call_data_property():
    """MockCall.data returns kwargs['data']."""
    client = MockIcapClient()
    client.scan_bytes(b"test content")

    assert client.last_call.data == b"test content"


def test_mock_call_data_property_none():
    """MockCall.data returns None when not a scan call."""
    client = MockIcapClient()
    client.options("avscan")

    assert client.last_call.data is None


def test_mock_call_filename_property():
    """MockCall.filename returns kwargs['filename']."""
    client = MockIcapClient()
    client.scan_bytes(b"test", filename="report.pdf")

    assert client.last_call.filename == "report.pdf"


def test_mock_call_filename_property_none():
    """MockCall.filename returns None when not provided."""
    client = MockIcapClient()
    client.scan_bytes(b"test")

    assert client.last_call.filename is None


def test_mock_call_service_property():
    """MockCall.service returns kwargs['service']."""
    client = MockIcapClient()
    client.scan_bytes(b"test", service="custom_service")

    assert client.last_call.service == "custom_service"


def test_mock_call_succeeded_property():
    """MockCall.succeeded reflects whether call raised."""
    client = MockIcapClient()

    # Successful call
    client.scan_bytes(b"test")
    assert client.last_call.succeeded is True

    # Failed call
    client.on_respmod(raises=IcapConnectionError("Failed"))
    with pytest.raises(IcapConnectionError):
        client.scan_bytes(b"test")
    assert client.last_call.succeeded is False


def test_mock_call_was_clean_property():
    """MockCall.was_clean reflects 204 No Modification response."""
    client = MockIcapClient()

    # Clean response
    client.scan_bytes(b"safe content")
    assert client.last_call.was_clean is True

    # Virus response
    client.on_respmod(IcapResponseBuilder().virus().build())
    client.scan_bytes(b"infected")
    assert client.last_call.was_clean is False


def test_mock_call_was_clean_false_on_exception():
    """MockCall.was_clean is False when exception was raised."""
    client = MockIcapClient()
    client.on_respmod(raises=IcapTimeoutError("Timeout"))

    with pytest.raises(IcapTimeoutError):
        client.scan_bytes(b"test")

    assert client.last_call.was_clean is False


def test_mock_call_was_virus_property():
    """MockCall.was_virus reflects X-Virus-ID header presence."""
    client = MockIcapClient()

    # Clean response - no virus
    client.scan_bytes(b"safe content")
    assert client.last_call.was_virus is False

    # Virus response
    client.on_respmod(IcapResponseBuilder().virus("Trojan.Test").build())
    client.scan_bytes(b"infected")
    assert client.last_call.was_virus is True


def test_mock_call_was_virus_false_on_exception():
    """MockCall.was_virus is False when exception was raised."""
    client = MockIcapClient()
    client.on_respmod(raises=IcapConnectionError("Failed"))

    with pytest.raises(IcapConnectionError):
        client.scan_bytes(b"test")

    assert client.last_call.was_virus is False


def test_mock_call_repr_clean():
    """MockCall repr shows clean result."""
    client = MockIcapClient()
    client.scan_bytes(b"test", filename="file.txt")

    repr_str = repr(client.last_call)
    assert "scan_bytes" in repr_str
    assert "file.txt" in repr_str
    assert "clean" in repr_str


def test_mock_call_repr_virus():
    """MockCall repr shows virus result with ID."""
    client = MockIcapClient()
    client.on_respmod(IcapResponseBuilder().virus("Trojan.Custom").build())
    client.scan_bytes(b"infected")

    repr_str = repr(client.last_call)
    assert "virus" in repr_str
    assert "Trojan.Custom" in repr_str


def test_mock_call_repr_exception():
    """MockCall repr shows exception type."""
    client = MockIcapClient()
    client.on_respmod(raises=IcapTimeoutError("Timeout"))

    with pytest.raises(IcapTimeoutError):
        client.scan_bytes(b"test")

    repr_str = repr(client.last_call)
    assert "raised" in repr_str
    assert "IcapTimeoutError" in repr_str


def test_mock_call_repr_truncates_long_data():
    """MockCall repr truncates long data."""
    client = MockIcapClient()
    client.scan_bytes(b"x" * 100)

    repr_str = repr(client.last_call)
    assert "..." in repr_str


# --- Call Query/Filter Methods Tests ---


def test_first_call_property():
    """first_call returns the first recorded call."""
    client = MockIcapClient()

    # No calls yet
    assert client.first_call is None

    client.scan_bytes(b"first")
    client.scan_bytes(b"second")

    assert client.first_call.data == b"first"


def test_last_call_property():
    """last_call returns the most recent call."""
    client = MockIcapClient()

    # No calls yet
    assert client.last_call is None

    client.scan_bytes(b"first")
    client.scan_bytes(b"second")

    assert client.last_call.data == b"second"


def test_last_scan_call_property():
    """last_scan_call returns most recent scan call only."""
    client = MockIcapClient()

    # No calls yet
    assert client.last_scan_call is None

    client.options("avscan")
    assert client.last_scan_call is None  # OPTIONS is not a scan

    client.scan_bytes(b"scanned")
    assert client.last_scan_call.data == b"scanned"

    client.options("avscan")  # Another non-scan
    # Still returns the scan_bytes call
    assert client.last_scan_call.method == "scan_bytes"
    assert client.last_scan_call.data == b"scanned"


def test_get_calls_all():
    """get_calls() without filter returns all calls."""
    client = MockIcapClient()
    client.options("avscan")
    client.scan_bytes(b"test")
    client.scan_bytes(b"test2")

    calls = client.get_calls()
    assert len(calls) == 3


def test_get_calls_filtered():
    """get_calls(method) filters by method name."""
    client = MockIcapClient()
    client.options("avscan")
    client.scan_bytes(b"test1")
    client.scan_bytes(b"test2")
    client.options("avscan")

    scan_calls = client.get_calls("scan_bytes")
    assert len(scan_calls) == 2
    assert all(c.method == "scan_bytes" for c in scan_calls)

    options_calls = client.get_calls("options")
    assert len(options_calls) == 2


def test_get_scan_calls():
    """get_scan_calls() returns only scan_* methods."""
    client = MockIcapClient()
    client.options("avscan")
    client.scan_bytes(b"bytes data")
    client.reqmod("avscan", b"GET / HTTP/1.1\r\n")

    # Create a temp file for scan_file
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"file content")
        temp_path = f.name

    try:
        client.scan_file(temp_path)

        scan_calls = client.get_scan_calls()
        assert len(scan_calls) == 2
        assert scan_calls[0].method == "scan_bytes"
        assert scan_calls[1].method == "scan_file"
    finally:
        import os

        os.unlink(temp_path)


def test_get_scan_calls_includes_scan_stream():
    """get_scan_calls() includes scan_stream."""
    client = MockIcapClient()
    stream = io.BytesIO(b"stream content")
    client.scan_stream(stream)

    scan_calls = client.get_scan_calls()
    assert len(scan_calls) == 1
    assert scan_calls[0].method == "scan_stream"


# --- Call Statistics Tests ---


def test_call_count_property():
    """call_count returns total number of calls."""
    client = MockIcapClient()

    assert client.call_count == 0

    client.scan_bytes(b"test")
    assert client.call_count == 1

    client.options("avscan")
    client.scan_bytes(b"test2")
    assert client.call_count == 3


def test_call_counts_by_method():
    """call_counts_by_method groups counts by method name."""
    client = MockIcapClient()

    client.scan_bytes(b"test1")
    client.scan_bytes(b"test2")
    client.options("avscan")
    client.scan_bytes(b"test3")
    client.reqmod("avscan", b"GET /\r\n")

    counts = client.call_counts_by_method
    assert counts["scan_bytes"] == 3
    assert counts["options"] == 1
    assert counts["reqmod"] == 1


def test_call_counts_by_method_empty():
    """call_counts_by_method returns empty dict when no calls."""
    client = MockIcapClient()
    assert client.call_counts_by_method == {}


# --- Enhanced Assertion Methods Tests ---


def test_assert_called_with_matches():
    """assert_called_with passes when kwargs match."""
    client = MockIcapClient()
    client.scan_bytes(b"content", filename="test.txt", service="avscan")

    # All of these should pass
    client.assert_called_with("scan_bytes", data=b"content")
    client.assert_called_with("scan_bytes", filename="test.txt")
    client.assert_called_with("scan_bytes", service="avscan")
    client.assert_called_with("scan_bytes", data=b"content", filename="test.txt")


def test_assert_called_with_fails_no_call():
    """assert_called_with fails if method never called."""
    client = MockIcapClient()

    with pytest.raises(AssertionError, match="never called"):
        client.assert_called_with("scan_bytes", data=b"test")


def test_assert_called_with_fails_wrong_value():
    """assert_called_with fails if value doesn't match."""
    client = MockIcapClient()
    client.scan_bytes(b"actual", filename="actual.txt")

    with pytest.raises(AssertionError, match="expected"):
        client.assert_called_with("scan_bytes", filename="expected.txt")


def test_assert_called_with_checks_last_call():
    """assert_called_with checks the most recent call to method."""
    client = MockIcapClient()
    client.scan_bytes(b"first", filename="first.txt")
    client.scan_bytes(b"second", filename="second.txt")

    # Should check the second call
    client.assert_called_with("scan_bytes", filename="second.txt")

    with pytest.raises(AssertionError):
        client.assert_called_with("scan_bytes", filename="first.txt")


def test_assert_any_call_matches():
    """assert_any_call passes when any call matches."""
    client = MockIcapClient()
    client.scan_bytes(b"first", filename="a.txt")
    client.scan_bytes(b"second", filename="b.txt")
    client.scan_bytes(b"third", filename="c.txt")

    # All of these should pass (different calls)
    client.assert_any_call("scan_bytes", filename="a.txt")
    client.assert_any_call("scan_bytes", filename="b.txt")
    client.assert_any_call("scan_bytes", filename="c.txt")


def test_assert_any_call_fails_no_match():
    """assert_any_call fails if no call matches."""
    client = MockIcapClient()
    client.scan_bytes(b"first", filename="a.txt")
    client.scan_bytes(b"second", filename="b.txt")

    with pytest.raises(AssertionError, match="No call"):
        client.assert_any_call("scan_bytes", filename="z.txt")


def test_assert_any_call_fails_no_calls():
    """assert_any_call fails if method never called."""
    client = MockIcapClient()

    with pytest.raises(AssertionError, match="never called"):
        client.assert_any_call("scan_bytes", data=b"test")


def test_assert_called_in_order_passes():
    """assert_called_in_order passes for correct order."""
    client = MockIcapClient()
    client.options("avscan")
    client.scan_bytes(b"test")
    client.reqmod("avscan", b"GET /\r\n")

    # Exact order
    client.assert_called_in_order(["options", "scan_bytes", "reqmod"])

    # Subsequence order (allows gaps)
    client.assert_called_in_order(["options", "reqmod"])
    client.assert_called_in_order(["options", "scan_bytes"])
    client.assert_called_in_order(["scan_bytes", "reqmod"])


def test_assert_called_in_order_fails():
    """assert_called_in_order fails for wrong order."""
    client = MockIcapClient()
    client.options("avscan")
    client.scan_bytes(b"test")

    with pytest.raises(AssertionError, match="not called in expected order"):
        client.assert_called_in_order(["scan_bytes", "options"])


def test_assert_called_in_order_empty():
    """assert_called_in_order passes for empty list."""
    client = MockIcapClient()
    client.assert_called_in_order([])  # Should pass


def test_assert_scanned_file_passes(tmp_path):
    """assert_scanned_file passes when file was scanned."""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"content")

    client = MockIcapClient()
    client.scan_file(test_file)

    client.assert_scanned_file(str(test_file))


def test_assert_scanned_file_fails():
    """assert_scanned_file fails when file wasn't scanned."""
    client = MockIcapClient()
    client.scan_bytes(b"test")  # Different method

    with pytest.raises(AssertionError, match="was not scanned"):
        client.assert_scanned_file("/some/file.txt")


def test_assert_scanned_with_filename_passes():
    """assert_scanned_with_filename passes when filename matches."""
    client = MockIcapClient()
    client.scan_bytes(b"content", filename="report.pdf")

    client.assert_scanned_with_filename("report.pdf")


def test_assert_scanned_with_filename_scan_stream():
    """assert_scanned_with_filename works with scan_stream."""
    client = MockIcapClient()
    stream = io.BytesIO(b"stream content")
    client.scan_stream(stream, filename="stream.bin")

    client.assert_scanned_with_filename("stream.bin")


def test_assert_scanned_with_filename_fails():
    """assert_scanned_with_filename fails when filename not found."""
    client = MockIcapClient()
    client.scan_bytes(b"content", filename="actual.txt")

    with pytest.raises(AssertionError, match="No scan was made"):
        client.assert_scanned_with_filename("expected.txt")


# --- Async Phase 4 Tests ---


@pytest.mark.asyncio
async def test_async_mock_call_response_field():
    """Async MockCall.response is populated after successful call."""
    client = MockAsyncIcapClient()
    response = await client.scan_bytes(b"test")

    call = client.last_call
    assert call.response is response
    assert call.exception is None


@pytest.mark.asyncio
async def test_async_mock_call_exception_field():
    """Async MockCall.exception is populated when call raises."""
    client = MockAsyncIcapClient()
    client.on_respmod(raises=IcapTimeoutError("Timeout"))

    with pytest.raises(IcapTimeoutError):
        await client.scan_bytes(b"test")

    call = client.last_call
    assert call.response is None
    assert isinstance(call.exception, IcapTimeoutError)


@pytest.mark.asyncio
async def test_async_mock_call_matched_by():
    """Async MockCall.matched_by tracks response source correctly."""
    client = MockAsyncIcapClient()

    # Default
    await client.scan_bytes(b"test1")
    assert client.last_call.matched_by == "default"

    # Matcher
    client.when(filename="virus.exe").respond(IcapResponseBuilder().virus().build())
    await client.scan_bytes(b"test2", filename="virus.exe")
    assert client.last_call.matched_by == "matcher"

    # Callback
    client.reset_responses()

    async def async_cb(data: bytes, **kwargs):
        return IcapResponseBuilder().clean().build()

    client.on_respmod(callback=async_cb)
    await client.scan_bytes(b"test3")
    assert client.last_call.matched_by == "callback"


@pytest.mark.asyncio
async def test_async_call_query_methods():
    """Async client call query methods work correctly."""
    client = MockAsyncIcapClient()

    await client.options("avscan")
    await client.scan_bytes(b"first")
    await client.scan_bytes(b"second")

    assert client.first_call.method == "options"
    assert client.last_call.data == b"second"
    assert client.last_scan_call.data == b"second"
    assert client.call_count == 3
    assert client.call_counts_by_method == {"options": 1, "scan_bytes": 2}


@pytest.mark.asyncio
async def test_async_enhanced_assertions():
    """Async client enhanced assertions work correctly."""
    client = MockAsyncIcapClient()

    await client.options("avscan")
    await client.scan_bytes(b"test", filename="file.txt")

    client.assert_called_with("scan_bytes", filename="file.txt")
    client.assert_any_call("scan_bytes", data=b"test")
    client.assert_called_in_order(["options", "scan_bytes"])


# === Phase 5: Strict Mode Tests ===


def test_strict_parameter_defaults_to_false():
    """Strict mode is disabled by default."""
    client = MockIcapClient()
    assert client._strict is False


def test_strict_parameter_can_be_enabled():
    """Strict mode can be enabled via constructor."""
    client = MockIcapClient(strict=True)
    assert client._strict is True


def test_assert_all_responses_used_passes_with_no_config():
    """assert_all_responses_used passes when using only defaults."""
    client = MockIcapClient()
    client.scan_bytes(b"test")
    client.assert_all_responses_used()  # Should not raise


def test_assert_all_responses_used_passes_when_queue_consumed():
    """assert_all_responses_used passes when all queued responses are consumed."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    client.scan_bytes(b"file1")
    client.scan_bytes(b"file2")

    client.assert_all_responses_used()  # Should not raise


def test_assert_all_responses_used_fails_with_unconsumed_queue():
    """assert_all_responses_used fails when queued responses remain."""
    client = MockIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    client.scan_bytes(b"file1")  # Only consume first response

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    assert "respmod: 1 of 2 queued responses not consumed" in str(exc_info.value)


def test_assert_all_responses_used_passes_when_callback_invoked():
    """assert_all_responses_used passes when callback is invoked at least once."""
    client = MockIcapClient()
    client.on_respmod(callback=lambda **kwargs: IcapResponseBuilder().clean().build())

    client.scan_bytes(b"test")

    client.assert_all_responses_used()  # Should not raise


def test_assert_all_responses_used_fails_with_unused_callback():
    """assert_all_responses_used fails when callback is configured but never invoked."""
    client = MockIcapClient()
    client.on_respmod(callback=lambda **kwargs: IcapResponseBuilder().clean().build())

    # No calls made

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    assert "respmod: callback was configured but never invoked" in str(exc_info.value)


def test_assert_all_responses_used_passes_when_matcher_triggered():
    """assert_all_responses_used passes when matcher is triggered at least once."""
    client = MockIcapClient()
    client.when(filename="virus.exe").respond(IcapResponseBuilder().virus().build())

    client.scan_bytes(b"content", filename="virus.exe")

    client.assert_all_responses_used()  # Should not raise


def test_assert_all_responses_used_fails_with_unused_matcher():
    """assert_all_responses_used fails when matcher is never triggered."""
    client = MockIcapClient()
    client.when(filename="virus.exe").respond(IcapResponseBuilder().virus().build())

    client.scan_bytes(b"content", filename="safe.txt")  # Matcher not triggered

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    assert "matcher[0] (filename='virus.exe'): never matched" in str(exc_info.value)


def test_assert_all_responses_used_fails_with_multiple_issues():
    """assert_all_responses_used reports all unused configurations."""
    client = MockIcapClient()

    # Set up multiple unused configurations
    client.on_options(
        IcapResponseBuilder().options().build(),
        IcapResponseBuilder().options().build(),
    )
    client.when(data_contains=b"EICAR").respond(IcapResponseBuilder().virus().build())

    # Consume one options response, but not the other
    client.options("avscan")

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    error_msg = str(exc_info.value)
    assert "options: 1 of 2 queued responses not consumed" in error_msg
    assert "matcher[0]" in error_msg


def test_assert_all_responses_used_shows_matcher_criteria():
    """assert_all_responses_used shows matcher criteria in error message."""
    client = MockIcapClient()
    client.when(service="avscan", filename_matches=r".*\.exe$").respond(
        IcapResponseBuilder().virus().build()
    )

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    error_msg = str(exc_info.value)
    assert "service='avscan'" in error_msg
    assert "filename_pattern=" in error_msg


@pytest.mark.asyncio
async def test_async_assert_all_responses_used_queue():
    """Async client assert_all_responses_used works with queues."""
    client = MockAsyncIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    await client.scan_bytes(b"file1")
    await client.scan_bytes(b"file2")

    client.assert_all_responses_used()  # Should not raise


@pytest.mark.asyncio
async def test_async_assert_all_responses_used_fails_unconsumed():
    """Async client assert_all_responses_used fails with unconsumed responses."""
    client = MockAsyncIcapClient()
    client.on_respmod(
        IcapResponseBuilder().clean().build(),
        IcapResponseBuilder().virus().build(),
    )

    await client.scan_bytes(b"file1")  # Only consume first

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    assert "respmod: 1 of 2 queued responses not consumed" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_assert_all_responses_used_callback():
    """Async client assert_all_responses_used tracks callback usage."""
    client = MockAsyncIcapClient()

    async def async_callback(**kwargs):
        return IcapResponseBuilder().clean().build()

    client.on_respmod(callback=async_callback)

    await client.scan_bytes(b"test")

    client.assert_all_responses_used()  # Should not raise


@pytest.mark.asyncio
async def test_async_assert_all_responses_used_callback_unused():
    """Async client assert_all_responses_used fails with unused async callback."""
    client = MockAsyncIcapClient()

    async def async_callback(**kwargs):
        return IcapResponseBuilder().clean().build()

    client.on_respmod(callback=async_callback)

    # No calls made

    with pytest.raises(AssertionError) as exc_info:
        client.assert_all_responses_used()

    assert "respmod: callback was configured but never invoked" in str(exc_info.value)


# === Phase 5: Marker-Based Strict Mode Tests ===


@pytest.mark.icap_mock(strict=True)
def test_marker_strict_mode_passes_with_defaults(icap_mock):
    """Marker-based strict mode passes when only defaults are used."""
    icap_mock.scan_bytes(b"test")
    # Test should pass - assert_all_responses_used called automatically at teardown


@pytest.mark.icap_mock(strict=True)
@pytest.mark.icap_response("clean")
@pytest.mark.icap_response("virus")
def test_marker_strict_mode_passes_when_queue_consumed(icap_mock):
    """Marker-based strict mode passes when all queued responses are consumed."""
    icap_mock.scan_bytes(b"file1")  # clean
    icap_mock.scan_bytes(b"file2")  # virus
    # Test should pass - all responses consumed


@pytest.mark.icap_mock(strict=False)
@pytest.mark.icap_response("clean")
@pytest.mark.icap_response("virus")
def test_marker_strict_mode_disabled_allows_unconsumed(icap_mock):
    """When strict=False, unconsumed responses don't cause failure."""
    icap_mock.scan_bytes(b"file1")  # Only consume first response
    # Test should pass - strict mode disabled


@pytest.mark.icap_mock()
@pytest.mark.icap_response("clean")
def test_marker_strict_mode_defaults_to_false(icap_mock):
    """Strict mode defaults to False when not specified."""
    # Don't consume the response
    assert icap_mock._strict is False
    # Test should pass - strict mode not enabled


@pytest.mark.icap_mock(strict=True, response="clean")
def test_marker_strict_mode_with_on_any_response(icap_mock):
    """Strict mode works with response= configuration (on_any)."""
    icap_mock.scan_bytes(b"file1")
    icap_mock.scan_bytes(b"file2")  # on_any responses are reusable
    # Test should pass - on_any is not a queue, always passes
