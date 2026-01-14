"""
Unit tests for ICAP client methods.

These tests cover the internal methods and public API of both
sync and async ICAP clients.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from icap import AsyncIcapClient, IcapClient
from icap.exception import IcapConnectionError, IcapProtocolError, IcapTimeoutError


def test_send_with_preview_complete_in_preview():
    """Test preview mode when entire body fits in preview size."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    # Return 204 No Modification
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    request = b"RESPMOD icap://localhost:1344/avscan ICAP/1.0\r\n\r\n"
    body = b"small"  # 5 bytes, fits in preview of 10

    response = client._send_with_preview(request, body, preview_size=10)

    assert response.status_code == 204
    # Verify ieof was sent (entire body fit in preview)
    sent_data = mock_socket.sendall.call_args[0][0]
    assert b"ieof" in sent_data


def test_send_with_preview_requires_continue():
    """Test preview mode when server requests remainder with 100 Continue."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    # First call returns 100 Continue, second returns 204
    mock_socket.recv.side_effect = [
        b"ICAP/1.0 100 Continue\r\n\r\n",
        b"ICAP/1.0 204 No Content\r\n\r\n",
    ]

    client._socket = mock_socket
    client._connected = True

    request = b"RESPMOD icap://localhost:1344/avscan ICAP/1.0\r\n\r\n"
    body = b"a" * 100  # 100 bytes, more than preview of 10

    response = client._send_with_preview(request, body, preview_size=10)

    assert response.status_code == 204
    # Should have called sendall multiple times (preview, then remainder)
    assert mock_socket.sendall.call_count >= 2


def test_send_with_preview_not_connected():
    """Test that _send_with_preview raises when not connected."""
    client = IcapClient("localhost", 1344)
    client._socket = None

    with pytest.raises(IcapConnectionError) as exc_info:
        client._send_with_preview(b"request", b"body", preview_size=10)

    assert "Not connected" in str(exc_info.value)


def test_send_with_preview_timeout():
    """Test that _send_with_preview handles socket timeout."""
    import socket

    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.sendall.side_effect = socket.timeout("timed out")

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapTimeoutError):
        client._send_with_preview(b"request", b"body", preview_size=10)


def test_send_with_preview_connection_error():
    """Test that _send_with_preview handles connection errors."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.sendall.side_effect = OSError("Connection reset")

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapConnectionError):
        client._send_with_preview(b"request", b"body", preview_size=10)

    assert not client._connected


def test_receive_response_simple():
    """Test receiving a simple ICAP response."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 200 OK\r\nServer: Test\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    response = client._receive_response()

    assert response.status_code == 200
    assert response.status_message == "OK"


def test_receive_response_with_body():
    """Test receiving response with Content-Length body."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"

    client._socket = mock_socket
    client._connected = True

    response = client._receive_response()

    assert response.status_code == 200
    assert b"hello" in response.body or response.body == b"hello"


def test_receive_response_not_connected():
    """Test that _receive_response raises when socket is None."""
    client = IcapClient("localhost", 1344)
    client._socket = None

    with pytest.raises(IcapConnectionError) as exc_info:
        client._receive_response()

    assert "Not connected" in str(exc_info.value)


def test_scan_stream_chunked_sends_chunks():
    """Test that _scan_stream_chunked properly chunks data."""
    from io import BytesIO

    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    stream = BytesIO(b"a" * 100)

    response = client._scan_stream_chunked(stream, "avscan", "test.txt", chunk_size=30)

    assert response.status_code == 204
    # Should have sent multiple chunks
    assert mock_socket.sendall.call_count >= 3  # headers + chunks + terminator


def test_scan_stream_chunked_not_connected(mocker):
    """Test _scan_stream_chunked auto-connects if needed."""
    from io import BytesIO

    client = IcapClient("localhost", 1344)
    client._connected = False

    mock_socket = mocker.MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"
    mock_socket.sendall = mocker.MagicMock()

    def set_connected():
        client._socket = mock_socket
        client._connected = True

    mocker.patch.object(client, "connect", side_effect=set_connected)

    stream = BytesIO(b"test data")
    client._scan_stream_chunked(stream, "avscan", None, chunk_size=100)


def test_iter_chunks_basic():
    """Test basic chunk iteration."""
    from io import BytesIO

    client = IcapClient("localhost", 1344)

    stream = BytesIO(b"hello world")
    chunks = list(client._iter_chunks(stream, chunk_size=5))

    assert chunks == [b"hello", b" worl", b"d"]


def test_iter_chunks_exact_size():
    """Test iteration when data is exact multiple of chunk size."""
    from io import BytesIO

    client = IcapClient("localhost", 1344)

    stream = BytesIO(b"abcdef")
    chunks = list(client._iter_chunks(stream, chunk_size=3))

    assert chunks == [b"abc", b"def"]


def test_iter_chunks_empty_stream():
    """Test iteration on empty stream."""
    from io import BytesIO

    client = IcapClient("localhost", 1344)

    stream = BytesIO(b"")
    chunks = list(client._iter_chunks(stream, chunk_size=10))

    assert chunks == []


def test_reqmod_basic():
    """Test basic REQMOD request."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    response = client.reqmod("avscan", b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")

    assert response.status_code == 204


def test_reqmod_with_body():
    """Test REQMOD with HTTP request body."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    response = client.reqmod(
        "avscan",
        b"POST /upload HTTP/1.1\r\nHost: test\r\n\r\n",
        http_body=b"file contents",
    )

    assert response.status_code == 204
    # Verify chunked encoding was used for body
    sent_data = mock_socket.sendall.call_args[0][0]
    assert b"req-body=" in sent_data


def test_reqmod_with_custom_headers():
    """Test REQMOD with custom ICAP headers."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    response = client.reqmod(
        "avscan",
        b"GET / HTTP/1.1\r\n\r\n",
        headers={"X-Custom": "value"},
    )

    assert response.status_code == 204
    sent_data = mock_socket.sendall.call_args[0][0]
    assert b"X-Custom: value" in sent_data


def test_reqmod_auto_connects(mocker):
    """Test that reqmod auto-connects if not connected."""
    client = IcapClient("localhost", 1344)
    client._connected = False

    mock_socket = mocker.MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 204 No Content\r\n\r\n"

    def set_connected():
        client._socket = mock_socket
        client._connected = True

    mock_connect = mocker.patch.object(client, "connect", side_effect=set_connected)

    response = client.reqmod("avscan", b"GET / HTTP/1.1\r\n\r\n")

    mock_connect.assert_called_once()
    assert response.status_code == 204


def test_options_basic():
    """Test basic OPTIONS request."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = (
        b"ICAP/1.0 200 OK\r\nMethods: RESPMOD, REQMOD\r\nAllow: 204\r\nPreview: 1024\r\n\r\n"
    )

    client._socket = mock_socket
    client._connected = True

    response = client.options("avscan")

    assert response.status_code == 200
    sent_data = mock_socket.sendall.call_args[0][0]
    assert b"OPTIONS" in sent_data
    assert b"null-body=0" in sent_data


def test_options_auto_connects(mocker):
    """Test that options auto-connects if not connected."""
    client = IcapClient("localhost", 1344)
    client._connected = False

    mock_socket = mocker.MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 200 OK\r\n\r\n"

    def set_connected():
        client._socket = mock_socket
        client._connected = True

    mock_connect = mocker.patch.object(client, "connect", side_effect=set_connected)

    response = client.options("avscan")

    mock_connect.assert_called_once()
    assert response.status_code == 200


def test_read_chunked_body_large_chunks():
    """Test reading chunked body with large chunk sizes."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""

    client._socket = mock_socket
    client._connected = True

    # Large chunk (1000 bytes in hex = 3E8)
    large_data = b"x" * 1000
    initial = b"3E8\r\n" + large_data + b"\r\n0\r\n\r\n"

    body = client._read_chunked_body(initial)
    assert body == large_data


def test_read_chunked_body_multiple_chunks():
    """Test reading multiple chunks in sequence."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""

    client._socket = mock_socket
    client._connected = True

    # Three chunks: "aaa", "bbb", "ccc"
    initial = b"3\r\naaa\r\n3\r\nbbb\r\n3\r\nccc\r\n0\r\n\r\n"

    body = client._read_chunked_body(initial)
    assert body == b"aaabbbccc"


@pytest.mark.asyncio
async def test_async_read_chunked_body_simple():
    """Test async chunked body reading."""
    client = AsyncIcapClient("localhost", 1344)

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b""

    client._reader = mock_reader
    client._connected = True

    body = await client._read_chunked_body(b"5\r\nHello\r\n0\r\n\r\n")
    assert body == b"Hello"


@pytest.mark.asyncio
async def test_async_read_chunked_body_connection_close():
    """Test async chunked body raises on connection close."""
    client = AsyncIcapClient("localhost", 1344)

    mock_reader = AsyncMock()
    mock_reader.read.return_value = b""  # Connection closed

    client._reader = mock_reader
    client._connected = True

    with pytest.raises(IcapProtocolError) as exc_info:
        await client._read_chunked_body(b"A\r\n")  # Expecting 10 bytes

    assert "Connection closed" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_receive_response_not_connected():
    """Test async _receive_response raises when not connected."""
    client = AsyncIcapClient("localhost", 1344)
    client._reader = None

    with pytest.raises(IcapConnectionError) as exc_info:
        await client._receive_response()

    assert "Not connected" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_receive_response_simple():
    """Test receiving simple async response."""
    client = AsyncIcapClient("localhost", 1344)

    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 200 OK\r\n\r\n",
        b"",
    ]

    client._reader = mock_reader
    client._connected = True

    response_data = await client._receive_response()
    assert b"200 OK" in response_data


@pytest.mark.asyncio
async def test_async_iter_chunks():
    """Test async chunk iteration."""
    from io import BytesIO

    client = AsyncIcapClient("localhost", 1344)

    stream = BytesIO(b"hello world")
    chunks = []
    async for chunk in client._iter_chunks(stream, 5):
        chunks.append(chunk)

    assert chunks == [b"hello", b" worl", b"d"]


@pytest.mark.asyncio
async def test_async_scan_stream_chunked():
    """Test async chunked stream scanning."""
    from io import BytesIO

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = MagicMock()
    mock_writer.write = MagicMock()
    mock_writer.drain = AsyncMock()

    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 204 No Content\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    stream = BytesIO(b"test data for chunked scan")

    response = await client._scan_stream_chunked(stream, "avscan", "test.txt", 10)

    assert response.status_code == 204


def test_connect_to_invalid_host(mocker):
    """Test connection to invalid host raises IcapConnectionError."""
    import socket

    mock_socket_instance = MagicMock()
    mock_socket_instance.connect.side_effect = socket.gaierror(
        socket.EAI_NONAME, "Name or service not known"
    )
    mocker.patch("socket.socket", return_value=mock_socket_instance)

    client = IcapClient("invalid.host.that.does.not.exist.local", 1344)

    with pytest.raises(IcapConnectionError) as exc_info:
        client.connect()

    assert "Failed to connect" in str(exc_info.value)
    mock_socket_instance.connect.assert_called_once()


def test_connect_to_refused_port(mocker):
    """Test connection to port with no listener raises IcapConnectionError."""
    mock_socket_instance = MagicMock()
    mock_socket_instance.connect.side_effect = ConnectionRefusedError("Connection refused")
    mocker.patch("socket.socket", return_value=mock_socket_instance)

    client = IcapClient("127.0.0.1", 1)

    with pytest.raises(IcapConnectionError) as exc_info:
        client.connect()

    assert "Failed to connect" in str(exc_info.value)
    mock_socket_instance.connect.assert_called_once()


async def test_async_connect_to_invalid_host(mocker):
    """Test async connection to invalid host raises IcapConnectionError."""
    import socket

    mocker.patch(
        "asyncio.open_connection",
        side_effect=socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
    )

    client = AsyncIcapClient("invalid.host.that.does.not.exist.local", 1344)

    with pytest.raises(IcapConnectionError) as exc_info:
        await client.connect()

    assert "Failed to connect" in str(exc_info.value)


async def test_async_connect_to_refused_port(mocker):
    """Test async connection to refused port raises IcapConnectionError."""
    mocker.patch(
        "asyncio.open_connection",
        side_effect=ConnectionRefusedError("Connection refused"),
    )

    client = AsyncIcapClient("127.0.0.1", 1)

    with pytest.raises(IcapConnectionError) as exc_info:
        await client.connect()

    assert "Failed to connect" in str(exc_info.value)


def test_timeout_during_recv():
    """Test that socket timeout during recv is properly handled."""
    import socket

    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.side_effect = socket.timeout("recv timed out")

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapTimeoutError):
        client._receive_response()


def test_sync_async_api_parity():
    """Verify sync and async clients have matching public APIs."""
    import inspect

    sync_methods = {
        name
        for name, _ in inspect.getmembers(IcapClient, predicate=inspect.isfunction)
        if not name.startswith("_")
    }

    async_methods = {
        name
        for name, _ in inspect.getmembers(AsyncIcapClient, predicate=inspect.isfunction)
        if not name.startswith("_")
    }

    # Core methods that should be in both
    expected_methods = {
        "connect",
        "disconnect",
        "options",
        "reqmod",
        "respmod",
        "scan_bytes",
        "scan_file",
        "scan_stream",
    }

    for method in expected_methods:
        assert method in sync_methods, f"Sync client missing {method}"
        assert method in async_methods, f"Async client missing {method}"


def test_sync_async_scan_stream_signature_parity():
    """Verify scan_stream has matching signatures (including chunk_size)."""
    import inspect

    sync_sig = inspect.signature(IcapClient.scan_stream)
    async_sig = inspect.signature(AsyncIcapClient.scan_stream)

    sync_params = set(sync_sig.parameters.keys())
    async_params = set(async_sig.parameters.keys())

    # Both should have chunk_size parameter
    assert "chunk_size" in sync_params
    assert "chunk_size" in async_params

    # Both should have same parameter names
    assert sync_params == async_params


def test_sync_async_respmod_signature_parity():
    """Verify respmod has matching signatures."""
    import inspect

    sync_sig = inspect.signature(IcapClient.respmod)
    async_sig = inspect.signature(AsyncIcapClient.respmod)

    sync_params = set(sync_sig.parameters.keys())
    async_params = set(async_sig.parameters.keys())

    assert sync_params == async_params


def test_is_connected_property_exists():
    """Verify both clients have is_connected property."""
    sync_client = IcapClient("localhost", 1344)
    async_client = AsyncIcapClient("localhost", 1344)

    # Both should have is_connected and start as False
    assert hasattr(sync_client, "is_connected")
    assert hasattr(async_client, "is_connected")
    assert sync_client.is_connected is False
    assert async_client.is_connected is False


# =============================================================================
# Async client unit tests with mocked I/O
# =============================================================================


@pytest.mark.asyncio
async def test_async_options_basic():
    """Test basic async OPTIONS request."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 200 OK\r\nMethods: RESPMOD, REQMOD\r\nAllow: 204\r\nPreview: 1024\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    response = await client.options("avscan")

    assert response.status_code == 200
    # Verify OPTIONS request was sent
    sent_data = mock_writer.write.call_args[0][0]
    assert b"OPTIONS" in sent_data
    assert b"null-body=0" in sent_data


@pytest.mark.asyncio
async def test_async_options_auto_connects(mocker):
    """Test that async options auto-connects if not connected."""
    client = AsyncIcapClient("localhost", 1344)
    client._connected = False

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [b"ICAP/1.0 200 OK\r\n\r\n", b""]

    async def set_connected():
        client._writer = mock_writer
        client._reader = mock_reader
        client._connected = True

    mock_connect = mocker.patch.object(client, "connect", side_effect=set_connected)

    response = await client.options("avscan")

    mock_connect.assert_called_once()
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_async_respmod_basic():
    """Test basic async RESPMOD request."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>"

    response = await client.respmod("avscan", http_request, http_response)

    assert response.status_code == 200
    sent_data = mock_writer.write.call_args[0][0]
    assert b"RESPMOD" in sent_data


@pytest.mark.asyncio
async def test_async_reqmod_basic():
    """Test basic async REQMOD request."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 200 OK\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    response = await client.reqmod("avscan", http_request)

    assert response.status_code == 200
    sent_data = mock_writer.write.call_args[0][0]
    assert b"REQMOD" in sent_data


@pytest.mark.asyncio
async def test_async_scan_bytes_basic():
    """Test async scan_bytes method."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 204 No Content\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    response = await client.scan_bytes(b"clean file content", service="avscan")

    assert response.status_code == 204
    assert response.is_no_modification


@pytest.mark.asyncio
async def test_async_scan_bytes_with_filename():
    """Test async scan_bytes with custom filename."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 204 No Content\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    response = await client.scan_bytes(b"clean file content", service="avscan", filename="test.pdf")

    assert response.status_code == 204
    sent_data = mock_writer.write.call_args[0][0]
    assert b"test.pdf" in sent_data


@pytest.mark.asyncio
async def test_async_scan_file_basic(mocker, tmp_path):
    """Test async scan_file method."""
    # Create a temporary test file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test file content")

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = [
        b"ICAP/1.0 204 No Content\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader
    client._connected = True

    response = await client.scan_file(str(test_file), service="avscan")

    assert response.status_code == 204
    assert response.is_no_modification


@pytest.mark.asyncio
async def test_async_scan_file_not_found():
    """Test async scan_file with non-existent file."""
    client = AsyncIcapClient("localhost", 1344)
    client._connected = True

    with pytest.raises(FileNotFoundError):
        await client.scan_file("/nonexistent/path/file.txt", service="avscan")


@pytest.mark.asyncio
async def test_async_send_with_preview_complete_in_preview():
    """Test async preview mode when entire body fits in preview size."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    # Server responds with 204 (no modification needed)
    mock_reader.read.side_effect = [
        b"ICAP/1.0 204 No Content\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader

    # Build a proper ICAP request with headers
    request = (
        b"RESPMOD icap://localhost:1344/avscan ICAP/1.0\r\n"
        b"Host: localhost:1344\r\n"
        b"Encapsulated: res-body=0\r\n"
        b"Preview: 1024\r\n"
        b"\r\n"
    )
    body = b"small"
    response = await client._send_with_preview(request, body, preview_size=1024)

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_async_send_with_preview_requires_continue():
    """Test async preview mode when server requests remaining body."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = AsyncMock()
    mock_reader = AsyncMock()
    # First response: 100 Continue, then 204 No Content
    mock_reader.read.side_effect = [
        b"ICAP/1.0 100 Continue\r\n\r\n",
        b"ICAP/1.0 204 No Content\r\n\r\n",
        b"",
    ]

    client._writer = mock_writer
    client._reader = mock_reader

    # Build request and large body
    request = (
        b"RESPMOD icap://localhost:1344/avscan ICAP/1.0\r\n"
        b"Host: localhost:1344\r\n"
        b"Encapsulated: res-body=0\r\n"
        b"Preview: 1024\r\n"
        b"\r\n"
    )
    body = b"x" * 2000
    response = await client._send_with_preview(request, body, preview_size=1024)

    assert response.status_code == 204
    # Should have written multiple times (preview + remaining)
    assert mock_writer.write.call_count >= 2


@pytest.mark.asyncio
async def test_async_disconnect():
    """Test async disconnect method."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader = AsyncMock()

    client._writer = mock_writer
    client._reader = mock_reader

    await client.disconnect()

    assert client.is_connected is False
    assert client._writer is None
    assert client._reader is None
    mock_writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_context_manager():
    """Test async context manager protocol."""
    client = AsyncIcapClient("localhost", 1344)

    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader = AsyncMock()

    async def mock_connect():
        client._writer = mock_writer
        client._reader = mock_reader

    client.connect = mock_connect

    async with client as ctx:
        assert ctx is client
        assert client.is_connected is True

    # After exiting, should be disconnected
    assert client.is_connected is False
