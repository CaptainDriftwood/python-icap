"""
Tests for error handling and edge cases in the ICAP client.

These tests verify that the client properly handles:
- Protocol errors (malformed responses)
- Server errors (5xx responses)
- Connection edge cases
- Chunked encoding edge cases
"""

from unittest.mock import MagicMock

import pytest

from icap import IcapClient, IcapResponse
from icap.exception import IcapProtocolError, IcapServerError


def test_invalid_status_line_raises_value_error():
    """Test that invalid status line raises ValueError."""
    with pytest.raises(ValueError):
        IcapResponse.parse(b"ICAP/1.0\r\n\r\n")


def test_malformed_status_code_raises_value_error():
    """Test that non-numeric status code raises ValueError during parsing."""
    with pytest.raises(ValueError):
        IcapResponse.parse(b"ICAP/1.0 ABC OK\r\n\r\n")


def test_empty_response_raises_value_error():
    """Test that empty response raises ValueError."""
    with pytest.raises(ValueError):
        IcapResponse.parse(b"")


def test_incomplete_status_line_raises_value_error():
    """Test that incomplete status line raises ValueError."""
    with pytest.raises(ValueError):
        IcapResponse.parse(b"ICAP/1.0 200\r\n\r\n")


def test_invalid_content_length_raises_protocol_error():
    """Test that invalid Content-Length header raises IcapProtocolError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 200 OK\r\nContent-Length: not-a-number\r\n\r\nbody"

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapProtocolError) as exc_info:
        client._receive_response()

    assert "Invalid Content-Length" in str(exc_info.value)


def test_invalid_chunk_size_raises_protocol_error():
    """Test that invalid chunk size in chunked encoding raises IcapProtocolError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"ICAP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n",
    ]

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapProtocolError) as exc_info:
        client._send_and_receive(b"dummy request")

    assert "Invalid chunk size" in str(exc_info.value)


def test_incomplete_response_raises_protocol_error():
    """Test that incomplete response (connection closed early) raises IcapProtocolError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"ICAP/1.0 200 OK\r\nContent-Length: 100\r\n\r\npartial",
        b"",
    ]

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapProtocolError) as exc_info:
        client._receive_response()

    assert "Incomplete response" in str(exc_info.value)
    assert "expected 100 bytes" in str(exc_info.value)


def test_500_internal_server_error():
    """Test that 500 response raises IcapServerError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 500 Internal Server Error\r\nServer: Test\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapServerError) as exc_info:
        client._receive_response()

    assert "500" in str(exc_info.value)
    assert "Internal Server Error" in str(exc_info.value)


def test_502_bad_gateway():
    """Test that 502 response raises IcapServerError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 502 Bad Gateway\r\nServer: Test\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapServerError) as exc_info:
        client._receive_response()

    assert "502" in str(exc_info.value)


def test_503_service_unavailable():
    """Test that 503 response raises IcapServerError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 503 Service Unavailable\r\nServer: Test\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapServerError) as exc_info:
        client._receive_response()

    assert "503" in str(exc_info.value)


def test_505_version_not_supported():
    """Test that 505 response raises IcapServerError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = (
        b"ICAP/1.0 505 ICAP Version Not Supported\r\nServer: Test\r\n\r\n"
    )

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapServerError) as exc_info:
        client._receive_response()

    assert "505" in str(exc_info.value)


def test_4xx_does_not_raise_server_error():
    """Test that 4xx responses don't raise IcapServerError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"ICAP/1.0 404 Service Not Found\r\nServer: Test\r\n\r\n"

    client._socket = mock_socket
    client._connected = True

    response = client._receive_response()
    assert response.status_code == 404


def test_read_chunked_body_simple():
    """Test reading a simple chunked body."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""

    client._socket = mock_socket
    client._connected = True

    body = client._read_chunked_body(b"5\r\nHello\r\n5\r\nWorld\r\n0\r\n\r\n")
    assert body == b"HelloWorld"


def test_read_chunked_body_with_extensions():
    """Test reading chunked body with chunk extensions (after semicolon)."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""

    client._socket = mock_socket
    client._connected = True

    body = client._read_chunked_body(b"5; ext=value\r\nHello\r\n0\r\n\r\n")
    assert body == b"Hello"


def test_read_chunked_body_empty():
    """Test reading empty chunked body (just terminator)."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""

    client._socket = mock_socket
    client._connected = True

    body = client._read_chunked_body(b"0\r\n\r\n")
    assert body == b""


def test_read_chunked_body_split_across_reads():
    """Test reading chunked body when data arrives in multiple reads."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"Hello",
        b"\r\n0\r\n\r\n",
    ]

    client._socket = mock_socket
    client._connected = True

    body = client._read_chunked_body(b"5\r\n")
    assert body == b"Hello"


def test_reconnect_after_disconnect(mocker):
    """Test that client can reconnect after disconnect."""
    client = IcapClient("localhost", 1344)

    mock_socket = mocker.MagicMock()
    mocker.patch("socket.socket", return_value=mock_socket)

    client.connect()
    assert client.is_connected

    client.disconnect()
    assert not client.is_connected

    client.connect()
    assert client.is_connected


def test_multiple_connect_calls_are_idempotent(mocker):
    """Test that calling connect() multiple times doesn't cause issues."""
    client = IcapClient("localhost", 1344)

    mock_socket = mocker.MagicMock()
    mock_socket_class = mocker.patch("socket.socket", return_value=mock_socket)

    client.connect()
    assert client.is_connected

    client.connect()
    assert client.is_connected

    assert mock_socket_class.call_count == 1


def test_disconnect_when_not_connected():
    """Test that disconnect() is safe when not connected."""
    client = IcapClient("localhost", 1344)
    assert not client.is_connected

    client.disconnect()
    assert not client.is_connected


def test_disconnect_multiple_times(mocker):
    """Test that disconnect() can be called multiple times safely."""
    client = IcapClient("localhost", 1344)

    mock_socket = mocker.MagicMock()
    mocker.patch("socket.socket", return_value=mock_socket)

    client.connect()
    client.disconnect()
    client.disconnect()
    assert not client.is_connected


def test_scan_nonexistent_file_raises_file_not_found():
    """Test that scanning non-existent file raises FileNotFoundError."""
    client = IcapClient("localhost", 1344)

    with pytest.raises(FileNotFoundError) as exc_info:
        client.scan_file("/nonexistent/path/to/file.txt")

    assert "not found" in str(exc_info.value).lower()


def test_preview_zero_raises_value_error():
    """Test that preview=0 raises ValueError."""
    client = IcapClient("localhost", 1344)
    client._connected = True
    client._socket = MagicMock()

    with pytest.raises(ValueError) as exc_info:
        client.respmod(
            "avscan",
            b"GET / HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nbody",
            preview=0,
        )

    assert "positive integer" in str(exc_info.value)


def test_preview_negative_raises_value_error():
    """Test that negative preview raises ValueError."""
    client = IcapClient("localhost", 1344)
    client._connected = True
    client._socket = MagicMock()

    with pytest.raises(ValueError) as exc_info:
        client.respmod(
            "avscan",
            b"GET / HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nbody",
            preview=-10,
        )

    assert "positive integer" in str(exc_info.value)


def test_response_with_empty_body():
    """Test parsing response with empty body."""
    response = IcapResponse.parse(b"ICAP/1.0 200 OK\r\nServer: Test\r\n\r\n")
    assert response.status_code == 200
    assert response.body == b""


def test_response_with_content_length_zero():
    """Test parsing response with Content-Length: 0."""
    response = IcapResponse.parse(b"ICAP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
    assert response.status_code == 200
    assert response.body == b""


def test_response_with_multi_word_status_message():
    """Test parsing response with multi-word status message."""
    response = IcapResponse.parse(b"ICAP/1.0 500 Internal Server Error\r\n\r\n")
    assert response.status_code == 500
    assert response.status_message == "Internal Server Error"


def test_204_no_modification_properties():
    """Test 204 No Modification response properties."""
    response = IcapResponse.parse(b'ICAP/1.0 204 No Content\r\nISTag: "test-tag"\r\n\r\n')
    assert response.status_code == 204
    assert response.is_no_modification
    assert response.is_success
    assert response.body == b""


def test_chunked_body_connection_close_raises_protocol_error():
    """Test that connection close during chunked body raises IcapProtocolError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    # First recv returns chunk size, second returns empty (connection closed)
    mock_socket.recv.side_effect = [
        b"5\r\nHello",  # Partial chunk data
        b"",  # Connection closed before terminator
    ]

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapProtocolError) as exc_info:
        client._read_chunked_body(b"")

    assert "Connection closed before chunked body complete" in str(exc_info.value)


def test_chunked_body_connection_close_during_chunk_data():
    """Test connection close while reading chunk data raises IcapProtocolError."""
    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [
        b"",  # Connection closed immediately
    ]

    client._socket = mock_socket
    client._connected = True

    with pytest.raises(IcapProtocolError) as exc_info:
        client._read_chunked_body(b"A\r\n")  # Expecting 10 bytes

    assert "Connection closed before chunked body complete" in str(exc_info.value)


def test_scan_stream_io_error_raises_protocol_error():
    """Test that IOError during stream.read raises IcapProtocolError."""

    client = IcapClient("localhost", 1344)
    client._connected = True
    client._socket = MagicMock()

    # Create a mock stream that raises IOError on read
    mock_stream = MagicMock()
    mock_stream.read.side_effect = OSError("Disk read error")

    with pytest.raises(IcapProtocolError) as exc_info:
        client.scan_stream(mock_stream)

    assert "Failed to read from stream" in str(exc_info.value)
    assert "Disk read error" in str(exc_info.value)


def test_iter_chunks_io_error_raises_protocol_error():
    """Test that IOError during chunked stream read raises IcapProtocolError."""
    client = IcapClient("localhost", 1344)

    mock_stream = MagicMock()
    mock_stream.read.side_effect = OSError("Device not ready")

    with pytest.raises(IcapProtocolError) as exc_info:
        list(client._iter_chunks(mock_stream, 1024))

    assert "Failed to read from stream" in str(exc_info.value)


def test_async_scan_stream_has_chunk_size_parameter():
    """Test that AsyncIcapClient.scan_stream accepts chunk_size parameter."""
    import inspect

    from icap import AsyncIcapClient

    sig = inspect.signature(AsyncIcapClient.scan_stream)
    params = list(sig.parameters.keys())

    assert "chunk_size" in params
    assert sig.parameters["chunk_size"].default == 0


def test_connect_timeout_raises_timeout_error(mocker):
    """Test that socket timeout during connect raises IcapTimeoutError."""
    import socket

    from icap.exception import IcapTimeoutError

    client = IcapClient("localhost", 1344)

    mock_socket = mocker.MagicMock()
    mock_socket.connect.side_effect = socket.timeout("Connection timed out")
    mocker.patch("socket.socket", return_value=mock_socket)

    with pytest.raises(IcapTimeoutError) as exc_info:
        client.connect()

    assert "timed out" in str(exc_info.value)
    assert not client.is_connected


def test_connect_ssl_error_raises_connection_error(mocker):
    """Test that SSL error during connect raises IcapConnectionError."""
    import ssl

    from icap.exception import IcapConnectionError

    # Create client with SSL context
    ssl_context = mocker.MagicMock(spec=ssl.SSLContext)
    ssl_context.wrap_socket.side_effect = ssl.SSLError("SSL handshake failed")

    client = IcapClient("localhost", 1344, ssl_context=ssl_context)

    mock_socket = mocker.MagicMock()
    mocker.patch("socket.socket", return_value=mock_socket)

    with pytest.raises(IcapConnectionError) as exc_info:
        client.connect()

    assert "SSL error" in str(exc_info.value)
    assert not client.is_connected


def test_disconnect_handles_oserror_gracefully(mocker):
    """Test that OSError during disconnect is handled gracefully."""
    client = IcapClient("localhost", 1344)

    mock_socket = mocker.MagicMock()
    mock_socket.close.side_effect = OSError("Socket already closed")
    mocker.patch("socket.socket", return_value=mock_socket)

    client.connect()
    assert client.is_connected

    # Should not raise, just log warning
    client.disconnect()
    assert not client.is_connected


def test_scan_stream_chunked_timeout_raises_timeout_error():
    """Test that socket timeout during chunked stream scan raises IcapTimeoutError."""
    import socket
    from io import BytesIO

    from icap.exception import IcapTimeoutError

    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    # First sendall succeeds (initial request), second times out (chunk data)
    mock_socket.sendall.side_effect = [None, socket.timeout("Send timed out")]

    client._socket = mock_socket
    client._connected = True

    # Use chunk_size > 0 to force chunked transfer path
    stream = BytesIO(b"test content for scanning")

    with pytest.raises(IcapTimeoutError) as exc_info:
        client.scan_stream(stream, service="avscan", chunk_size=1024)

    assert "timed out" in str(exc_info.value)


def test_scan_stream_chunked_oserror_raises_connection_error():
    """Test that OSError during chunked stream scan raises IcapConnectionError."""
    from io import BytesIO

    from icap.exception import IcapConnectionError

    client = IcapClient("localhost", 1344)

    mock_socket = MagicMock()
    # First sendall succeeds, second raises OSError
    mock_socket.sendall.side_effect = [None, OSError("Connection reset by peer")]

    client._socket = mock_socket
    client._connected = True

    stream = BytesIO(b"test content for scanning")

    with pytest.raises(IcapConnectionError) as exc_info:
        client.scan_stream(stream, service="avscan", chunk_size=1024)

    assert "Connection error" in str(exc_info.value)
    assert not client.is_connected


def test_host_property_returns_address():
    """Test that host property returns the configured address."""
    client = IcapClient("icap.example.com", 1344)
    assert client.host == "icap.example.com"


def test_port_property_returns_port():
    """Test that port property returns the configured port."""
    client = IcapClient("localhost", 9999)
    assert client.port == 9999


def test_port_setter_with_valid_int():
    """Test that port setter accepts valid integer."""
    client = IcapClient("localhost", 1344)
    client.port = 8080
    assert client.port == 8080


def test_port_setter_with_invalid_type_raises_type_error():
    """Test that port setter raises TypeError for non-integer."""
    client = IcapClient("localhost", 1344)

    with pytest.raises(TypeError) as exc_info:
        client.port = "not-an-int"

    assert "not a valid type" in str(exc_info.value)


async def test_async_connect_timeout_raises_timeout_error(mocker):
    """Test that asyncio timeout during connect raises IcapTimeoutError."""
    import asyncio

    from icap import AsyncIcapClient
    from icap.exception import IcapTimeoutError

    mocker.patch(
        "asyncio.open_connection",
        side_effect=asyncio.TimeoutError("Connection timed out"),
    )

    client = AsyncIcapClient("localhost", 1344)

    with pytest.raises(IcapTimeoutError) as exc_info:
        await client.connect()

    assert "timed out" in str(exc_info.value)
    assert not client.is_connected


async def test_async_connect_ssl_error_raises_connection_error(mocker):
    """Test that SSL error during async connect raises IcapConnectionError."""
    import ssl

    from icap import AsyncIcapClient
    from icap.exception import IcapConnectionError

    mocker.patch(
        "asyncio.open_connection",
        side_effect=ssl.SSLError("SSL handshake failed"),
    )

    ssl_context = mocker.MagicMock(spec=ssl.SSLContext)
    client = AsyncIcapClient("localhost", 1344, ssl_context=ssl_context)

    with pytest.raises(IcapConnectionError) as exc_info:
        await client.connect()

    assert "SSL error" in str(exc_info.value)
    assert not client.is_connected


async def test_async_disconnect_handles_oserror_gracefully(mocker):
    """Test that OSError during async disconnect is handled gracefully."""
    from icap import AsyncIcapClient

    client = AsyncIcapClient("localhost", 1344)

    # Mock the writer to raise OSError on wait_closed
    mock_writer = mocker.MagicMock()
    mock_writer.close = mocker.MagicMock()
    mock_writer.wait_closed = mocker.AsyncMock(side_effect=OSError("Socket already closed"))

    mock_reader = mocker.MagicMock()

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()
    assert client.is_connected

    # Should not raise, just log warning and clean up
    await client.disconnect()
    assert not client.is_connected


async def test_async_host_property_returns_address():
    """Test that async client host property returns the configured address."""
    from icap import AsyncIcapClient

    client = AsyncIcapClient("icap.example.com", 1344)
    assert client.host == "icap.example.com"


async def test_async_port_property_returns_port():
    """Test that async client port property returns the configured port."""
    from icap import AsyncIcapClient

    client = AsyncIcapClient("localhost", 9999)
    assert client.port == 9999


async def test_async_scan_stream_io_error_raises_protocol_error(mocker):
    """Test that IOError during async stream.read raises IcapProtocolError."""
    from icap import AsyncIcapClient
    from icap.exception import IcapProtocolError

    client = AsyncIcapClient("localhost", 1344)

    # Mock connection
    mock_writer = mocker.MagicMock()
    mock_reader = mocker.MagicMock()
    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    # Create a mock stream that raises OSError on read
    mock_stream = mocker.MagicMock()
    mock_stream.read.side_effect = OSError("Disk read error")

    with pytest.raises(IcapProtocolError) as exc_info:
        await client.scan_stream(mock_stream)

    assert "Failed to read from stream" in str(exc_info.value)


async def test_async_iter_chunks_io_error_raises_protocol_error(mocker):
    """Test that IOError during async chunked stream read raises IcapProtocolError."""
    from icap import AsyncIcapClient
    from icap.exception import IcapProtocolError

    client = AsyncIcapClient("localhost", 1344)

    # Mock connection
    mock_writer = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()
    mock_reader = mocker.MagicMock()
    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    # Create a mock stream that raises OSError on read
    mock_stream = mocker.MagicMock()
    mock_stream.read.side_effect = OSError("Device not ready")

    with pytest.raises(IcapProtocolError) as exc_info:
        # Use chunk_size > 0 to trigger _iter_chunks path
        await client.scan_stream(mock_stream, chunk_size=1024)

    assert "Failed to read from stream" in str(exc_info.value)


async def test_async_scan_stream_chunked_timeout_raises_timeout_error(mocker):
    """Test that timeout during async chunked stream scan raises IcapTimeoutError."""
    import asyncio
    from io import BytesIO

    from icap import AsyncIcapClient
    from icap.exception import IcapTimeoutError

    client = AsyncIcapClient("localhost", 1344)

    # Mock connection
    mock_writer = mocker.MagicMock()
    # write raises timeout error
    mock_writer.write.side_effect = [None, asyncio.TimeoutError("Send timed out")]
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    stream = BytesIO(b"test content for scanning")

    with pytest.raises(IcapTimeoutError) as exc_info:
        await client.scan_stream(stream, chunk_size=1024)

    assert "timed out" in str(exc_info.value)


async def test_async_scan_stream_chunked_oserror_raises_connection_error(mocker):
    """Test that OSError during async chunked stream scan raises IcapConnectionError."""
    from io import BytesIO

    from icap import AsyncIcapClient
    from icap.exception import IcapConnectionError

    client = AsyncIcapClient("localhost", 1344)

    # Mock connection
    mock_writer = mocker.MagicMock()
    # First write succeeds, second raises OSError
    mock_writer.write.side_effect = [None, OSError("Connection reset by peer")]
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    stream = BytesIO(b"test content for scanning")

    with pytest.raises(IcapConnectionError) as exc_info:
        await client.scan_stream(stream, chunk_size=1024)

    assert "Connection error" in str(exc_info.value)


async def test_async_send_and_receive_connection_reset_raises_connection_error(mocker):
    """Test that ConnectionResetError during async send raises IcapConnectionError."""
    from icap import AsyncIcapClient
    from icap.exception import IcapConnectionError

    client = AsyncIcapClient("localhost", 1344)

    # Mock connection
    mock_writer = mocker.MagicMock()
    mock_writer.write.side_effect = ConnectionResetError("Connection reset by peer")
    mock_writer.drain = mocker.AsyncMock()
    mock_writer.close = mocker.MagicMock()

    mock_reader = mocker.MagicMock()
    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    with pytest.raises(IcapConnectionError) as exc_info:
        await client._send_and_receive(b"test request")

    assert "Connection error" in str(exc_info.value)


async def test_async_send_and_receive_broken_pipe_raises_connection_error(mocker):
    """Test that BrokenPipeError during async send raises IcapConnectionError."""
    from icap import AsyncIcapClient
    from icap.exception import IcapConnectionError

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = mocker.MagicMock()
    mock_writer.write.side_effect = BrokenPipeError("Broken pipe")
    mock_writer.drain = mocker.AsyncMock()
    mock_writer.close = mocker.MagicMock()

    mock_reader = mocker.MagicMock()
    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    with pytest.raises(IcapConnectionError) as exc_info:
        await client._send_and_receive(b"test request")

    assert "Connection error" in str(exc_info.value)


async def test_async_receive_response_invalid_content_length_raises_protocol_error(mocker):
    """Test that invalid Content-Length raises IcapProtocolError in async client."""
    from icap import AsyncIcapClient
    from icap.exception import IcapProtocolError

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = mocker.MagicMock()
    mock_writer.write = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    mock_reader.read = mocker.AsyncMock(
        return_value=b"ICAP/1.0 200 OK\r\nContent-Length: not-a-number\r\n\r\nbody"
    )

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    with pytest.raises(IcapProtocolError) as exc_info:
        await client._send_and_receive(b"test request")

    assert "Invalid Content-Length" in str(exc_info.value)


async def test_async_receive_response_incomplete_body_raises_protocol_error(mocker):
    """Test that incomplete body raises IcapProtocolError in async client."""
    from icap import AsyncIcapClient
    from icap.exception import IcapProtocolError

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = mocker.MagicMock()
    mock_writer.write = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    # First read returns headers with Content-Length: 100, second read returns partial body then EOF
    mock_reader.read = mocker.AsyncMock(
        side_effect=[
            b"ICAP/1.0 200 OK\r\nContent-Length: 100\r\n\r\npartial",
            b"",  # Connection closed before all bytes received
        ]
    )

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    with pytest.raises(IcapProtocolError) as exc_info:
        await client._send_and_receive(b"test request")

    assert "Incomplete response" in str(exc_info.value)


async def test_async_send_and_receive_server_error_raises_server_error(mocker):
    """Test that 5xx response raises IcapServerError in async client."""
    from icap import AsyncIcapClient
    from icap.exception import IcapServerError

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = mocker.MagicMock()
    mock_writer.write = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    mock_reader.read = mocker.AsyncMock(
        return_value=b"ICAP/1.0 500 Internal Server Error\r\nServer: Test\r\n\r\n"
    )

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    with pytest.raises(IcapServerError) as exc_info:
        await client._send_and_receive(b"test request")

    assert "500" in str(exc_info.value)


async def test_async_receive_response_timeout_during_body_raises_timeout_error(mocker):
    """Test that timeout during body read raises IcapTimeoutError in async client."""
    import asyncio

    from icap import AsyncIcapClient
    from icap.exception import IcapTimeoutError

    client = AsyncIcapClient("localhost", 1344, timeout=0.1)

    mock_writer = mocker.MagicMock()
    mock_writer.write = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    # First read returns headers, second read times out
    mock_reader.read = mocker.AsyncMock(
        side_effect=[
            b"ICAP/1.0 200 OK\r\nContent-Length: 100\r\n\r\npartial",
            asyncio.TimeoutError("Read timed out"),
        ]
    )

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    async def mock_wait_for(coro, timeout):
        return await coro

    mocker.patch("asyncio.wait_for", mock_wait_for)

    await client.connect()

    with pytest.raises(IcapTimeoutError) as exc_info:
        await client._receive_response()

    assert "Timeout" in str(exc_info.value)


async def test_async_chunked_body_connection_closed_raises_protocol_error(mocker):
    """Test that connection closed during async chunked body raises IcapProtocolError."""
    from icap import AsyncIcapClient
    from icap.exception import IcapProtocolError

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = mocker.MagicMock()
    mock_writer.write = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    # First read returns chunked headers, second read returns partial chunk, third returns EOF
    mock_reader.read = mocker.AsyncMock(
        side_effect=[
            b"ICAP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello",
            b"",  # Connection closed before chunk terminator
        ]
    )

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    await client.connect()

    with pytest.raises(IcapProtocolError) as exc_info:
        await client._receive_response()

    assert "Connection closed before chunked body complete" in str(exc_info.value)


async def test_async_scan_bytes_auto_connects(mocker):
    """Test that async scan_bytes auto-connects if not connected."""
    from icap import AsyncIcapClient

    client = AsyncIcapClient("localhost", 1344)

    mock_writer = mocker.MagicMock()
    mock_writer.write = mocker.MagicMock()
    mock_writer.drain = mocker.AsyncMock()

    mock_reader = mocker.MagicMock()
    mock_reader.read = mocker.AsyncMock(return_value=b"ICAP/1.0 204 No Modification\r\n\r\n")

    mocker.patch(
        "asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    )

    # Should auto-connect and complete the scan
    assert not client.is_connected
    response = await client.scan_bytes(b"test content")
    assert response.is_no_modification
    assert client.is_connected
