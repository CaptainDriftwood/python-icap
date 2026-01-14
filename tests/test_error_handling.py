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
