"""
Unit tests for python-icap ICAP client using pytest.
"""

import ssl

import pytest

from icap import AsyncIcapClient, IcapClient, IcapResponse

# IcapResponse tests


def test_parse_success_response():
    """Test parsing a successful ICAP response."""
    raw_response = b"ICAP/1.0 200 OK\r\nServer: C-ICAP/1.0\r\nConnection: close\r\n\r\nBody content"

    response = IcapResponse.parse(raw_response)

    assert response.status_code == 200
    assert response.status_message == "OK"
    assert "Server" in response.headers
    assert response.headers["Server"] == "C-ICAP/1.0"
    assert response.body == b"Body content"


def test_parse_no_modification_response():
    """Test parsing 204 No Modification response."""
    raw_response = b"ICAP/1.0 204 No Content\r\nServer: C-ICAP/1.0\r\n\r\n"

    response = IcapResponse.parse(raw_response)

    assert response.status_code == 204
    assert response.status_message == "No Content"
    assert response.is_no_modification
    assert response.is_success


def test_is_success():
    """Test is_success property."""
    success_response = IcapResponse(200, "OK", {}, b"")
    assert success_response.is_success

    no_mod_response = IcapResponse(204, "No Content", {}, b"")
    assert no_mod_response.is_success

    error_response = IcapResponse(500, "Internal Error", {}, b"")
    assert not error_response.is_success


def test_invalid_response():
    """Test parsing an invalid response raises ValueError."""
    with pytest.raises(ValueError):
        IcapResponse.parse(b"Invalid response")


# IcapClient tests


def test_client_initialization():
    """Test client initialization."""
    client = IcapClient("localhost", 1344)

    assert client.host == "localhost"
    assert client.port == 1344
    assert not client.is_connected


def test_port_setter_valid():
    """Test setting valid port."""
    client = IcapClient("localhost")
    client.port = 8080
    assert client.port == 8080


def test_port_setter_invalid():
    """Test setting an invalid port raises TypeError."""
    client = IcapClient("localhost")
    with pytest.raises(TypeError):
        client.port = "invalid"


def test_build_request():
    """Test building ICAP request."""
    client = IcapClient("localhost", 1344)

    request_line = "OPTIONS icap://localhost:1344/avscan ICAP/1.0\r\n"
    headers = {"Host": "localhost:1344", "Encapsulated": "null-body=0"}

    request = client._build_request(request_line, headers)

    assert isinstance(request, bytes)
    assert b"OPTIONS" in request
    assert b"Host: localhost:1344" in request
    assert b"Encapsulated: null-body=0" in request
    assert request.endswith(b"\r\n\r\n")


def test_context_manager():
    """Test context manager protocol."""
    # This test won't actually connect since there's no server
    # We're just testing the structure
    client = IcapClient("localhost", 1344)

    assert not client.is_connected
    # Note: Can't test actual connection without a server
    # but we can verify the methods exist
    assert hasattr(client, "__enter__")
    assert hasattr(client, "__exit__")


# Preview mode tests


def test_respmod_has_preview_parameter():
    """Test that respmod method accepts preview parameter."""
    client = IcapClient("localhost", 1344)
    # Check that the method signature includes preview parameter
    import inspect

    sig = inspect.signature(client.respmod)
    assert "preview" in sig.parameters
    # Check default is None
    assert sig.parameters["preview"].default is None


def test_parse_100_continue_response():
    """Test parsing 100 Continue response for preview mode."""
    raw_response = b"ICAP/1.0 100 Continue\r\nServer: C-ICAP/1.0\r\n\r\n"

    response = IcapResponse.parse(raw_response)

    assert response.status_code == 100
    assert response.status_message == "Continue"
    # Note: is_success is 200-299, so 100 is not considered "success" in that sense
    assert not response.is_success


def test_send_with_preview_method_exists():
    """Test that _send_with_preview method exists on the client."""
    client = IcapClient("localhost", 1344)
    assert hasattr(client, "_send_with_preview")
    assert callable(client._send_with_preview)


# SSL/TLS tests


def test_client_accepts_ssl_context_parameter():
    """Test that IcapClient accepts ssl_context parameter."""
    ssl_context = ssl.create_default_context()
    client = IcapClient("localhost", 1344, ssl_context=ssl_context)

    # Verify the ssl_context is stored
    assert client._ssl_context is ssl_context


def test_client_ssl_context_defaults_to_none():
    """Test that ssl_context defaults to None."""
    client = IcapClient("localhost", 1344)
    assert client._ssl_context is None


def test_async_client_accepts_ssl_context_parameter():
    """Test that AsyncIcapClient accepts ssl_context parameter."""
    ssl_context = ssl.create_default_context()
    client = AsyncIcapClient("localhost", 1344, ssl_context=ssl_context)

    # Verify the ssl_context is stored
    assert client._ssl_context is ssl_context


def test_async_client_ssl_context_defaults_to_none():
    """Test that ssl_context defaults to None for async client."""
    client = AsyncIcapClient("localhost", 1344)
    assert client._ssl_context is None


# =============================================================================
# IcapProtocol base class tests
# =============================================================================


def test_protocol_constants():
    """Test IcapProtocol class constants."""
    from icap._protocol import IcapProtocol

    assert IcapProtocol.DEFAULT_PORT == 1344
    assert IcapProtocol.CRLF == "\r\n"
    assert IcapProtocol.ICAP_VERSION == "ICAP/1.0"
    assert IcapProtocol.BUFFER_SIZE == 8192
    assert IcapProtocol.USER_AGENT == "Python-ICAP-Client/1.0"


def test_protocol_build_request():
    """Test IcapProtocol._build_request method."""
    from icap._protocol import IcapProtocol

    protocol = IcapProtocol()
    request_line = "OPTIONS icap://localhost:1344/avscan ICAP/1.0\r\n"
    headers = {"Host": "localhost:1344", "User-Agent": "Test"}

    result = protocol._build_request(request_line, headers)

    assert isinstance(result, bytes)
    assert b"OPTIONS icap://localhost:1344/avscan ICAP/1.0\r\n" in result
    assert b"Host: localhost:1344\r\n" in result
    assert b"User-Agent: Test\r\n" in result


def test_protocol_build_http_request_header_with_filename():
    """Test _build_http_request_header with filename."""
    from icap._protocol import IcapProtocol

    protocol = IcapProtocol()
    result = protocol._build_http_request_header("test.txt")

    assert result == b"GET /test.txt HTTP/1.1\r\nHost: file-scan\r\n\r\n"


def test_protocol_build_http_request_header_without_filename():
    """Test _build_http_request_header without filename."""
    from icap._protocol import IcapProtocol

    protocol = IcapProtocol()
    result = protocol._build_http_request_header(None)

    assert result == b"GET /scan HTTP/1.1\r\nHost: file-scan\r\n\r\n"


def test_protocol_build_http_response_header():
    """Test _build_http_response_header method."""
    from icap._protocol import IcapProtocol

    protocol = IcapProtocol()
    result = protocol._build_http_response_header(100)

    assert b"HTTP/1.1 200 OK\r\n" in result
    assert b"Content-Type: application/octet-stream\r\n" in result
    assert b"Content-Length: 100\r\n" in result


def test_protocol_build_http_response_header_chunked():
    """Test _build_http_response_header_chunked method."""
    from icap._protocol import IcapProtocol

    protocol = IcapProtocol()
    result = protocol._build_http_response_header_chunked()

    assert b"HTTP/1.1 200 OK\r\n" in result
    assert b"Transfer-Encoding: chunked\r\n" in result


def test_protocol_encode_chunked():
    """Test _encode_chunked static method."""
    from icap._protocol import IcapProtocol

    result = IcapProtocol._encode_chunked(b"Hello")
    assert result == b"5\r\nHello\r\n"


def test_protocol_encode_chunked_empty():
    """Test _encode_chunked with empty data."""
    from icap._protocol import IcapProtocol

    result = IcapProtocol._encode_chunked(b"")
    assert result == b""


def test_protocol_encode_chunk_terminator():
    """Test _encode_chunk_terminator static method."""
    from icap._protocol import IcapProtocol

    result = IcapProtocol._encode_chunk_terminator()
    assert result == b"0\r\n\r\n"


# =============================================================================
# IcapResponse tests
# =============================================================================


def test_response_repr():
    """Test IcapResponse.__repr__ method."""
    response = IcapResponse(200, "OK", {}, b"")
    repr_str = repr(response)

    assert "IcapResponse" in repr_str
    assert "200" in repr_str
    assert "OK" in repr_str


def test_response_repr_with_special_message():
    """Test IcapResponse.__repr__ with special characters."""
    response = IcapResponse(204, "No Content", {}, b"")
    repr_str = repr(response)

    assert "204" in repr_str
    assert "No Content" in repr_str


def test_response_is_success_boundary_cases():
    """Test is_success property at boundary values."""
    # 199 is not success
    response_199 = IcapResponse(199, "Info", {}, b"")
    assert not response_199.is_success

    # 200 is success
    response_200 = IcapResponse(200, "OK", {}, b"")
    assert response_200.is_success

    # 299 is success
    response_299 = IcapResponse(299, "Custom", {}, b"")
    assert response_299.is_success

    # 300 is not success
    response_300 = IcapResponse(300, "Redirect", {}, b"")
    assert not response_300.is_success


def test_response_parse_with_no_body():
    """Test parsing response with no body section."""
    raw = b"ICAP/1.0 204 No Content\r\nServer: Test\r\n\r\n"
    response = IcapResponse.parse(raw)

    assert response.status_code == 204
    assert response.body == b""


def test_response_parse_with_empty_headers():
    """Test parsing response with no headers."""
    raw = b"ICAP/1.0 200 OK\r\n\r\nbody content"
    response = IcapResponse.parse(raw)

    assert response.status_code == 200
    assert response.headers == {}
    assert response.body == b"body content"
