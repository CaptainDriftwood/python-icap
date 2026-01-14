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
