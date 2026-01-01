"""
Unit tests for PyCap ICAP client.
"""

import unittest
from pycap import IcapClient, IcapResponse
from pycap.exception import IcapException


class TestIcapResponse(unittest.TestCase):
    """Test IcapResponse parsing."""
    
    def test_parse_success_response(self):
        """Test parsing a successful ICAP response."""
        raw_response = b"ICAP/1.0 200 OK\r\nServer: C-ICAP/1.0\r\nConnection: close\r\n\r\nBody content"
        
        response = IcapResponse.parse(raw_response)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status_message, "OK")
        self.assertIn("Server", response.headers)
        self.assertEqual(response.headers["Server"], "C-ICAP/1.0")
        self.assertEqual(response.body, b"Body content")
    
    def test_parse_no_modification_response(self):
        """Test parsing 204 No Modification response."""
        raw_response = b"ICAP/1.0 204 No Content\r\nServer: C-ICAP/1.0\r\n\r\n"
        
        response = IcapResponse.parse(raw_response)
        
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.status_message, "No Content")
        self.assertTrue(response.is_no_modification)
        self.assertTrue(response.is_success)
    
    def test_is_success(self):
        """Test is_success property."""
        success_response = IcapResponse(200, "OK", {}, b"")
        self.assertTrue(success_response.is_success)
        
        no_mod_response = IcapResponse(204, "No Content", {}, b"")
        self.assertTrue(no_mod_response.is_success)
        
        error_response = IcapResponse(500, "Internal Error", {}, b"")
        self.assertFalse(error_response.is_success)
    
    def test_invalid_response(self):
        """Test parsing invalid response raises ValueError."""
        with self.assertRaises(ValueError):
            IcapResponse.parse(b"Invalid response")


class TestIcapClient(unittest.TestCase):
    """Test IcapClient functionality."""
    
    def test_initialization(self):
        """Test client initialization."""
        client = IcapClient("localhost", 1344)
        
        self.assertEqual(client.host, "localhost")
        self.assertEqual(client.port, 1344)
        self.assertFalse(client._connected)
    
    def test_port_setter_valid(self):
        """Test setting valid port."""
        client = IcapClient("localhost")
        client.port = 8080
        self.assertEqual(client.port, 8080)
    
    def test_port_setter_invalid(self):
        """Test setting invalid port raises TypeError."""
        client = IcapClient("localhost")
        with self.assertRaises(TypeError):
            client.port = "invalid"
    
    def test_build_request(self):
        """Test building ICAP request."""
        client = IcapClient("localhost", 1344)
        
        request_line = "OPTIONS icap://localhost:1344/avscan ICAP/1.0\r\n"
        headers = {
            "Host": "localhost:1344",
            "Encapsulated": "null-body=0"
        }
        
        request = client._build_request(request_line, headers)
        
        self.assertIsInstance(request, bytes)
        self.assertIn(b"OPTIONS", request)
        self.assertIn(b"Host: localhost:1344", request)
        self.assertIn(b"Encapsulated: null-body=0", request)
        self.assertTrue(request.endswith(b"\r\n\r\n"))
    
    def test_context_manager(self):
        """Test context manager protocol."""
        # This test won't actually connect since there's no server
        # We're just testing the structure
        client = IcapClient("localhost", 1344)
        
        self.assertFalse(client._connected)
        # Note: Can't test actual connection without a server
        # but we can verify the methods exist
        self.assertTrue(hasattr(client, '__enter__'))
        self.assertTrue(hasattr(client, '__exit__'))


if __name__ == '__main__':
    unittest.main()
