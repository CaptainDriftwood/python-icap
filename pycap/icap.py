import socket
from typing import Dict, Optional, Tuple
from .response import IcapResponse


# TODO Add async support as well
# TODO Add support for context management protocol
# TODO Add method to scan filepath, or IO object

class IcapClient:
    """
    ICAP (Internet Content Adaptation Protocol) Client implementation.
    Based on RFC 3507.
    """
    DEFAULT_PORT = 1344
    CRLF = "\r\n"
    ICAP_VERSION = "ICAP/1.0"
    
    # Default buffer size for receiving data
    BUFFER_SIZE = 8192

    def __init__(self, address, port=DEFAULT_PORT, timeout=10):
        """
        Initialize ICAP client.
        
        Args:
            address: ICAP server hostname or IP address
            port: ICAP server port (default: 1344)
            timeout: Socket timeout in seconds (default: 10)
        """
        self._address = address
        self._port = port
        self._timeout = timeout
        self._socket = None
        self._connected = False

    @property
    def host(self):
        return self._address

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, p: int):
        if not isinstance(p, int):
            raise TypeError("Port is not valid type. Please enter an int value.")
        self._port = p

    def connect(self):
        """Connect to the ICAP server."""
        if self._connected:
            return
            
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self._timeout)
        self._socket.connect((self.host, self.port))
        self._connected = True

    def disconnect(self):
        """Disconnect from the ICAP server."""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
        self._connected = False

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

    def options(self, service: str) -> IcapResponse:
        """
        Send OPTIONS request to ICAP server.
        
        Args:
            service: ICAP service name (e.g., "avscan")
            
        Returns:
            IcapResponse object
        """
        if not self._connected:
            self.connect()
            
        # Build OPTIONS request
        request_line = f"OPTIONS icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Encapsulated": "null-body=0"
        }
        
        request = self._build_request(request_line, headers)
        return self._send_and_receive(request)

    def respmod(self, service: str, http_request: bytes, http_response: bytes, 
                headers: Optional[Dict[str, str]] = None) -> IcapResponse:
        """
        Send RESPMOD request to ICAP server.
        
        Args:
            service: ICAP service name
            http_request: Original HTTP request headers
            http_response: HTTP response to be scanned/modified
            headers: Additional ICAP headers
            
        Returns:
            IcapResponse object
        """
        if not self._connected:
            self.connect()
            
        request_line = f"RESPMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        
        # Build encapsulated header offsets
        req_hdr = len(http_request) if http_request else 0
        res_hdr = req_hdr
        res_body = res_hdr + len(http_response.split(b'\r\n\r\n', 1)[0]) + 4
        
        icap_headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Allow": "204",
        }
        
        if http_request:
            icap_headers["Encapsulated"] = f"req-hdr=0, res-hdr={req_hdr}, res-body={res_body}"
        else:
            icap_headers["Encapsulated"] = f"res-hdr=0, res-body={res_body}"
            
        if headers:
            icap_headers.update(headers)
        
        request = self._build_request(request_line, icap_headers)
        
        # Add HTTP headers and body
        if http_request:
            request += http_request
        request += http_response
        
        return self._send_and_receive(request)

    def reqmod(self, service: str, http_request: bytes, http_body: Optional[bytes] = None,
               headers: Optional[Dict[str, str]] = None) -> IcapResponse:
        """
        Send REQMOD request to ICAP server.
        
        Args:
            service: ICAP service name
            http_request: HTTP request to be scanned/modified
            http_body: Optional HTTP request body
            headers: Additional ICAP headers
            
        Returns:
            IcapResponse object
        """
        if not self._connected:
            self.connect()
            
        request_line = f"REQMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        
        # Calculate encapsulated offsets
        req_hdr_offset = 0
        
        icap_headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Allow": "204",
        }
        
        if http_body:
            body_offset = len(http_request)
            icap_headers["Encapsulated"] = f"req-hdr={req_hdr_offset}, req-body={body_offset}"
        else:
            null_body_offset = len(http_request)
            icap_headers["Encapsulated"] = f"req-hdr={req_hdr_offset}, null-body={null_body_offset}"
            
        if headers:
            icap_headers.update(headers)
        
        request = self._build_request(request_line, icap_headers)
        request += http_request
        
        if http_body:
            # Add chunked body
            chunk_size = hex(len(http_body))[2:]
            request += f"{chunk_size}{self.CRLF}".encode()
            request += http_body
            request += f"{self.CRLF}0{self.CRLF}{self.CRLF}".encode()
        
        return self._send_and_receive(request)

    def _build_request(self, request_line: str, headers: Dict[str, str]) -> bytes:
        """Build ICAP request from request line and headers."""
        request = request_line
        for key, value in headers.items():
            request += f"{key}: {value}{self.CRLF}"
        request += self.CRLF
        return request.encode('utf-8')

    def _send_and_receive(self, request: bytes) -> IcapResponse:
        """Send request and receive response."""
        self._socket.sendall(request)
        
        # Receive response
        response_data = b""
        while True:
            chunk = self._socket.recv(self.BUFFER_SIZE)
            if not chunk:
                break
            response_data += chunk
            
            # Check if we have received the complete response
            # Simple check: if we have headers and body
            if b"\r\n\r\n" in response_data:
                # For now, we'll do a simple check
                # A more robust implementation would parse Content-Length or chunked encoding
                break
        
        return IcapResponse.parse(response_data)
