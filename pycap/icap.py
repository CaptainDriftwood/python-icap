import socket
import logging
from typing import Dict, Optional, Union, BinaryIO
from pathlib import Path
from .response import IcapResponse


logger = logging.getLogger(__name__)


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
        logger.debug(f"Initialized IcapClient for {address}:{port}")

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
            logger.debug("Already connected")
            return
            
        logger.info(f"Connecting to {self.host}:{self.port}")
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self._timeout)
        self._socket.connect((self.host, self.port))
        self._connected = True
        logger.info(f"Connected to {self.host}:{self.port}")

    def disconnect(self):
        """Disconnect from the ICAP server."""
        if self._socket:
            try:
                self._socket.close()
                logger.info(f"Disconnected from {self.host}:{self.port}")
            except (OSError, socket.error) as e:
                logger.warning(f"Error while disconnecting: {e}")
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
        
        logger.debug(f"Sending OPTIONS request for service: {service}")
        # Build OPTIONS request
        request_line = f"OPTIONS icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Encapsulated": "null-body=0"
        }
        
        request = self._build_request(request_line, headers)
        response = self._send_and_receive(request)
        logger.debug(f"OPTIONS response: {response.status_code} {response.status_message}")
        return response

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
        
        logger.debug(f"Sending RESPMOD request for service: {service}")
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
        
        response = self._send_and_receive(request)
        logger.debug(f"RESPMOD response: {response.status_code} {response.status_message}")
        return response

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
        
        logger.debug(f"Sending REQMOD request for service: {service}")
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
            chunk_size = f"{len(http_body):X}"
            request += f"{chunk_size}{self.CRLF}".encode()
            request += http_body
            request += f"{self.CRLF}0{self.CRLF}{self.CRLF}".encode()
        
        response = self._send_and_receive(request)
        logger.debug(f"REQMOD response: {response.status_code} {response.status_message}")
        return response

    def scan_file(self, filepath: Union[str, Path], service: str = "avscan") -> IcapResponse:
        """
        Convenience method to scan a file using RESPMOD.
        
        Args:
            filepath: Path to the file to scan (string or Path object)
            service: ICAP service name (default: "avscan")
            
        Returns:
            IcapResponse object
            
        Example:
            >>> with IcapClient('localhost') as client:
            ...     response = client.scan_file('/path/to/file.pdf')
            ...     if response.is_no_modification:
            ...         print("File is clean")
        """
        filepath = Path(filepath)
        logger.info(f"Scanning file: {filepath}")
        
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            return self.scan_stream(f, service=service, filename=filepath.name)

    def scan_stream(self, stream: BinaryIO, service: str = "avscan", 
                    filename: Optional[str] = None) -> IcapResponse:
        """
        Convenience method to scan a file-like object using RESPMOD.
        
        Args:
            stream: File-like object (must support read())
            service: ICAP service name (default: "avscan")
            filename: Optional filename to use in HTTP headers
            
        Returns:
            IcapResponse object
            
        Example:
            >>> with open('file.pdf', 'rb') as f:
            ...     with IcapClient('localhost') as client:
            ...         response = client.scan_stream(f, filename='file.pdf')
            ...         if response.is_no_modification:
            ...             print("Stream is clean")
        """
        content = stream.read()
        logger.info(f"Scanning stream ({len(content)} bytes){f' - {filename}' if filename else ''}")
        
        # Build HTTP request headers
        resource = f"/{filename}" if filename else "/scan"
        http_request = f"GET {resource} HTTP/1.1\r\nHost: file-scan\r\n\r\n".encode()
        
        # Build HTTP response with file content
        http_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(content)}\r\n"
            f"\r\n"
        ).encode() + content
        
        return self.respmod(service, http_request, http_response)

    def _build_request(self, request_line: str, headers: Dict[str, str]) -> bytes:
        """Build ICAP request from request line and headers."""
        request = request_line
        for key, value in headers.items():
            request += f"{key}: {value}{self.CRLF}"
        request += self.CRLF
        return request.encode('utf-8')

    def _send_and_receive(self, request: bytes) -> IcapResponse:
        """Send request and receive response."""
        logger.debug(f"Sending {len(request)} bytes to ICAP server")
        self._socket.sendall(request)
        
        # Receive response headers first
        response_data = b""
        header_end_marker = b"\r\n\r\n"
        
        # Read until we get the complete headers
        while header_end_marker not in response_data:
            chunk = self._socket.recv(self.BUFFER_SIZE)
            if not chunk:
                break
            response_data += chunk
        
        # Parse headers to determine if there's a body and how to read it
        if header_end_marker in response_data:
            header_section, body_start = response_data.split(header_end_marker, 1)
            headers_str = header_section.decode('utf-8', errors='ignore')
            
            # Check for Content-Length header to know how much body to read
            content_length = None
            for line in headers_str.split('\r\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    if key.strip().lower() == 'content-length':
                        content_length = int(value.strip())
                        break
            
            # If we have Content-Length, read exactly that many bytes
            if content_length is not None:
                logger.debug(f"Reading {content_length} bytes of body content")
                response_data = header_section + header_end_marker
                bytes_read = len(body_start)
                response_data += body_start
                
                while bytes_read < content_length:
                    chunk = self._socket.recv(min(self.BUFFER_SIZE, content_length - bytes_read))
                    if not chunk:
                        break
                    response_data += chunk
                    bytes_read += len(chunk)
            else:
                # For responses without Content-Length (like 204), headers are enough
                # Keep what we have
                logger.debug("No Content-Length header, using headers only")
        
        logger.debug(f"Received {len(response_data)} bytes from ICAP server")
        return IcapResponse.parse(response_data)
