import logging
import socket
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, Optional, Union

from ._protocol import IcapProtocol
from .exception import IcapConnectionError, IcapProtocolError, IcapServerError, IcapTimeoutError
from .response import IcapResponse

logger = logging.getLogger(__name__)


class IcapClient(IcapProtocol):
    """
    ICAP (Internet Content Adaptation Protocol) Client implementation.
    Based on RFC 3507.
    """

    def __init__(
        self, address: str, port: int = IcapProtocol.DEFAULT_PORT, timeout: int = 10
    ) -> None:
        """
        Initialize ICAP client.

        Args:
            address: ICAP server hostname or IP address
            port: ICAP server port (default: 1344)
            timeout: Socket timeout in seconds (default: 10)
        """
        self._address: str = address
        self._port: int = port
        self._timeout: int = timeout
        self._socket: Optional[socket.socket] = None
        self._connected: bool = False
        logger.debug(f"Initialized IcapClient for {address}:{port}")

    @property
    def host(self) -> str:
        return self._address

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, p: int) -> None:
        if not isinstance(p, int):
            raise TypeError("Port is not valid type. Please enter an int value.")
        self._port = p

    @property
    def is_connected(self) -> bool:
        """Return True if the client is currently connected to the server."""
        return self._connected

    def connect(self) -> None:
        """Connect to the ICAP server.

        Raises:
            IcapConnectionError: If connection to the server fails.
            IcapTimeoutError: If connection times out.
        """
        if self._connected:
            logger.debug("Already connected")
            return

        logger.info(f"Connecting to {self.host}:{self.port}")
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self._timeout)
            self._socket.connect((self.host, self.port))
            self._connected = True
            logger.info(f"Connected to {self.host}:{self.port}")
        except socket.timeout as e:
            self._socket = None
            raise IcapTimeoutError(f"Connection to {self.host}:{self.port} timed out") from e
        except OSError as e:
            self._socket = None
            raise IcapConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}") from e

    def disconnect(self) -> None:
        """Disconnect from the ICAP server."""
        if self._socket:
            try:
                self._socket.close()
                logger.info(f"Disconnected from {self.host}:{self.port}")
            except OSError as e:
                logger.warning(f"Error while disconnecting: {e}")
            self._socket = None
        self._connected = False

    def __enter__(self) -> "IcapClient":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
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
        request_line = (
            f"OPTIONS icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )
        headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Encapsulated": "null-body=0",
        }

        request = self._build_request(request_line, headers)
        response = self._send_and_receive(request)
        logger.debug(f"OPTIONS response: {response.status_code} {response.status_message}")
        return response

    def respmod(
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: Optional[Dict[str, str]] = None,
    ) -> IcapResponse:
        """
        Send RESPMOD request to ICAP server.

        Args:
            service: ICAP service name
            http_request: Original HTTP request headers
            http_response: HTTP response to be scanned/modified (headers + body)
            headers: Additional ICAP headers

        Returns:
            IcapResponse object
        """
        if not self._connected:
            self.connect()

        logger.debug(f"Sending RESPMOD request for service: {service}")
        request_line = (
            f"RESPMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )

        # Split HTTP response into headers and body
        if b"\r\n\r\n" in http_response:
            http_res_headers, http_res_body = http_response.split(b"\r\n\r\n", 1)
            http_res_headers += b"\r\n\r\n"  # Include the separator
        else:
            http_res_headers = http_response
            http_res_body = b""

        # Calculate encapsulated header offsets (relative to start of encapsulated body)
        # Per RFC 3507: offsets mark where each section begins in the message body
        req_hdr_len = len(http_request) if http_request else 0
        res_hdr_offset = req_hdr_len
        res_body_offset = res_hdr_offset + len(http_res_headers)

        icap_headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Allow": "204",
        }

        if http_request:
            icap_headers["Encapsulated"] = (
                f"req-hdr=0, res-hdr={res_hdr_offset}, res-body={res_body_offset}"
            )
        else:
            icap_headers["Encapsulated"] = f"res-hdr=0, res-body={len(http_res_headers)}"

        if headers:
            icap_headers.update(headers)

        request = self._build_request(request_line, icap_headers)

        # Add encapsulated headers (NOT chunked per RFC 3507)
        if http_request:
            request += http_request
        request += http_res_headers

        # Add encapsulated body with chunked transfer encoding (REQUIRED per RFC 3507)
        if http_res_body:
            chunk_size = f"{len(http_res_body):X}{self.CRLF}"
            request += chunk_size.encode()
            request += http_res_body
            request += f"{self.CRLF}".encode()

        # Terminating zero-length chunk
        request += f"0{self.CRLF}{self.CRLF}".encode()

        response = self._send_and_receive(request)
        logger.debug(f"RESPMOD response: {response.status_code} {response.status_message}")
        return response

    def reqmod(
        self,
        service: str,
        http_request: bytes,
        http_body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> IcapResponse:
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
        request_line = (
            f"REQMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )

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

        with open(filepath, "rb") as f:
            return self.scan_stream(f, service=service, filename=filepath.name)

    def scan_stream(
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: Optional[str] = None,
        chunk_size: int = 0,
    ) -> IcapResponse:
        """
        Convenience method to scan a file-like object using RESPMOD.

        Args:
            stream: File-like object (must support read())
            service: ICAP service name (default: "avscan")
            filename: Optional filename to use in HTTP headers
            chunk_size: If > 0, use chunked streaming to avoid loading entire
                       file into memory. Set to e.g. 65536 for 64KB chunks.
                       If 0 (default), reads entire stream into memory.

        Returns:
            IcapResponse object

        Example:
            >>> with open('file.pdf', 'rb') as f:
            ...     with IcapClient('localhost') as client:
            ...         response = client.scan_stream(f, filename='file.pdf')
            ...         if response.is_no_modification:
            ...             print("Stream is clean")

            >>> # For large files, use chunked streaming:
            >>> with open('large_file.bin', 'rb') as f:
            ...     with IcapClient('localhost') as client:
            ...         response = client.scan_stream(f, chunk_size=65536)
        """
        if chunk_size > 0:
            return self._scan_stream_chunked(stream, service, filename, chunk_size)

        content = stream.read()
        logger.info(f"Scanning stream ({len(content)} bytes){f' - {filename}' if filename else ''}")
        return self.scan_bytes(content, service=service, filename=filename)

    def _scan_stream_chunked(
        self,
        stream: BinaryIO,
        service: str,
        filename: Optional[str],
        chunk_size: int,
    ) -> IcapResponse:
        """
        Scan a stream using chunked transfer encoding to avoid loading
        the entire file into memory.

        Args:
            stream: File-like object to scan
            service: ICAP service name
            filename: Optional filename for HTTP headers
            chunk_size: Size of chunks to read and send

        Returns:
            IcapResponse object
        """
        if not self._connected:
            self.connect()

        if self._socket is None:
            raise IcapConnectionError("Not connected to ICAP server")

        logger.info(
            f"Scanning stream in chunks of {chunk_size} bytes{f' - {filename}' if filename else ''}"
        )

        # Build ICAP request line and headers
        request_line = (
            f"RESPMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )

        # Build HTTP request headers (encapsulated)
        resource = f"/{filename}" if filename else "/scan"
        http_request = f"GET {resource} HTTP/1.1\r\nHost: file-scan\r\n\r\n".encode()

        # Build HTTP response headers (we'll use chunked transfer encoding)
        http_response_headers = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )

        # Calculate encapsulated offsets
        req_hdr_len = len(http_request)
        res_hdr_len = len(http_response_headers)

        icap_headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Python-ICAP-Client/1.0",
            "Allow": "204",
            "Encapsulated": f"req-hdr=0, res-hdr={req_hdr_len}, res-body={req_hdr_len + res_hdr_len}",
        }

        # Build and send ICAP headers
        icap_request = self._build_request(request_line, icap_headers)
        icap_request += http_request
        icap_request += http_response_headers

        try:
            self._socket.sendall(icap_request)

            # Stream the body in chunks
            total_bytes = 0
            for chunk in self._iter_chunks(stream, chunk_size):
                # Send chunk size in hex followed by CRLF
                chunk_header = f"{len(chunk):X}\r\n".encode()
                self._socket.sendall(chunk_header)
                self._socket.sendall(chunk)
                self._socket.sendall(b"\r\n")
                total_bytes += len(chunk)

            # Send final zero-length chunk to indicate end
            self._socket.sendall(b"0\r\n\r\n")
            logger.debug(f"Sent {total_bytes} bytes in chunked encoding")

            # Receive and parse response
            return self._receive_response()

        except socket.timeout as e:
            raise IcapTimeoutError(f"Request to {self.host}:{self.port} timed out") from e
        except OSError as e:
            self._connected = False
            raise IcapConnectionError(f"Connection error with {self.host}:{self.port}: {e}") from e

    def _iter_chunks(self, stream: BinaryIO, chunk_size: int) -> Iterator[bytes]:
        """Iterate over a stream in chunks."""
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def _receive_response(self) -> IcapResponse:
        """Receive and parse ICAP response from the socket."""
        if self._socket is None:
            raise IcapConnectionError("Not connected to ICAP server")

        response_data = b""
        header_end_marker = b"\r\n\r\n"

        # Read until we get the complete headers
        while header_end_marker not in response_data:
            chunk = self._socket.recv(self.BUFFER_SIZE)
            if not chunk:
                break
            response_data += chunk

        # Parse headers to determine if there's a body
        if header_end_marker in response_data:
            header_section, body_start = response_data.split(header_end_marker, 1)
            headers_str = header_section.decode("utf-8", errors="ignore")

            content_length = None
            for line in headers_str.split("\r\n")[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.strip().lower() == "content-length":
                        content_length = int(value.strip())
                        break

            if content_length is not None:
                response_data = header_section + header_end_marker
                bytes_read = len(body_start)
                response_data += body_start

                while bytes_read < content_length:
                    chunk = self._socket.recv(min(self.BUFFER_SIZE, content_length - bytes_read))
                    if not chunk:
                        break
                    response_data += chunk
                    bytes_read += len(chunk)

        logger.debug(f"Received {len(response_data)} bytes from ICAP server")

        try:
            response = IcapResponse.parse(response_data)
        except ValueError as e:
            raise IcapProtocolError(f"Failed to parse ICAP response: {e}") from e

        if 500 <= response.status_code < 600:
            raise IcapServerError(
                f"ICAP server error: {response.status_code} {response.status_message}"
            )

        return response

    def scan_bytes(
        self, data: bytes, service: str = "avscan", filename: Optional[str] = None
    ) -> IcapResponse:
        """
        Convenience method to scan bytes content using RESPMOD.

        Args:
            data: Bytes content to scan
            service: ICAP service name (default: "avscan")
            filename: Optional filename to use in HTTP headers

        Returns:
            IcapResponse object

        Example:
            >>> with IcapClient('localhost') as client:
            ...     content = b"some file content"
            ...     response = client.scan_bytes(content, filename='data.bin')
            ...     if response.is_no_modification:
            ...         print("Content is clean")
        """
        logger.info(f"Scanning bytes ({len(data)} bytes){f' - {filename}' if filename else ''}")

        # Build HTTP request headers
        resource = f"/{filename}" if filename else "/scan"
        http_request = f"GET {resource} HTTP/1.1\r\nHost: file-scan\r\n\r\n".encode()

        # Build HTTP response with bytes content
        http_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(data)}\r\n"
            f"\r\n"
        ).encode() + data

        return self.respmod(service, http_request, http_response)

    def _send_and_receive(self, request: bytes) -> IcapResponse:
        """Send request and receive response.

        Raises:
            IcapConnectionError: If not connected or connection is lost.
            IcapTimeoutError: If the operation times out.
            IcapProtocolError: If the response cannot be parsed.
            IcapServerError: If the server returns a 5xx error.
        """
        if self._socket is None:
            raise IcapConnectionError("Not connected to ICAP server")

        try:
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
                headers_str = header_section.decode("utf-8", errors="ignore")

                # Parse headers into dict for easier lookup
                content_length = None
                is_chunked = False
                for line in headers_str.split("\r\n")[1:]:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key_lower = key.strip().lower()
                        value_stripped = value.strip().lower()
                        if key_lower == "content-length":
                            content_length = int(value.strip())
                        elif key_lower == "transfer-encoding" and "chunked" in value_stripped:
                            is_chunked = True

                if content_length is not None:
                    # Read exactly Content-Length bytes
                    logger.debug(f"Reading {content_length} bytes of body content")
                    response_data = header_section + header_end_marker
                    bytes_read = len(body_start)
                    response_data += body_start

                    while bytes_read < content_length:
                        chunk = self._socket.recv(
                            min(self.BUFFER_SIZE, content_length - bytes_read)
                        )
                        if not chunk:
                            break
                        response_data += chunk
                        bytes_read += len(chunk)

                elif is_chunked:
                    # Read chunked transfer encoding
                    logger.debug("Reading chunked response body")
                    response_data = header_section + header_end_marker
                    chunked_body = self._read_chunked_body(body_start)
                    response_data += chunked_body

                else:
                    # For responses without Content-Length (like 204), headers are enough
                    logger.debug("No Content-Length header, using headers only")

            logger.debug(f"Received {len(response_data)} bytes from ICAP server")

        except socket.timeout as e:
            raise IcapTimeoutError(f"Request to {self.host}:{self.port} timed out") from e
        except OSError as e:
            self._connected = False
            raise IcapConnectionError(f"Connection error with {self.host}:{self.port}: {e}") from e

        try:
            response = IcapResponse.parse(response_data)
        except ValueError as e:
            raise IcapProtocolError(f"Failed to parse ICAP response: {e}") from e

        # Check for server errors
        if 500 <= response.status_code < 600:
            raise IcapServerError(
                f"ICAP server error: {response.status_code} {response.status_message}"
            )

        return response

    def _read_chunked_body(self, initial_data: bytes) -> bytes:
        """Read a chunked transfer encoded body from the socket.

        Args:
            initial_data: Any data already read after the headers

        Returns:
            The decoded (de-chunked) body content
        """
        if self._socket is None:
            raise IcapConnectionError("Not connected to ICAP server")

        buffer = initial_data
        body = b""

        while True:
            # Ensure we have enough data to read the chunk size line
            while b"\r\n" not in buffer:
                chunk = self._socket.recv(self.BUFFER_SIZE)
                if not chunk:
                    return body  # Connection closed
                buffer += chunk

            # Parse chunk size (hex)
            size_line, buffer = buffer.split(b"\r\n", 1)
            try:
                # Chunk size may have extensions after semicolon, ignore them
                chunk_size = int(size_line.split(b";")[0].strip(), 16)
            except ValueError:
                logger.warning(f"Invalid chunk size: {size_line}")
                return body

            if chunk_size == 0:
                # Final chunk - read trailing CRLF
                break

            # Read chunk data
            while len(buffer) < chunk_size + 2:  # +2 for trailing CRLF
                chunk = self._socket.recv(self.BUFFER_SIZE)
                if not chunk:
                    return body
                buffer += chunk

            # Extract chunk data (excluding trailing CRLF)
            body += buffer[:chunk_size]
            buffer = buffer[chunk_size + 2 :]  # Skip chunk data and CRLF

        return body
