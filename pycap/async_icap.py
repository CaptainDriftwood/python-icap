"""Async ICAP client implementation."""

import asyncio
import logging
import ssl
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Union

from ._protocol import IcapProtocol
from .exception import IcapConnectionError, IcapProtocolError, IcapServerError, IcapTimeoutError
from .response import IcapResponse

logger = logging.getLogger(__name__)


class AsyncIcapClient(IcapProtocol):
    """
    Async ICAP (Internet Content Adaptation Protocol) Client implementation.
    Based on RFC 3507.

    Supports optional SSL/TLS encryption for secure connections to ICAP servers.

    Example:
        >>> import asyncio
        >>> from pycap import AsyncIcapClient
        >>>
        >>> async def scan():
        ...     async with AsyncIcapClient('localhost') as client:
        ...         response = await client.scan_bytes(b"content", filename="test.txt")
        ...         print(f"Clean: {response.is_no_modification}")
        >>>
        >>> asyncio.run(scan())

    Example with SSL:
        >>> import asyncio
        >>> import ssl
        >>> from pycap import AsyncIcapClient
        >>>
        >>> async def scan_secure():
        ...     ssl_context = ssl.create_default_context()
        ...     async with AsyncIcapClient('icap.example.com', ssl_context=ssl_context) as client:
        ...         response = await client.scan_bytes(b"content")
        ...         print(f"Clean: {response.is_no_modification}")
        >>>
        >>> asyncio.run(scan_secure())
    """

    def __init__(
        self,
        address: str,
        port: int = IcapProtocol.DEFAULT_PORT,
        timeout: float = 10.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        """
        Initialize async ICAP client.

        Args:
            address: ICAP server hostname or IP address
            port: ICAP server port (default: 1344)
            timeout: Operation timeout in seconds (default: 10.0)
            ssl_context: Optional SSL context for TLS connections. If provided,
                the connection will be wrapped with SSL/TLS. You can create a
                context using ssl.create_default_context() for standard TLS,
                or customize it for specific certificate requirements.

        Example:
            >>> # Standard TLS with system CA certificates
            >>> ssl_ctx = ssl.create_default_context()
            >>> client = AsyncIcapClient('icap.example.com', ssl_context=ssl_ctx)

            >>> # TLS with custom CA certificate
            >>> ssl_ctx = ssl.create_default_context(cafile='/path/to/ca.pem')
            >>> client = AsyncIcapClient('icap.example.com', ssl_context=ssl_ctx)
        """
        self._address: str = address
        self._port: int = port
        self._timeout: float = timeout
        self._ssl_context: Optional[ssl.SSLContext] = ssl_context
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        logger.debug(
            f"Initialized AsyncIcapClient for {address}:{port} (SSL: {ssl_context is not None})"
        )

    @property
    def host(self) -> str:
        """Return the server host."""
        return self._address

    @property
    def port(self) -> int:
        """Return the server port."""
        return self._port

    @property
    def is_connected(self) -> bool:
        """Return True if the client is currently connected to the server."""
        return self._writer is not None

    async def connect(self) -> None:
        """Connect to the ICAP server.

        If an ssl_context was provided during initialization, the connection
        will be wrapped with SSL/TLS.

        Raises:
            IcapConnectionError: If connection to the server fails, including
                SSL/TLS handshake errors.
            IcapTimeoutError: If connection times out.
        """
        if self._writer is not None:
            logger.debug("Already connected")
            return

        logger.info(f"Connecting to {self.host}:{self.port}")
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._address,
                    self._port,
                    ssl=self._ssl_context,
                    server_hostname=self.host if self._ssl_context else None,
                ),
                timeout=self._timeout,
            )
            logger.info(
                f"Connected to {self.host}:{self.port} (SSL: {self._ssl_context is not None})"
            )
        except asyncio.TimeoutError as e:
            raise IcapTimeoutError(f"Connection to {self.host}:{self.port} timed out") from e
        except ssl.SSLError as e:
            raise IcapConnectionError(
                f"SSL error connecting to {self.host}:{self.port}: {e}"
            ) from e
        except OSError as e:
            raise IcapConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from the ICAP server."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
                logger.info(f"Disconnected from {self.host}:{self.port}")
            except OSError as e:
                logger.warning(f"Error while disconnecting: {e}")
            self._writer = None
            self._reader = None

    async def __aenter__(self) -> "AsyncIcapClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        """Async context manager exit."""
        await self.disconnect()
        return False

    async def options(self, service: str) -> IcapResponse:
        """
        Send OPTIONS request to ICAP server.

        Args:
            service: ICAP service name (e.g., "avscan")

        Returns:
            IcapResponse object
        """
        if self._writer is None:
            await self.connect()

        logger.debug(f"Sending OPTIONS request for service: {service}")
        request_line = (
            f"OPTIONS icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )
        headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": self.USER_AGENT,
            "Encapsulated": "null-body=0",
        }

        request = self._build_request(request_line, headers)
        response = await self._send_and_receive(request)
        logger.debug(f"OPTIONS response: {response.status_code} {response.status_message}")
        return response

    async def respmod(
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: Optional[Dict[str, str]] = None,
        preview: Optional[int] = None,
    ) -> IcapResponse:
        """
        Send RESPMOD request to ICAP server.

        Args:
            service: ICAP service name
            http_request: Original HTTP request headers
            http_response: HTTP response to be scanned/modified (headers + body)
            headers: Additional ICAP headers
            preview: Optional preview size in bytes. If set, sends only the first
                N bytes of the body initially, then waits for server response.
                If server responds with 100 Continue, sends the remaining data.
                Use OPTIONS to query the server's preferred preview size.

        Returns:
            IcapResponse object
        """
        if self._writer is None:
            await self.connect()

        logger.debug(f"Sending RESPMOD request for service: {service}")
        request_line = (
            f"RESPMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )

        # Split HTTP response into headers and body
        if b"\r\n\r\n" in http_response:
            http_res_headers, http_res_body = http_response.split(b"\r\n\r\n", 1)
            http_res_headers += b"\r\n\r\n"
        else:
            http_res_headers = http_response
            http_res_body = b""

        # Calculate encapsulated header offsets
        req_hdr_len = len(http_request) if http_request else 0
        res_hdr_offset = req_hdr_len
        res_body_offset = res_hdr_offset + len(http_res_headers)

        icap_headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": self.USER_AGENT,
            "Allow": "204",
        }

        if http_request:
            icap_headers["Encapsulated"] = (
                f"req-hdr=0, res-hdr={res_hdr_offset}, res-body={res_body_offset}"
            )
        else:
            icap_headers["Encapsulated"] = f"res-hdr=0, res-body={len(http_res_headers)}"

        # Add Preview header if preview mode is requested
        if preview is not None:
            icap_headers["Preview"] = str(preview)

        if headers:
            icap_headers.update(headers)

        request = self._build_request(request_line, icap_headers)

        # Add encapsulated headers
        if http_request:
            request += http_request
        request += http_res_headers

        # Handle preview mode
        if preview is not None and http_res_body:
            return await self._send_with_preview(request, http_res_body, preview)

        # Add encapsulated body with chunked transfer encoding
        if http_res_body:
            chunk_size = f"{len(http_res_body):X}{self.CRLF}"
            request += chunk_size.encode()
            request += http_res_body
            request += f"{self.CRLF}".encode()

        # Terminating zero-length chunk
        request += f"0{self.CRLF}{self.CRLF}".encode()

        response = await self._send_and_receive(request)
        logger.debug(f"RESPMOD response: {response.status_code} {response.status_message}")
        return response

    async def reqmod(
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
        if self._writer is None:
            await self.connect()

        logger.debug(f"Sending REQMOD request for service: {service}")
        request_line = (
            f"REQMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )

        req_hdr_offset = 0
        icap_headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": self.USER_AGENT,
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
            chunk_size = f"{len(http_body):X}"
            request += f"{chunk_size}{self.CRLF}".encode()
            request += http_body
            request += f"{self.CRLF}0{self.CRLF}{self.CRLF}".encode()

        response = await self._send_and_receive(request)
        logger.debug(f"REQMOD response: {response.status_code} {response.status_message}")
        return response

    async def scan_file(
        self,
        filepath: Union[str, Path],
        service: str = "avscan",
    ) -> IcapResponse:
        """
        Convenience method to scan a file using RESPMOD.

        Args:
            filepath: Path to the file to scan (string or Path object)
            service: ICAP service name (default: "avscan")

        Returns:
            IcapResponse object

        Example:
            >>> async with AsyncIcapClient('localhost') as client:
            ...     response = await client.scan_file('/path/to/file.pdf')
            ...     if response.is_no_modification:
            ...         print("File is clean")
        """
        filepath = Path(filepath)
        logger.info(f"Scanning file: {filepath}")

        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        # Read file in executor to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        content = await loop.run_in_executor(None, filepath.read_bytes)

        return await self.scan_bytes(content, service=service, filename=filepath.name)

    async def scan_stream(
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: Optional[str] = None,
    ) -> IcapResponse:
        """
        Convenience method to scan a file-like object using RESPMOD.

        Note: This reads the entire stream into memory. For large files,
        consider using scan_file() instead.

        Args:
            stream: File-like object (must support read())
            service: ICAP service name (default: "avscan")
            filename: Optional filename to use in HTTP headers

        Returns:
            IcapResponse object
        """
        # Read stream in executor to avoid blocking
        loop = asyncio.get_running_loop()
        content = await loop.run_in_executor(None, stream.read)

        logger.info(f"Scanning stream ({len(content)} bytes){f' - {filename}' if filename else ''}")
        return await self.scan_bytes(content, service=service, filename=filename)

    async def scan_bytes(
        self,
        data: bytes,
        service: str = "avscan",
        filename: Optional[str] = None,
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
            >>> async with AsyncIcapClient('localhost') as client:
            ...     content = b"some file content"
            ...     response = await client.scan_bytes(content, filename='data.bin')
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

        return await self.respmod(service, http_request, http_response)

    async def _send_and_receive(self, request: bytes) -> IcapResponse:
        """Send request and receive response.

        Raises:
            IcapConnectionError: If not connected or connection is lost.
            IcapTimeoutError: If the operation times out.
            IcapProtocolError: If the response cannot be parsed.
            IcapServerError: If the server returns a 5xx error.
        """
        if self._writer is None or self._reader is None:
            raise IcapConnectionError("Not connected to ICAP server")

        try:
            logger.debug(f"Sending {len(request)} bytes to ICAP server")

            # Send request
            self._writer.write(request)
            await asyncio.wait_for(self._writer.drain(), timeout=self._timeout)

            # Receive response
            response_data = await self._receive_response()

            logger.debug(f"Received {len(response_data)} bytes from ICAP server")

        except asyncio.TimeoutError as e:
            raise IcapTimeoutError(f"Request to {self.host}:{self.port} timed out") from e
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            self._writer = None
            self._reader = None
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

    async def _receive_response(self) -> bytes:
        """Receive and return raw ICAP response data."""
        if self._reader is None:
            raise IcapConnectionError("Not connected to ICAP server")

        response_data = b""
        header_end_marker = b"\r\n\r\n"

        # Read until we get the complete headers
        while header_end_marker not in response_data:
            try:
                chunk = await asyncio.wait_for(
                    self._reader.read(self.BUFFER_SIZE),
                    timeout=self._timeout,
                )
                if not chunk:
                    break
                response_data += chunk
            except asyncio.TimeoutError:
                raise IcapTimeoutError(
                    f"Timeout reading response from {self.host}:{self.port}"
                ) from None

        # Parse headers to determine if there's a body
        if header_end_marker in response_data:
            header_section, body_start = response_data.split(header_end_marker, 1)
            headers_str = header_section.decode("utf-8", errors="ignore")

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
                    try:
                        chunk = await asyncio.wait_for(
                            self._reader.read(min(self.BUFFER_SIZE, content_length - bytes_read)),
                            timeout=self._timeout,
                        )
                        if not chunk:
                            break
                        response_data += chunk
                        bytes_read += len(chunk)
                    except asyncio.TimeoutError:
                        raise IcapTimeoutError(
                            f"Timeout reading response body from {self.host}:{self.port}"
                        ) from None

            elif is_chunked:
                # Read chunked transfer encoding
                logger.debug("Reading chunked response body")
                response_data = header_section + header_end_marker
                chunked_body = await self._read_chunked_body(body_start)
                response_data += chunked_body

        return response_data

    async def _read_chunked_body(self, initial_data: bytes) -> bytes:
        """Read a chunked transfer encoded body.

        Args:
            initial_data: Any data already read after the headers

        Returns:
            The decoded (de-chunked) body content
        """
        if self._reader is None:
            raise IcapConnectionError("Not connected to ICAP server")

        buffer = initial_data
        body = b""

        while True:
            # Ensure we have enough data to read the chunk size line
            while b"\r\n" not in buffer:
                try:
                    chunk = await asyncio.wait_for(
                        self._reader.read(self.BUFFER_SIZE),
                        timeout=self._timeout,
                    )
                    if not chunk:
                        return body
                    buffer += chunk
                except asyncio.TimeoutError:
                    raise IcapTimeoutError(
                        f"Timeout reading chunked body from {self.host}:{self.port}"
                    ) from None

            # Parse chunk size (hex)
            size_line, buffer = buffer.split(b"\r\n", 1)
            try:
                chunk_size = int(size_line.split(b";")[0].strip(), 16)
            except ValueError:
                logger.warning(f"Invalid chunk size: {size_line}")
                return body

            if chunk_size == 0:
                break

            # Read chunk data
            while len(buffer) < chunk_size + 2:
                try:
                    chunk = await asyncio.wait_for(
                        self._reader.read(self.BUFFER_SIZE),
                        timeout=self._timeout,
                    )
                    if not chunk:
                        return body
                    buffer += chunk
                except asyncio.TimeoutError:
                    raise IcapTimeoutError(
                        f"Timeout reading chunked body from {self.host}:{self.port}"
                    ) from None

            body += buffer[:chunk_size]
            buffer = buffer[chunk_size + 2 :]

        return body

    async def _send_with_preview(
        self, request: bytes, body: bytes, preview_size: int
    ) -> IcapResponse:
        """Send an ICAP request with preview mode.

        Per RFC 3507, preview mode allows the server to make a decision based on
        the first N bytes without receiving the full payload. This can significantly
        improve performance for large files.

        Args:
            request: The ICAP request (headers + encapsulated HTTP headers)
            body: The full HTTP response body to be sent
            preview_size: Number of bytes to send in the preview

        Returns:
            IcapResponse object
        """
        if self._writer is None or self._reader is None:
            raise IcapConnectionError("Not connected to ICAP server")

        try:
            # Determine preview and remainder portions
            preview_data = body[:preview_size]
            remainder_data = body[preview_size:]
            is_complete = len(body) <= preview_size

            logger.debug(
                f"Sending preview: {len(preview_data)} bytes, "
                f"remainder: {len(remainder_data)} bytes, "
                f"complete in preview: {is_complete}"
            )

            # Build the preview chunk
            # If the entire body fits in preview, use "ieof" extension per RFC 3507
            if is_complete:
                # Use ieof (implicit end of file) when entire message fits in preview
                chunk_header = f"{len(preview_data):X}; ieof{self.CRLF}".encode()
                preview_chunk = chunk_header + preview_data + f"{self.CRLF}".encode()
                # Zero-length terminator
                preview_chunk += f"0{self.CRLF}{self.CRLF}".encode()
            else:
                # Normal preview chunk without ieof
                chunk_header = f"{len(preview_data):X}{self.CRLF}".encode()
                preview_chunk = chunk_header + preview_data + f"{self.CRLF}".encode()
                # Zero-length terminator for preview section
                preview_chunk += f"0{self.CRLF}{self.CRLF}".encode()

            # Send request with preview
            self._writer.write(request + preview_chunk)
            await asyncio.wait_for(self._writer.drain(), timeout=self._timeout)

            # Receive initial response (could be 100 Continue, 204, or 200)
            response_data = await self._receive_response()
            response = IcapResponse.parse(response_data)

            # If server responds with 100 Continue, send the rest of the body
            if response.status_code == 100:
                logger.debug("Received 100 Continue, sending remainder of body")

                # Send the remainder of the body
                if remainder_data:
                    chunk_header = f"{len(remainder_data):X}{self.CRLF}".encode()
                    remainder_chunk = chunk_header + remainder_data + f"{self.CRLF}".encode()
                    self._writer.write(remainder_chunk)

                # Send final zero-length chunk
                self._writer.write(f"0{self.CRLF}{self.CRLF}".encode())
                await asyncio.wait_for(self._writer.drain(), timeout=self._timeout)

                # Receive final response
                response_data = await self._receive_response()
                response = IcapResponse.parse(response_data)

            # Check for server errors
            if 500 <= response.status_code < 600:
                raise IcapServerError(
                    f"ICAP server error: {response.status_code} {response.status_message}"
                )

            logger.debug(f"Preview response: {response.status_code} {response.status_message}")
            return response

        except asyncio.TimeoutError as e:
            raise IcapTimeoutError(f"Request to {self.host}:{self.port} timed out") from e
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            self._writer = None
            self._reader = None
            raise IcapConnectionError(f"Connection error with {self.host}:{self.port}: {e}") from e
