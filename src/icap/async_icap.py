"""Async ICAP client implementation."""

import asyncio
import logging
import ssl
from pathlib import Path
from typing import Any, AsyncIterator, BinaryIO, Dict, Optional, Union

from ._protocol import (
    IcapProtocol,
    parse_chunk_size,
    parse_response_headers,
    prepare_preview_data,
    validate_body_size,
    validate_content_length,
)
from .exception import IcapConnectionError, IcapProtocolError, IcapServerError, IcapTimeoutError
from .response import IcapResponse

logger = logging.getLogger(__name__)


class AsyncIcapClient(IcapProtocol):
    """
    Asynchronous ICAP (Internet Content Adaptation Protocol) client.

    This client communicates with ICAP servers (RFC 3507) for content inspection,
    typically used for virus scanning, content filtering, or data loss prevention.
    Uses asyncio for non-blocking I/O operations.

    API Overview:
        **High-level methods (recommended for most use cases):**
        - `scan_file(path)` - Scan a file by path
        - `scan_bytes(data)` - Scan in-memory bytes
        - `scan_stream(file_obj)` - Scan a file-like object

        **Low-level methods (for advanced/custom ICAP interactions):**
        - `options(service)` - Query server capabilities
        - `respmod(service, http_req, http_resp)` - Response modification mode
        - `reqmod(service, http_req)` - Request modification mode

    Service Names:
        The `service` parameter identifies which ICAP service to use. Common names:
        - "avscan" or "srv_clamav" - ClamAV virus scanning (c-icap)
        - "squidclamav" - SquidClamav service
        - "echo" - Echo service (testing)

        The exact service name depends on your ICAP server configuration.
        Use `options(service)` to verify a service exists and check its capabilities.

    Concurrency:
        Each AsyncIcapClient instance maintains a single connection. For concurrent
        scanning, create multiple client instances (one per concurrent operation).

    Example:
        >>> import asyncio
        >>> from icap import AsyncIcapClient
        >>>
        >>> async def scan():
        ...     async with AsyncIcapClient('localhost') as client:
        ...         response = await client.scan_file('/path/to/file.pdf')
        ...         if response.is_no_modification:
        ...             print("File is clean")
        ...         else:
        ...             print(f"Threat: {response.headers.get('X-Virus-ID')}")
        >>>
        >>> asyncio.run(scan())

    Example with concurrent scanning:
        >>> async def scan_multiple(files):
        ...     async def scan_one(path):
        ...         async with AsyncIcapClient('localhost') as client:
        ...             return path, await client.scan_file(path)
        ...     return await asyncio.gather(*[scan_one(f) for f in files])

    Example with SSL/TLS:
        >>> import ssl
        >>> ssl_context = ssl.create_default_context()
        >>>
        >>> async with AsyncIcapClient('icap.example.com', ssl_context=ssl_context) as client:
        ...     response = await client.scan_bytes(b"content")
        ...     print(f"Clean: {response.is_no_modification}")

    See Also:
        - IcapClient: Synchronous version for non-async code
        - IcapResponse: Response object returned by all methods
    """

    # Default maximum response size (100MB)
    DEFAULT_MAX_RESPONSE_SIZE: int = 104_857_600

    # Maximum header section size (64KB) - prevents DoS from endless headers
    MAX_HEADER_SIZE: int = 65536

    def __init__(
        self,
        address: str,
        port: int = IcapProtocol.DEFAULT_PORT,
        timeout: float = 10.0,
        ssl_context: Optional[ssl.SSLContext] = None,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
    ) -> None:
        """
        Initialize async ICAP client.

        Args:
            address: ICAP server hostname or IP address
            port: ICAP server port (default: 1344)
            timeout: Operation timeout in seconds (default: 10.0). Accepts float
                for sub-second precision (e.g., 0.5 for 500ms). Note: the sync
                IcapClient uses int for timeout due to socket.settimeout() semantics.
            ssl_context: Optional SSL context for TLS connections. If provided,
                the connection will be wrapped with SSL/TLS. You can create a
                context using ssl.create_default_context() for standard TLS,
                or customize it for specific certificate requirements.
            max_response_size: Maximum allowed response size in bytes (default: 100MB).
                This limits both Content-Length values and individual chunk sizes
                in chunked transfer encoding. Increase this if you need to scan
                files larger than 100MB. Must be a positive integer.

        Example:
            >>> # Standard TLS with system CA certificates
            >>> ssl_ctx = ssl.create_default_context()
            >>> client = AsyncIcapClient('icap.example.com', ssl_context=ssl_ctx)

            >>> # TLS with custom CA certificate
            >>> ssl_ctx = ssl.create_default_context(cafile='/path/to/ca.pem')
            >>> client = AsyncIcapClient('icap.example.com', ssl_context=ssl_ctx)

            >>> # Scanning large files (up to 500MB)
            >>> client = AsyncIcapClient('localhost', max_response_size=500_000_000)
        """
        if max_response_size <= 0:
            raise ValueError("max_response_size must be a positive integer")
        self._address: str = address
        self._port: int = port
        self._timeout: float = timeout
        self._ssl_context: Optional[ssl.SSLContext] = ssl_context
        self._max_response_size: int = max_response_size
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
        Send OPTIONS request to query ICAP server capabilities.

        The OPTIONS request retrieves information about the ICAP service,
        including supported methods, preview size, and transfer encodings.

        Args:
            service: ICAP service name (e.g., "avscan")

        Returns:
            IcapResponse with headers containing server capabilities:
                - Methods: Supported ICAP methods (e.g., "RESPMOD, REQMOD")
                - Preview: Suggested preview size in bytes for this service
                - Transfer-Preview: File extensions that benefit from preview
                - Max-Connections: Maximum concurrent connections allowed
                - Options-TTL: How long (seconds) to cache this OPTIONS response
                - Service-ID: Unique identifier for this service instance

        Example:
            >>> async with AsyncIcapClient('localhost') as client:
            ...     response = await client.options("avscan")
            ...     preview_size = int(response.headers.get("Preview", 0))
            ...     methods = response.headers.get("Methods", "")
            ...     print(f"Preview: {preview_size}, Methods: {methods}")
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
            if preview <= 0:
                raise ValueError("preview size must be a positive integer")
            return await self._send_with_preview(request, http_res_body, preview)

        # Add encapsulated body with chunked transfer encoding
        if http_res_body:
            request += self._encode_chunked(http_res_body)

        # Terminating zero-length chunk
        request += self._encode_chunk_terminator()

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
            request += self._encode_chunked(http_body)
            request += self._encode_chunk_terminator()

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
        chunk_size: int = 0,
    ) -> IcapResponse:
        """
        Convenience method to scan a file-like object using RESPMOD.

        By default, reads the entire stream into memory. For large files,
        set chunk_size to stream in chunks without loading the entire file.

        Args:
            stream: File-like object (must support read())
            service: ICAP service name (default: "avscan")
            filename: Optional filename to use in HTTP headers
            chunk_size: Controls memory usage for large files.
                - 0 (default): Reads entire stream into memory before sending.
                  Simple but may exhaust memory for very large files.
                - >0: Uses chunked streaming, reading and sending in chunks of
                  this size (bytes). Set to 65536 for 64KB chunks, 1048576 for 1MB.
                  Recommended for files larger than available memory.

        Returns:
            IcapResponse object

        Example:
            >>> async with AsyncIcapClient('localhost') as client:
            ...     # Stream entire file into memory
            ...     with open('file.txt', 'rb') as f:
            ...         response = await client.scan_stream(f)
            ...
            ...     # Stream large file in chunks
            ...     with open('large_file.bin', 'rb') as f:
            ...         response = await client.scan_stream(f, chunk_size=65536)
        """
        if chunk_size > 0:
            return await self._scan_stream_chunked(stream, service, filename, chunk_size)

        # Read stream in executor to avoid blocking
        loop = asyncio.get_running_loop()
        try:
            content = await loop.run_in_executor(None, stream.read)
        except OSError as e:
            raise IcapProtocolError(f"Failed to read from stream: {e}") from e

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

        # Build HTTP request and response headers using base class methods
        http_request = self._build_http_request_header(filename)
        http_response = self._build_http_response_header(len(data)) + data

        return await self.respmod(service, http_request, http_response)

    async def _scan_stream_chunked(
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
        if not self.is_connected:
            await self.connect()

        if self._writer is None or self._reader is None:
            raise IcapConnectionError("Not connected to ICAP server")

        logger.info(
            f"Scanning stream in chunks of {chunk_size} bytes{f' - {filename}' if filename else ''}"
        )

        # Build ICAP request line and headers
        request_line = (
            f"RESPMOD icap://{self.host}:{self.port}/{service} {self.ICAP_VERSION}{self.CRLF}"
        )

        # Build HTTP request and response headers using base class methods
        http_request = self._build_http_request_header(filename)
        http_response_headers = self._build_http_response_header_chunked()

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
            self._writer.write(icap_request)
            await self._writer.drain()

            total_bytes = 0
            async for chunk in self._iter_chunks(stream, chunk_size):
                chunk_header = f"{len(chunk):X}\r\n".encode()
                self._writer.write(chunk_header)
                self._writer.write(chunk)
                self._writer.write(b"\r\n")
                await self._writer.drain()
                total_bytes += len(chunk)

            self._writer.write(self._encode_chunk_terminator())
            await self._writer.drain()
            logger.debug(f"Sent {total_bytes} bytes in chunked encoding")

            # Receive response
            response = await self._receive_response()

        except asyncio.TimeoutError:
            raise IcapTimeoutError(f"Request to {self.host}:{self.port} timed out") from None
        except OSError as e:
            self._writer = None
            self._reader = None
            raise IcapConnectionError(f"Connection error with {self.host}:{self.port}: {e}") from e

        # Check for server errors
        if 500 <= response.status_code < 600:
            raise IcapServerError(
                f"ICAP server error: {response.status_code} {response.status_message}"
            )

        return response

    async def _iter_chunks(self, stream: BinaryIO, chunk_size: int) -> AsyncIterator[bytes]:
        """Iterate over a stream in chunks, yielding each chunk asynchronously."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                chunk = await loop.run_in_executor(None, lambda: stream.read(chunk_size))
            except OSError as e:
                raise IcapProtocolError(f"Failed to read from stream: {e}") from e
            if not chunk:
                break
            yield chunk

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
            response = await self._receive_response()

            logger.debug(f"Received response: {response.status_code} {response.status_message}")

        except asyncio.TimeoutError as e:
            raise IcapTimeoutError(f"Request to {self.host}:{self.port} timed out") from e
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass  # Best effort cleanup
            self._writer = None
            self._reader = None
            raise IcapConnectionError(f"Connection error with {self.host}:{self.port}: {e}") from e

        # Check for server errors
        if 500 <= response.status_code < 600:
            raise IcapServerError(
                f"ICAP server error: {response.status_code} {response.status_message}"
            )

        return response

    async def _receive_response(self) -> IcapResponse:
        """Receive and parse ICAP response from the server."""
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

                # Prevent DoS from endless header data
                if len(response_data) > self.MAX_HEADER_SIZE:
                    raise IcapProtocolError(
                        f"Response header section exceeds maximum size "
                        f"({self.MAX_HEADER_SIZE:,} bytes)"
                    )
            except asyncio.TimeoutError:
                raise IcapTimeoutError(
                    f"Timeout reading response from {self.host}:{self.port}"
                ) from None

        # Parse headers to determine if there's a body
        if header_end_marker in response_data:
            header_section, body_start = response_data.split(header_end_marker, 1)
            headers_str = header_section.decode("utf-8", errors="ignore")

            # Parse headers to determine body handling
            headers = parse_response_headers(headers_str)

            if headers.content_length is not None:
                content_length = headers.content_length
                # Validate content length against maximum allowed size
                validate_content_length(content_length, self._max_response_size)

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

                # Validate we received all expected bytes
                if bytes_read < content_length:
                    raise IcapProtocolError(
                        f"Incomplete response: expected {content_length} bytes, got {bytes_read}"
                    )

            elif headers.is_chunked:
                # Read chunked transfer encoding
                logger.debug("Reading chunked response body")
                response_data = header_section + header_end_marker
                chunked_body = await self._read_chunked_body(body_start)
                response_data += chunked_body

        return IcapResponse.parse(response_data)

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
                        raise IcapProtocolError("Connection closed before chunked body complete")
                    buffer += chunk
                except asyncio.TimeoutError:
                    raise IcapTimeoutError(
                        f"Timeout reading chunked body from {self.host}:{self.port}"
                    ) from None

            # Parse and validate chunk size
            size_line, buffer = buffer.split(b"\r\n", 1)
            chunk_size = parse_chunk_size(size_line, self._max_response_size)

            if chunk_size == 0:
                # Final chunk - consume trailing CRLF (and any trailer headers)
                # Per RFC 7230, after the 0-size chunk there may be trailer headers
                # followed by a final CRLF. We need to read until we see the empty line.
                while True:
                    while b"\r\n" not in buffer:
                        try:
                            chunk = await asyncio.wait_for(
                                self._reader.read(self.BUFFER_SIZE),
                                timeout=self._timeout,
                            )
                            if not chunk:
                                break
                            buffer += chunk
                        except asyncio.TimeoutError:
                            break
                    if b"\r\n" not in buffer:
                        break
                    line, buffer = buffer.split(b"\r\n", 1)
                    if not line:
                        # Empty line signals end of chunked body
                        break
                break

            # Read chunk data
            while len(buffer) < chunk_size + 2:
                try:
                    chunk = await asyncio.wait_for(
                        self._reader.read(self.BUFFER_SIZE),
                        timeout=self._timeout,
                    )
                    if not chunk:
                        raise IcapProtocolError("Connection closed before chunked body complete")
                    buffer += chunk
                except asyncio.TimeoutError:
                    raise IcapTimeoutError(
                        f"Timeout reading chunked body from {self.host}:{self.port}"
                    ) from None

            body += buffer[:chunk_size]

            # Validate total body size against maximum allowed
            validate_body_size(len(body), self._max_response_size)

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
            # Prepare preview data using shared utility
            preview = prepare_preview_data(
                body, preview_size, self._encode_chunked, self._encode_chunk_terminator
            )

            logger.debug(
                f"Sending preview: {preview_size} bytes, "
                f"remainder: {len(preview.remainder)} bytes, "
                f"complete in preview: {preview.is_complete}"
            )

            # Send request with preview
            self._writer.write(request + preview.preview_chunk)
            await asyncio.wait_for(self._writer.drain(), timeout=self._timeout)

            # Receive initial response (could be 100 Continue, 204, or 200)
            response = await self._receive_response()

            # If server responds with 100 Continue, send the rest of the body
            if response.status_code == 100:
                logger.debug("Received 100 Continue, sending remainder of body")

                # Send the remainder of the body
                if preview.remainder:
                    self._writer.write(self._encode_chunked(preview.remainder))

                # Send final zero-length chunk
                self._writer.write(self._encode_chunk_terminator())
                await asyncio.wait_for(self._writer.drain(), timeout=self._timeout)

                # Receive final response
                response = await self._receive_response()

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
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass  # Best effort cleanup
            self._writer = None
            self._reader = None
            raise IcapConnectionError(f"Connection error with {self.host}:{self.port}: {e}") from e
