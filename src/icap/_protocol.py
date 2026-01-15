"""Shared ICAP protocol constants and utilities.

This module contains protocol-level constants and request building logic
shared between the sync IcapClient and async AsyncIcapClient.
"""

from typing import Dict, Optional


class IcapProtocol:
    """Base class with shared ICAP protocol constants and utilities."""

    DEFAULT_PORT: int = 1344
    CRLF: str = "\r\n"
    ICAP_VERSION: str = "ICAP/1.0"
    BUFFER_SIZE: int = 8192
    USER_AGENT: str = "Python-ICAP-Client/1.0"

    def _build_request(self, request_line: str, headers: Dict[str, str]) -> bytes:
        """Build ICAP request from request line and headers.

        Args:
            request_line: The ICAP request line (e.g., "OPTIONS icap://... ICAP/1.0\\r\\n")
            headers: Dictionary of ICAP headers

        Returns:
            Encoded request bytes
        """
        request = request_line
        for key, value in headers.items():
            request += f"{key}: {value}{self.CRLF}"
        request += self.CRLF
        return request.encode("utf-8")

    def _build_http_request_header(self, filename: Optional[str]) -> bytes:
        """Build encapsulated HTTP request header for file scanning.

        Args:
            filename: Optional filename to include in the request path

        Returns:
            HTTP request header bytes
        """
        resource = f"/{filename}" if filename else "/scan"
        return f"GET {resource} HTTP/1.1\r\nHost: file-scan\r\n\r\n".encode()

    def _build_http_response_header(self, content_length: int) -> bytes:
        """Build encapsulated HTTP response header for file scanning.

        Args:
            content_length: Length of the content being scanned

        Returns:
            HTTP response header bytes
        """
        return (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {content_length}\r\n"
            f"\r\n"
        ).encode()

    def _build_http_response_header_chunked(self) -> bytes:
        """Build encapsulated HTTP response header for chunked transfer.

        Returns:
            HTTP response header bytes with chunked transfer encoding
        """
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )

    @staticmethod
    def _encode_chunked(data: bytes) -> bytes:
        """Encode data as a single HTTP chunk.

        Args:
            data: Data to encode

        Returns:
            Chunk-encoded bytes including size header and trailing CRLF
        """
        if not data:
            return b""
        chunk_size = f"{len(data):X}\r\n"
        return chunk_size.encode() + data + b"\r\n"

    @staticmethod
    def _encode_chunk_terminator() -> bytes:
        """Return the chunk terminator sequence.

        Returns:
            Zero-length chunk terminator bytes
        """
        return b"0\r\n\r\n"
