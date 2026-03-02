"""Shared ICAP protocol constants and utilities.

This module contains protocol-level constants and request building logic
shared between the sync IcapClient and async AsyncIcapClient.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional

from .exception import IcapProtocolError

# Characters that are invalid in header names (per RFC 7230)
# Header names must be tokens: 1*tchar where tchar excludes CTLs, separators
_INVALID_HEADER_NAME_CHARS = re.compile(r"[\x00-\x1f\x7f()<>@,;:\\\"/\[\]?={} \t]")

# Characters that are invalid in header values (control chars except HTAB)
# CRLF injection is the main concern - values must not contain CR or LF
_INVALID_HEADER_VALUE_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


class IcapProtocol:
    """Base class with shared ICAP protocol constants and utilities."""

    DEFAULT_PORT: int = 1344
    CRLF: str = "\r\n"
    ICAP_VERSION: str = "ICAP/1.0"
    BUFFER_SIZE: int = 8192
    USER_AGENT: str = "Python-ICAP-Client/1.0"

    @staticmethod
    def _validate_header(name: str, value: str) -> None:
        """Validate header name and value to prevent injection attacks.

        Args:
            name: Header name
            value: Header value

        Raises:
            ValueError: If header name or value contains invalid characters
        """
        if not name:
            raise ValueError("Header name cannot be empty")

        if _INVALID_HEADER_NAME_CHARS.search(name):
            raise ValueError(
                f"Invalid header name {name!r}: contains invalid characters "
                "(control characters, spaces, or separators not allowed)"
            )

        if _INVALID_HEADER_VALUE_CHARS.search(value):
            raise ValueError(
                f"Invalid header value for {name!r}: contains control characters "
                "(CR, LF, and other control characters not allowed)"
            )

    def _build_request(self, request_line: str, headers: Dict[str, str]) -> bytes:
        """Build ICAP request from request line and headers.

        Args:
            request_line: The ICAP request line (e.g., "OPTIONS icap://... ICAP/1.0\\r\\n")
            headers: Dictionary of ICAP headers

        Returns:
            Encoded request bytes

        Raises:
            ValueError: If any header name or value contains invalid characters
        """
        request = request_line
        for key, value in headers.items():
            self._validate_header(key, value)
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


# =============================================================================
# Shared Protocol Utilities
# =============================================================================
# These functions contain pure protocol logic shared between sync and async
# clients. They perform no I/O operations.


@dataclass
class ResponseHeaders:
    """Parsed response header information."""

    content_length: int | None
    """Content-Length header value, or None if not present."""

    is_chunked: bool
    """True if Transfer-Encoding: chunked is present."""


@dataclass
class PreviewData:
    """Data prepared for preview mode transmission."""

    preview_chunk: bytes
    """Encoded preview chunk including terminator (with ieof if complete)."""

    remainder: bytes
    """Remaining body data to send after 100 Continue."""

    is_complete: bool
    """True if entire body fits in preview (no remainder needed)."""


def parse_response_headers(headers_str: str) -> ResponseHeaders:
    """Parse response headers to extract Content-Length and Transfer-Encoding.

    This function extracts the information needed to determine how to read
    the response body: by Content-Length, by chunked encoding, or no body.

    Args:
        headers_str: Raw headers string (decoded from bytes, excluding the
                     terminating CRLF CRLF)

    Returns:
        ResponseHeaders with content_length and is_chunked fields.

    Raises:
        IcapProtocolError: If Content-Length header has an invalid value.
    """
    content_length: int | None = None
    is_chunked = False

    for line in headers_str.split("\r\n")[1:]:  # Skip status line
        if ":" in line:
            key, value = line.split(":", 1)
            key_lower = key.strip().lower()
            value_stripped = value.strip().lower()

            if key_lower == "content-length":
                try:
                    content_length = int(value.strip())
                except ValueError:
                    raise IcapProtocolError(
                        f"Invalid Content-Length header: {value.strip()!r}"
                    ) from None
            elif key_lower == "transfer-encoding" and "chunked" in value_stripped:
                is_chunked = True

    return ResponseHeaders(content_length=content_length, is_chunked=is_chunked)


def parse_chunk_size(size_line: bytes, max_size: int) -> int:
    """Parse and validate a chunk size line from chunked transfer encoding.

    Per RFC 7230, chunk size is a hex number optionally followed by extensions
    after a semicolon. This function parses the size and validates it against
    the maximum allowed size.

    Args:
        size_line: Raw chunk size line (without trailing CRLF)
        max_size: Maximum allowed chunk size in bytes

    Returns:
        The parsed chunk size as an integer.

    Raises:
        IcapProtocolError: If the chunk size is invalid or exceeds max_size.
    """
    try:
        # Chunk size may have extensions after semicolon, ignore them
        chunk_size = int(size_line.split(b";")[0].strip(), 16)
    except ValueError:
        raise IcapProtocolError(f"Invalid chunk size in response: {size_line!r}") from None

    if chunk_size > max_size:
        raise IcapProtocolError(
            f"Chunk size ({chunk_size:,} bytes) exceeds maximum allowed size ({max_size:,} bytes)"
        )

    return chunk_size


def validate_body_size(current_size: int, max_size: int) -> None:
    """Validate that body size doesn't exceed maximum allowed.

    Args:
        current_size: Current accumulated body size in bytes
        max_size: Maximum allowed size in bytes

    Raises:
        IcapProtocolError: If current_size exceeds max_size.
    """
    if current_size > max_size:
        raise IcapProtocolError(
            f"Chunked response body ({current_size:,} bytes) exceeds "
            f"maximum allowed size ({max_size:,} bytes)"
        )


def validate_content_length(content_length: int, max_size: int) -> None:
    """Validate Content-Length against maximum allowed size.

    Args:
        content_length: Declared content length in bytes
        max_size: Maximum allowed size in bytes

    Raises:
        IcapProtocolError: If content_length exceeds max_size.
    """
    if content_length > max_size:
        raise IcapProtocolError(
            f"Response Content-Length ({content_length:,} bytes) exceeds "
            f"maximum allowed size ({max_size:,} bytes)"
        )


def prepare_preview_data(
    body: bytes,
    preview_size: int,
    encode_chunked: callable,
    encode_terminator: callable,
) -> PreviewData:
    """Prepare body data for preview mode transmission.

    Splits the body into preview and remainder portions, and encodes the
    preview chunk with appropriate terminator (ieof if complete).

    Per RFC 3507 Section 4.5, if the entire body fits within the preview,
    the zero-length chunk terminator should include the "ieof" extension
    to indicate no more data follows.

    Args:
        body: Full body content to be sent
        preview_size: Maximum bytes to include in preview
        encode_chunked: Function to encode data as a chunk (IcapProtocol._encode_chunked)
        encode_terminator: Function to get terminator (IcapProtocol._encode_chunk_terminator)

    Returns:
        PreviewData with encoded preview_chunk, remainder, and is_complete flag.
    """
    preview_data = body[:preview_size]
    remainder = body[preview_size:]
    is_complete = len(body) <= preview_size

    # Build the preview chunk
    preview_chunk = encode_chunked(preview_data)

    if is_complete:
        # Use ieof on zero-length chunk to indicate no more data
        preview_chunk += b"0; ieof\r\n\r\n"
    else:
        # Normal zero-length terminator for preview section
        preview_chunk += encode_terminator()

    return PreviewData(preview_chunk=preview_chunk, remainder=remainder, is_complete=is_complete)
