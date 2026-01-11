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

    def _build_icap_headers(
        self,
        host: str,
        port: int,
        encapsulated: str,
        allow_204: bool = True,
    ) -> Dict[str, str]:
        """Build common ICAP headers.

        Args:
            host: ICAP server host
            port: ICAP server port
            encapsulated: Encapsulated header value
            allow_204: Whether to include Allow: 204 header

        Returns:
            Dictionary of ICAP headers
        """
        headers = {
            "Host": f"{host}:{port}",
            "User-Agent": self.USER_AGENT,
            "Encapsulated": encapsulated,
        }
        if allow_204:
            headers["Allow"] = "204"
        return headers

    def _calculate_respmod_encapsulated(
        self,
        http_request: Optional[bytes],
        http_response_headers: bytes,
    ) -> str:
        """Calculate the Encapsulated header value for RESPMOD.

        Args:
            http_request: HTTP request headers (optional)
            http_response_headers: HTTP response headers

        Returns:
            Encapsulated header value string
        """
        if http_request:
            req_hdr_len = len(http_request)
            res_hdr_offset = req_hdr_len
            res_body_offset = res_hdr_offset + len(http_response_headers)
            return f"req-hdr=0, res-hdr={res_hdr_offset}, res-body={res_body_offset}"
        else:
            return f"res-hdr=0, res-body={len(http_response_headers)}"

    def _calculate_reqmod_encapsulated(
        self,
        http_request: bytes,
        has_body: bool,
    ) -> str:
        """Calculate the Encapsulated header value for REQMOD.

        Args:
            http_request: HTTP request headers
            has_body: Whether there's a request body

        Returns:
            Encapsulated header value string
        """
        if has_body:
            return f"req-hdr=0, req-body={len(http_request)}"
        else:
            return f"req-hdr=0, null-body={len(http_request)}"

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
