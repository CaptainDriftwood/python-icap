from dataclasses import dataclass
from typing import Dict, Iterator, MutableMapping, Optional

__all__ = ["CaseInsensitiveDict", "EncapsulatedParts", "IcapResponse"]


@dataclass
class EncapsulatedParts:
    """
    Parsed representation of the ICAP Encapsulated header.

    The Encapsulated header indicates byte offsets of different parts of the
    encapsulated HTTP message within the ICAP response body. This is useful
    for understanding which parts of the HTTP message were modified.

    Attributes:
        req_hdr: Offset of the encapsulated HTTP request headers, or None if not present.
        req_body: Offset of the encapsulated HTTP request body, or None if not present.
        res_hdr: Offset of the encapsulated HTTP response headers, or None if not present.
        res_body: Offset of the encapsulated HTTP response body, or None if not present.
        null_body: Offset indicating no body follows, or None if not present.
        opt_body: Offset of OPTIONS response body, or None if not present.

    Example:
        >>> response.encapsulated.res_hdr
        0
        >>> response.encapsulated.res_body
        128
    """

    req_hdr: Optional[int] = None
    req_body: Optional[int] = None
    res_hdr: Optional[int] = None
    res_body: Optional[int] = None
    null_body: Optional[int] = None
    opt_body: Optional[int] = None

    @classmethod
    def parse(cls, header_value: str) -> "EncapsulatedParts":
        """
        Parse an Encapsulated header value.

        Args:
            header_value: The Encapsulated header value (e.g., "res-hdr=0, res-body=128")

        Returns:
            EncapsulatedParts with parsed offsets.

        Example:
            >>> EncapsulatedParts.parse("req-hdr=0, res-hdr=45, res-body=128")
            EncapsulatedParts(req_hdr=0, req_body=None, res_hdr=45, res_body=128, ...)
        """
        parts = cls()
        for segment in header_value.split(","):
            segment = segment.strip()
            if "=" in segment:
                name, value = segment.split("=", 1)
                name = name.strip().replace("-", "_")
                try:
                    offset = int(value.strip())
                    if hasattr(parts, name):
                        setattr(parts, name, offset)
                except ValueError:
                    pass  # Skip invalid offset values
        return parts


class CaseInsensitiveDict(MutableMapping[str, str]):
    """
    A dictionary with case-insensitive string keys.

    Per RFC 3507, ICAP header field names are case-insensitive, following HTTP/1.1
    conventions (RFC 7230 Section 3.2). This dictionary allows header lookups
    regardless of case while preserving the original case for display.

    Example:
        >>> headers = CaseInsensitiveDict()
        >>> headers["X-Virus-ID"] = "EICAR"
        >>> headers["x-virus-id"]
        'EICAR'
        >>> headers["X-VIRUS-ID"]
        'EICAR'
    """

    def __init__(self, data: Optional[Dict[str, str]] = None) -> None:
        # Store as {lowercase_key: (original_key, value)}
        self._store: Dict[str, tuple[str, str]] = {}
        if data:
            for key, value in data.items():
                self[key] = value

    def __setitem__(self, key: str, value: str) -> None:
        # Store with lowercase key, but preserve original case
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key: str) -> str:
        return self._store[key.lower()][1]

    def __delitem__(self, key: str) -> None:
        del self._store[key.lower()]

    def __iter__(self) -> Iterator[str]:
        # Iterate over original-case keys
        return (original_key for original_key, _ in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key.lower() in self._store

    def __repr__(self) -> str:
        items = ", ".join(f"{k!r}: {v!r}" for k, v in self.items())
        return f"CaseInsensitiveDict({{{items}}})"


class IcapResponse:
    """
    Represents an ICAP response from an ICAP server.

    This class encapsulates the result of an ICAP request (OPTIONS, REQMOD, or RESPMOD).
    For virus scanning use cases, the most important property is `is_no_modification`,
    which indicates the scanned content is clean.

    Attributes:
        status_code: ICAP status code. Common values:
            - 100: Continue (server wants more data after preview)
            - 200: OK (content was modified or virus detected)
            - 204: No Modification (content is clean, no changes needed)
            - 400: Bad Request
            - 404: Service Not Found
            - 500+: Server Error
        status_message: Human-readable status message (e.g., "OK", "No Content").
        headers: Case-insensitive dictionary of ICAP response headers (per RFC 3507).
            Lookups work regardless of case: headers["X-Virus-ID"] == headers["x-virus-id"].
            May include:
            - "X-Virus-ID": Name of detected virus (when virus found)
            - "X-Infection-Found": Details about the infection
            - "ISTag": Server state tag for caching
            - "Encapsulated": Byte offsets of encapsulated HTTP message parts
        body: Response body bytes. For RESPMOD responses with modifications,
            this contains the modified HTTP response. Empty for 204 responses.

    Example:
        >>> response = client.scan_file("/path/to/file.pdf")
        >>> if response.is_no_modification:
        ...     print("File is clean")
        ... else:
        ...     virus = response.headers.get("X-Virus-ID", "Unknown threat")
        ...     print(f"Threat detected: {virus}")
    """

    def __init__(
        self,
        status_code: int,
        status_message: str,
        headers: MutableMapping[str, str],
        body: bytes,
    ):
        """
        Initialize ICAP response.

        Args:
            status_code: ICAP status code (e.g., 200, 204).
            status_message: Status message (e.g., "OK", "No Content").
            headers: ICAP response headers. Will be converted to case-insensitive
                dictionary if not already (per RFC 3507, header names are case-insensitive).
            body: Response body bytes (may contain modified HTTP response).
        """
        self.status_code = status_code
        self.status_message = status_message
        # Ensure headers are case-insensitive per RFC 3507
        if isinstance(headers, CaseInsensitiveDict):
            self.headers = headers
        else:
            self.headers = CaseInsensitiveDict(dict(headers))
        self.body = body

    @property
    def is_success(self) -> bool:
        """
        Check if response indicates success (2xx status code).

        Returns True for both 200 (OK, content modified) and 204 (No Modification).
        For virus scanning, you typically want to check `is_no_modification` instead,
        as a 200 response often indicates a threat was detected and the content
        was modified (e.g., replaced with an error page).

        Returns:
            True if status code is in the 200-299 range.

        Example:
            >>> response = client.options("avscan")
            >>> if response.is_success:
            ...     print("Server responded successfully")
        """
        return 200 <= self.status_code < 300

    @property
    def is_no_modification(self) -> bool:
        """
        Check if server returned 204 No Modification.

        This is the primary method to check if scanned content is clean.
        A 204 response means the ICAP server inspected the content and
        determined no modification is needed (i.e., no threats detected).

        Returns:
            True if status code is 204, indicating content is clean/safe.

        Example:
            >>> response = client.scan_bytes(content)
            >>> if response.is_no_modification:
            ...     print("Content is clean")
            ... else:
            ...     # Could be 200 (threat found) or error
            ...     print(f"Status: {response.status_code}")
        """
        return self.status_code == 204

    @property
    def encapsulated(self) -> Optional[EncapsulatedParts]:
        """
        Parse and return the Encapsulated header parts.

        The Encapsulated header indicates byte offsets of HTTP message parts
        within the ICAP response body. This helps identify which parts were
        modified by the ICAP server.

        Returns:
            EncapsulatedParts with parsed offsets, or None if no Encapsulated header.

        Example:
            >>> response = client.respmod("avscan", http_request, http_response)
            >>> if response.encapsulated and response.encapsulated.res_body is not None:
            ...     body_offset = response.encapsulated.res_body
            ...     modified_body = response.body[body_offset:]
        """
        enc_header = self.headers.get("Encapsulated")
        if enc_header is None:
            return None
        return EncapsulatedParts.parse(enc_header)

    @classmethod
    def parse(cls, data: bytes) -> "IcapResponse":
        """
        Parse ICAP response from raw bytes.

        Args:
            data: Raw response data

        Returns:
            IcapResponse object
        """
        parts = data.split(b"\r\n\r\n", 1)
        header_section = parts[0].decode("utf-8", errors="ignore")
        body = parts[1] if len(parts) > 1 else b""

        lines = header_section.split("\r\n")
        status_line = lines[0]

        # Expected format: ICAP/1.0 200 OK
        status_parts = status_line.split(" ", 2)
        if len(status_parts) < 3:
            raise ValueError(f"Invalid ICAP status line: {status_line}")

        status_code = int(status_parts[1])

        # Validate status code is in valid HTTP/ICAP range (100-599)
        if not (100 <= status_code <= 599):
            raise ValueError(f"Invalid ICAP status code: {status_code} (must be 100-599)")
        status_message = status_parts[2]

        headers: CaseInsensitiveDict = CaseInsensitiveDict()
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                # Handle duplicate headers by combining with comma (RFC 7230 Section 3.2.2)
                if key in headers:
                    headers[key] = headers[key] + ", " + value
                else:
                    headers[key] = value

        return cls(status_code, status_message, headers, body)

    def __repr__(self):
        return f"IcapResponse(status={self.status_code}, message='{self.status_message}')"
