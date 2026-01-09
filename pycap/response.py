from typing import Dict


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
        headers: Dictionary of ICAP response headers. May include:
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

    def __init__(self, status_code: int, status_message: str, headers: Dict[str, str], body: bytes):
        """
        Initialize ICAP response.

        Args:
            status_code: ICAP status code (e.g., 200, 204).
            status_message: Status message (e.g., "OK", "No Content").
            headers: ICAP response headers as a dictionary.
            body: Response body bytes (may contain modified HTTP response).
        """
        self.status_code = status_code
        self.status_message = status_message
        self.headers = headers
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

    @classmethod
    def parse(cls, data: bytes) -> "IcapResponse":
        """
        Parse ICAP response from raw bytes.

        Args:
            data: Raw response data

        Returns:
            IcapResponse object
        """
        # Split headers and body
        parts = data.split(b"\r\n\r\n", 1)
        header_section = parts[0].decode("utf-8", errors="ignore")
        body = parts[1] if len(parts) > 1 else b""

        # Parse status line
        lines = header_section.split("\r\n")
        status_line = lines[0]

        # Parse status line: ICAP/1.0 200 OK
        status_parts = status_line.split(" ", 2)
        if len(status_parts) < 3:
            raise ValueError(f"Invalid ICAP status line: {status_line}")

        status_code = int(status_parts[1])
        status_message = status_parts[2]

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        return cls(status_code, status_message, headers, body)

    def __repr__(self):
        return f"IcapResponse(status={self.status_code}, message='{self.status_message}')"
