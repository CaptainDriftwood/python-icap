from typing import Dict


class IcapResponse:
    """
    Represents an ICAP response.
    """

    def __init__(self, status_code: int, status_message: str, headers: Dict[str, str], body: bytes):
        """
        Initialize ICAP response.

        Args:
            status_code: ICAP status code (e.g., 200, 204)
            status_message: Status message (e.g., "OK", "No Content")
            headers: ICAP response headers
            body: Response body (may contain HTTP headers/body)
        """
        self.status_code = status_code
        self.status_message = status_message
        self.headers = headers
        self.body = body

    @property
    def is_success(self) -> bool:
        """Check if response indicates success."""
        return 200 <= self.status_code < 300

    @property
    def is_no_modification(self) -> bool:
        """Check if server returned 204 (no modification needed)."""
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
