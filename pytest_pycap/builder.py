"""Fluent builder for creating IcapResponse objects for testing."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pycap import IcapResponse


class IcapResponseBuilder:
    """
    Fluent builder for creating IcapResponse objects.

    Provides a convenient API for constructing test responses without
    memorizing constructor arguments.

    Example:
        # Clean response (204 No Modification)
        response = IcapResponseBuilder().clean().build()

        # Virus detected
        response = IcapResponseBuilder().virus("Trojan.Generic").build()

        # Custom response
        response = (
            IcapResponseBuilder()
            .with_status(200, "OK")
            .with_header("X-Custom", "value")
            .with_body(b"modified content")
            .build()
        )
    """

    def __init__(self) -> None:
        self._status_code: int = 204
        self._status_message: str = "No Modification"
        self._headers: dict[str, str] = {}
        self._body: bytes = b""

    def clean(self) -> IcapResponseBuilder:
        """Configure as 204 No Modification (content is safe)."""
        self._status_code = 204
        self._status_message = "No Modification"
        return self

    def virus(self, name: str = "EICAR-Test-Signature") -> IcapResponseBuilder:
        """Configure as virus detected with X-Virus-ID header."""
        self._status_code = 200
        self._status_message = "OK"
        self._headers["X-Virus-ID"] = name
        self._headers["X-Infection-Found"] = f"Type=0; Resolution=2; Threat={name};"
        return self

    def options(
        self,
        methods: list[str] | None = None,
        preview: int = 1024,
    ) -> IcapResponseBuilder:
        """Configure as OPTIONS response with server capabilities."""
        self._status_code = 200
        self._status_message = "OK"
        self._headers["Methods"] = ", ".join(methods or ["RESPMOD", "REQMOD"])
        self._headers["Preview"] = str(preview)
        self._headers["Transfer-Preview"] = "*"
        self._headers["Max-Connections"] = "100"
        return self

    def error(
        self,
        code: int = 500,
        message: str = "Internal Server Error",
    ) -> IcapResponseBuilder:
        """Configure as server error."""
        self._status_code = code
        self._status_message = message
        return self

    def continue_response(self) -> IcapResponseBuilder:
        """Configure as 100 Continue (for preview mode)."""
        self._status_code = 100
        self._status_message = "Continue"
        return self

    def with_status(self, code: int, message: str) -> IcapResponseBuilder:
        """Set custom status code and message."""
        self._status_code = code
        self._status_message = message
        return self

    def with_header(self, key: str, value: str) -> IcapResponseBuilder:
        """Add a custom header."""
        self._headers[key] = value
        return self

    def with_headers(self, headers: dict[str, str]) -> IcapResponseBuilder:
        """Add multiple headers."""
        self._headers.update(headers)
        return self

    def with_body(self, body: bytes) -> IcapResponseBuilder:
        """Set response body."""
        self._body = body
        return self

    def build(self) -> IcapResponse:
        """Build the IcapResponse object."""
        from pycap import IcapResponse

        return IcapResponse(
            status_code=self._status_code,
            status_message=self._status_message,
            headers=self._headers.copy(),
            body=self._body,
        )
