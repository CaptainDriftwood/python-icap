"""
Fluent builder for creating IcapResponse objects for testing.

This module provides IcapResponseBuilder, a convenient way to construct
IcapResponse objects for use in tests without needing to remember the
exact constructor arguments or ICAP protocol details.

Example:
    >>> from pytest_py_cap import IcapResponseBuilder
    >>>
    >>> # Build a clean response (204 No Modification)
    >>> clean = IcapResponseBuilder().clean().build()
    >>> clean.is_no_modification
    True
    >>>
    >>> # Build a virus detection response
    >>> virus = IcapResponseBuilder().virus("Trojan.Gen").build()
    >>> virus.headers["X-Virus-ID"]
    'Trojan.Gen'
    >>>
    >>> # Build a custom response
    >>> custom = (
    ...     IcapResponseBuilder()
    ...     .with_status(200, "OK")
    ...     .with_header("X-Custom", "value")
    ...     .build()
    ... )
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py_cap import IcapResponse


class IcapResponseBuilder:
    """
    Fluent builder for creating IcapResponse objects.

    Provides a convenient, chainable API for constructing test responses without
    memorizing constructor arguments or ICAP protocol specifics. Starts with
    default values for a 204 No Modification response.

    The builder supports two usage patterns:
        1. **Preset methods**: Use clean(), virus(), options(), or error() for
           common response types with sensible defaults.
        2. **Custom building**: Use with_status(), with_header(), with_headers(),
           and with_body() to construct arbitrary responses.

    Default State:
        - status_code: 204
        - status_message: "No Modification"
        - headers: {} (empty dict)
        - body: b"" (empty bytes)

    Preset Methods:
        clean(): Configure as 204 No Modification (safe content).
        virus(name): Configure as 200 OK with X-Virus-ID header.
        options(methods, preview): Configure as OPTIONS response.
        error(code, message): Configure as server error (default 500).
        continue_response(): Configure as 100 Continue (preview mode).

    Custom Methods:
        with_status(code, message): Set custom status code and message.
        with_header(key, value): Add a single header.
        with_headers(headers): Add multiple headers from dict.
        with_body(body): Set response body bytes.

    Finalization:
        build(): Create and return the IcapResponse object.

    Example - Clean response (content is safe):
        >>> response = IcapResponseBuilder().clean().build()
        >>> response.status_code
        204
        >>> response.is_no_modification
        True

    Example - Virus detected:
        >>> response = IcapResponseBuilder().virus("EICAR-Test").build()
        >>> response.status_code
        200
        >>> response.headers["X-Virus-ID"]
        'EICAR-Test'
        >>> response.headers["X-Infection-Found"]
        'Type=0; Resolution=2; Threat=EICAR-Test;'

    Example - OPTIONS response:
        >>> response = IcapResponseBuilder().options(methods=["RESPMOD"]).build()
        >>> response.headers["Methods"]
        'RESPMOD'
        >>> response.headers["Preview"]
        '1024'

    Example - Server error:
        >>> response = IcapResponseBuilder().error(503, "Service Unavailable").build()
        >>> response.status_code
        503
        >>> response.is_success
        False

    Example - Custom response with chaining:
        >>> response = (
        ...     IcapResponseBuilder()
        ...     .with_status(200, "OK")
        ...     .with_header("X-Custom-Header", "custom-value")
        ...     .with_header("ISTag", "server-tag-123")
        ...     .with_body(b"Modified content here")
        ...     .build()
        ... )

    Example - Using with MockIcapClient:
        >>> from pytest_py_cap import MockIcapClient, IcapResponseBuilder
        >>> client = MockIcapClient()
        >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
        >>> response = client.scan_bytes(b"malware")
        >>> assert not response.is_no_modification

    See Also:
        IcapResponse: The response object this builder creates.
        MockIcapClient: Use with on_options/on_respmod/on_reqmod to configure mocks.
    """

    def __init__(self) -> None:
        """
        Initialize the builder with default values for a clean response.

        Default state:
            - status_code: 204
            - status_message: "No Modification"
            - headers: {} (empty)
            - body: b"" (empty)
        """
        self._status_code: int = 204
        self._status_message: str = "No Modification"
        self._headers: dict[str, str] = {}
        self._body: bytes = b""

    def clean(self) -> IcapResponseBuilder:
        """
        Configure as 204 No Modification response.

        This indicates the scanned content is safe and doesn't need modification.
        This is the default state, so calling clean() is optional unless you
        need to reset after calling another preset method.

        Returns:
            Self for method chaining.

        Example:
            >>> response = IcapResponseBuilder().clean().build()
            >>> response.status_code
            204
            >>> response.is_no_modification
            True
        """
        self._status_code = 204
        self._status_message = "No Modification"
        return self

    def virus(self, name: str = "EICAR-Test-Signature") -> IcapResponseBuilder:
        """
        Configure as virus/threat detection response.

        Sets up a 200 OK response with X-Virus-ID and X-Infection-Found headers,
        which is the standard way ICAP servers report detected threats.

        Args:
            name: The virus/threat name to include in headers.
                  Default: "EICAR-Test-Signature" (standard test signature).

        Returns:
            Self for method chaining.

        Example:
            >>> response = IcapResponseBuilder().virus("Trojan.Generic").build()
            >>> response.status_code
            200
            >>> response.headers["X-Virus-ID"]
            'Trojan.Generic'
            >>> response.is_no_modification
            False
        """
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
        """
        Configure as OPTIONS response with server capabilities.

        Sets up a 200 OK response with headers describing what the ICAP server
        supports. Used when testing code that queries server capabilities.

        Args:
            methods: List of supported ICAP methods.
                     Default: ["RESPMOD", "REQMOD"]
            preview: Preview size in bytes the server accepts.
                     Default: 1024

        Returns:
            Self for method chaining.

        Headers set:
            - Methods: Comma-separated list of supported methods
            - Preview: Preview size in bytes
            - Transfer-Preview: "*" (all file types support preview)
            - Max-Connections: "100"

        Example:
            >>> response = IcapResponseBuilder().options().build()
            >>> response.headers["Methods"]
            'RESPMOD, REQMOD'
            >>> response.headers["Preview"]
            '1024'

        Example - Custom methods:
            >>> response = IcapResponseBuilder().options(methods=["RESPMOD"]).build()
            >>> response.headers["Methods"]
            'RESPMOD'
        """
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
        """
        Configure as server error response.

        Args:
            code: HTTP-style error code (default: 500).
                  Common values: 400, 404, 500, 502, 503, 505
            message: Human-readable error message.
                     Default: "Internal Server Error"

        Returns:
            Self for method chaining.

        Example:
            >>> response = IcapResponseBuilder().error().build()
            >>> response.status_code
            500
            >>> response.is_success
            False

        Example - Service unavailable:
            >>> response = IcapResponseBuilder().error(503, "Service Unavailable").build()
            >>> response.status_code
            503
        """
        self._status_code = code
        self._status_message = message
        return self

    def continue_response(self) -> IcapResponseBuilder:
        """
        Configure as 100 Continue response.

        This response is sent by the server during preview mode to request
        the full content after reviewing the preview bytes.

        Returns:
            Self for method chaining.

        Example:
            >>> response = IcapResponseBuilder().continue_response().build()
            >>> response.status_code
            100
            >>> response.status_message
            'Continue'
        """
        self._status_code = 100
        self._status_message = "Continue"
        return self

    def with_status(self, code: int, message: str) -> IcapResponseBuilder:
        """
        Set custom status code and message.

        Use this for status codes not covered by the preset methods.

        Args:
            code: ICAP status code (e.g., 200, 204, 400, 500).
            message: Human-readable status message.

        Returns:
            Self for method chaining.

        Example:
            >>> response = (
            ...     IcapResponseBuilder()
            ...     .with_status(418, "I'm a teapot")
            ...     .build()
            ... )
            >>> response.status_code
            418
        """
        self._status_code = code
        self._status_message = message
        return self

    def with_header(self, key: str, value: str) -> IcapResponseBuilder:
        """
        Add a single header to the response.

        Can be called multiple times to add multiple headers.

        Args:
            key: Header name (e.g., "X-Custom-Header", "ISTag").
            value: Header value.

        Returns:
            Self for method chaining.

        Example:
            >>> response = (
            ...     IcapResponseBuilder()
            ...     .clean()
            ...     .with_header("ISTag", "server-v1.0")
            ...     .with_header("X-Request-ID", "12345")
            ...     .build()
            ... )
            >>> response.headers["ISTag"]
            'server-v1.0'
        """
        self._headers[key] = value
        return self

    def with_headers(self, headers: dict[str, str]) -> IcapResponseBuilder:
        """
        Add multiple headers from a dictionary.

        Merges with existing headers; later values override earlier ones.

        Args:
            headers: Dictionary of header names to values.

        Returns:
            Self for method chaining.

        Example:
            >>> response = (
            ...     IcapResponseBuilder()
            ...     .clean()
            ...     .with_headers({
            ...         "ISTag": "server-v1.0",
            ...         "X-Request-ID": "12345",
            ...     })
            ...     .build()
            ... )
        """
        self._headers.update(headers)
        return self

    def with_body(self, body: bytes) -> IcapResponseBuilder:
        """
        Set the response body.

        For RESPMOD responses with modifications, this would contain the
        modified HTTP response. Usually empty for 204 responses.

        Args:
            body: Response body as bytes.

        Returns:
            Self for method chaining.

        Example:
            >>> response = (
            ...     IcapResponseBuilder()
            ...     .with_status(200, "OK")
            ...     .with_body(b"HTTP/1.1 403 Forbidden\\r\\n\\r\\nBlocked")
            ...     .build()
            ... )
            >>> response.body
            b'HTTP/1.1 403 Forbidden\\r\\n\\r\\nBlocked'
        """
        self._body = body
        return self

    def build(self) -> IcapResponse:
        """
        Build and return the IcapResponse object.

        This is the terminal method that creates the actual response object
        from the configured state. The builder can be reused after calling
        build() by calling configuration methods again.

        Returns:
            A new IcapResponse instance with the configured values.

        Example:
            >>> builder = IcapResponseBuilder()
            >>> clean = builder.clean().build()
            >>> virus = builder.virus().build()  # Reuse same builder
        """
        from py_cap import IcapResponse

        return IcapResponse(
            status_code=self._status_code,
            status_message=self._status_message,
            headers=self._headers.copy(),
            body=self._body,
        )
