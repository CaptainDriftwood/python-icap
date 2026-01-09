"""
Mock ICAP clients for testing without network I/O.

This module provides mock implementations of IcapClient and AsyncIcapClient
that can be used in tests without requiring a real ICAP server. The mocks
support configurable responses and call recording for assertions.

Classes:
    MockCall: Dataclass recording details of a single method call.
    MockIcapClient: Synchronous mock implementing the full IcapClient interface.
    MockAsyncIcapClient: Asynchronous mock implementing the AsyncIcapClient interface.

Example:
    >>> from pytest_pycap import MockIcapClient, IcapResponseBuilder
    >>>
    >>> # Create mock with default clean responses
    >>> client = MockIcapClient()
    >>> response = client.scan_bytes(b"content")
    >>> assert response.is_no_modification
    >>>
    >>> # Configure to return virus detection
    >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
    >>> response = client.scan_bytes(b"malware")
    >>> assert not response.is_no_modification
    >>>
    >>> # Verify calls were made
    >>> client.assert_called("scan_bytes", times=2)
"""

from __future__ import annotations

import inspect
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Protocol

from .builder import IcapResponseBuilder

if TYPE_CHECKING:
    from pycap import IcapResponse


class ResponseCallback(Protocol):
    """
    Protocol for synchronous response callbacks.

    Callbacks receive the request context and return an IcapResponse.
    Use this for dynamic response generation based on content, filename,
    or service name.

    The callback signature is flexible:
        - Required: `data` (bytes) - the content being scanned
        - Optional keyword arguments: `service`, `filename`, and others

    Example signatures (all valid):
        >>> def simple_callback(data: bytes, **kwargs) -> IcapResponse: ...
        >>> def detailed_callback(
        ...     data: bytes,
        ...     *,
        ...     service: str,
        ...     filename: str | None,
        ...     **kwargs
        ... ) -> IcapResponse: ...

    Example:
        >>> def eicar_detector(data: bytes, **kwargs) -> IcapResponse:
        ...     if b"EICAR" in data:
        ...         return IcapResponseBuilder().virus("EICAR-Test").build()
        ...     return IcapResponseBuilder().clean().build()
        >>>
        >>> client = MockIcapClient()
        >>> client.on_respmod(callback=eicar_detector)

    See Also:
        AsyncResponseCallback: Async version for MockAsyncIcapClient.
        MockIcapClient.on_respmod: Configure callbacks for scan methods.
    """

    def __call__(
        self,
        data: bytes,
        *,
        service: str,
        filename: str | None = None,
        **kwargs: Any,
    ) -> IcapResponse: ...


class AsyncResponseCallback(Protocol):
    """
    Protocol for asynchronous response callbacks.

    Async version of ResponseCallback for use with MockAsyncIcapClient.
    Callbacks receive the request context and return an IcapResponse.

    Note: MockAsyncIcapClient also accepts synchronous callbacks for
    convenience - they will be called directly without awaiting.

    Example:
        >>> async def async_scanner(data: bytes, **kwargs) -> IcapResponse:
        ...     # Can perform async operations if needed
        ...     if b"EICAR" in data:
        ...         return IcapResponseBuilder().virus("EICAR-Test").build()
        ...     return IcapResponseBuilder().clean().build()
        >>>
        >>> client = MockAsyncIcapClient()
        >>> client.on_respmod(callback=async_scanner)

    See Also:
        ResponseCallback: Sync version for MockIcapClient.
        MockAsyncIcapClient.on_respmod: Configure callbacks for scan methods.
    """

    async def __call__(
        self,
        data: bytes,
        *,
        service: str,
        filename: str | None = None,
        **kwargs: Any,
    ) -> IcapResponse: ...


@dataclass
class ResponseMatcher:
    """
    A rule that matches scan calls and returns a specific response.

    ResponseMatcher provides declarative conditional responses based on
    service name, filename, or content. Matchers are checked in registration
    order; the first match wins.

    Attributes:
        service: Exact service name to match (e.g., "avscan").
        filename: Exact filename to match (e.g., "malware.exe").
        filename_pattern: Compiled regex pattern to match against filename.
        data_contains: Bytes that must be present in the scanned content.
        response: The IcapResponse to return when this matcher matches.
        times: Maximum number of times this matcher can be used (None = unlimited).

    Matching Logic:
        All specified criteria must match (AND logic). Unspecified criteria
        (None values) are ignored. For example:

        - `service="avscan"` matches any call with service="avscan"
        - `service="avscan", filename="test.exe"` requires both to match
        - `data_contains=b"EICAR"` matches any content containing those bytes

    Example:
        >>> # Create a matcher that triggers on .exe files
        >>> matcher = ResponseMatcher(
        ...     filename_pattern=re.compile(r".*\\.exe$"),
        ...     response=IcapResponseBuilder().virus("Blocked.Exe").build(),
        ... )
        >>> matcher.matches(service="avscan", filename="test.exe", data=b"content")
        True
        >>> matcher.matches(service="avscan", filename="test.pdf", data=b"content")
        False

    See Also:
        MatcherBuilder: Fluent API for creating matchers via when().
        MockIcapClient.when: Register matchers on the mock client.
    """

    service: str | None = None
    filename: str | None = None
    filename_pattern: re.Pattern[str] | None = None
    data_contains: bytes | None = None
    response: IcapResponse | None = None
    times: int | None = None
    _match_count: int = field(default=0, repr=False)

    def matches(self, **kwargs: Any) -> bool:
        """
        Check if this matcher applies to the given call kwargs.

        All specified criteria must match (AND logic). Criteria that are None
        are not checked.

        Args:
            **kwargs: Call arguments including data, service, filename, etc.

        Returns:
            True if all specified criteria match, False otherwise.
        """
        # Check service match
        if self.service is not None:
            if kwargs.get("service") != self.service:
                return False

        # Check exact filename match
        if self.filename is not None:
            if kwargs.get("filename") != self.filename:
                return False

        # Check filename pattern match
        if self.filename_pattern is not None:
            filename = kwargs.get("filename")
            if filename is None or not self.filename_pattern.match(filename):
                return False

        # Check data contains
        if self.data_contains is not None:
            data = kwargs.get("data", b"")
            if self.data_contains not in data:
                return False

        return True

    def consume(self) -> IcapResponse:
        """
        Return the response and increment the match count.

        Returns:
            The configured IcapResponse.

        Raises:
            ValueError: If no response is configured.
        """
        if self.response is None:
            raise ValueError("No response configured for this matcher")
        self._match_count += 1
        return self.response

    def is_exhausted(self) -> bool:
        """
        Check if this matcher has reached its usage limit.

        Returns:
            True if times limit is set and has been reached, False otherwise.
        """
        if self.times is None:
            return False
        return self._match_count >= self.times


class MatcherBuilder:
    """
    Fluent builder for creating and registering ResponseMatchers.

    MatcherBuilder provides a readable, chainable API for configuring
    conditional responses. Created via MockIcapClient.when(), it collects
    match criteria and registers the matcher when respond() is called.

    Example - Simple filename matching:
        >>> client = MockIcapClient()
        >>> client.when(filename="malware.exe").respond(
        ...     IcapResponseBuilder().virus("Known.Malware").build()
        ... )

    Example - Pattern matching with regex:
        >>> client.when(filename_matches=r".*\\.exe$").respond(
        ...     IcapResponseBuilder().virus("Policy.BlockedExecutable").build()
        ... )

    Example - Content-based matching:
        >>> client.when(data_contains=b"EICAR").respond(
        ...     IcapResponseBuilder().virus("EICAR-Test").build()
        ... )

    Example - Combined criteria (AND logic):
        >>> client.when(
        ...     service="avscan",
        ...     filename_matches=r".*\\.docx$",
        ...     data_contains=b"PK\\x03\\x04",  # ZIP header (Office files are ZIPs)
        ... ).respond(
        ...     IcapResponseBuilder().virus("Macro.Suspicious").build()
        ... )

    Example - Limited use matcher:
        >>> client.when(data_contains=b"bad").respond(
        ...     IcapResponseBuilder().virus().build(),
        ...     times=2,  # Only match first 2 times
        ... )

    See Also:
        MockIcapClient.when: Entry point for creating matchers.
        ResponseMatcher: The underlying matcher dataclass.
    """

    def __init__(
        self,
        client: MockIcapClient,
        *,
        service: str | None = None,
        filename: str | None = None,
        filename_matches: str | None = None,
        data_contains: bytes | None = None,
    ) -> None:
        """
        Initialize the builder with match criteria.

        This constructor is not called directly; use MockIcapClient.when() instead.

        Args:
            client: The mock client to register the matcher with.
            service: Exact service name to match.
            filename: Exact filename to match.
            filename_matches: Regex pattern string to match against filename.
            data_contains: Bytes that must be present in scanned content.
        """
        self._client = client
        self._service = service
        self._filename = filename
        self._filename_pattern = re.compile(filename_matches) if filename_matches else None
        self._data_contains = data_contains

    def respond(
        self,
        response: IcapResponse,
        *,
        times: int | None = None,
    ) -> MockIcapClient:
        """
        Register this matcher with the specified response.

        Creates a ResponseMatcher from the configured criteria and registers
        it with the client. Matchers are checked in registration order.

        Args:
            response: The IcapResponse to return when this matcher matches.
            times: Maximum number of times this matcher can be used.
                   None means unlimited (default).

        Returns:
            The MockIcapClient for method chaining.

        Example:
            >>> client.when(filename="test.exe").respond(
            ...     IcapResponseBuilder().virus().build()
            ... ).when(filename="safe.txt").respond(
            ...     IcapResponseBuilder().clean().build()
            ... )
        """
        matcher = ResponseMatcher(
            service=self._service,
            filename=self._filename,
            filename_pattern=self._filename_pattern,
            data_contains=self._data_contains,
            response=response,
            times=times,
        )
        self._client._matchers.append(matcher)
        return self._client


class MockResponseExhaustedError(Exception):
    """
    Raised when all queued mock responses have been consumed.

    This error indicates that more method calls were made than responses
    were configured. Configure additional responses or use a callback
    for dynamic response generation.

    Example:
        >>> client = MockIcapClient()
        >>> client.on_respmod(
        ...     IcapResponseBuilder().clean().build(),
        ...     IcapResponseBuilder().virus().build(),
        ... )
        >>> client.scan_bytes(b"file1")  # Returns clean
        >>> client.scan_bytes(b"file2")  # Returns virus
        >>> client.scan_bytes(b"file3")  # Raises MockResponseExhaustedError
    """

    pass


@dataclass
class MockCall:
    """
    Record of a single method call on a MockIcapClient.

    MockCall instances are created automatically when methods are called on
    the mock client and stored in the `calls` list for later inspection.

    Attributes:
        method: Name of the method that was called (e.g., "scan_bytes", "options").
        timestamp: Unix timestamp when the call was made (from time.time()).
        kwargs: Dictionary of keyword arguments passed to the method. The keys
            depend on the method called:
            - options: {"service": str}
            - respmod: {"service": str, "http_request": bytes, "http_response": bytes,
                        "headers": dict|None, "preview": int|None}
            - reqmod: {"service": str, "http_request": bytes, "http_body": bytes|None,
                       "headers": dict|None}
            - scan_bytes: {"data": bytes, "service": str, "filename": str|None}
            - scan_file: {"filepath": str, "service": str, "data": bytes}
            - scan_stream (sync): {"data": bytes, "service": str, "filename": str|None,
                                   "chunk_size": int}
            - scan_stream (async): {"data": bytes, "service": str, "filename": str|None}
              Note: async scan_stream doesn't have chunk_size (matches AsyncIcapClient API)

    Example:
        >>> client = MockIcapClient()
        >>> client.scan_bytes(b"test", filename="test.txt")
        >>> call = client.calls[0]
        >>> call.method
        'scan_bytes'
        >>> call.kwargs["data"]
        b'test'
        >>> call.kwargs["filename"]
        'test.txt'
    """

    method: str
    timestamp: float
    kwargs: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        args_str = ", ".join(f"{k}={v!r}" for k, v in self.kwargs.items())
        return f"MockCall({self.method}({args_str}))"


class MockIcapClient:
    """
    Mock ICAP client for testing without network I/O.

    Implements the full IcapClient interface with configurable responses
    and call recording for assertions. By default, all methods return clean/success
    responses (204 No Modification for scans, 200 OK for OPTIONS).

    The mock provides three main capabilities:
        1. **Response Configuration**: Set what responses methods should return
        2. **Exception Injection**: Make methods raise specific exceptions
        3. **Call Recording**: Track all method calls for assertions

    Attributes:
        host: Mock server hostname (default: "mock-icap-server").
        port: Mock server port (default: 1344).
        is_connected: Whether connect() has been called.
        calls: List of MockCall objects recording all method invocations.

    Configuration Methods:
        on_options(response, raises): Configure OPTIONS method behavior.
        on_respmod(response, raises): Configure RESPMOD and scan_* methods.
        on_reqmod(response, raises): Configure REQMOD method behavior.
        on_any(response, raises): Configure all methods at once.

    Assertion Methods:
        assert_called(method, times): Assert a method was called.
        assert_not_called(method): Assert a method was not called.
        assert_scanned(data): Assert specific bytes were scanned.
        reset_calls(): Clear call history for fresh assertions.

    IcapClient Interface:
        connect(): Simulates connection (sets is_connected=True).
        disconnect(): Simulates disconnection (sets is_connected=False).
        options(service): Returns configured OPTIONS response.
        respmod(service, http_request, http_response, ...): Returns RESPMOD response.
        reqmod(service, http_request, ...): Returns REQMOD response.
        scan_bytes(data, service, filename): High-level scan, uses RESPMOD response.
        scan_file(filepath, service): Reads file and scans, uses RESPMOD response.
        scan_stream(stream, service, filename): Reads stream and scans.

    Example - Basic usage:
        >>> client = MockIcapClient()
        >>> response = client.scan_bytes(b"safe content")
        >>> assert response.is_no_modification  # Default is clean
        >>> client.assert_called("scan_bytes", times=1)

    Example - Configure virus detection:
        >>> client = MockIcapClient()
        >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
        >>> response = client.scan_bytes(b"malware")
        >>> assert not response.is_no_modification
        >>> assert response.headers["X-Virus-ID"] == "Trojan.Gen"

    Example - Simulate timeout error:
        >>> from pycap.exception import IcapTimeoutError
        >>> client = MockIcapClient()
        >>> client.on_any(raises=IcapTimeoutError("Connection timed out"))
        >>> client.scan_bytes(b"content")  # Raises IcapTimeoutError

    Example - Different responses per method:
        >>> client = MockIcapClient()
        >>> client.on_options(IcapResponseBuilder().options().build())
        >>> client.on_respmod(IcapResponseBuilder().virus().build())
        >>> client.options("avscan").is_success  # True
        >>> client.scan_bytes(b"data").is_no_modification  # False (virus)

    Example - Context manager:
        >>> with MockIcapClient() as client:
        ...     response = client.scan_file("/path/to/file.txt")
        ...     assert response.is_no_modification

    Example - Inspect call history:
        >>> client = MockIcapClient()
        >>> client.scan_bytes(b"test", filename="test.txt", service="avscan")
        >>> call = client.calls[0]
        >>> call.method  # "scan_bytes"
        >>> call.kwargs["data"]  # b"test"
        >>> call.kwargs["filename"]  # "test.txt"

    See Also:
        MockAsyncIcapClient: Async version with same API but awaitable methods.
        IcapResponseBuilder: Fluent builder for creating test responses.
        MockCall: Dataclass representing a recorded method call.
    """

    def __init__(
        self,
        host: str = "mock-icap-server",
        port: int = 1344,
    ) -> None:
        """
        Initialize the mock ICAP client.

        Args:
            host: Mock server hostname (default: "mock-icap-server").
                  This value is stored but not used for actual connections.
            port: Mock server port (default: 1344).
                  This value is stored but not used for actual connections.
        """
        self._host = host
        self._port = port
        self._connected = False
        self._calls: list[MockCall] = []

        # Response queues for sequential responses (Phase 1)
        self._response_queues: dict[str, deque[IcapResponse | Exception]] = {
            "options": deque(),
            "respmod": deque(),
            "reqmod": deque(),
        }

        # Track whether queue mode is active for each method
        # When True and queue is empty, raises MockResponseExhaustedError
        self._queue_active: dict[str, bool] = {
            "options": False,
            "respmod": False,
            "reqmod": False,
        }

        # Default responses (clean/success) - used when queue mode is not active
        self._options_response: IcapResponse | Exception = IcapResponseBuilder().options().build()
        self._respmod_response: IcapResponse | Exception = IcapResponseBuilder().clean().build()
        self._reqmod_response: IcapResponse | Exception = IcapResponseBuilder().clean().build()

        # Callbacks for dynamic response generation (Phase 2)
        self._callbacks: dict[str, ResponseCallback | AsyncResponseCallback | None] = {
            "options": None,
            "respmod": None,
            "reqmod": None,
        }

        # Content matchers for declarative conditional responses (Phase 3)
        self._matchers: list[ResponseMatcher] = []

    # === Configuration API ===

    def on_options(
        self,
        *responses: IcapResponse | Exception,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure what the OPTIONS method returns.

        Supports three usage patterns:
            1. **Single response**: Pass one response that all calls will return.
            2. **Response sequence**: Pass multiple responses that are consumed
               in order. When exhausted, raises MockResponseExhaustedError.
            3. **Exception injection**: Use raises= to make all calls raise.

        Args:
            *responses: One or more IcapResponse objects (or Exceptions).
                        If multiple provided, they form a queue consumed in order.
            raises: Exception to raise on all calls. Takes precedence over responses.

        Returns:
            Self for method chaining.

        Raises:
            MockResponseExhaustedError: When all queued responses are consumed
                and another call is made.

        Example - Single response:
            >>> client = MockIcapClient()
            >>> client.on_options(IcapResponseBuilder().options(methods=["RESPMOD"]).build())
            >>> response = client.options("avscan")
            >>> response.headers["Methods"]
            'RESPMOD'

        Example - Response sequence:
            >>> client = MockIcapClient()
            >>> client.on_options(
            ...     IcapResponseBuilder().options(methods=["RESPMOD"]).build(),
            ...     IcapResponseBuilder().error(503, "Service Unavailable").build(),
            ... )
            >>> client.options("avscan").is_success  # True (first response)
            >>> client.options("avscan").is_success  # False (503 error)

        Example - Raise exception:
            >>> client.on_options(raises=IcapConnectionError("Server unavailable"))

        See Also:
            reset_responses: Clear queued responses without clearing call history.
            on_respmod: Configure RESPMOD method responses.
            on_reqmod: Configure REQMOD method responses.
        """
        if raises is not None:
            self._response_queues["options"].clear()
            self._queue_active["options"] = False
            self._options_response = raises
        elif len(responses) == 1:
            self._response_queues["options"].clear()
            self._queue_active["options"] = False
            self._options_response = responses[0]
        elif len(responses) > 1:
            self._response_queues["options"].clear()
            self._response_queues["options"].extend(responses)
            self._queue_active["options"] = True
        return self

    def on_respmod(
        self,
        *responses: IcapResponse | Exception,
        raises: Exception | None = None,
        callback: ResponseCallback | None = None,
    ) -> MockIcapClient:
        """
        Configure what RESPMOD and scan methods return.

        This affects respmod(), scan_bytes(), scan_file(), and scan_stream()
        since the scan_* methods use RESPMOD internally.

        Supports four usage patterns:
            1. **Single response**: Pass one response that all calls will return.
            2. **Response sequence**: Pass multiple responses that are consumed
               in order. When exhausted, raises MockResponseExhaustedError.
            3. **Exception injection**: Use raises= to make all calls raise.
            4. **Callback**: Use callback= for dynamic response generation.

        Args:
            *responses: One or more IcapResponse objects (or Exceptions).
                        If multiple provided, they form a queue consumed in order.
            raises: Exception to raise on all calls. Takes precedence over responses.
            callback: Function called with (data, service=, filename=, **kwargs)
                      that returns an IcapResponse. Used for dynamic responses.
                      Takes precedence over responses and raises.

        Returns:
            Self for method chaining.

        Raises:
            MockResponseExhaustedError: When all queued responses are consumed
                and another call is made.

        Example - Single response (all scans return same result):
            >>> client = MockIcapClient()
            >>> client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
            >>> response = client.scan_bytes(b"content")
            >>> assert not response.is_no_modification

        Example - Response sequence (consumed in order):
            >>> client = MockIcapClient()
            >>> client.on_respmod(
            ...     IcapResponseBuilder().clean().build(),
            ...     IcapResponseBuilder().virus("Trojan.Gen").build(),
            ... )
            >>> client.scan_bytes(b"file1").is_no_modification  # True (clean)
            >>> client.scan_bytes(b"file2").is_no_modification  # False (virus)

        Example - Exception injection:
            >>> client.on_respmod(raises=IcapTimeoutError("Scan timed out"))

        Example - Dynamic callback:
            >>> def eicar_detector(data: bytes, **kwargs) -> IcapResponse:
            ...     if b"EICAR" in data:
            ...         return IcapResponseBuilder().virus("EICAR-Test").build()
            ...     return IcapResponseBuilder().clean().build()
            >>> client = MockIcapClient()
            >>> client.on_respmod(callback=eicar_detector)
            >>> client.scan_bytes(b"safe").is_no_modification  # True
            >>> client.scan_bytes(b"X5O!P%@AP...EICAR...").is_no_modification  # False

        See Also:
            reset_responses: Clear queued responses without clearing call history.
            on_options: Configure OPTIONS method responses.
            on_reqmod: Configure REQMOD method responses.
            ResponseCallback: Protocol defining the callback signature.
        """
        if callback is not None:
            # Callback mode: clear other configurations
            self._response_queues["respmod"].clear()
            self._queue_active["respmod"] = False
            self._callbacks["respmod"] = callback
        elif raises is not None:
            # Clear queue and set default to exception
            self._response_queues["respmod"].clear()
            self._queue_active["respmod"] = False
            self._callbacks["respmod"] = None
            self._respmod_response = raises
        elif len(responses) == 1:
            # Single response: set as default, clear queue
            self._response_queues["respmod"].clear()
            self._queue_active["respmod"] = False
            self._callbacks["respmod"] = None
            self._respmod_response = responses[0]
        elif len(responses) > 1:
            # Multiple responses: queue them all
            self._response_queues["respmod"].clear()
            self._response_queues["respmod"].extend(responses)
            self._queue_active["respmod"] = True
            self._callbacks["respmod"] = None
        return self

    def on_reqmod(
        self,
        *responses: IcapResponse | Exception,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure what the REQMOD method returns.

        Supports three usage patterns:
            1. **Single response**: Pass one response that all calls will return.
            2. **Response sequence**: Pass multiple responses that are consumed
               in order. When exhausted, raises MockResponseExhaustedError.
            3. **Exception injection**: Use raises= to make all calls raise.

        Args:
            *responses: One or more IcapResponse objects (or Exceptions).
                        If multiple provided, they form a queue consumed in order.
            raises: Exception to raise on all calls. Takes precedence over responses.

        Returns:
            Self for method chaining.

        Raises:
            MockResponseExhaustedError: When all queued responses are consumed
                and another call is made.

        Example - Single response:
            >>> client = MockIcapClient()
            >>> client.on_reqmod(IcapResponseBuilder().clean().build())
            >>> http_req = b"POST /upload HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
            >>> response = client.reqmod("avscan", http_req, b"file content")
            >>> assert response.is_no_modification

        Example - Response sequence:
            >>> client = MockIcapClient()
            >>> client.on_reqmod(
            ...     IcapResponseBuilder().clean().build(),
            ...     IcapResponseBuilder().error(500).build(),
            ... )
            >>> client.reqmod("avscan", http_req, b"file1").is_success  # True
            >>> client.reqmod("avscan", http_req, b"file2").is_success  # False

        See Also:
            reset_responses: Clear queued responses without clearing call history.
            on_options: Configure OPTIONS method responses.
            on_respmod: Configure RESPMOD method responses.
        """
        if raises is not None:
            self._response_queues["reqmod"].clear()
            self._queue_active["reqmod"] = False
            self._reqmod_response = raises
        elif len(responses) == 1:
            self._response_queues["reqmod"].clear()
            self._queue_active["reqmod"] = False
            self._reqmod_response = responses[0]
        elif len(responses) > 1:
            self._response_queues["reqmod"].clear()
            self._response_queues["reqmod"].extend(responses)
            self._queue_active["reqmod"] = True
        return self

    def on_any(
        self,
        response: IcapResponse | None = None,
        *,
        raises: Exception | None = None,
    ) -> MockIcapClient:
        """
        Configure all methods (OPTIONS, RESPMOD, REQMOD) at once.

        Convenience method to set the same response or exception for all methods.
        Note: This sets a single response for all methods, not a sequence.

        Args:
            response: IcapResponse to return from all methods.
            raises: Exception to raise from all methods. Takes precedence.

        Returns:
            Self for method chaining.

        Example - All methods return clean:
            >>> client = MockIcapClient()
            >>> client.on_any(IcapResponseBuilder().clean().build())

        Example - All methods fail:
            >>> client.on_any(raises=IcapConnectionError("Server down"))
        """
        if raises is not None:
            self.on_options(raises=raises)
            self.on_respmod(raises=raises)
            self.on_reqmod(raises=raises)
        elif response is not None:
            self.on_options(response)
            self.on_respmod(response)
            self.on_reqmod(response)
        return self

    def reset_responses(self) -> None:
        """
        Clear all response queues and reset to defaults.

        This clears any queued responses but does NOT clear call history.
        Use reset_calls() to clear call history.

        After calling reset_responses(), the mock returns default responses:
        - OPTIONS: 200 OK with standard server capabilities
        - RESPMOD/scan_*: 204 No Modification (clean)
        - REQMOD: 204 No Modification (clean)

        Example:
            >>> client = MockIcapClient()
            >>> client.on_respmod(
            ...     IcapResponseBuilder().virus().build(),
            ...     IcapResponseBuilder().virus().build(),
            ... )
            >>> client.scan_bytes(b"file1")  # Returns virus
            >>> client.reset_responses()
            >>> client.scan_bytes(b"file2")  # Returns clean (default)
            >>> len(client.calls)  # 2 - call history preserved
            2

        See Also:
            reset_calls: Clear call history without resetting responses.
        """
        # Clear all queues
        for queue in self._response_queues.values():
            queue.clear()

        # Reset queue active flags
        for method in self._queue_active:
            self._queue_active[method] = False

        # Reset defaults
        self._options_response = IcapResponseBuilder().options().build()
        self._respmod_response = IcapResponseBuilder().clean().build()
        self._reqmod_response = IcapResponseBuilder().clean().build()

        # Clear callbacks
        for method in self._callbacks:
            self._callbacks[method] = None

        # Clear matchers
        self._matchers.clear()

    def when(
        self,
        *,
        service: str | None = None,
        filename: str | None = None,
        filename_matches: str | None = None,
        data_contains: bytes | None = None,
    ) -> MatcherBuilder:
        """
        Create a conditional response matcher.

        Returns a MatcherBuilder that collects match criteria and registers
        the matcher when respond() is called. Matchers are checked in registration
        order; the first match wins. Matchers take highest priority in response
        resolution (before callbacks, queues, and defaults).

        Args:
            service: Exact service name to match (e.g., "avscan").
            filename: Exact filename to match (e.g., "malware.exe").
            filename_matches: Regex pattern string to match against filename.
            data_contains: Bytes that must be present in scanned content.

        Returns:
            MatcherBuilder for configuring the response.

        Example - Filename matching:
            >>> client = MockIcapClient()
            >>> client.when(filename="malware.exe").respond(
            ...     IcapResponseBuilder().virus("Known.Malware").build()
            ... )
            >>> client.scan_bytes(b"content", filename="malware.exe").is_no_modification
            False  # virus detected
            >>> client.scan_bytes(b"content", filename="safe.txt").is_no_modification
            True  # falls through to default

        Example - Pattern matching:
            >>> client.when(filename_matches=r".*\\.exe$").respond(
            ...     IcapResponseBuilder().virus("Policy.BlockedExecutable").build()
            ... )

        Example - Content matching:
            >>> client.when(data_contains=b"EICAR").respond(
            ...     IcapResponseBuilder().virus("EICAR-Test").build()
            ... )

        Example - Combined criteria:
            >>> client.when(service="avscan", data_contains=b"malicious").respond(
            ...     IcapResponseBuilder().virus().build()
            ... )

        Example - Multiple matchers with chaining:
            >>> client.when(filename="virus.exe").respond(
            ...     IcapResponseBuilder().virus().build()
            ... ).when(filename="clean.txt").respond(
            ...     IcapResponseBuilder().clean().build()
            ... )

        Example - Limited use matcher:
            >>> client.when(data_contains=b"bad").respond(
            ...     IcapResponseBuilder().virus().build(),
            ...     times=2,  # Only match first 2 times
            ... )

        See Also:
            MatcherBuilder: Builder returned by this method.
            ResponseMatcher: The underlying matcher dataclass.
            reset_responses: Clears all matchers along with other configurations.
        """
        return MatcherBuilder(
            self,
            service=service,
            filename=filename,
            filename_matches=filename_matches,
            data_contains=data_contains,
        )

    # === Assertion API ===

    @property
    def calls(self) -> list[MockCall]:
        """
        Get a copy of all recorded method calls.

        Returns a copy to prevent accidental modification. Each MockCall
        contains the method name, timestamp, and keyword arguments.

        Returns:
            List of MockCall objects in chronological order.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"test1")
            >>> client.scan_bytes(b"test2")
            >>> len(client.calls)
            2
            >>> client.calls[0].kwargs["data"]
            b'test1'
        """
        return self._calls.copy()

    def assert_called(self, method: str, *, times: int | None = None) -> None:
        """
        Assert that a method was called.

        Args:
            method: Method name to check (e.g., "scan_bytes", "options", "respmod").
            times: If provided, assert the method was called exactly this many times.

        Raises:
            AssertionError: If the method was never called, or was called a
                different number of times than expected.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"content")
            >>> client.assert_called("scan_bytes")  # Passes
            >>> client.assert_called("scan_bytes", times=1)  # Passes
            >>> client.assert_called("scan_bytes", times=2)  # Raises AssertionError
            >>> client.assert_called("options")  # Raises AssertionError
        """
        matching = [c for c in self._calls if c.method == method]
        if not matching:
            raise AssertionError(f"Method '{method}' was never called")
        if times is not None and len(matching) != times:
            raise AssertionError(
                f"Method '{method}' was called {len(matching)} times, expected {times}"
            )

    def assert_not_called(self, method: str | None = None) -> None:
        """
        Assert that a method (or any method) was not called.

        Args:
            method: Specific method name to check. If None, asserts no methods
                    were called at all.

        Raises:
            AssertionError: If the method (or any method) was called.

        Example:
            >>> client = MockIcapClient()
            >>> client.assert_not_called()  # Passes - nothing called yet
            >>> client.assert_not_called("options")  # Passes
            >>> client.scan_bytes(b"test")
            >>> client.assert_not_called("options")  # Still passes
            >>> client.assert_not_called("scan_bytes")  # Raises AssertionError
            >>> client.assert_not_called()  # Raises AssertionError
        """
        if method is None:
            if self._calls:
                raise AssertionError(f"Expected no calls, got: {self._calls}")
        else:
            matching = [c for c in self._calls if c.method == method]
            if matching:
                raise AssertionError(f"Method '{method}' was called {len(matching)} times")

    def assert_scanned(self, data: bytes) -> None:
        """
        Assert that specific content was scanned.

        Checks if the given bytes were passed to scan_bytes() or respmod().
        For respmod(), checks if the http_response ends with the given data.

        Args:
            data: The exact bytes that should have been scanned.

        Raises:
            AssertionError: If the data was not found in any scan call.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"test content")
            >>> client.assert_scanned(b"test content")  # Passes
            >>> client.assert_scanned(b"other")  # Raises AssertionError
        """
        for call in self._calls:
            if call.method in ("scan_bytes", "respmod"):
                if call.kwargs.get("data") == data:
                    return
                if call.kwargs.get("http_response", b"").endswith(data):
                    return
        raise AssertionError(f"Content {data!r} was not scanned")

    def reset_calls(self) -> None:
        """
        Clear the call history.

        Use this between test phases to reset assertions.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"test1")
            >>> client.assert_called("scan_bytes", times=1)
            >>> client.reset_calls()
            >>> client.assert_not_called()  # Passes - history cleared
            >>> client.scan_bytes(b"test2")
            >>> client.assert_called("scan_bytes", times=1)  # Only counts new call
        """
        self._calls.clear()

    # === IcapClient Interface ===

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("Port is not a valid type. Please enter an int value.")
        self._port = value

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        """Simulate connection (no-op)."""
        self._connected = True

    def disconnect(self) -> None:
        """Simulate disconnection (no-op)."""
        self._connected = False

    def __enter__(self) -> MockIcapClient:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        self.disconnect()
        return False

    def _record_call(self, method: str, **kwargs: Any) -> None:
        """Record a method call."""
        self._calls.append(
            MockCall(
                method=method,
                timestamp=time.time(),
                kwargs=kwargs,
            )
        )

    def _get_response(self, response_or_exception: IcapResponse | Exception) -> IcapResponse:
        """Return response or raise exception."""
        if isinstance(response_or_exception, Exception):
            raise response_or_exception
        return response_or_exception

    def _get_method_response(self, method: str) -> IcapResponse:
        """
        Get the next response for the given method.

        Resolution order:
        1. If a matcher matches the call kwargs → return matcher's response
        2. If callback is set → invoke callback with last call's kwargs
        3. If queue has items → pop and return/raise
        4. If queue is empty AND queue_active is True → raise MockResponseExhaustedError
        5. Otherwise → use default response
        """
        # Get kwargs from the last recorded call for matching
        last_call = self._calls[-1] if self._calls else None
        call_kwargs = last_call.kwargs if last_call is not None else {}

        # Check matchers first (highest priority)
        for matcher in self._matchers:
            if not matcher.is_exhausted() and matcher.matches(**call_kwargs):
                return matcher.consume()

        # Check for callback
        callback = self._callbacks.get(method)
        if callback is not None:
            if last_call is not None:
                return callback(**last_call.kwargs)
            # Fallback if no call recorded (shouldn't happen in normal use)
            return callback(data=b"", service="avscan", filename=None)

        queue = self._response_queues[method]

        if queue:
            # Queue has items - pop the next one
            response_or_exception = queue.popleft()
            return self._get_response(response_or_exception)

        if self._queue_active[method]:
            # Queue was active but is now empty - all responses consumed
            raise MockResponseExhaustedError(
                f"All queued {method} responses have been consumed. "
                f"Configure more responses with on_{method}() or use reset_responses()."
            )

        # Use default response for this method
        default_responses = {
            "options": self._options_response,
            "respmod": self._respmod_response,
            "reqmod": self._reqmod_response,
        }
        return self._get_response(default_responses[method])

    def options(self, service: str) -> IcapResponse:
        """Send OPTIONS request (mocked)."""
        self._record_call("options", service=service)
        return self._get_method_response("options")

    def respmod(
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: dict[str, str] | None = None,
        preview: int | None = None,
    ) -> IcapResponse:
        """Send RESPMOD request (mocked)."""
        self._record_call(
            "respmod",
            service=service,
            http_request=http_request,
            http_response=http_response,
            headers=headers,
            preview=preview,
        )
        return self._get_method_response("respmod")

    def reqmod(
        self,
        service: str,
        http_request: bytes,
        http_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> IcapResponse:
        """Send REQMOD request (mocked)."""
        self._record_call(
            "reqmod",
            service=service,
            http_request=http_request,
            http_body=http_body,
            headers=headers,
        )
        return self._get_method_response("reqmod")

    def scan_bytes(
        self,
        data: bytes,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan bytes content (mocked)."""
        self._record_call(
            "scan_bytes",
            data=data,
            service=service,
            filename=filename,
        )
        return self._get_method_response("respmod")

    def scan_file(
        self,
        filepath: str | Path,
        service: str = "avscan",
    ) -> IcapResponse:
        """Scan a file (mocked - actually reads the file)."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        data = filepath.read_bytes()
        self._record_call(
            "scan_file",
            filepath=str(filepath),
            service=service,
            data=data,
        )
        return self._get_method_response("respmod")

    def scan_stream(
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: str | None = None,
        chunk_size: int = 0,
    ) -> IcapResponse:
        """Scan a stream (mocked - actually reads the stream)."""
        data = stream.read()
        self._record_call(
            "scan_stream",
            data=data,
            service=service,
            filename=filename,
            chunk_size=chunk_size,
        )
        return self._get_method_response("respmod")


class MockAsyncIcapClient(MockIcapClient):
    """
    Async mock ICAP client for testing without network I/O.

    Inherits from MockIcapClient and provides the same functionality with
    async/await syntax. All ICAP methods (options, respmod, reqmod, scan_*)
    are coroutines that must be awaited.

    The configuration API (on_options, on_respmod, on_reqmod, on_any) and
    assertion API (assert_called, assert_not_called, assert_scanned, reset_calls)
    are synchronous and inherited directly from MockIcapClient.

    Attributes:
        host: Mock server hostname (inherited from MockIcapClient).
        port: Mock server port (inherited from MockIcapClient).
        is_connected: Whether connect() has been called.
        calls: List of MockCall objects recording all method invocations.

    Example - Basic async usage:
        >>> async def test_scan(mock_async_icap_client):
        ...     async with mock_async_icap_client as client:
        ...         response = await client.scan_bytes(b"content")
        ...         assert response.is_no_modification
        ...         client.assert_called("scan_bytes", times=1)

    Example - Configure virus detection:
        >>> async def test_virus(mock_async_icap_client):
        ...     mock_async_icap_client.on_respmod(
        ...         IcapResponseBuilder().virus("Trojan.Gen").build()
        ...     )
        ...     async with mock_async_icap_client as client:
        ...         response = await client.scan_file("/path/to/file.txt")
        ...         assert not response.is_no_modification

    Example - Error handling:
        >>> async def test_timeout(mock_async_icap_client):
        ...     mock_async_icap_client.on_any(raises=IcapTimeoutError("Timeout"))
        ...     async with mock_async_icap_client as client:
        ...         with pytest.raises(IcapTimeoutError):
        ...             await client.scan_bytes(b"content")

    See Also:
        MockIcapClient: Synchronous version with full API documentation.
        IcapResponseBuilder: Fluent builder for creating test responses.
    """

    async def _get_method_response_async(self, method: str) -> IcapResponse:
        """
        Get the next response for the given method (async version).

        Resolution order:
        1. If a matcher matches the call kwargs → return matcher's response
        2. If callback is set (sync or async) → invoke callback
        3. Fall back to sync implementation (queue → default)
        """
        # Get kwargs from the last recorded call for matching
        last_call = self._calls[-1] if self._calls else None
        call_kwargs = last_call.kwargs if last_call is not None else {}

        # Check matchers first (highest priority)
        for matcher in self._matchers:
            if not matcher.is_exhausted() and matcher.matches(**call_kwargs):
                return matcher.consume()

        # Check for callback
        callback = self._callbacks.get(method)
        if callback is not None:
            kwargs = (
                call_kwargs if call_kwargs else {"data": b"", "service": "avscan", "filename": None}
            )

            # Check if callback is async and await if needed
            if inspect.iscoroutinefunction(callback):
                return await callback(**kwargs)
            else:
                return callback(**kwargs)

        # Fall back to sync implementation for queue/default cases
        return super()._get_method_response(method)

    async def connect(self) -> None:  # type: ignore[override]
        """Simulate async connection (no-op)."""
        self._connected = True

    async def disconnect(self) -> None:  # type: ignore[override]
        """Simulate async disconnection (no-op)."""
        self._connected = False

    async def __aenter__(self) -> MockAsyncIcapClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        await self.disconnect()
        return False

    async def options(self, service: str) -> IcapResponse:  # type: ignore[override]
        """Send OPTIONS request (mocked)."""
        self._record_call("options", service=service)
        return await self._get_method_response_async("options")

    async def respmod(  # type: ignore[override]
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: dict[str, str] | None = None,
        preview: int | None = None,
    ) -> IcapResponse:
        """Send RESPMOD request (mocked)."""
        self._record_call(
            "respmod",
            service=service,
            http_request=http_request,
            http_response=http_response,
            headers=headers,
            preview=preview,
        )
        return await self._get_method_response_async("respmod")

    async def reqmod(  # type: ignore[override]
        self,
        service: str,
        http_request: bytes,
        http_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> IcapResponse:
        """Send REQMOD request (mocked)."""
        self._record_call(
            "reqmod",
            service=service,
            http_request=http_request,
            http_body=http_body,
            headers=headers,
        )
        return await self._get_method_response_async("reqmod")

    async def scan_bytes(  # type: ignore[override]
        self,
        data: bytes,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan bytes content (mocked)."""
        self._record_call(
            "scan_bytes",
            data=data,
            service=service,
            filename=filename,
        )
        return await self._get_method_response_async("respmod")

    async def scan_file(  # type: ignore[override]
        self,
        filepath: str | Path,
        service: str = "avscan",
    ) -> IcapResponse:
        """Scan a file (mocked)."""
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        data = filepath.read_bytes()
        self._record_call(
            "scan_file",
            filepath=str(filepath),
            service=service,
            data=data,
        )
        return await self._get_method_response_async("respmod")

    async def scan_stream(  # type: ignore[override]
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan a stream (mocked)."""
        data = stream.read()
        self._record_call(
            "scan_stream",
            data=data,
            service=service,
            filename=filename,
        )
        return await self._get_method_response_async("respmod")
