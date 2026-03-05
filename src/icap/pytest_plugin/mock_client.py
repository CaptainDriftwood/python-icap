"""
Synchronous mock ICAP client for testing.

This module provides MockIcapClient, a mock implementation of IcapClient
that can be used in tests without requiring a real ICAP server.
"""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from .builder import IcapResponseBuilder
from .call_record import MockCall, MockResponseExhaustedError
from .matchers import MatcherBuilder, ResponseMatcher
from .protocols import AsyncResponseCallback, ResponseCallback

if TYPE_CHECKING:
    from icap import IcapResponse


class MockIcapClient:
    """
    Mock ICAP client for testing without network I/O.

    Implements the full IcapClient interface with configurable responses
    and call recording for assertions. By default, all methods return clean/success
    responses (204 No Modification for scans, 200 OK for OPTIONS).

    The mock provides six main capabilities:

        1. **Response Configuration**: Set what responses methods should return.
        2. **Response Sequences**: Queue multiple responses consumed in order.
        3. **Dynamic Callbacks**: Generate responses based on request content.
        4. **Content Matchers**: Declarative rules matching filename, service, or data.
        5. **Call Recording**: Track all calls with rich inspection and filtering.
        6. **Strict Mode**: Validate all configured responses were consumed.

    Response Resolution Order:
        When a method is called, the mock determines the response in this order:
        1. **Matchers** - First matching rule wins (via when().respond())
        2. **Callbacks** - If defined for the method (via on_respmod(callback=...))
        3. **Queue** - Next queued response if available (via on_respmod(r1, r2, r3))
        4. **Default** - Single configured response (via on_respmod(response))

    Attributes:
        host: Mock server hostname (default: "mock-icap-server").
        port: Mock server port (default: 1344).
        is_connected: Whether connect() has been called.
        calls: List of MockCall objects recording all method invocations.
        call_count: Total number of calls made.
        first_call: First call made (or None if no calls).
        last_call: Most recent call (or None if no calls).
        last_scan_call: Most recent scan_bytes/scan_file/scan_stream call.

    Configuration Methods:
        on_options(*responses, raises, callback): Configure OPTIONS responses.
        on_respmod(*responses, raises, callback): Configure scan method responses.
        on_reqmod(*responses, raises, callback): Configure REQMOD responses.
        on_any(response, raises): Configure all methods at once.
        when(service, filename, filename_matches, data_contains): Create matchers.
        reset_responses(): Clear all configured responses and matchers.

    Assertion Methods:
        assert_called(method, times): Assert method was called N times.
        assert_not_called(method): Assert method was never called.
        assert_scanned(data): Assert specific bytes were scanned.
        assert_called_with(method, **kwargs): Assert last call had specific args.
        assert_any_call(method, **kwargs): Assert any call had specific args.
        assert_called_in_order(methods): Assert methods called in sequence.
        assert_scanned_file(filepath): Assert specific file was scanned.
        assert_scanned_with_filename(filename): Assert filename was used.
        assert_all_responses_used(): Validate all responses consumed (strict mode).
        reset_calls(): Clear call history.

    Query Methods:
        get_calls(method): Filter calls by method name.
        get_scan_calls(): Get all scan_bytes/scan_file/scan_stream calls.
        call_counts_by_method: Dict of method name to call count.

    Example - Basic usage:
        >>> client = MockIcapClient()
        >>> response = client.scan_bytes(b"safe content")
        >>> assert response.is_no_modification  # Default is clean
        >>> client.assert_called("scan_bytes", times=1)

    Example - Response sequence (consumed in order):
        >>> client = MockIcapClient()
        >>> client.on_respmod(
        ...     IcapResponseBuilder().clean().build(),
        ...     IcapResponseBuilder().virus("Trojan").build(),
        ...     IcapResponseBuilder().clean().build(),
        ... )
        >>> client.scan_bytes(b"file1").is_no_modification  # True (clean)
        >>> client.scan_bytes(b"file2").is_no_modification  # False (virus)
        >>> client.scan_bytes(b"file3").is_no_modification  # True (clean)

    Example - Dynamic callback:
        >>> def eicar_detector(data: bytes, **kwargs) -> IcapResponse:
        ...     if b"EICAR" in data:
        ...         return IcapResponseBuilder().virus("EICAR-Test").build()
        ...     return IcapResponseBuilder().clean().build()
        >>> client = MockIcapClient()
        >>> client.on_respmod(callback=eicar_detector)
        >>> client.scan_bytes(b"safe").is_no_modification  # True
        >>> client.scan_bytes(b"EICAR test").is_no_modification  # False

    Example - Content matchers:
        >>> client = MockIcapClient()
        >>> client.when(filename_matches=r".*\\.exe$").respond(
        ...     IcapResponseBuilder().virus("Blocked.Exe").build()
        ... )
        >>> client.when(data_contains=b"EICAR").respond(
        ...     IcapResponseBuilder().virus("EICAR-Test").build()
        ... )
        >>> client.scan_bytes(b"safe", filename="doc.pdf").is_no_modification  # True
        >>> client.scan_bytes(b"safe", filename="app.exe").is_no_modification  # False

    Example - Exception injection:
        >>> from icap.exception import IcapTimeoutError
        >>> client = MockIcapClient()
        >>> client.on_any(raises=IcapTimeoutError("Connection timed out"))
        >>> client.scan_bytes(b"content")  # Raises IcapTimeoutError

    Example - Rich call inspection:
        >>> client = MockIcapClient()
        >>> client.on_respmod(IcapResponseBuilder().virus("Trojan").build())
        >>> client.scan_bytes(b"malware", filename="bad.exe")
        >>> call = client.last_call
        >>> call.filename  # "bad.exe"
        >>> call.was_virus  # True
        >>> call.matched_by  # "default"
        >>> call.response.headers["X-Virus-ID"]  # "Trojan"

    Example - Strict mode (validate all responses used):
        >>> client = MockIcapClient(strict=True)
        >>> client.on_respmod(
        ...     IcapResponseBuilder().clean().build(),
        ...     IcapResponseBuilder().virus().build(),
        ... )
        >>> client.scan_bytes(b"file1")
        >>> client.scan_bytes(b"file2")
        >>> client.assert_all_responses_used()  # Passes - all consumed

    See Also:
        MockAsyncIcapClient: Async version with same API but awaitable methods.
        IcapResponseBuilder: Fluent builder for creating test responses.
        MockCall: Dataclass representing a recorded method call.
        ResponseMatcher: Dataclass for content-based matching rules.
        MatcherBuilder: Fluent API for creating matchers via when().
    """

    def __init__(
        self,
        host: str = "mock-icap-server",
        port: int = 1344,
        *,
        strict: bool = False,
    ) -> None:
        """
        Initialize the mock ICAP client.

        Args:
            host: Mock server hostname (default: "mock-icap-server").
                  This value is stored but not used for actual connections.
            port: Mock server port (default: 1344).
                  This value is stored but not used for actual connections.
            strict: If True, enables strict mode validation. Use
                    assert_all_responses_used() to verify all configured
                    responses were consumed. Default: False.
        """
        self._host = host
        self._port = port
        self._connected = False
        self._strict = strict
        self._calls: list[MockCall] = []

        # Response queues for sequential responses
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

        # Track initial queue sizes for strict mode validation
        self._initial_queue_sizes: dict[str, int] = {
            "options": 0,
            "respmod": 0,
            "reqmod": 0,
        }

        # Track callback usage for strict mode validation
        self._callback_used: dict[str, bool] = {
            "options": False,
            "respmod": False,
            "reqmod": False,
        }

        # Default responses (clean/success) - used when queue mode is not active
        self._options_response: IcapResponse | Exception = IcapResponseBuilder().options().build()
        self._respmod_response: IcapResponse | Exception = IcapResponseBuilder().clean().build()
        self._reqmod_response: IcapResponse | Exception = IcapResponseBuilder().clean().build()

        # Callbacks for dynamic response generation
        self._callbacks: dict[str, ResponseCallback | AsyncResponseCallback | None] = {
            "options": None,
            "respmod": None,
            "reqmod": None,
        }

        # Content matchers for declarative conditional responses
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
            self._initial_queue_sizes["options"] = 0
            self._options_response = raises
        elif len(responses) == 1:
            self._response_queues["options"].clear()
            self._queue_active["options"] = False
            self._initial_queue_sizes["options"] = 0
            self._options_response = responses[0]
        elif len(responses) > 1:
            self._response_queues["options"].clear()
            self._response_queues["options"].extend(responses)
            self._queue_active["options"] = True
            self._initial_queue_sizes["options"] = len(responses)
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
            self._initial_queue_sizes["respmod"] = 0
            self._callback_used["respmod"] = False
            self._callbacks["respmod"] = callback
        elif raises is not None:
            # Clear queue and set default to exception
            self._response_queues["respmod"].clear()
            self._queue_active["respmod"] = False
            self._initial_queue_sizes["respmod"] = 0
            self._callbacks["respmod"] = None
            self._respmod_response = raises
        elif len(responses) == 1:
            # Single response: set as default, clear queue
            self._response_queues["respmod"].clear()
            self._queue_active["respmod"] = False
            self._initial_queue_sizes["respmod"] = 0
            self._callbacks["respmod"] = None
            self._respmod_response = responses[0]
        elif len(responses) > 1:
            # Multiple responses: queue them all
            self._response_queues["respmod"].clear()
            self._response_queues["respmod"].extend(responses)
            self._queue_active["respmod"] = True
            self._initial_queue_sizes["respmod"] = len(responses)
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
            self._initial_queue_sizes["reqmod"] = 0
            self._reqmod_response = raises
        elif len(responses) == 1:
            self._response_queues["reqmod"].clear()
            self._queue_active["reqmod"] = False
            self._initial_queue_sizes["reqmod"] = 0
            self._reqmod_response = responses[0]
        elif len(responses) > 1:
            self._response_queues["reqmod"].clear()
            self._response_queues["reqmod"].extend(responses)
            self._queue_active["reqmod"] = True
            self._initial_queue_sizes["reqmod"] = len(responses)
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
        for queue in self._response_queues.values():
            queue.clear()

        for method in self._queue_active:
            self._queue_active[method] = False

        self._options_response = IcapResponseBuilder().options().build()
        self._respmod_response = IcapResponseBuilder().clean().build()
        self._reqmod_response = IcapResponseBuilder().clean().build()

        for method in self._callbacks:
            self._callbacks[method] = None

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

    @property
    def first_call(self) -> MockCall | None:
        """
        Get the first recorded call, or None if no calls were made.

        Returns:
            The first MockCall, or None if calls list is empty.

        Example:
            >>> client = MockIcapClient()
            >>> client.first_call  # None
            >>> client.scan_bytes(b"first")
            >>> client.scan_bytes(b"second")
            >>> client.first_call.data
            b'first'
        """
        return self._calls[0] if self._calls else None

    @property
    def last_call(self) -> MockCall | None:
        """
        Get the most recent call, or None if no calls were made.

        Returns:
            The last MockCall, or None if calls list is empty.

        Example:
            >>> client = MockIcapClient()
            >>> client.last_call  # None
            >>> client.scan_bytes(b"first")
            >>> client.scan_bytes(b"second")
            >>> client.last_call.data
            b'second'
        """
        return self._calls[-1] if self._calls else None

    @property
    def last_scan_call(self) -> MockCall | None:
        """
        Get the most recent scan call (scan_bytes, scan_file, scan_stream).

        Returns:
            The last scan-related MockCall, or None if no scan calls were made.

        Example:
            >>> client = MockIcapClient()
            >>> client.options("avscan")  # Not a scan
            >>> client.scan_bytes(b"test")  # This is a scan
            >>> client.options("avscan")  # Not a scan
            >>> client.last_scan_call.method
            'scan_bytes'
            >>> client.last_scan_call.data
            b'test'
        """
        scan_methods = {"scan_bytes", "scan_file", "scan_stream"}
        for call in reversed(self._calls):
            if call.method in scan_methods:
                return call
        return None

    def get_calls(self, method: str | None = None) -> list[MockCall]:
        """
        Get calls, optionally filtered by method name.

        Args:
            method: If provided, only return calls with this method name.
                    If None, returns all calls.

        Returns:
            List of matching MockCall objects in chronological order.

        Example:
            >>> client = MockIcapClient()
            >>> client.options("avscan")
            >>> client.scan_bytes(b"file1")
            >>> client.scan_bytes(b"file2")
            >>> len(client.get_calls())  # All calls
            3
            >>> len(client.get_calls("scan_bytes"))  # Only scan_bytes
            2
            >>> [c.data for c in client.get_calls("scan_bytes")]
            [b'file1', b'file2']
        """
        if method is None:
            return self._calls.copy()
        return [c for c in self._calls if c.method == method]

    def get_scan_calls(self) -> list[MockCall]:
        """
        Get all scan-related calls (scan_bytes, scan_file, scan_stream).

        Convenience method for filtering to only scan operations, excluding
        lower-level calls like options, respmod, and reqmod.

        Returns:
            List of scan MockCall objects in chronological order.

        Example:
            >>> client = MockIcapClient()
            >>> client.options("avscan")
            >>> client.scan_bytes(b"file1")
            >>> client.scan_file("/path/to/file.txt")
            >>> len(client.get_scan_calls())
            2
            >>> [c.method for c in client.get_scan_calls()]
            ['scan_bytes', 'scan_file']
        """
        scan_methods = {"scan_bytes", "scan_file", "scan_stream"}
        return [c for c in self._calls if c.method in scan_methods]

    @property
    def call_count(self) -> int:
        """
        Get the total number of calls made.

        Returns:
            The number of recorded method calls.

        Example:
            >>> client = MockIcapClient()
            >>> client.call_count
            0
            >>> client.scan_bytes(b"test")
            >>> client.options("avscan")
            >>> client.call_count
            2
        """
        return len(self._calls)

    @property
    def call_counts_by_method(self) -> dict[str, int]:
        """
        Get call counts grouped by method name.

        Returns:
            Dictionary mapping method names to their call counts.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"file1")
            >>> client.scan_bytes(b"file2")
            >>> client.options("avscan")
            >>> client.call_counts_by_method
            {'scan_bytes': 2, 'options': 1}
        """
        counts: dict[str, int] = {}
        for call in self._calls:
            counts[call.method] = counts.get(call.method, 0) + 1
        return counts

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

    def assert_called_with(self, method: str, **kwargs: Any) -> None:
        """
        Assert that a method was called with specific arguments.

        Finds the most recent call to the method and checks that the provided
        kwargs match the call's arguments. Only the provided kwargs are checked;
        additional arguments in the call are allowed.

        Args:
            method: Method name to check.
            **kwargs: Expected keyword arguments (partial match).

        Raises:
            AssertionError: If the method was never called, or the most recent
                call doesn't match the expected kwargs.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"content", filename="test.txt", service="avscan")
            >>> client.assert_called_with("scan_bytes", data=b"content")  # Passes
            >>> client.assert_called_with("scan_bytes", filename="test.txt")  # Passes
            >>> client.assert_called_with("scan_bytes", filename="other.txt")  # Fails
        """
        matching = [c for c in self._calls if c.method == method]
        if not matching:
            raise AssertionError(f"Method '{method}' was never called")

        last_call = matching[-1]
        for key, expected_value in kwargs.items():
            actual_value = last_call.kwargs.get(key)
            if actual_value != expected_value:
                raise AssertionError(
                    f"Method '{method}' called with {key}={actual_value!r}, "
                    f"expected {key}={expected_value!r}"
                )

    def assert_any_call(self, method: str, **kwargs: Any) -> None:
        """
        Assert that at least one call matches the specified arguments.

        Searches all calls to the method for one that matches all provided kwargs.
        Unlike assert_called_with, this doesn't require the match to be the most
        recent call.

        Args:
            method: Method name to check.
            **kwargs: Expected keyword arguments (partial match).

        Raises:
            AssertionError: If no call matches the expected kwargs.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"first", filename="a.txt")
            >>> client.scan_bytes(b"second", filename="b.txt")
            >>> client.scan_bytes(b"third", filename="c.txt")
            >>> client.assert_any_call("scan_bytes", filename="b.txt")  # Passes
            >>> client.assert_any_call("scan_bytes", filename="z.txt")  # Fails
        """
        matching = [c for c in self._calls if c.method == method]
        if not matching:
            raise AssertionError(f"Method '{method}' was never called")

        for call in matching:
            if all(call.kwargs.get(k) == v for k, v in kwargs.items()):
                return  # Found a match

        raise AssertionError(
            f"No call to '{method}' matched kwargs {kwargs!r}. "
            f"Actual calls: {[c.kwargs for c in matching]}"
        )

    def assert_called_in_order(self, methods: list[str]) -> None:
        """
        Assert that methods were called in the specified order.

        Checks that the call history contains the methods in the given order.
        Other calls may appear between the specified methods.

        Args:
            methods: List of method names in expected order.

        Raises:
            AssertionError: If the methods weren't called in order.

        Example:
            >>> client = MockIcapClient()
            >>> client.options("avscan")
            >>> client.scan_bytes(b"test")
            >>> client.assert_called_in_order(["options", "scan_bytes"])  # Passes
            >>> client.assert_called_in_order(["scan_bytes", "options"])  # Fails
        """
        if not methods:
            return

        actual_methods = [c.method for c in self._calls]
        method_index = 0

        for actual in actual_methods:
            if method_index < len(methods) and actual == methods[method_index]:
                method_index += 1

        if method_index != len(methods):
            missing = methods[method_index:]
            raise AssertionError(
                f"Methods not called in expected order. "
                f"Expected: {methods}, Actual order: {actual_methods}. "
                f"Missing or out of order: {missing}"
            )

    def assert_scanned_file(self, filepath: str) -> None:
        """
        Assert that a specific file path was scanned.

        Checks if scan_file() was called with the given filepath.

        Args:
            filepath: The file path that should have been scanned.

        Raises:
            AssertionError: If the file was not scanned.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_file("/path/to/file.txt")
            >>> client.assert_scanned_file("/path/to/file.txt")  # Passes
            >>> client.assert_scanned_file("/other/file.txt")  # Fails
        """
        for call in self._calls:
            if call.method == "scan_file" and call.kwargs.get("filepath") == filepath:
                return
        raise AssertionError(f"File '{filepath}' was not scanned")

    def assert_scanned_with_filename(self, filename: str) -> None:
        """
        Assert that a scan was made with a specific filename argument.

        Checks scan_bytes and scan_stream calls for the given filename.
        Note: This checks the filename argument, not the filepath in scan_file().

        Args:
            filename: The filename argument that should have been used.

        Raises:
            AssertionError: If no scan was made with that filename.

        Example:
            >>> client = MockIcapClient()
            >>> client.scan_bytes(b"content", filename="report.pdf")
            >>> client.assert_scanned_with_filename("report.pdf")  # Passes
            >>> client.assert_scanned_with_filename("other.pdf")  # Fails
        """
        for call in self._calls:
            if call.method in ("scan_bytes", "scan_stream"):
                if call.kwargs.get("filename") == filename:
                    return
        raise AssertionError(f"No scan was made with filename '{filename}'")

    def assert_all_responses_used(self) -> None:
        """
        Assert that all configured responses were consumed (strict mode validation).

        This method verifies that:
        1. All queued responses were consumed (queue is empty)
        2. All configured callbacks were invoked at least once
        3. All registered matchers were triggered at least once

        This is useful for ensuring that test setup matches test behavior -
        if you configure specific responses, they should all be used.

        Raises:
            AssertionError: If any configured responses, callbacks, or matchers
                were not used during the test.

        Example - All queued responses consumed:
            >>> client = MockIcapClient(strict=True)
            >>> client.on_respmod(
            ...     IcapResponseBuilder().clean().build(),
            ...     IcapResponseBuilder().virus().build(),
            ... )
            >>> client.scan_bytes(b"file1")
            >>> client.scan_bytes(b"file2")
            >>> client.assert_all_responses_used()  # Passes

        Example - Unused responses fail:
            >>> client = MockIcapClient(strict=True)
            >>> client.on_respmod(
            ...     IcapResponseBuilder().clean().build(),
            ...     IcapResponseBuilder().virus().build(),
            ... )
            >>> client.scan_bytes(b"file1")  # Only consume first response
            >>> client.assert_all_responses_used()  # Raises AssertionError

        Example - Unused callback fails:
            >>> client = MockIcapClient(strict=True)
            >>> client.on_respmod(callback=lambda **kwargs: IcapResponseBuilder().clean().build())
            >>> client.assert_all_responses_used()  # Raises AssertionError (callback never called)

        Example - Unused matcher fails:
            >>> client = MockIcapClient(strict=True)
            >>> client.when(filename="malware.exe").respond(
            ...     IcapResponseBuilder().virus().build()
            ... )
            >>> client.scan_bytes(b"content", filename="safe.txt")  # Matcher not triggered
            >>> client.assert_all_responses_used()  # Raises AssertionError

        See Also:
            strict: Constructor parameter to enable strict mode.
        """
        errors: list[str] = []

        for method, queue in self._response_queues.items():
            initial_size = self._initial_queue_sizes[method]
            remaining = len(queue)
            if remaining > 0:
                consumed = initial_size - remaining
                errors.append(
                    f"{method}: {remaining} of {initial_size} queued responses not consumed "
                    f"(consumed {consumed})"
                )

        for method, callback in self._callbacks.items():
            if callback is not None and not self._callback_used[method]:
                errors.append(f"{method}: callback was configured but never invoked")

        for i, matcher in enumerate(self._matchers):
            if matcher._match_count == 0:
                criteria = []
                if matcher.service:
                    criteria.append(f"service={matcher.service!r}")
                if matcher.filename:
                    criteria.append(f"filename={matcher.filename!r}")
                if matcher.filename_pattern:
                    criteria.append(f"filename_pattern={matcher.filename_pattern.pattern!r}")
                if matcher.data_contains:
                    criteria.append(f"data_contains={matcher.data_contains!r}")
                criteria_str = ", ".join(criteria) if criteria else "no criteria"
                errors.append(f"matcher[{i}] ({criteria_str}): never matched")

        if errors:
            raise AssertionError(
                "Not all configured responses were used:\n  - " + "\n  - ".join(errors)
            )

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

    def _record_call(self, method: str, **kwargs: Any) -> MockCall:
        """
        Record a method call and return the MockCall object.

        Args:
            method: Name of the method being called.
            **kwargs: Arguments passed to the method.

        Returns:
            The newly created MockCall object (also appended to self._calls).
        """
        call = MockCall(
            method=method,
            timestamp=time.time(),
            kwargs=kwargs,
            call_index=len(self._calls),
        )
        self._calls.append(call)
        return call

    def _get_response_with_metadata(
        self, method: str, call_kwargs: dict[str, Any]
    ) -> tuple[IcapResponse | Exception, str]:
        """
        Get the next response and metadata for the given method.

        This method determines the response and tracks how it was resolved
        (matcher, callback, queue, or default).

        Args:
            method: The ICAP method name ("options", "respmod", "reqmod").
            call_kwargs: The arguments passed to the method call.

        Returns:
            A tuple of (response_or_exception, matched_by) where:
            - response_or_exception: The IcapResponse or Exception to return/raise
            - matched_by: String indicating resolution source: "matcher", "callback",
              "queue", or "default"

        Raises:
            MockResponseExhaustedError: When queue is exhausted and queue_active is True.
        """
        # Check matchers first (highest priority)
        for matcher in self._matchers:
            if not matcher.is_exhausted() and matcher.matches(**call_kwargs):
                return matcher.consume(), "matcher"

        callback = self._callbacks.get(method)
        if callback is not None:
            self._callback_used[method] = True
            # Type checker can't narrow callback type; sync client only uses sync callbacks
            return callback(**call_kwargs), "callback"  # type: ignore[return-value]

        queue = self._response_queues[method]

        if queue:
            response_or_exception = queue.popleft()
            return response_or_exception, "queue"

        if self._queue_active[method]:
            raise MockResponseExhaustedError(
                f"All queued {method} responses have been consumed. "
                f"Configure more responses with on_{method}() or use reset_responses()."
            )

        default_responses: dict[str, IcapResponse | Exception] = {
            "options": self._options_response,
            "respmod": self._respmod_response,
            "reqmod": self._reqmod_response,
        }
        return default_responses[method], "default"

    def _execute_call(self, call: MockCall, response_method: str) -> IcapResponse:
        """
        Execute a recorded call and update it with response metadata.

        This method:
        1. Resolves the response using _get_response_with_metadata
        2. Updates the MockCall with response/exception/matched_by
        3. Returns the response or raises the exception

        Args:
            call: The MockCall object to update.
            response_method: The method key for response lookup ("options", "respmod", "reqmod").

        Returns:
            The IcapResponse.

        Raises:
            Exception: If the response was configured as an exception.
        """
        try:
            response_or_exception, matched_by = self._get_response_with_metadata(
                response_method, call.kwargs
            )
            call.matched_by = matched_by

            if isinstance(response_or_exception, Exception):
                call.exception = response_or_exception
                raise response_or_exception

            call.response = response_or_exception
            return response_or_exception

        except MockResponseExhaustedError:
            # MockResponseExhaustedError is a configuration error, not a mock response
            # Still record that it happened
            call.matched_by = "queue"
            raise

    def options(self, service: str) -> IcapResponse:
        """Send OPTIONS request (mocked)."""
        call = self._record_call("options", service=service)
        return self._execute_call(call, "options")

    def respmod(
        self,
        service: str,
        http_request: bytes,
        http_response: bytes,
        headers: dict[str, str] | None = None,
        preview: int | None = None,
    ) -> IcapResponse:
        """Send RESPMOD request (mocked)."""
        call = self._record_call(
            "respmod",
            service=service,
            http_request=http_request,
            http_response=http_response,
            headers=headers,
            preview=preview,
        )
        return self._execute_call(call, "respmod")

    def reqmod(
        self,
        service: str,
        http_request: bytes,
        http_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> IcapResponse:
        """Send REQMOD request (mocked)."""
        call = self._record_call(
            "reqmod",
            service=service,
            http_request=http_request,
            http_body=http_body,
            headers=headers,
        )
        return self._execute_call(call, "reqmod")

    def scan_bytes(
        self,
        data: bytes,
        service: str = "avscan",
        filename: str | None = None,
    ) -> IcapResponse:
        """Scan bytes content (mocked)."""
        call = self._record_call(
            "scan_bytes",
            data=data,
            service=service,
            filename=filename,
        )
        return self._execute_call(call, "respmod")

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
        call = self._record_call(
            "scan_file",
            filepath=str(filepath),
            service=service,
            data=data,
        )
        return self._execute_call(call, "respmod")

    def scan_stream(
        self,
        stream: BinaryIO,
        service: str = "avscan",
        filename: str | None = None,
        chunk_size: int = 0,
    ) -> IcapResponse:
        """Scan a stream (mocked - actually reads the stream)."""
        data = stream.read()
        call = self._record_call(
            "scan_stream",
            data=data,
            service=service,
            filename=filename,
            chunk_size=chunk_size,
        )
        return self._execute_call(call, "respmod")


__all__ = ["MockIcapClient"]
