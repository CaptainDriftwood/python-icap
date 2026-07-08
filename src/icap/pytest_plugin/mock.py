"""
Mock ICAP clients for testing without network I/O.

This module re-exports mock components from their individual modules
for backward compatibility. New code should import from the specific modules:

    from icap.pytest_plugin.mock_client import MockIcapClient
    from icap.pytest_plugin.mock_async import MockAsyncIcapClient
    from icap.pytest_plugin.matchers import ResponseMatcher, MatcherBuilder
    from icap.pytest_plugin.call_record import MockCall, MockResponseExhaustedError
    from icap.pytest_plugin.protocols import ResponseCallback, AsyncResponseCallback

Key Features:
    - **Response Configuration**: Set static, sequential, or dynamic responses.
    - **Content Matchers**: Declarative rules for conditional responses.
    - **Call Recording**: Track all method calls with rich inspection.
    - **Assertion API**: Verify calls, arguments, and scan behavior.
    - **Strict Mode**: Validate all configured responses were consumed.

Classes:
    MockCall: Dataclass recording details of a single method call.
    MockIcapClient: Synchronous mock implementing the full IcapClient interface.
    MockAsyncIcapClient: Asynchronous mock implementing the AsyncIcapClient interface.
    ResponseMatcher: Dataclass for content-based conditional responses.
    MatcherBuilder: Fluent builder for creating matchers via when().
    ResponseCallback: Protocol for dynamic response callbacks.
    AsyncResponseCallback: Protocol for async dynamic response callbacks.
    MockResponseExhaustedError: Raised when all queued responses are consumed.

Basic Example:
    >>> from icap.pytest_plugin import MockIcapClient, IcapResponseBuilder
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

See Also:
    icap.pytest_plugin: Main package with fixtures and builders.
    IcapResponseBuilder: Fluent builder for creating test responses.
"""

from __future__ import annotations

# Re-export all components for backward compatibility
from .call_record import MockCall, MockResponseExhaustedError
from .matchers import MatcherBuilder, ResponseMatcher
from .mock_async import MockAsyncIcapClient
from .mock_client import MockIcapClient
from .protocols import AsyncResponseCallback, ResponseCallback

__all__ = [
    "AsyncResponseCallback",
    "MatcherBuilder",
    "MockAsyncIcapClient",
    "MockCall",
    "MockIcapClient",
    "MockResponseExhaustedError",
    "ResponseCallback",
    "ResponseMatcher",
]
