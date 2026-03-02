"""
Content matchers for conditional mock responses.

This module provides declarative matching rules for MockIcapClient,
allowing responses to be configured based on service name, filename,
or content patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from icap import IcapResponse

    from .mock_client import MockIcapClient


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


__all__ = ["ResponseMatcher", "MatcherBuilder"]
