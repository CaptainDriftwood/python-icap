"""
Property-based fuzzing tests using Hypothesis.

These tests use random input generation to find edge cases in parsing
and validation logic that might not be caught by example-based tests.
"""

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from icap import IcapResponse
from icap._protocol import (
    parse_chunk_size,
    parse_response_headers,
    validate_body_size,
    validate_content_length,
)
from icap.exception import IcapProtocolError
from icap.response import EncapsulatedParts

# =============================================================================
# IcapResponse.parse() fuzzing
# =============================================================================


@given(st.binary())
@settings(max_examples=500)
def test_fuzz_response_parse_arbitrary_bytes(data: bytes):
    """IcapResponse.parse should never crash on arbitrary bytes.

    It should either:
    - Return a valid IcapResponse
    - Raise ValueError for malformed input
    """
    try:
        response = IcapResponse.parse(data)
        # If parsing succeeds, verify basic invariants
        assert isinstance(response.status_code, int)
        assert isinstance(response.status_message, str)
        assert isinstance(response.body, bytes)
    except ValueError:
        pass  # Expected for malformed input


@given(
    status_code=st.integers(min_value=100, max_value=599),
    status_message=st.text(min_size=1, max_size=50).filter(
        lambda s: "\r" not in s and "\n" not in s
    ),
)
@settings(max_examples=200)
def test_fuzz_response_parse_valid_status_line(status_code: int, status_message: str):
    """Valid status lines should always parse successfully."""
    data = f"ICAP/1.0 {status_code} {status_message}\r\n\r\n".encode()
    response = IcapResponse.parse(data)

    assert response.status_code == status_code
    assert response.status_message == status_message


@given(status_code=st.integers().filter(lambda x: x < 100 or x > 599))
@settings(max_examples=100)
def test_fuzz_response_parse_invalid_status_code(status_code: int):
    """Status codes outside 100-599 should raise ValueError."""
    data = f"ICAP/1.0 {status_code} Test\r\n\r\n".encode()

    with pytest.raises(ValueError, match="Invalid ICAP status code"):
        IcapResponse.parse(data)


@given(
    header_name=st.text(
        alphabet=st.characters(blacklist_categories=("Cc", "Cs"), blacklist_characters=":\r\n"),
        min_size=1,
        max_size=30,
    ),
    header_value=st.text(max_size=100).filter(lambda s: "\r" not in s and "\n" not in s),
)
@settings(max_examples=200)
def test_fuzz_response_parse_headers(header_name: str, header_value: str):
    """Headers should be parsed correctly regardless of content."""
    # Skip header names that would be stripped to empty
    assume(header_name.strip())

    data = f"ICAP/1.0 200 OK\r\n{header_name}: {header_value}\r\n\r\n".encode()

    try:
        response = IcapResponse.parse(data)
        # Header should be accessible (case-insensitive)
        # Note: header name gets stripped, so compare stripped versions
        stripped_name = header_name.strip()
        assert stripped_name in response.headers or stripped_name.lower() in response.headers
    except ValueError:
        pass  # Some header names may be invalid


# =============================================================================
# parse_chunk_size() fuzzing
# =============================================================================


@given(chunk_size=st.integers(min_value=0, max_value=100_000_000))
@settings(max_examples=300)
def test_fuzz_chunk_size_valid_hex(chunk_size: int):
    """Valid hex chunk sizes should parse correctly."""
    size_line = f"{chunk_size:X}".encode()
    max_size = 100_000_001  # Larger than any generated value

    result = parse_chunk_size(size_line, max_size)
    assert result == chunk_size


@given(chunk_size=st.integers(min_value=0, max_value=1000))
@settings(max_examples=100)
def test_fuzz_chunk_size_with_extension(chunk_size: int):
    """Chunk sizes with extensions should parse correctly."""
    size_line = f"{chunk_size:X}; ieof".encode()
    max_size = 10_000

    result = parse_chunk_size(size_line, max_size)
    assert result == chunk_size


@given(chunk_size=st.integers(min_value=1001, max_value=10000))
@settings(max_examples=100)
def test_fuzz_chunk_size_exceeds_max(chunk_size: int):
    """Chunk sizes exceeding max should raise IcapProtocolError."""
    size_line = f"{chunk_size:X}".encode()
    max_size = 1000

    with pytest.raises(IcapProtocolError, match="exceeds maximum"):
        parse_chunk_size(size_line, max_size)


@given(data=st.binary())
@settings(max_examples=300)
def test_fuzz_chunk_size_arbitrary_bytes(data: bytes):
    """parse_chunk_size should handle arbitrary bytes without crashing.

    It should either return a valid size or raise IcapProtocolError.
    """
    max_size = 100_000_000

    try:
        result = parse_chunk_size(data, max_size)
        assert isinstance(result, int)
        assert result >= 0
        assert result <= max_size
    except IcapProtocolError:
        pass  # Expected for invalid input


# =============================================================================
# parse_response_headers() fuzzing
# =============================================================================


@given(content_length=st.integers(min_value=0, max_value=1_000_000_000))
@settings(max_examples=200)
def test_fuzz_response_headers_valid_content_length(content_length: int):
    """Valid Content-Length values should parse correctly."""
    headers_str = f"ICAP/1.0 200 OK\r\nContent-Length: {content_length}"

    result = parse_response_headers(headers_str)
    assert result.content_length == content_length
    assert result.is_chunked is False


@given(content_length=st.integers(max_value=-1))
@settings(max_examples=100)
def test_fuzz_response_headers_negative_content_length(content_length: int):
    """Negative Content-Length should raise IcapProtocolError."""
    headers_str = f"ICAP/1.0 200 OK\r\nContent-Length: {content_length}"

    with pytest.raises(IcapProtocolError, match="must be non-negative"):
        parse_response_headers(headers_str)


def test_fuzz_response_headers_chunked():
    """Transfer-Encoding: chunked should be detected."""
    headers_str = "ICAP/1.0 200 OK\r\nTransfer-Encoding: chunked"

    result = parse_response_headers(headers_str)
    assert result.is_chunked is True
    assert result.content_length is None


@given(header_value=st.text(max_size=50).filter(lambda s: "\r" not in s and "\n" not in s))
@settings(max_examples=100)
def test_fuzz_response_headers_invalid_content_length(header_value: str):
    """Non-numeric Content-Length should raise IcapProtocolError."""
    # Filter out values that could be valid integers
    assume(not header_value.strip().lstrip("-").isdigit())
    assume(header_value.strip())  # Must have some content

    headers_str = f"ICAP/1.0 200 OK\r\nContent-Length: {header_value}"

    with pytest.raises(IcapProtocolError, match="Invalid Content-Length"):
        parse_response_headers(headers_str)


# =============================================================================
# EncapsulatedParts.parse() fuzzing
# =============================================================================


@given(offset=st.integers(min_value=0, max_value=1_000_000))
@settings(max_examples=200)
def test_fuzz_encapsulated_valid_offsets(offset: int):
    """Valid offsets should parse correctly."""
    header_value = f"res-hdr=0, res-body={offset}"

    result = EncapsulatedParts.parse(header_value)
    assert result.res_hdr == 0
    assert result.res_body == offset


@given(
    req_hdr=st.integers(min_value=0, max_value=1000),
    res_hdr=st.integers(min_value=0, max_value=1000),
    res_body=st.integers(min_value=0, max_value=10000),
)
@settings(max_examples=200)
def test_fuzz_encapsulated_multiple_fields(req_hdr: int, res_hdr: int, res_body: int):
    """Multiple fields should all be parsed."""
    header_value = f"req-hdr={req_hdr}, res-hdr={res_hdr}, res-body={res_body}"

    result = EncapsulatedParts.parse(header_value)
    assert result.req_hdr == req_hdr
    assert result.res_hdr == res_hdr
    assert result.res_body == res_body


@given(offset=st.integers(max_value=-1))
@settings(max_examples=100)
def test_fuzz_encapsulated_negative_offset(offset: int):
    """Negative offsets should be silently ignored (treated as invalid)."""
    header_value = f"res-body={offset}"

    result = EncapsulatedParts.parse(header_value)
    # Negative offsets are ignored, field remains None
    assert result.res_body is None


@given(header_value=st.text(max_size=200))
@settings(max_examples=300)
def test_fuzz_encapsulated_arbitrary_text(header_value: str):
    """EncapsulatedParts.parse should handle arbitrary text without crashing.

    It should either parse valid fields or silently ignore invalid segments.
    """
    result = EncapsulatedParts.parse(header_value)

    # Result should always be a valid EncapsulatedParts instance
    assert isinstance(result, EncapsulatedParts)
    # All fields should be None or valid integers
    for field in [
        result.req_hdr,
        result.req_body,
        result.res_hdr,
        result.res_body,
        result.null_body,
        result.opt_body,
    ]:
        assert field is None or isinstance(field, int)


# =============================================================================
# validate_body_size() and validate_content_length() fuzzing
# =============================================================================


@given(
    current_size=st.integers(min_value=0, max_value=1_000_000),
    max_size=st.integers(min_value=1, max_value=1_000_000),
)
@settings(max_examples=200)
def test_fuzz_validate_body_size(current_size: int, max_size: int):
    """validate_body_size should raise only when size exceeds max."""
    if current_size > max_size:
        with pytest.raises(IcapProtocolError, match="exceeds maximum"):
            validate_body_size(current_size, max_size)
    else:
        # Should not raise
        validate_body_size(current_size, max_size)


@given(
    content_length=st.integers(min_value=0, max_value=1_000_000),
    max_size=st.integers(min_value=1, max_value=1_000_000),
)
@settings(max_examples=200)
def test_fuzz_validate_content_length(content_length: int, max_size: int):
    """validate_content_length should raise only when length exceeds max."""
    if content_length > max_size:
        with pytest.raises(IcapProtocolError, match="exceeds maximum"):
            validate_content_length(content_length, max_size)
    else:
        # Should not raise
        validate_content_length(content_length, max_size)
