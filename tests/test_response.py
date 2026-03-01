"""
Unit tests for IcapResponse and CaseInsensitiveDict.

These tests verify correct parsing of ICAP responses, including
header handling per RFC 3507 and RFC 7230.
"""

import pytest

from icap import CaseInsensitiveDict, IcapResponse

# =============================================================================
# CaseInsensitiveDict tests
# =============================================================================


def test_case_insensitive_dict_basic():
    """Basic case-insensitive key access."""
    headers = CaseInsensitiveDict()
    headers["X-Virus-ID"] = "EICAR"

    assert headers["X-Virus-ID"] == "EICAR"
    assert headers["x-virus-id"] == "EICAR"
    assert headers["X-VIRUS-ID"] == "EICAR"
    assert headers["x-Virus-Id"] == "EICAR"


def test_case_insensitive_dict_contains():
    """Case-insensitive 'in' operator."""
    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "text/plain"

    assert "Content-Type" in headers
    assert "content-type" in headers
    assert "CONTENT-TYPE" in headers
    assert "X-Missing" not in headers


def test_case_insensitive_dict_get():
    """Case-insensitive get() method."""
    headers = CaseInsensitiveDict()
    headers["X-Virus-ID"] = "EICAR"

    assert headers.get("X-Virus-ID") == "EICAR"
    assert headers.get("x-virus-id") == "EICAR"
    assert headers.get("X-Missing") is None
    assert headers.get("X-Missing", "default") == "default"


def test_case_insensitive_dict_preserves_original_case():
    """Original case is preserved when iterating."""
    headers = CaseInsensitiveDict()
    headers["X-Virus-ID"] = "EICAR"
    headers["Content-Type"] = "text/plain"

    keys = list(headers.keys())
    assert "X-Virus-ID" in keys
    assert "Content-Type" in keys


def test_case_insensitive_dict_overwrite():
    """Setting with different case overwrites value."""
    headers = CaseInsensitiveDict()
    headers["X-Virus-ID"] = "first"
    headers["x-virus-id"] = "second"

    assert len(headers) == 1
    assert headers["X-Virus-ID"] == "second"


def test_case_insensitive_dict_delete():
    """Case-insensitive deletion."""
    headers = CaseInsensitiveDict()
    headers["X-Virus-ID"] = "EICAR"

    del headers["x-virus-id"]
    assert "X-Virus-ID" not in headers


def test_case_insensitive_dict_init_with_data():
    """Initialize with existing dictionary."""
    headers = CaseInsensitiveDict({"X-Virus-ID": "EICAR", "Content-Type": "text/plain"})

    assert headers["x-virus-id"] == "EICAR"
    assert headers["content-type"] == "text/plain"


def test_case_insensitive_dict_repr():
    """String representation."""
    headers = CaseInsensitiveDict()
    headers["X-Test"] = "value"

    assert "X-Test" in repr(headers)
    assert "value" in repr(headers)


# =============================================================================
# IcapResponse header parsing tests
# =============================================================================


def test_parse_header_case_insensitive():
    """Parsed headers should be case-insensitive (RFC 3507)."""
    data = b"ICAP/1.0 200 OK\r\nX-Virus-ID: EICAR\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Virus-ID"] == "EICAR"
    assert response.headers["x-virus-id"] == "EICAR"
    assert response.headers["X-VIRUS-ID"] == "EICAR"


def test_parse_duplicate_headers_combined():
    """Duplicate headers should be combined with comma (RFC 7230 Section 3.2.2)."""
    data = b"ICAP/1.0 200 OK\r\nX-Tag: first\r\nX-Tag: second\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Tag"] == "first, second"


def test_parse_duplicate_headers_case_insensitive():
    """Duplicate headers with different case should still be combined."""
    data = b"ICAP/1.0 200 OK\r\nX-Tag: first\r\nx-tag: second\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Tag"] == "first, second"


def test_parse_header_value_with_colon():
    """Header values containing colons should be preserved."""
    data = b"ICAP/1.0 200 OK\r\nX-Timestamp: 2024-01-15T12:30:00Z\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Timestamp"] == "2024-01-15T12:30:00Z"


def test_parse_header_empty_value():
    """Headers with empty values should be handled."""
    data = b"ICAP/1.0 200 OK\r\nX-Empty:\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Empty"] == ""


def test_parse_header_whitespace_preserved():
    """Internal whitespace in header values should be preserved."""
    data = b"ICAP/1.0 200 OK\r\nX-Message: hello   world\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Message"] == "hello   world"


def test_parse_header_leading_trailing_whitespace_stripped():
    """Leading and trailing whitespace in values should be stripped."""
    data = b"ICAP/1.0 200 OK\r\nX-Padded:   value   \r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Padded"] == "value"


def test_parse_header_with_utf8():
    """UTF-8 characters in header values should be handled."""
    data = "ICAP/1.0 200 OK\r\nX-Info: café résumé\r\n\r\n".encode("utf-8")
    response = IcapResponse.parse(data)

    assert response.headers["X-Info"] == "café résumé"


def test_parse_header_with_equals():
    """Header values with equals signs should be preserved."""
    data = b"ICAP/1.0 200 OK\r\nX-Auth: token=abc123\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Auth"] == "token=abc123"


def test_parse_header_with_semicolon():
    """Header values with semicolons should be preserved."""
    data = b"ICAP/1.0 200 OK\r\nX-Options: a=1; b=2; c=3\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-Options"] == "a=1; b=2; c=3"


def test_parse_multiple_colons_in_value():
    """Multiple colons in value should all be preserved."""
    data = b"ICAP/1.0 200 OK\r\nX-URL: http://example.com:8080/path\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.headers["X-URL"] == "http://example.com:8080/path"


def test_response_init_converts_dict_to_case_insensitive():
    """IcapResponse.__init__ should convert regular dict to CaseInsensitiveDict."""
    response = IcapResponse(200, "OK", {"X-Virus-ID": "EICAR"}, b"")

    assert response.headers["x-virus-id"] == "EICAR"
    assert isinstance(response.headers, CaseInsensitiveDict)


def test_response_init_accepts_case_insensitive_dict():
    """IcapResponse.__init__ should accept CaseInsensitiveDict directly."""
    headers = CaseInsensitiveDict({"X-Test": "value"})
    response = IcapResponse(200, "OK", headers, b"")

    assert response.headers is headers


# =============================================================================
# IcapResponse basic parsing tests
# =============================================================================


def test_parse_basic_response():
    """Basic response parsing."""
    data = b"ICAP/1.0 204 No Content\r\n\r\n"
    response = IcapResponse.parse(data)

    assert response.status_code == 204
    assert response.status_message == "No Content"
    assert response.is_no_modification
    assert response.is_success


def test_parse_response_with_body():
    """Response with body content."""
    data = b"ICAP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    response = IcapResponse.parse(data)

    assert response.status_code == 200
    assert response.body == b"hello"


def test_parse_invalid_status_line():
    """Invalid status line should raise ValueError."""
    data = b"INVALID\r\n\r\n"

    with pytest.raises(ValueError, match="Invalid ICAP status line"):
        IcapResponse.parse(data)
