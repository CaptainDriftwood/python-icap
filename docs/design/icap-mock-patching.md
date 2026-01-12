# Design: Automatic Import Patching for pytest_py_cap

This document analyzes design options for adding automatic monkeypatching functionality to the `pytest_py_cap` plugin, enabling seamless mocking of `IcapClient` usage in user code.

## Problem Statement

Currently, the pytest plugin provides mock client fixtures (`mock_icap_client`, `mock_async_icap_client`), but these don't automatically replace `IcapClient` behavior in user code.

When user code does:

```python
# myapp/scanner.py
from py_cap import IcapClient

def scan(data):
    client = IcapClient("localhost")
    return client.scan_bytes(data)
```

And a test uses:

```python
def test_scan(mock_icap_client):
    result = scan(b"content")  # Still uses REAL IcapClient!
    mock_icap_client.assert_called("scan_bytes")  # Fails - mock wasn't used
```

The mock fixture is injected into the test, but `scan()` still instantiates a real `IcapClient` internally.

---

## Industry Research: How Similar Libraries Handle This

### Summary of Approaches

| Library | Target Level | Auto-Intercept | User Setup Required |
|---------|--------------|----------------|---------------------|
| **responses** | `requests.Session.send` method | Yes (when activated) | Decorator/context manager |
| **moto** | botocore event system (`before-send`) | Yes (when activated) | Decorator/context manager |
| **respx** | HTTPX transport layer | Yes (when activated) | Decorator/context/fixture |
| **pytest-httpx** | HTTPX client internals | Yes (automatic) | Just use fixture |
| **httpretty** | Python socket/SSL modules | Yes (when activated) | Decorator/context manager |
| **pytest-mock** | Any Python object (explicit) | No | Must specify target path |

### Key Insight

**The most elegant solutions patch at a low architectural level** - a single interception point that ALL operations flow through. This eliminates the need for users to specify module paths.

- **responses**: Patches `requests.Session.send` - the single method all HTTP requests use
- **moto**: Hooks into botocore's `before-send` event handler
- **respx/pytest-httpx**: Replace the HTTPX transport layer
- **httpretty**: Patches Python's socket module (works with ANY HTTP library)

### Detailed Patterns

#### responses (for requests library)

```python
@responses.activate
def test_example():
    responses.add(responses.GET, 'http://example.com/', body='test')
    # ALL requests.get/post/etc calls are now intercepted
    result = requests.get('http://example.com/')
```

**How it works:**
- Patches `requests.adapters.HTTPAdapter.send()` method
- Uses `unittest.mock.patch` internally
- Maintains registry of mock responses
- No module path specification needed

#### moto (for AWS boto3)

```python
@mock_aws
def test_s3():
    client = boto3.client('s3', region_name='us-east-1')
    client.create_bucket(Bucket='mybucket')
    # ALL boto3 calls automatically mocked
```

**How it works:**
- Registers event handler on botocore's `before-send` event
- Event handler intercepts HTTP requests before they reach AWS
- Must be activated BEFORE creating boto3 clients
- No module path specification needed

#### pytest-httpx (for httpx)

```python
def test_example(httpx_mock):
    httpx_mock.add_response(status_code=200, content=b"test")
    # ALL httpx requests automatically intercepted
    response = httpx.get("https://example.com/")
```

**How it works:**
- Patches httpx transport layer
- Fixture auto-patches when used
- No decorator needed - just use the fixture
- No module path specification needed

---

## py_cap Architecture Analysis

Looking at the `IcapClient` implementation:

```python
# py_cap/icap.py
class IcapClient(IcapProtocol):
    def _send_and_receive(self, request: bytes) -> IcapResponse:
        """ALL operations flow through this method"""
        # ... socket operations ...

    def scan_bytes(self, data, service="avscan", filename=None):
        # ... builds request ...
        return self.respmod(service, http_request, http_response)

    def respmod(self, service, http_request, http_response, ...):
        # ... builds ICAP request ...
        return self._send_and_receive(request)  # <-- ALL roads lead here
```

**Key finding:** `_send_and_receive()` is the single method ALL sync operations flow through. Similarly, the async client likely has an equivalent method.

This means we can use the **same pattern as `responses`** - patch at the method level rather than requiring module path specification.

---

## Revised Design Options

### Option 1: Method-Level Patching (Recommended)

Patch `IcapClient._send_and_receive` and `AsyncIcapClient` equivalent at the class level.

**Usage:**

```python
# Simple - just use the fixture
def test_scan(icap_mock):
    # ALL IcapClient instances automatically use mock
    result = scan(b"content")
    icap_mock.assert_called("scan_bytes")

# Or with decorator for explicit activation
@pytest.mark.icap_mock
def test_scan(icap_mock):
    result = scan(b"content")
```

**Implementation:**

```python
# pytest_py_cap/patching.py
from __future__ import annotations

from typing import TYPE_CHECKING, Generator
from unittest.mock import patch, MagicMock

import pytest

from .mock import MockIcapClient, MockAsyncIcapClient
from .builder import IcapResponseBuilder

if TYPE_CHECKING:
    from _pytest.fixtures import FixtureRequest


class IcapMock:
    """
    Central mock controller that intercepts all IcapClient operations.

    Similar to how `responses` works for the requests library.
    """

    def __init__(self):
        self._sync_mock = MockIcapClient()
        self._async_mock = MockAsyncIcapClient()
        self._patches: list = []
        self._active = False

        # Track all client instances created while mock is active
        self._client_instances: list = []

    @property
    def sync(self) -> MockIcapClient:
        """Access the sync mock client for configuration and assertions."""
        return self._sync_mock

    @property
    def async_(self) -> MockAsyncIcapClient:
        """Access the async mock client for configuration and assertions."""
        return self._async_mock

    def start(self) -> None:
        """Activate mocking - intercept all IcapClient operations."""
        if self._active:
            return

        import py_cap
        from py_cap.icap import IcapClient
        from py_cap.async_icap import AsyncIcapClient

        # Store original methods
        self._original_send_receive = IcapClient._send_and_receive
        self._original_async_send_receive = getattr(
            AsyncIcapClient, '_send_and_receive', None
        )

        # Create interceptor that delegates to our mock
        def mock_send_receive(client_self, request: bytes):
            # Determine which method was called based on request content
            # and delegate to appropriate mock method
            return self._intercept_sync(client_self, request)

        async def mock_async_send_receive(client_self, request: bytes):
            return await self._intercept_async(client_self, request)

        # Patch at class level
        self._patches.append(
            patch.object(IcapClient, '_send_and_receive', mock_send_receive)
        )
        self._patches.append(
            patch.object(IcapClient, 'connect', lambda self: None)
        )
        self._patches.append(
            patch.object(IcapClient, 'disconnect', lambda self: None)
        )
        self._patches.append(
            patch.object(IcapClient, 'is_connected', property(lambda self: True))
        )

        # Same for async client
        self._patches.append(
            patch.object(AsyncIcapClient, '_send_and_receive', mock_async_send_receive)
        )

        for p in self._patches:
            p.start()

        self._active = True

    def stop(self) -> None:
        """Deactivate mocking - restore original behavior."""
        if not self._active:
            return

        for p in reversed(self._patches):
            p.stop()
        self._patches.clear()
        self._active = False

    def _intercept_sync(self, client, request: bytes):
        """Intercept sync client operations and return mock response."""
        # The mock client methods handle response generation
        # We just need to return an appropriate response based on configuration
        return self._sync_mock._get_next_response()

    async def _intercept_async(self, client, request: bytes):
        """Intercept async client operations and return mock response."""
        return self._async_mock._get_next_response()

    # Delegate common methods to sync mock for convenience
    def __getattr__(self, name: str):
        return getattr(self._sync_mock, name)

    def reset(self) -> None:
        """Reset all mock state."""
        self._sync_mock.reset_calls()
        self._sync_mock.reset_responses()
        self._async_mock.reset_calls()
        self._async_mock.reset_responses()


@pytest.fixture
def icap_mock() -> Generator[IcapMock, None, None]:
    """
    Fixture that automatically mocks all IcapClient operations.

    When this fixture is used, ANY IcapClient instance created during the test
    will have its network operations intercepted and handled by the mock.

    This works similarly to the `responses` library for `requests` or
    `moto` for boto3 - no need to specify which modules to patch.

    Example - Basic usage:
        def test_scan(icap_mock):
            # Your application code uses IcapClient normally
            from myapp.scanner import scan_file
            result = scan_file("/path/to/file")

            # Assert against the mock
            icap_mock.assert_called("scan_bytes")
            assert icap_mock.last_call.was_clean

    Example - Configure responses:
        def test_virus_detection(icap_mock):
            icap_mock.on_respmod(
                IcapResponseBuilder().virus("Trojan.Test").build()
            )

            result = scan_file("/path/to/file")
            assert not result.is_clean

    Example - Response sequences:
        def test_multiple_scans(icap_mock):
            icap_mock.on_respmod(
                IcapResponseBuilder().clean().build(),
                IcapResponseBuilder().virus("Malware").build(),
                IcapResponseBuilder().clean().build(),
            )

            assert scan(b"file1").is_clean      # First response
            assert not scan(b"file2").is_clean  # Second response (virus)
            assert scan(b"file3").is_clean      # Third response

    Example - Content-based matching:
        def test_conditional_response(icap_mock):
            icap_mock.when(filename_matches=r".*\\.exe$").respond(
                IcapResponseBuilder().virus("Blocked.Executable").build()
            )

            assert scan(b"data", filename="safe.txt").is_clean
            assert not scan(b"data", filename="app.exe").is_clean

    Example - Async code:
        async def test_async_scan(icap_mock):
            result = await async_scan(b"data")
            icap_mock.async_.assert_called("scan_bytes")
    """
    mock = IcapMock()
    mock.start()
    try:
        yield mock
    finally:
        mock.stop()


# Context manager for non-fixture usage
class icap_mock_context:
    """
    Context manager for mocking IcapClient operations.

    Example:
        with icap_mock_context() as mock:
            mock.on_respmod(IcapResponseBuilder().clean().build())
            result = scan_file("/path")
    """

    def __init__(self):
        self._mock = IcapMock()

    def __enter__(self) -> IcapMock:
        self._mock.start()
        return self._mock

    def __exit__(self, *args) -> None:
        self._mock.stop()


# Decorator for explicit activation
def activate_icap_mock(func):
    """
    Decorator to activate ICAP mocking for a test function.

    Example:
        @activate_icap_mock
        def test_scan():
            # IcapClient is mocked within this function
            result = scan_file("/path")
    """
    def wrapper(*args, **kwargs):
        with icap_mock_context() as mock:
            # Inject mock as first argument if function expects it
            import inspect
            sig = inspect.signature(func)
            if 'icap_mock' in sig.parameters:
                kwargs['icap_mock'] = mock
            return func(*args, **kwargs)
    return wrapper
```

**Pros:**
- No module path specification needed (like `responses`, `moto`)
- Works with ANY code that uses `IcapClient`
- Familiar pattern for users of `responses` or `moto`
- Clean API

**Cons:**
- More complex implementation
- Must handle all client methods appropriately

---

### Option 2: Module-Level Patching (Simpler but Less Elegant)

Requires users to specify which modules to patch.

**Usage:**

```python
@pytest.mark.patch_icap("myapp.scanner")
def test_scan(icap_mock):
    result = scan(b"content")
    icap_mock.assert_called("scan_bytes")
```

**Implementation:** (See previous version of this document)

**Pros:**
- Simpler to implement
- Explicit about what's being patched

**Cons:**
- Users must know/specify module paths
- Less elegant than industry-standard solutions
- Verbose for projects with many modules

---

### Option 3: Hybrid (Both Approaches)

Provide both automatic class-level patching AND explicit module targeting.

```python
# Automatic - works for most cases
def test_scan(icap_mock):
    result = scan(b"content")

# Explicit - for edge cases or clarity
@pytest.mark.patch_icap("myapp.scanner.IcapClient")
def test_specific(icap_mock):
    result = scan(b"content")
```

---

## Recommended Approach

**Option 1: Method-Level Patching** is recommended because:

1. **Industry standard**: Matches `responses`, `moto`, `respx`, `pytest-httpx`
2. **Better UX**: No module path specification needed
3. **Just works**: Users don't need to understand Python import mechanics
4. **Future-proof**: Works with any code structure

### Implementation Considerations

1. **Intercept at `_send_and_receive`**: This is the single point ALL operations flow through
2. **Track method context**: Need to determine which high-level method was called (scan_bytes, respmod, etc.)
3. **Handle both sync and async**: Patch both client implementations
4. **Mock connection state**: Override `connect()`, `disconnect()`, `is_connected`

### API Design

```python
# Fixture provides full mock control
def test_scan(icap_mock):
    # Configure responses
    icap_mock.on_respmod(IcapResponseBuilder().clean().build())

    # Configure error injection
    icap_mock.on_any(raises=IcapTimeoutError("timeout"))

    # Configure conditional responses
    icap_mock.when(filename="virus.exe").respond(
        IcapResponseBuilder().virus().build()
    )

    # Run test
    result = my_app.scan(b"data")

    # Assertions
    icap_mock.assert_called("scan_bytes")
    icap_mock.assert_scanned(b"data")
    assert icap_mock.call_count == 1
```

---

## Comparison Summary

| Approach | Module Paths Needed | Industry Standard | Implementation Complexity |
|----------|---------------------|-------------------|---------------------------|
| Option 1: Method-Level | No | Yes (like responses/moto) | Medium |
| Option 2: Module-Level | Yes | No (like pytest-mock) | Low |
| Option 3: Hybrid | Optional | Partial | High |

---

## Integration Steps

1. **Analyze async client**: Verify `AsyncIcapClient` has equivalent interception point
2. **Implement `IcapMock` class**: Central controller for all mocking
3. **Update mock clients**: Ensure `MockIcapClient` can be used as response source
4. **Create fixture**: `icap_mock` fixture that activates/deactivates patching
5. **Add context manager**: For non-pytest usage
6. **Add decorator**: For explicit activation pattern
7. **Write tests**: Comprehensive test coverage for patching behavior
8. **Update documentation**: Usage examples and migration guide

---

## Alternative: Keep Current Approach

If the complexity isn't justified, the current approach of providing mock objects and letting users handle patching is valid. Document recommended patterns:

1. **Dependency Injection** - Pass clients as function parameters
2. **pytest `monkeypatch`** - Use pytest's built-in fixture
3. **`unittest.mock.patch`** - Standard library patching

This keeps the plugin simple while still providing high-quality mock objects.

---

## References

- [responses library](https://github.com/getsentry/responses) - Mock for requests
- [moto library](https://docs.getmoto.org/) - Mock for AWS boto3
- [respx library](https://lundberg.github.io/respx/) - Mock for httpx
- [pytest-httpx](https://colin-b.github.io/pytest_httpx/) - pytest plugin for httpx
- [httpretty](https://httpretty.readthedocs.io/) - Socket-level HTTP mocking
- [pytest-mock](https://pytest-mock.readthedocs.io/) - General mocking for pytest