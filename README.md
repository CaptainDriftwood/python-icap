<p align="center">
  <img src=".github/assets/logo.svg" alt="python-icap logo" width="450">
</p>
<h1 align="center">python-icap</h1>

[![Tests](https://github.com/CaptainDriftwood/python-icap/actions/workflows/test.yml/badge.svg)](https://github.com/CaptainDriftwood/python-icap/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/CaptainDriftwood/python-icap/graph/badge.svg)](https://codecov.io/gh/CaptainDriftwood/python-icap)
[![Lint](https://github.com/CaptainDriftwood/python-icap/actions/workflows/lint.yml/badge.svg)](https://github.com/CaptainDriftwood/python-icap/actions/workflows/lint.yml)
[![Type Check](https://github.com/CaptainDriftwood/python-icap/actions/workflows/typecheck.yml/badge.svg)](https://github.com/CaptainDriftwood/python-icap/actions/workflows/typecheck.yml)
[![CodeQL](https://github.com/CaptainDriftwood/python-icap/actions/workflows/codeql.yml/badge.svg)](https://github.com/CaptainDriftwood/python-icap/actions/workflows/codeql.yml)

[![Python 3.8 | 3.9 | 3.10 | 3.11 | 3.12 | 3.13 | 3.14](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)

A pure Python ICAP (Internet Content Adaptation Protocol) client with no external dependencies. Implements RFC 3507 for communicating with ICAP servers like c-icap and SquidClamav, supporting OPTIONS, REQMOD, and RESPMOD methods.

## Table of Contents

- [Overview](#overview)
- [What is ICAP?](#what-is-icap)
  - [Key Differences from HTTP](#key-differences-from-http)
  - [How ICAP Works](#how-icap-works)
  - [How ICAP Packages HTTP Content](#how-icap-packages-http-content)
  - [ICAP Methods](#icap-methods)
  - [Common Use Cases](#common-use-cases)
- [ICAP Servers and Tools](#icap-servers-and-tools)
  - [c-icap](#c-icap)
  - [SquidClamav](#squidclamav)
  - [ClamAV](#clamav)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [Using Context Manager](#using-context-manager)
  - [Scanning Content with RESPMOD](#scanning-content-with-respmod)
  - [Scanning Files](#scanning-files)
  - [Manual File Scanning (lower-level API)](#manual-file-scanning-lower-level-api)
- [Async Usage](#async-usage)
  - [Basic Async Example](#basic-async-example)
  - [Concurrent Scanning](#concurrent-scanning)
- [SSL/TLS Support](#ssltls-support)
  - [Basic TLS Connection](#basic-tls-connection)
  - [TLS with Custom CA Certificate](#tls-with-custom-ca-certificate)
  - [TLS with Client Certificate Authentication](#tls-with-client-certificate-authentication)
  - [Async Client with TLS](#async-client-with-tls)
- [Logging](#logging)
- [Error Handling](#error-handling)
- [Testing Virus Detection with EICAR](#testing-virus-detection-with-eicar)
- [Docker Integration Testing](#docker-integration-testing)
  - [Docker Services](#docker-services)
- [Development](#development)
  - [Setup](#setup)
  - [Project Structure](#project-structure)
- [Pytest Plugin](#pytest-plugin)
  - [Live Client Fixtures](#live-client-fixtures)
  - [Mock Client Fixtures](#mock-client-fixtures)
  - [Response Fixtures](#response-fixtures)
  - [IcapResponseBuilder](#icapresponsebuilder)
  - [MockIcapClient](#mockicapclient)
  - [icap_mock Marker](#icap_mock-marker)
- [Protocol Reference](#protocol-reference)
- [License](#license)

## Overview

python-icap provides a clean, Pythonic API for integrating ICAP into your applications:

- **Sync and async clients** - Both `IcapClient` and `AsyncIcapClient` with full API parity
- **High-level file scanning** - Simple `scan_file()`, `scan_bytes()`, and `scan_stream()` methods
- **SSL/TLS support** - Secure connections with custom certificates and mutual TLS
- **Pytest plugin** - Mock clients and fixtures for testing without a live server
- **Zero dependencies** - Pure Python stdlib implementation

## What is ICAP?

**ICAP (Internet Content Adaptation Protocol)** is a simple protocol that lets network devices (like proxies) send HTTP content to a separate server for inspection or modification before passing it along.

Think of it this way:
- **Without ICAP**: A proxy receives an HTTP response and forwards it directly to the client
- **With ICAP**: The proxy first asks an ICAP server "Is this content safe/appropriate?" before forwarding

ICAP is essentially a **wrapper around HTTP messages**. The proxy packages up the HTTP request or response and sends it to the ICAP server using ICAP's own simple format. The ICAP server can then:
- **Approve it** (204 No Modification) - "Looks fine, send it as-is"
- **Modify it** (200 OK with modified content) - "Here's a cleaned-up version"
- **Block it** (200 OK with error page) - "This contains a virus, show this warning instead"

### Key Differences from HTTP

| Aspect | HTTP | ICAP |
|--------|------|------|
| Default port | 80 (or 443 for HTTPS) | 1344 |
| Purpose | Transfer web content | Inspect/modify HTTP content |
| Request types | GET, POST, PUT, DELETE, etc. | OPTIONS, REQMOD, RESPMOD |
| Used by | Browsers, apps, servers | Proxies, security appliances |

ICAP was designed to be HTTP-like so that developers familiar with HTTP can easily understand it. The main difference is that ICAP **carries HTTP messages inside it** rather than being an HTTP message itself.

### How ICAP Works

```
┌──────────┐     HTTP Request      ┌──────────────┐    ICAP Request    ┌─────────────┐
│  Client  │ ──────────────────▶   │  HTTP Proxy  │ ────────────────▶  │ ICAP Server │
│          │                       │  (e.g. Squid)│                    │ (e.g. c-icap│
│          │                       │              │ ◀────────────────  │  + ClamAV)  │
│          │ ◀──────────────────   │              │    ICAP Response   │             │
└──────────┘     HTTP Response     └──────────────┘    (modified/clean)└─────────────┘
```

1. **Client** sends HTTP request to a **proxy server**
2. **Proxy** forwards the request/response to an **ICAP server** for inspection
3. **ICAP server** scans, modifies, or approves the content
4. **Proxy** returns the (possibly modified) response to the client

### How ICAP Packages HTTP Content

When ICAP sends HTTP content to the server, it uses the `Encapsulated` header to tell the server where each piece of the HTTP message begins:

```
Encapsulated: req-hdr=0, res-hdr=45, res-body=128
```

This means:
- HTTP request headers start at byte 0
- HTTP response headers start at byte 45
- HTTP response body starts at byte 128

This allows the ICAP server to efficiently parse the message without scanning through the entire content. The body portion uses **chunked transfer encoding** (the same technique HTTP uses for streaming) so content can be processed incrementally.

### ICAP Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| **OPTIONS** | Query server capabilities | Check what services are available, preview sizes, etc. |
| **REQMOD** | Request Modification | Scan uploads, filter outbound requests, access control |
| **RESPMOD** | Response Modification | Virus scanning, content filtering, ad insertion, language translation |

### Common Use Cases

- **Antivirus scanning** - Scan downloads for malware (ClamAV, Sophos, etc.)
- **Content filtering** - Block inappropriate content, enforce policies
- **Data Loss Prevention (DLP)** - Scan uploads for sensitive data
- **Ad insertion** - Insert advertisements into cached content
- **Format conversion** - Adapt content for mobile devices

## ICAP Servers and Tools

### c-icap

[c-icap](https://c-icap.sourceforge.net/) is the most popular open-source ICAP server implementation. It provides:

- Full ICAP protocol support (RFC 3507)
- Plugin architecture for custom services
- ICAP over TLS support
- C API for developing content adaptation services

**Resources:**
- [Official Website](https://c-icap.sourceforge.net/)
- [GitHub Repository](https://github.com/c-icap/c-icap-server)
- [Documentation](https://c-icap.sourceforge.net/documentation.html)
- [Configuration Wiki](https://sourceforge.net/p/c-icap/wiki/configcicap/)

### SquidClamav

[SquidClamav](https://squidclamav.darold.net/) is a dedicated ClamAV antivirus service for ICAP. It provides:

- High-performance virus scanning for HTTP traffic
- Integration with ClamAV and Google Safe Browsing
- Configurable file type and content-type filtering
- Failover support for multiple ClamAV servers

**Resources:**
- [Official Website](https://squidclamav.darold.net/)
- [Documentation](https://squidclamav.darold.net/documentation.html)
- [GitHub Repository](https://github.com/darold/squidclamav)

### ClamAV

[ClamAV](https://www.clamav.net/) is an open-source antivirus engine used by SquidClamav:

- Regular virus definition updates
- Supports multiple file formats and archives
- clamd daemon for high-performance scanning
- Google Safe Browsing database integration

## Installation

> **Note:** This package is not yet published to PyPI due to a name collision. Install directly from source.

```bash
# Standard installation
pip install .

# Development installation (editable)
pip install -e .
```

## Usage

### Basic Example

```python
from icap import IcapClient

# Create client and connect
client = IcapClient('localhost', port=1344)
client.connect()

# Check server options
response = client.options('avscan')
print(f"Status: {response.status_code} - {response.status_message}")

# Disconnect when done
client.disconnect()
```

### Using Context Manager

```python
from icap import IcapClient

# Automatically handles connection/disconnection
with IcapClient('localhost', port=1344) as client:
    response = client.options('avscan')
    print(f"Status: {response.status_code}")
```

### Scanning Content with RESPMOD

```python
from icap import IcapClient

# HTTP request headers
http_request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"

# HTTP response to scan
http_response = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: 13\r
\r
Hello, World!"""

with IcapClient('localhost', port=1344) as client:
    response = client.respmod('avscan', http_request, http_response)
    
    if response.is_no_modification:
        print("Content is clean (204 No Modification)")
    elif response.is_success:
        print(f"Content modified: {response.body}")
    else:
        print(f"Error: {response.status_code}")
```

### Scanning Files

The library provides convenient methods for scanning files directly:

```python
from icap import IcapClient
from pathlib import Path

# Scan a file by path (string)
with IcapClient('localhost') as client:
    response = client.scan_file('/path/to/file.pdf')
    if response.is_no_modification:
        print("File is clean")
    else:
        print("File contains threats")

# Scan a file using pathlib.Path object
with IcapClient('localhost') as client:
    file_path = Path('/path/to/document.pdf')
    response = client.scan_file(file_path)
    if response.is_no_modification:
        print("File is clean")

# Scan a file-like object (stream)
with open('document.pdf', 'rb') as f:
    with IcapClient('localhost') as client:
        response = client.scan_stream(f, filename='document.pdf')
        if response.is_no_modification:
            print("Stream is clean")

# Scan bytes content directly
with IcapClient('localhost') as client:
    content = b"Some file content or data"
    response = client.scan_bytes(content, filename='data.bin')
    if response.is_no_modification:
        print("Content is clean")
```

### Manual File Scanning (lower-level API)

```python
from icap import IcapClient

def scan_file(filepath, icap_host='localhost', service='avscan'):
    """Scan a file using ICAP (lower-level approach)."""
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # Build HTTP response with file content
    http_response = f"""HTTP/1.1 200 OK\r
Content-Type: application/octet-stream\r
Content-Length: {len(content)}\r
\r
""".encode() + content
    
    http_request = b"GET / HTTP/1.1\r\nHost: file-scan\r\n\r\n"
    
    with IcapClient(icap_host) as client:
        response = client.respmod(service, http_request, http_response)
        return response.is_no_modification  # True if clean

# Example usage
if scan_file('/path/to/file.pdf'):
    print("File is clean")
else:
    print("File contains threats")
```

## Async Usage

python-icap includes an async client (`AsyncIcapClient`) for use with `asyncio`. The async client provides the same API as the sync client but with `async`/`await` syntax.

### Basic Async Example

```python
import asyncio
from icap import AsyncIcapClient

async def main():
    async with AsyncIcapClient('localhost', port=1344) as client:
        # Check server options
        response = await client.options('avscan')
        print(f"Status: {response.status_code}")

        # Scan content
        response = await client.scan_bytes(b"Hello, World!", filename="test.txt")
        if response.is_no_modification:
            print("Content is clean")

asyncio.run(main())
```

### Concurrent Scanning

The async client enables scanning multiple files concurrently for improved throughput:

```python
import asyncio
from icap import AsyncIcapClient

async def scan_file(filepath: str) -> tuple[str, bool]:
    """Scan a single file and return (filepath, is_clean)."""
    async with AsyncIcapClient('localhost', port=1344) as client:
        response = await client.scan_file(filepath)
        return filepath, response.is_no_modification

async def scan_multiple_files(files: list[str]) -> dict[str, bool]:
    """Scan multiple files concurrently."""
    tasks = [scan_file(f) for f in files]
    results = await asyncio.gather(*tasks)
    return dict(results)

# Example usage
async def main():
    files = ['/path/to/file1.pdf', '/path/to/file2.doc', '/path/to/file3.txt']
    results = await scan_multiple_files(files)

    for filepath, is_clean in results.items():
        status = "clean" if is_clean else "THREAT DETECTED"
        print(f"{filepath}: {status}")

asyncio.run(main())
```

**Note:** Each `AsyncIcapClient` instance creates its own connection. For true concurrency, create multiple client instances (one per concurrent scan) as shown above.

## SSL/TLS Support

Both sync and async clients support SSL/TLS encryption for secure connections to ICAP servers. Pass an `ssl.SSLContext` to the client constructor:

### Basic TLS Connection

```python
import ssl
from icap import IcapClient

# Create SSL context with system CA certificates
ssl_context = ssl.create_default_context()

with IcapClient('icap.example.com', ssl_context=ssl_context) as client:
    response = client.scan_bytes(b"content to scan")
    print(f"Clean: {response.is_no_modification}")
```

### TLS with Custom CA Certificate

```python
import ssl
from icap import IcapClient

# Use a custom CA certificate
ssl_context = ssl.create_default_context(cafile='/path/to/ca.pem')

with IcapClient('icap.example.com', ssl_context=ssl_context) as client:
    response = client.scan_file('/path/to/file.pdf')
```

### TLS with Client Certificate Authentication

```python
import ssl
from icap import IcapClient

# Create context with client certificate for mutual TLS
ssl_context = ssl.create_default_context()
ssl_context.load_cert_chain(
    certfile='/path/to/client.pem',
    keyfile='/path/to/client-key.pem'
)

with IcapClient('icap.example.com', ssl_context=ssl_context) as client:
    response = client.options('avscan')
```

### Async Client with TLS

```python
import asyncio
import ssl
from icap import AsyncIcapClient

async def secure_scan():
    ssl_context = ssl.create_default_context()

    async with AsyncIcapClient('icap.example.com', ssl_context=ssl_context) as client:
        response = await client.scan_bytes(b"content")
        print(f"Clean: {response.is_no_modification}")

asyncio.run(secure_scan())
```

## Logging

The library uses Python's standard `logging` module. Configure it to see detailed operation logs:

```python
import logging
from icap import IcapClient

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Now all ICAP operations will be logged
with IcapClient('localhost') as client:
    response = client.scan_file('/path/to/file.pdf')
```

## Error Handling

The library provides specific exceptions for different failure modes:

```python
from icap import IcapClient
from icap.exception import (
    IcapException,
    IcapConnectionError,
    IcapTimeoutError,
    IcapProtocolError,
    IcapServerError,
)

try:
    with IcapClient('localhost', port=1344) as client:
        response = client.scan_file('/path/to/file.pdf')

        if response.is_no_modification:
            print("File is clean")
        else:
            print("Threat detected")

except IcapConnectionError as e:
    print(f"Failed to connect to ICAP server: {e}")
except IcapTimeoutError as e:
    print(f"Request timed out: {e}")
except IcapProtocolError as e:
    print(f"Protocol error: {e}")
except IcapServerError as e:
    print(f"Server error (5xx): {e}")
except IcapException as e:
    print(f"ICAP error: {e}")
```

## Testing Virus Detection with EICAR

The [EICAR test string](https://www.eicar.org/download-anti-malware-testfile/) is a standard way to test antivirus detection without using actual malware:

```python
from icap import IcapClient

# EICAR test string - triggers antivirus detection
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

with IcapClient('localhost', port=1344) as client:
    # Test with clean content - should return 204 No Modification
    clean_response = client.scan_bytes(b"Hello, World!", filename="clean.txt")
    print(f"Clean file: {'CLEAN' if clean_response.is_no_modification else 'DETECTED'}")

    # Test with EICAR - should be detected as a threat
    eicar_response = client.scan_bytes(EICAR, filename="eicar.com")
    print(f"EICAR file: {'CLEAN' if eicar_response.is_no_modification else 'DETECTED'}")
```

## Docker Integration Testing

For integration testing with a real ICAP server (c-icap with ClamAV), use the provided Docker setup:

```bash
# Start ICAP server with ClamAV
docker compose -f docker/docker-compose.yml up -d

# Wait for services to initialize
sleep 10

# Run integration tests
python examples/integration_test.py

# Stop services
docker compose -f docker/docker-compose.yml down
```

Or if you have [just](https://just.systems/) installed:

```bash
# Start ICAP server
just docker-up

# Run integration tests
just test-integration

# Stop services
just docker-down
```

### Docker Services

The Docker Compose setup includes:
- **c-icap**: ICAP server
- **ClamAV**: Antivirus engine
- **squidclamav**: Integration adapter

See the `docker/` directory for configuration details.

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and [just](https://just.systems/) as a command runner.

### Setup

```bash
# Install dependencies
uv sync --all-extras

# Run unit tests
uv run pytest -m "not integration"

# Run linter
uv run ruff check

# Run type checker
uv run ty check src/icap
```

Or using just (run `just` to see all available commands):

```bash
just install      # Install dependencies
just test         # Run unit tests
just lint         # Run linter
just typecheck    # Run type checker
just ci           # Run full CI checks (fmt, lint, typecheck, test)
```

### Project Structure

```
python-icap/
├── src/icap/
│   ├── __init__.py       # Package exports
│   ├── icap.py           # Synchronous ICAP client
│   ├── async_icap.py     # Asynchronous ICAP client
│   ├── _protocol.py      # Shared protocol constants
│   ├── response.py       # Response handling
│   └── exception.py      # Custom exceptions
├── pytest_src/icap/        # Pytest plugin for ICAP testing
├── tests/                # Unit tests
├── examples/             # Usage examples
├── docker/               # Docker setup for integration testing
│   ├── Dockerfile
│   └── docker-compose.yml
├── pyproject.toml        # Project configuration
└── uv.lock               # Locked dependencies
```

## Pytest Plugin

python-icap includes a pytest plugin (icap.pytest_plugin) that provides fixtures and mocks for testing ICAP integrations without requiring a live ICAP server.

The plugin is automatically registered when python-icap is installed (via the `pytest11` entry point).

### Live Client Fixtures

These fixtures connect to a real ICAP server (requires a running server):

| Fixture | Description |
|---------|-------------|
| `icap_client` | Pre-connected `IcapClient` instance. Configurable via `@pytest.mark.icap` marker. |
| `async_icap_client` | Pre-connected `AsyncIcapClient` for async tests. Configurable via `@pytest.mark.icap` marker. |
| `icap_service_config` | Default ICAP service configuration dict (host, port, service). |
| `sample_clean_content` | Sample clean bytes content for testing. |
| `sample_file` | Temporary sample file (Path) for testing file scanning. |

```python
import pytest

# Basic usage - uses default localhost:1344
def test_scan_clean_file(icap_client, sample_file):
    response = icap_client.scan_file(sample_file)
    assert response.is_no_modification

# Custom configuration via marker
@pytest.mark.icap(host='icap.example.com', port=1344)
def test_custom_server(icap_client):
    response = icap_client.options('avscan')
    assert response.is_success

# Async usage
@pytest.mark.icap(host='icap.example.com', port=1344)
async def test_async_scan(async_icap_client):
    response = await async_icap_client.options('avscan')
    assert response.is_success
```

### Mock Client Fixtures

These fixtures provide mock ICAP clients that work without a server:

| Fixture | Description |
|---------|-------------|
| `mock_icap_client` | Mock client with default clean (204) responses. |
| `mock_async_icap_client` | Async mock client with default clean responses. |
| `mock_icap_client_virus` | Mock client configured to return virus detection. |
| `mock_icap_client_timeout` | Mock client that raises `IcapTimeoutError`. |
| `mock_icap_client_connection_error` | Mock client that raises `IcapConnectionError`. |

```python
def test_scan_clean_content(mock_icap_client):
    """Test with mock that returns clean responses."""
    response = mock_icap_client.scan_bytes(b"safe content")
    assert response.is_no_modification
    mock_icap_client.assert_called("scan_bytes", times=1)

def test_virus_detection(mock_icap_client_virus):
    """Test with mock configured to detect viruses."""
    response = mock_icap_client_virus.scan_bytes(b"malware")
    assert not response.is_no_modification
    assert "X-Virus-ID" in response.headers

def test_timeout_handling(mock_icap_client_timeout):
    """Test timeout error handling."""
    with pytest.raises(IcapTimeoutError):
        mock_icap_client_timeout.scan_bytes(b"content")

async def test_async_mock(mock_async_icap_client):
    """Test async mock client."""
    async with mock_async_icap_client as client:
        response = await client.scan_bytes(b"content")
        assert response.is_no_modification
```

### Response Fixtures

Pre-built `IcapResponse` objects for assertions:

| Fixture | Description |
|---------|-------------|
| `icap_response_builder` | Factory for building custom responses. |
| `icap_response_clean` | Pre-built 204 No Modification response. |
| `icap_response_virus` | Pre-built virus detection response. |
| `icap_response_options` | Pre-built OPTIONS response. |
| `icap_response_error` | Pre-built 500 error response. |

```python
def test_with_response_fixtures(icap_response_clean, icap_response_virus):
    """Use pre-built response fixtures for assertions."""
    assert icap_response_clean.is_no_modification
    assert icap_response_clean.status_code == 204

    assert not icap_response_virus.is_no_modification
    assert "X-Virus-ID" in icap_response_virus.headers
```

### IcapResponseBuilder

Fluent builder for creating custom `IcapResponse` objects:

```python
from icap.pytest_plugin import IcapResponseBuilder

# Clean response (204 No Modification)
response = IcapResponseBuilder().clean().build()

# Virus detection response
response = IcapResponseBuilder().virus("Trojan.Generic").build()

# OPTIONS response with custom methods
response = IcapResponseBuilder().options(methods=["RESPMOD"], preview=2048).build()

# Error response
response = IcapResponseBuilder().error(503, "Service Unavailable").build()

# Custom response with headers and body
response = (
    IcapResponseBuilder()
    .with_status(200, "OK")
    .with_header("X-Custom", "value")
    .with_body(b"modified content")
    .build()
)
```

**Builder Methods:**

| Method | Description |
|--------|-------------|
| `clean()` | Configure as 204 No Modification |
| `virus(name)` | Configure as virus detected with X-Virus-ID header |
| `options(methods, preview)` | Configure as OPTIONS response |
| `error(code, message)` | Configure as error response |
| `continue_response()` | Configure as 100 Continue |
| `with_status(code, message)` | Set custom status |
| `with_header(key, value)` | Add a header |
| `with_headers(dict)` | Add multiple headers |
| `with_body(bytes)` | Set response body |
| `build()` | Create the IcapResponse |

### MockIcapClient

The `MockIcapClient` provides a full mock implementation with configurable responses, call recording, and rich assertions:

```python
from icap.pytest_plugin import MockIcapClient, IcapResponseBuilder
from icap.exception import IcapTimeoutError

# Create and configure mock
client = MockIcapClient()

# Configure custom responses
client.on_respmod(IcapResponseBuilder().virus("Trojan.Gen").build())
client.on_options(IcapResponseBuilder().options().build())

# Use like a real client
response = client.scan_bytes(b"content")
assert not response.is_no_modification

# Assertions on calls
client.assert_called("scan_bytes", times=1)
client.assert_scanned(b"content")

# Configure exception injection
client.on_any(raises=IcapTimeoutError("Timeout"))

# Context manager support
with MockIcapClient() as client:
    response = client.scan_file("/path/to/file.txt")
```

**Response Sequences:**

Queue multiple responses that are consumed in order:

```python
client = MockIcapClient()
client.on_respmod(
    IcapResponseBuilder().clean().build(),
    IcapResponseBuilder().virus("Trojan").build(),
    IcapResponseBuilder().clean().build(),
)

client.scan_bytes(b"file1").is_no_modification  # True (clean)
client.scan_bytes(b"file2").is_no_modification  # False (virus)
client.scan_bytes(b"file3").is_no_modification  # True (clean)
```

**Dynamic Callbacks:**

Generate responses based on content:

```python
def eicar_detector(data: bytes, **kwargs):
    if b"EICAR" in data:
        return IcapResponseBuilder().virus("EICAR-Test").build()
    return IcapResponseBuilder().clean().build()

client = MockIcapClient()
client.on_respmod(callback=eicar_detector)

client.scan_bytes(b"safe").is_no_modification  # True
client.scan_bytes(b"EICAR test").is_no_modification  # False
```

**Content Matchers:**

Declarative rules for conditional responses:

```python
client = MockIcapClient()

# Match by filename pattern
client.when(filename_matches=r".*\.exe$").respond(
    IcapResponseBuilder().virus("Blocked.Exe").build()
)

# Match by content
client.when(data_contains=b"EICAR").respond(
    IcapResponseBuilder().virus("EICAR-Test").build()
)

client.scan_bytes(b"safe", filename="doc.pdf").is_no_modification  # True
client.scan_bytes(b"safe", filename="app.exe").is_no_modification  # False
```

**Rich Call Inspection:**

Access detailed information about each call:

```python
client = MockIcapClient()
client.scan_bytes(b"content", filename="test.txt")

call = client.last_call
call.method      # "scan_bytes"
call.data        # b"content"
call.filename    # "test.txt"
call.was_clean   # True
call.matched_by  # "default"
```

**Strict Mode:**

Validate all configured responses were consumed:

```python
client = MockIcapClient(strict=True)
client.on_respmod(
    IcapResponseBuilder().clean().build(),
    IcapResponseBuilder().virus().build(),
)

client.scan_bytes(b"file1")
client.scan_bytes(b"file2")
client.assert_all_responses_used()  # Passes - all consumed
```

**Configuration Methods:**

| Method | Description |
|--------|-------------|
| `on_options(*responses, raises=)` | Configure OPTIONS responses (single or sequence) |
| `on_respmod(*responses, raises=, callback=)` | Configure RESPMOD/scan_* responses |
| `on_reqmod(*responses, raises=)` | Configure REQMOD responses |
| `on_any(response, raises=)` | Configure all methods at once |
| `when(filename=, filename_matches=, data_contains=)` | Create content matchers |
| `reset_responses()` | Clear all configured responses |

**Assertion Methods:**

| Method | Description |
|--------|-------------|
| `assert_called(method, times=)` | Assert method was called |
| `assert_not_called(method=)` | Assert method was not called |
| `assert_scanned(data)` | Assert specific content was scanned |
| `assert_called_with(method, **kwargs)` | Assert last call had specific args |
| `assert_any_call(method, **kwargs)` | Assert any call had specific args |
| `assert_called_in_order(methods)` | Assert methods called in sequence |
| `assert_all_responses_used()` | Validate all responses consumed (strict mode) |
| `reset_calls()` | Clear call history |

**Call Properties:**

| Property | Description |
|----------|-------------|
| `calls` | List of all `MockCall` objects |
| `call_count` | Total number of calls |
| `first_call` | First call made (or None) |
| `last_call` | Most recent call (or None) |
| `last_scan_call` | Most recent scan_bytes/scan_file/scan_stream call |
| `get_calls(method)` | Filter calls by method name |
| `get_scan_calls()` | Get all scan-related calls |

### icap_mock Marker

The `@pytest.mark.icap_mock` marker provides declarative mock configuration:

```python
import pytest
from icap.exception import IcapTimeoutError

# Configure clean response
@pytest.mark.icap_mock(response="clean")
def test_clean_scan(icap_mock):
    response = icap_mock.scan_bytes(b"content")
    assert response.is_no_modification

# Configure virus detection
@pytest.mark.icap_mock(response="virus", virus_name="Trojan.Custom")
def test_virus_detection(icap_mock):
    response = icap_mock.scan_bytes(b"malware")
    assert response.headers["X-Virus-ID"] == "Trojan.Custom"

# Configure error response
@pytest.mark.icap_mock(response="error")
def test_error_response(icap_mock):
    response = icap_mock.scan_bytes(b"content")
    assert response.status_code == 500

# Configure exception
@pytest.mark.icap_mock(raises=IcapTimeoutError)
def test_timeout(icap_mock):
    with pytest.raises(IcapTimeoutError):
        icap_mock.scan_bytes(b"content")

# Strict mode - fails if not all responses consumed
@pytest.mark.icap_mock(strict=True)
@pytest.mark.icap_response("clean")
@pytest.mark.icap_response("virus")
def test_strict_mode(icap_mock):
    icap_mock.scan_bytes(b"file1")  # clean
    icap_mock.scan_bytes(b"file2")  # virus
    # Test passes - all responses consumed

# Per-method configuration
@pytest.mark.icap_mock(
    respmod={"response": "virus"},
    options={"response": "clean"},
)
def test_mixed_config(icap_mock):
    scan_response = icap_mock.scan_bytes(b"content")
    assert not scan_response.is_no_modification

    options_response = icap_mock.options("avscan")
    assert options_response.is_no_modification
```

**Stacked Response Markers:**

Use `@pytest.mark.icap_response` to queue multiple responses declaratively:

```python
# Responses are consumed top-to-bottom
@pytest.mark.icap_response("clean")
@pytest.mark.icap_response("virus", virus_name="Trojan.Gen")
@pytest.mark.icap_response("clean")
def test_sequence(icap_mock):
    r1 = icap_mock.scan_bytes(b"file1")  # clean
    r2 = icap_mock.scan_bytes(b"file2")  # virus
    r3 = icap_mock.scan_bytes(b"file3")  # clean
    assert r1.is_no_modification
    assert not r2.is_no_modification
    assert r3.is_no_modification

# Custom error responses
@pytest.mark.icap_response("error", code=503, message="Unavailable")
def test_custom_error(icap_mock):
    response = icap_mock.scan_bytes(b"content")
    assert response.status_code == 503
```

**Marker Parameters:**

| Parameter | Description |
|-----------|-------------|
| `response` | `"clean"`, `"virus"`, `"error"`, or `IcapResponse` |
| `virus_name` | Custom virus name (when `response="virus"`) |
| `raises` | Exception class or instance to raise |
| `strict` | If `True`, fails test if configured responses not consumed |
| `options` | Dict with per-method config for OPTIONS |
| `respmod` | Dict with per-method config for RESPMOD |
| `reqmod` | Dict with per-method config for REQMOD |

## Protocol Reference

- **[RFC 3507](https://datatracker.ietf.org/doc/rfc3507/)**: Internet Content Adaptation Protocol (ICAP)
- Default Port: 1344
- Methods: OPTIONS, REQMOD, RESPMOD

## License

MIT License
