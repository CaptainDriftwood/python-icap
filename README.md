# PyCap - Python ICAP Client

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
- [Logging](#logging)
- [Error Handling](#error-handling)
- [Testing Virus Detection with EICAR](#testing-virus-detection-with-eicar)
- [Docker Integration Testing](#docker-integration-testing)
  - [Docker Services](#docker-services)
- [Development](#development)
  - [Setup](#setup)
  - [Project Structure](#project-structure)
- [Pytest Plugin](#pytest-plugin)
  - [Available Fixtures](#available-fixtures)
- [Protocol Reference](#protocol-reference)
- [License](#license)

## Overview

PyCap is a Python library for communicating with ICAP servers. It supports the standard ICAP methods:
- **OPTIONS** - Query server capabilities
- **REQMOD** - Request modification mode (scan/modify HTTP requests)
- **RESPMOD** - Response modification mode (scan/modify HTTP responses)

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

> **Note:** This package is not yet published to PyPI due to a name collision. Install directly from the source.

```bash
# Standard installation
pip install .

# Development installation (editable)
pip install -e .
```

## Usage

### Basic Example

```python
from pycap import IcapClient

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
from pycap import IcapClient

# Automatically handles connection/disconnection
with IcapClient('localhost', port=1344) as client:
    response = client.options('avscan')
    print(f"Status: {response.status_code}")
```

### Scanning Content with RESPMOD

```python
from pycap import IcapClient

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
from pycap import IcapClient
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
from pycap import IcapClient

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

PyCap includes an async client (`AsyncIcapClient`) for use with `asyncio`. The async client provides the same API as the sync client but with `async`/`await` syntax.

### Basic Async Example

```python
import asyncio
from pycap import AsyncIcapClient

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
from pycap import AsyncIcapClient

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

## Logging

The library uses Python's standard `logging` module. Configure it to see detailed operation logs:

```python
import logging
from pycap import IcapClient

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Now all ICAP operations will be logged
with IcapClient('localhost') as client:
    response = client.scan_file('/path/to/file.pdf')
```

## Error Handling

The library provides specific exceptions for different failure modes:

```python
from pycap import IcapClient
from pycap.exception import (
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
from pycap import IcapClient

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

See `docker/` directory for configuration details.

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and [just](https://just.systems/) as a command runner.

### Setup

```bash
# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run linter
uv run ruff check

# Run type checker
uv run pyright
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
pycap/
├── pycap/
│   ├── __init__.py       # Package exports
│   ├── icap.py           # Main ICAP client
│   ├── response.py       # Response handling
│   └── exception.py      # Custom exceptions
├── pytest_pycap/         # Pytest plugin for ICAP testing
├── tests/                # Unit tests
├── examples/             # Usage examples
├── docker/               # Docker setup for integration testing
│   ├── Dockerfile
│   └── docker-compose.yml
├── pyproject.toml        # Project configuration
└── uv.lock               # Locked dependencies
```

## Pytest Plugin

PyCap includes a pytest plugin (`pytest_pycap`) that provides fixtures for testing ICAP integrations.

### Available Fixtures

| Fixture | Description |
|---------|-------------|
| `icap_client` | Pre-connected `IcapClient` instance. Configurable via `@pytest.mark.icap` marker. |
| `async_icap_client` | Pre-connected `AsyncIcapClient` instance for async tests. Configurable via `@pytest.mark.icap` marker. |
| `icap_service_config` | Default ICAP service configuration dict (host, port, service). |
| `sample_clean_content` | Sample clean bytes content for testing. |
| `sample_file` | Temporary sample file (Path) for testing file scanning. |

**Sync Usage:**

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

# Using sample content
def test_scan_content(icap_client, sample_clean_content):
    response = icap_client.scan_bytes(sample_clean_content)
    assert response.is_no_modification
```

**Async Usage:**

```python
import pytest

# Basic async usage
async def test_async_scan(async_icap_client, sample_file):
    response = await async_icap_client.scan_file(sample_file)
    assert response.is_no_modification

# Custom configuration via marker (same marker works for both sync and async)
@pytest.mark.icap(host='icap.example.com', port=1344)
async def test_async_custom_server(async_icap_client):
    response = await async_icap_client.options('avscan')
    assert response.is_success
```

The plugin is automatically registered when PyCap is installed (via the `pytest11` entry point).

## Protocol Reference

- **[RFC 3507](https://datatracker.ietf.org/doc/rfc3507/)**: Internet Content Adaptation Protocol (ICAP)
- Default Port: 1344
- Methods: OPTIONS, REQMOD, RESPMOD

### Limitations

- **Preview mode not yet implemented** - ICAP preview mode (where the client sends only the first N bytes before waiting for a server decision) is not currently supported. See [Issue #17](https://github.com/CaptainDriftwood/pycap/issues/17) for progress on this feature.

## License

MIT License
