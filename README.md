# PyCap - Python ICAP Client

A Python implementation of the ICAP (Internet Content Adaptation Protocol) client based on [RFC 3507](https://www.rfc-editor.org/rfc/rfc3507).

## Overview

PyCap is a Python library for communicating with ICAP servers. It supports the standard ICAP methods:
- **OPTIONS** - Query server capabilities
- **REQMOD** - Request modification mode (scan/modify HTTP requests)
- **RESPMOD** - Response modification mode (scan/modify HTTP responses)

This implementation is based on the [net-icap](https://github.com/cattywampus/net-icap) repository patterns.

## What is ICAP?

**ICAP (Internet Content Adaptation Protocol)** is a lightweight protocol for performing "remote procedure calls" on HTTP messages. It enables content transformation and filtering at network edges rather than requiring all processing through centralized servers.

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

```bash
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

## Key Improvements from Initial Implementation

The initial implementation had several issues that have been corrected:

1. **Socket Connection**: Changed from `bind()` to `connect()` - clients should connect to servers, not bind to ports
2. **Proper ICAP Protocol**: Implemented full ICAP request/response handling according to RFC 3507
3. **Context Manager**: Added `__enter__` and `__exit__` for proper resource management
4. **Response Parsing**: Complete IcapResponse class with status code, headers, and body parsing
5. **Multiple Methods**: Implemented OPTIONS, REQMOD, and RESPMOD methods
6. **Error Handling**: Added custom exceptions for better error reporting
7. **Encapsulated Header**: Proper calculation of encapsulated header offsets
8. **Logging Support**: Integrated logging throughout for debugging and monitoring
9. **Convenience Methods**: Added `scan_file()` and `scan_stream()` for easy file scanning

## Docker Integration Testing

For integration testing with a real ICAP server (c-icap with ClamAV), use the provided Docker setup:

```bash
# Start ICAP server with ClamAV
docker-compose up -d

# Wait for services to initialize
sleep 10

# Run integration tests
python examples/integration_test.py

# Stop services
docker-compose down
```

### Docker Services

The Docker Compose setup includes:
- **c-icap**: ICAP server
- **ClamAV**: Antivirus engine
- **squidclamav**: Integration adapter

See `docker/` directory for configuration details.

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

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

## Protocol Reference

- **RFC 3507**: Internet Content Adaptation Protocol (ICAP)
- Default Port: 1344
- Methods: OPTIONS, REQMOD, RESPMOD

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
