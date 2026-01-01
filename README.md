# PyCap - Python ICAP Client

A Python implementation of the ICAP (Internet Content Adaptation Protocol) client based on RFC 3507.

## Overview

PyCap is a Python library for communicating with ICAP servers. It supports the standard ICAP methods:
- **OPTIONS** - Query server capabilities
- **REQMOD** - Request modification mode (scan/modify HTTP requests)
- **RESPMOD** - Response modification mode (scan/modify HTTP responses)

This implementation is based on the [net-icap](https://github.com/cattywampus/net-icap) repository patterns.

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

# Scan a file by path
with IcapClient('localhost') as client:
    response = client.scan_file('/path/to/file.pdf')
    if response.is_no_modification:
        print("File is clean")
    else:
        print("File contains threats")

# Scan a file-like object
with open('document.pdf', 'rb') as f:
    with IcapClient('localhost') as client:
        response = client.scan_stream(f, filename='document.pdf')
        if response.is_no_modification:
            print("Stream is clean")
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

### Running Tests

```bash
python -m pytest tests/
```

### Project Structure

```
pycap/
├── pycap/
│   ├── __init__.py       # Package exports
│   ├── icap.py           # Main ICAP client
│   ├── response.py       # Response handling
│   ├── exception.py      # Custom exceptions
│   └── request.py        # Request utilities (future)
├── tests/                # Unit tests
├── examples/             # Usage examples
├── docker/               # Docker setup for testing
│   ├── Dockerfile
│   └── docker-compose.yml
├── setup.py
└── README.md
```

## Protocol Reference

- **RFC 3507**: Internet Content Adaptation Protocol (ICAP)
- Default Port: 1344
- Methods: OPTIONS, REQMOD, RESPMOD

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
