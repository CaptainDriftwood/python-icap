#!/usr/bin/env python3
"""
Basic example of using the python-icap ICAP client.

This example demonstrates the recommended high-level API methods:
- scan_bytes(): Scan in-memory content
- scan_file(): Scan a file from disk
- options(): Query server capabilities

For advanced use cases, see the low-level respmod() and reqmod() methods.
"""

from test_utils import EICAR_TEST_STRING

from icap import IcapClient


def main():
    # Configuration
    ICAP_HOST = "localhost"
    ICAP_PORT = 1344
    SERVICE = "avscan"

    print("=" * 60)
    print("python-icap ICAP Client - Basic Example")
    print("=" * 60)

    # Example 1: Query server capabilities with OPTIONS
    print("\n1. Querying server capabilities...")
    try:
        with IcapClient(ICAP_HOST, ICAP_PORT) as client:
            response = client.options(SERVICE)
            print(f"   Status: {response.status_code} {response.status_message}")
            print(f"   Methods: {response.headers.get('Methods', 'N/A')}")
            print(f"   Preview: {response.headers.get('Preview', 'N/A')} bytes")
    except Exception as e:
        print(f"   Error: {e}")

    # Example 2: Scan clean content using scan_bytes() (recommended)
    print("\n2. Scanning clean content...")
    try:
        clean_content = b"Hello, World! This is clean content."

        with IcapClient(ICAP_HOST, ICAP_PORT) as client:
            response = client.scan_bytes(clean_content, service=SERVICE)
            print(f"   Status: {response.status_code} {response.status_message}")

            if response.is_no_modification:
                print("   Result: Content is CLEAN (204 No Modification)")
            else:
                print("   Result: Content was modified or flagged")
    except Exception as e:
        print(f"   Error: {e}")

    # Example 3: Scan EICAR test virus
    print("\n3. Scanning EICAR test virus...")
    try:
        with IcapClient(ICAP_HOST, ICAP_PORT) as client:
            response = client.scan_bytes(EICAR_TEST_STRING, service=SERVICE)
            print(f"   Status: {response.status_code} {response.status_message}")

            if response.is_no_modification:
                print("   Result: Content passed (unexpected for EICAR)")
            else:
                virus_id = response.headers.get("X-Virus-ID", "Unknown threat")
                print(f"   Result: THREAT DETECTED - {virus_id}")
    except Exception as e:
        print(f"   Error: {e}")

    # Example 4: Scan a file (if you have one)
    print("\n4. Scanning a file...")
    try:
        import os
        import tempfile

        # Create a temporary file for demonstration
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False) as f:
            f.write(b"This is a test file with clean content.")
            temp_path = f.name

        try:
            with IcapClient(ICAP_HOST, ICAP_PORT) as client:
                response = client.scan_file(temp_path, service=SERVICE)
                print(f"   File: {temp_path}")
                print(f"   Status: {response.status_code} {response.status_message}")

                if response.is_no_modification:
                    print("   Result: File is CLEAN")
                else:
                    print("   Result: File was flagged")
        finally:
            os.unlink(temp_path)  # Clean up temp file
    except Exception as e:
        print(f"   Error: {e}")

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
