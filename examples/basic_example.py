#!/usr/bin/env python3
"""
Basic example of using the PyCap ICAP client.
"""

from test_utils import EICAR_TEST_STRING

from pycap import IcapClient


def main():
    # Configuration
    ICAP_HOST = "localhost"
    ICAP_PORT = 1344
    SERVICE = "avscan"

    print("=" * 60)
    print("PyCap ICAP Client - Basic Example")
    print("=" * 60)

    # Example 1: Test OPTIONS method
    print("\n1. Testing OPTIONS method...")
    try:
        with IcapClient(ICAP_HOST, ICAP_PORT) as client:
            response = client.options(SERVICE)
            print(f"   Status: {response.status_code} {response.status_message}")
            print(f"   Headers: {response.headers}")
    except Exception as e:
        print(f"   Error: {e}")

    # Example 2: Scan clean content
    print("\n2. Scanning clean content with RESPMOD...")
    try:
        http_request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
        http_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"
        )

        with IcapClient(ICAP_HOST, ICAP_PORT) as client:
            response = client.respmod(SERVICE, http_request, http_response)
            print(f"   Status: {response.status_code} {response.status_message}")

            if response.is_no_modification:
                print("   Result: Content is CLEAN (204 No Modification)")
            elif response.is_success:
                print("   Result: Content was modified/blocked")
            else:
                print("   Result: Error occurred")
    except Exception as e:
        print(f"   Error: {e}")

    # Example 3: Scan EICAR test virus
    print("\n3. Scanning EICAR test virus...")
    try:
        http_request = b"GET /test.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
        http_response = (
            f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(EICAR_TEST_STRING)}\r\n\r\n".encode()
            + EICAR_TEST_STRING
        )

        with IcapClient(ICAP_HOST, ICAP_PORT) as client:
            response = client.respmod(SERVICE, http_request, http_response)
            print(f"   Status: {response.status_code} {response.status_message}")

            if response.is_no_modification:
                print("   Result: Content passed (204 No Modification)")
            elif response.status_code == 200:
                print("   Result: VIRUS DETECTED - Content blocked/modified")
            else:
                print("   Result: Unexpected response")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
