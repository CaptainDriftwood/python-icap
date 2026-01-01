#!/usr/bin/env python3
"""
Integration test script for PyCap with Docker ICAP server.

This script tests the ICAP client against a real c-icap server with ClamAV.
Run this after starting the Docker services with docker-compose.
"""

import sys
import time
from pycap import IcapClient, IcapException


def test_connection(host='localhost', port=1344, service='avscan'):
    """Test basic connection and OPTIONS method."""
    print("Test 1: Connection and OPTIONS")
    print("-" * 40)
    try:
        with IcapClient(host, port) as client:
            response = client.options(service)
            print(f"✓ Connected successfully")
            print(f"✓ Status: {response.status_code} {response.status_message}")
            print(f"✓ Headers: {response.headers}")
            return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False


def test_clean_content(host='localhost', port=1344, service='avscan'):
    """Test scanning clean content."""
    print("\nTest 2: Scan Clean Content")
    print("-" * 40)
    try:
        http_request = b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"
        http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nClean text!"
        
        with IcapClient(host, port) as client:
            response = client.respmod(service, http_request, http_response)
            
            if response.is_no_modification:
                print(f"✓ Content is clean (204 No Modification)")
                return True
            elif response.is_success:
                print(f"✓ Got response: {response.status_code}")
                return True
            else:
                print(f"✗ Unexpected status: {response.status_code}")
                return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False


def test_eicar_virus(host='localhost', port=1344, service='avscan'):
    """Test detection of EICAR test virus."""
    print("\nTest 3: Detect EICAR Test Virus")
    print("-" * 40)
    try:
        # Standard EICAR test virus string
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        
        http_request = b"GET /virus.txt HTTP/1.1\r\nHost: test.local\r\n\r\n"
        http_response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(eicar)}\r\n\r\n".encode() + eicar
        
        with IcapClient(host, port) as client:
            response = client.respmod(service, http_request, http_response)
            
            # A virus should NOT return 204 (no modification)
            if response.is_no_modification:
                print(f"✗ Virus NOT detected! (got 204)")
                return False
            else:
                print(f"✓ Virus detected! Status: {response.status_code}")
                return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False


def test_large_content(host='localhost', port=1344, service='avscan'):
    """Test scanning larger content."""
    print("\nTest 4: Scan Large Content")
    print("-" * 40)
    try:
        # Create 1MB of clean content
        large_content = b"A" * (1024 * 1024)
        
        http_request = b"GET /large.bin HTTP/1.1\r\nHost: test.local\r\n\r\n"
        http_response = f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(large_content)}\r\n\r\n".encode() + large_content
        
        with IcapClient(host, port, timeout=30) as client:
            response = client.respmod(service, http_request, http_response)
            
            if response.is_success or response.is_no_modification:
                print(f"✓ Large content scanned successfully")
                return True
            else:
                print(f"✗ Failed with status: {response.status_code}")
                return False
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False


def main():
    print("=" * 60)
    print("PyCap Integration Tests")
    print("=" * 60)
    print("\nMake sure Docker services are running:")
    print("  docker-compose -f docker/docker-compose.yml up -d")
    print("\nWaiting 5 seconds for services to be ready...")
    time.sleep(5)
    
    # Run tests
    results = []
    results.append(("Connection Test", test_connection()))
    results.append(("Clean Content Test", test_clean_content()))
    results.append(("EICAR Virus Test", test_eicar_virus()))
    results.append(("Large Content Test", test_large_content()))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        symbol = "✓" if passed else "✗"
        print(f"{symbol} {name}: {status}")
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    print("=" * 60)
    
    # Exit with appropriate code
    sys.exit(0 if passed_count == total_count else 1)


if __name__ == '__main__':
    main()
