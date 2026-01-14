# Quick Start Guide for Docker Integration Testing

## Prerequisites

- Docker installed
- Docker Compose installed
- Python 3.8+ installed

## Step-by-Step Setup

### 1. Build and Start ICAP Server

```bash
cd docker
docker-compose up -d
```

This starts:
- c-icap server on port 1344
- ClamAV antivirus daemon
- squidclamav integration

### 2. Wait for Services to Initialize

```bash
# ClamAV needs time to load virus definitions
# Wait at least 30 seconds on first run
sleep 30
```

You can check logs to see when ready:
```bash
docker-compose logs -f
```

Look for messages like:
- "ClamAV is ready"
- "c-icap server started"

### 3. Install Python Package

```bash
cd ..
pip install -e .
```

### 4. Run Integration Tests

```bash
python examples/integration_test.py
```

Expected output:
```
Test 1: Connection and OPTIONS
----------------------------------------
✓ Connected successfully
✓ Status: 200 OK

Test 2: Scan Clean Content
----------------------------------------
✓ Content is clean (204 No Modification)

Test 3: Detect EICAR Test Virus
----------------------------------------
✓ Virus detected! Status: 200

Test 4: Scan Large Content
----------------------------------------
✓ Large content scanned successfully

Total: 4/4 tests passed
```

### 5. Run Example Script

```bash
python examples/basic_example.py
```

### 6. Stop Services

```bash
cd docker
docker-compose down
```

To also remove volumes (ClamAV data):
```bash
docker-compose down -v
```

## Troubleshooting

### Service Not Ready

If tests fail immediately, the services might not be ready yet:
```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs

# Wait longer and retry
sleep 30
python examples/integration_test.py
```

### Connection Refused

If you get "Connection refused" errors:
```bash
# Check if ICAP port is listening
netstat -an | grep 1344

# Or using Docker:
docker-compose exec icap-server netstat -an | grep 1344
```

### ClamAV Not Detecting Viruses

If EICAR test doesn't detect the virus:
```bash
# Check ClamAV status
docker-compose exec icap-server clamdscan --version

# Update virus definitions
docker-compose exec icap-server freshclam

# Restart services
docker-compose restart
```

### Docker Build Fails

If the Docker build fails:
```bash
# Clean up and rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

## Manual Testing

You can also test manually using Python:

```python
from icap import IcapClient

# Test connection
with IcapClient('localhost', 1344) as client:
    response = client.options('avscan')
    print(f"Status: {response.status_code}")
    print(f"Headers: {response.headers}")
```

## Configuration Files

The Docker setup includes these configuration files:

- `docker/Dockerfile` - Container image definition
- `docker/docker-compose.yml` - Service orchestration
- `docker/c-icap.conf` - ICAP server configuration
- `docker/squidclamav.conf` - ClamAV integration settings
- `docker/start.sh` - Service startup script

You can modify these to adjust:
- Port numbers
- Timeout values
- Logging levels
- Memory limits
- Thread pool sizes

## Continuous Integration

To use in CI/CD pipelines:

```yaml
# Example GitHub Actions
steps:
  - name: Start ICAP services
    run: |
      cd docker
      docker-compose up -d
      sleep 30
  
  - name: Install package
    run: pip install -e .
  
  - name: Run tests
    run: python examples/integration_test.py
  
  - name: Stop services
    run: |
      cd docker
      docker-compose down
```

## Performance Notes

- **First Run**: Takes 1-2 minutes for ClamAV to download virus definitions
- **Subsequent Runs**: Services start in ~10-15 seconds
- **Scan Time**: Small files < 1ms, Large files depends on size
- **Memory**: Container uses ~500MB RAM (mostly ClamAV)

## Security Notes

⚠️ **Development Only**: This Docker setup is for development and testing only.

For production:
- Use official c-icap and ClamAV images
- Configure proper security policies
- Set up TLS/SSL
- Implement rate limiting
- Add authentication
- Use proper log management
- Monitor resource usage

## Additional Resources

- [RFC 3507 - ICAP Specification](https://datatracker.ietf.org/doc/html/rfc3507)
- [c-icap Documentation](http://c-icap.sourceforge.net/)
- [ClamAV Documentation](https://docs.clamav.net/)
- [EICAR Test File](https://www.eicar.org/download-anti-malware-testfile/)
