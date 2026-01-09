# Default recipe: list available commands
default:
    @just --list

# Install dependencies
install:
    uv sync --all-extras

# Run all checks (lint, typecheck, test)
check: lint typecheck test

# Run unit tests
test *args:
    uv run pytest -m "not integration" {{ args }}

# Run integration tests (requires Docker)
test-integration *args:
    uv run pytest -m "integration and not ssl" {{ args }}

# Run integration tests including SSL (requires Docker and certs)
test-integration-ssl *args:
    uv run pytest -m integration {{ args }}

# Run all tests
test-all *args:
    uv run pytest {{ args }}

# Run tests across all Python versions (3.8-3.14)
test-all-versions *args:
    uv run nox -s tests {{ args }}

# Run tests for a specific Python version
test-version version *args:
    uv run nox -s tests-{{ version }} {{ args }}

# Run all nox sessions
nox *args:
    uv run nox {{ args }}

# Run linter
lint:
    uv run ruff check .

# Run linter and fix auto-fixable issues
lint-fix:
    uv run ruff check --fix .

# Format code (includes import sorting)
fmt:
    uv run ruff check --fix --select I .
    uv run ruff format .

# Check formatting without making changes
fmt-check:
    uv run ruff check --select I .
    uv run ruff format --check .

# Run type checker
typecheck:
    uv run ty check pycap

# Aliases for type checking
alias type := typecheck
alias ty := typecheck

# Generate SSL certificates for TLS testing
# Uses Docker so no local openssl installation is required.
# Certificates are written directly to docker/certs/ via volume mount.
generate-certs:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p docker/certs
    docker run --rm -v "$(pwd)/docker/certs:/certs" alpine sh -c ' \
        apk add --no-cache openssl >/dev/null 2>&1 && \
        cd /certs && \
        echo "Generating CA certificate..." && \
        printf "%s\n" \
            "basicConstraints=critical,CA:TRUE" \
            "keyUsage=critical,keyCertSign,cRLSign" \
            "subjectKeyIdentifier=hash" \
            > ca-ext.cnf && \
        openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
            -nodes -keyout ca-key.pem -out ca.pem \
            -subj "/CN=ICAP Test CA/O=PyCap Test/C=US" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash" 2>/dev/null && \
        echo "Generating server certificate..." && \
        openssl req -newkey rsa:4096 -nodes -keyout server-key.pem \
            -out server.csr \
            -subj "/CN=localhost/O=PyCap Test/C=US" 2>/dev/null && \
        printf "%s\n" \
            "authorityKeyIdentifier=keyid,issuer" \
            "basicConstraints=CA:FALSE" \
            "keyUsage=digitalSignature,keyEncipherment" \
            "extendedKeyUsage=serverAuth" \
            "subjectAltName=DNS:localhost,DNS:icap-server,IP:127.0.0.1" \
            > server-ext.cnf && \
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
            -CAcreateserial -out server.pem -days 365 \
            -extfile server-ext.cnf 2>/dev/null && \
        rm -f server.csr server-ext.cnf ca-ext.cnf ca-key.pem ca.srl && \
        chmod 644 ca.pem server.pem && \
        chmod 600 server-key.pem && \
        echo "Certificates generated in docker/certs/:" && \
        echo "  - ca.pem (CA certificate - use as cafile in ssl_context)" && \
        echo "  - server.pem (server certificate)" && \
        echo "  - server-key.pem (server private key)"'

# Build Docker images
docker-build:
    docker compose -f docker/docker-compose.yml build

# Start ICAP server for integration testing
docker-up:
    docker compose -f docker/docker-compose.yml up -d

# Stop ICAP server
docker-down:
    docker compose -f docker/docker-compose.yml down

# View ICAP server logs
docker-logs:
    docker compose -f docker/docker-compose.yml logs -f

# Clean up build artifacts and caches
clean:
    rm -rf build/ dist/ *.egg-info/
    rm -rf .pytest_cache/ .ruff_cache/
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Build package
build:
    uv build

# Run a full CI-like check
ci: fmt-check lint typecheck test
