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
    uv run pytest -m integration {{ args }}

# Run all tests
test-all *args:
    uv run pytest {{ args }}

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
    uv run pyright pycap

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