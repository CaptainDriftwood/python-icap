# Contributing to py-cap

Thank you for your interest in contributing to py-cap!

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/CaptainDriftwood/py-cap.git
   cd py_cap
   ```

2. **Install uv** (if not already installed)
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Install dependencies**
   ```bash
   uv sync --all-extras
   ```

4. **Install pre-commit hooks**
   ```bash
   uv run pre-commit install
   ```

## Development Commands

This project uses [just](https://just.systems/) as a command runner. Run `just` to see all available commands.

```bash
just install      # Install dependencies
just test         # Run unit tests
just lint         # Run linter
just fmt          # Format code
just typecheck    # Run type checker
just ci           # Run full CI checks
```

## Running Tests

```bash
# Unit tests only
just test

# Integration tests (requires Docker)
just docker-up
just test-integration
just docker-down

# All Python versions
just test-all-versions
```

## Code Style

- **Formatter/Linter**: [Ruff](https://github.com/astral-sh/ruff)
- **Type Checker**: [ty](https://github.com/astral-sh/ty)
- **Line Length**: 100 characters
- **Quotes**: Double quotes
- **Imports**: Sorted by ruff (isort rules)

Run `just fmt` before committing to auto-format your code.

## Type Hints

All public API functions and methods should have type hints. Run `just typecheck` to verify.

## Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Write tests** for any new functionality
3. **Ensure all checks pass**: `just ci`
4. **Use conventional commit messages**:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation only
   - `test:` Adding/updating tests
   - `refactor:` Code refactoring
   - `chore:` Maintenance tasks
5. **Submit a PR** against the `master` branch

## Testing Guidelines

- Use standalone test functions, not test classes
- Mark integration tests with `@pytest.mark.integration`
- Mark SSL tests with `@pytest.mark.ssl`
- Use pytest-asyncio for async tests (asyncio_mode is "auto")

## Questions?

Open an issue or check the [README](README.md) for more information.