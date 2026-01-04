# PyCap Project Roadmap

---

## Table of Contents

- [Project Status](#project-status)
- [Completed Work](#completed-work)
- [Remaining Tasks](#remaining-tasks)
  - [High Priority](#high-priority)
  - [Medium Priority](#medium-priority)
  - [Low Priority](#low-priority)
- [Package Rename & PyPI Publishing](#package-rename--pypi-publishing)
- [GitHub Actions Improvements](#github-actions-improvements)
- [Code Quality Items](#code-quality-items)
- [Future Enhancements](#future-enhancements)
- [References](#references)

---

## Project Status

| Component | Status | Notes |
|-----------|--------|-------|
| Core ICAP Client | ✅ Complete | Full RFC 3507 implementation |
| Async Client | ✅ Complete | `AsyncIcapClient` with full feature parity |
| SSL/TLS Support | ✅ Complete | `ssl_context` parameter for secure connections |
| Preview Mode | ✅ Complete | RFC 3507 preview support for efficient scanning |
| Pytest Plugin | ✅ Complete | Both sync and async fixtures with SSL support |
| Unit Tests | ✅ Complete | Comprehensive coverage including pytester tests |
| Integration Tests | ✅ Complete | Docker-based with c-icap/ClamAV, including SSL tests |
| Documentation | ✅ Complete | README with examples, AWS Lambda example |
| LICENSE File | ✅ Complete | MIT License |
| PyPI Publishing | ❌ Pending | Blocked on package rename |

---

## Completed Work

### Core Implementation

- ✅ **RESPMOD encapsulated header calculation** - Fixed in `pycap/icap.py`. Offsets now correctly calculate `req-hdr=0`, `res-hdr=len(http_request)`, `res-body=len(http_request) + len(response_headers)`. Verified against RFC 3507.

- ✅ **Chunked encoding for RESPMOD body** - `respmod()` now correctly implements chunked transfer encoding per RFC 3507: headers sent without chunking, body with chunked encoding, terminating zero-length chunk included.

- ✅ **Response parsing for chunked responses** - Added `_read_chunked_body()` method. `_send_and_receive()` detects `Transfer-Encoding: chunked` and parses accordingly.

- ✅ **Shared protocol base class** - Created `pycap/_protocol.py` with `IcapProtocol` base class containing shared constants (`DEFAULT_PORT`, `CRLF`, `ICAP_VERSION`, `BUFFER_SIZE`, `USER_AGENT`) and request building utilities.

### Async Support

- ✅ **AsyncIcapClient implementation** - Full async client in `pycap/async_icap.py` with:
  - Async context manager (`__aenter__`, `__aexit__`)
  - All ICAP methods: `options()`, `respmod()`, `reqmod()`
  - Convenience methods: `scan_bytes()`, `scan_file()`, `scan_stream()`
  - Proper timeout handling with `asyncio.wait_for()`
  - File I/O via `loop.run_in_executor()` for Python 3.8 compatibility

- ✅ **Async exports** - `AsyncIcapClient` exported from `pycap/__init__.py`

- ✅ **pytest-asyncio configuration** - Added to dev dependencies, `asyncio_mode = "auto"` in pyproject.toml

- ✅ **Async integration tests** - `tests/test_async_integration.py` with concurrent scan tests

### Pytest Plugin

- ✅ **Entry point registration** - Correct `[project.entry-points.pytest11]` in pyproject.toml

- ✅ **Marker registration** - `@pytest.mark.icap` registered via `pytest_configure()` hook

- ✅ **Sync fixture** - `icap_client` fixture with marker-based configuration

- ✅ **Async fixture** - `async_icap_client` fixture using async context manager pattern

- ✅ **Helper fixtures** - `icap_service_config`, `sample_clean_content`, `sample_file`

### Testing Infrastructure

- ✅ **Removed hardcoded sleep** - Replaced with `wait_for_icap_service()` that polls with OPTIONS requests. Added `pytest-timeout` for graceful failure.

- ✅ **Integration test workflow** - Added `workflow_dispatch` trigger with `run_integration` input. Unit tests explicitly exclude integration tests with `-m "not integration"`.

### Documentation & Configuration

- ✅ **README updated** - Removed `setup.py` references, added `pyproject.toml` and `uv.lock` to structure, added uv usage instructions.

- ✅ **Python 3.13 classifier** - Added to pyproject.toml classifiers.

- ✅ **Python 3.14 classifier** - Added to pyproject.toml classifiers.

- ✅ **Project URLs** - Homepage and Repository URLs in pyproject.toml.

### SSL/TLS Support

- ✅ **SSL/TLS parameter** - Added `ssl_context` parameter to both `IcapClient` and `AsyncIcapClient` for secure connections.

- ✅ **Docker TLS setup** - Added TLS-enabled ICAP server on port 11344 with self-signed certificates.

- ✅ **SSL integration tests** - Added `tests/test_ssl_integration.py` with comprehensive TLS tests.

- ✅ **Pytest plugin SSL support** - Added `ssl_context` to `@pytest.mark.icap` marker.

### ICAP Preview Mode

- ✅ **Preview mode implementation** - Added `preview` parameter to `respmod()` for efficient scanning of large files per RFC 3507.

- ✅ **100 Continue handling** - Proper handling of ICAP 100 Continue responses for preview mode.

### Recent Additions

- ✅ **MIT LICENSE file** - Added LICENSE file for public release (closes #4).

- ✅ **Pytester plugin tests** - Added `tests/test_pytest_plugin.py` with comprehensive plugin validation (closes #5).

- ✅ **Public `is_connected` property** - Added to both clients, replacing private attribute access (closes #6).

- ✅ **Keywords in pyproject.toml** - Added for PyPI discoverability (closes #7).

- ✅ **Workflow branch consistency** - Added `master` to lint.yml triggers (closes #8).

- ✅ **Typecheck workflow updated** - Now uses uv and ty type checker (closes #9).

- ✅ **Version sync** - Using `importlib.metadata.version()` for single source of truth.

- ✅ **AWS Lambda example** - Added `examples/lambda_handler.py` for S3 virus scanning.

---

## Remaining Tasks

### High Priority

#### 1. Package Rename for PyPI

**Status:** ❌ Not Done

The name `pycap` is taken on PyPI (REDCap API client). Chosen alternative: `py-cap`.

See [Package Rename & PyPI Publishing](#package-rename--pypi-publishing) section for full migration plan.

---

### Medium Priority

#### 2. Improve Error Handling in Chunked Reading

**Status:** ⚠️ Review Needed

In `_read_chunked_body()`, invalid chunk data returns partial data silently.

**Current behavior:**
```python
except ValueError:
    logger.warning(f"Invalid chunk size: {size_line}")
    return body  # Silently returns partial data
```

**Recommendation:** Consider raising `IcapProtocolError` instead:

```python
except ValueError:
    raise IcapProtocolError(f"Invalid chunk size received: {size_line}")
```

---

#### 9. Add README Badges

**Status:** ❌ Not Done

Add status badges to README.md for quick project health visibility.

**Recommended badges:**

```markdown
# py-cap

[![PyPI version](https://img.shields.io/pypi/v/py-cap.svg)](https://pypi.org/project/py-cap/)
[![Python versions](https://img.shields.io/pypi/pyversions/py-cap.svg)](https://pypi.org/project/py-cap/)
[![License](https://img.shields.io/pypi/l/py-cap.svg)](https://github.com/CaptainDriftwood/py-cap/blob/main/LICENSE)
[![Tests](https://github.com/CaptainDriftwood/py-cap/actions/workflows/test.yml/badge.svg)](https://github.com/CaptainDriftwood/py-cap/actions/workflows/test.yml)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Downloads](https://img.shields.io/pypi/dm/py-cap.svg)](https://pypi.org/project/py-cap/)
```

**Optional badges (after setup):**
- Code coverage (Codecov)
- Documentation status (Read the Docs)
- Security (Snyk or CodeQL)

---

#### 10. Add Docker Integration Test Fixture

**Status:** ❌ Not Done

Create a pytest fixture that manages Docker Compose infrastructure for integration testing, making it available to users of the pytest plugin.

**Recommendation:** Add to `pytest_pycap/__init__.py`:

```python
import subprocess
import time
from pathlib import Path
from typing import Generator, Optional

import pytest

from pycap import IcapClient


@pytest.fixture(scope="session")
def icap_server(request) -> Generator[dict, None, None]:
    """
    Start an ICAP server using Docker Compose for integration testing.

    This fixture:
    - Starts c-icap + ClamAV using Docker Compose
    - Waits for the service to be ready
    - Yields connection configuration
    - Tears down containers after tests complete

    Requires:
    - Docker and Docker Compose installed
    - docker/docker-compose.yml in the project

    Example:
        @pytest.mark.integration
        def test_real_scan(icap_server, sample_clean_content):
            with IcapClient(icap_server['host'], icap_server['port']) as client:
                response = client.scan_bytes(sample_clean_content)
                assert response.is_no_modification

    Configuration via marker:
        @pytest.mark.icap_server(compose_file="custom/docker-compose.yml", timeout=120)
        def test_custom_server(icap_server):
            ...
    """
    marker = request.node.get_closest_marker("icap_server")

    # Default configuration
    compose_file = Path("docker/docker-compose.yml")
    startup_timeout = 60
    service_host = "localhost"
    service_port = 1344

    # Override with marker kwargs if provided
    if marker and marker.kwargs:
        if "compose_file" in marker.kwargs:
            compose_file = Path(marker.kwargs["compose_file"])
        if "timeout" in marker.kwargs:
            startup_timeout = marker.kwargs["timeout"]
        if "host" in marker.kwargs:
            service_host = marker.kwargs["host"]
        if "port" in marker.kwargs:
            service_port = marker.kwargs["port"]

    if not compose_file.exists():
        pytest.skip(f"Docker Compose file not found: {compose_file}")

    # Start containers
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d"],
        check=True,
        capture_output=True,
    )

    # Wait for service to be ready
    config = {"host": service_host, "port": service_port, "service": "avscan"}
    _wait_for_icap_service(config, timeout=startup_timeout)

    yield config

    # Teardown
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "down", "-v"],
        check=True,
        capture_output=True,
    )


def _wait_for_icap_service(config: dict, timeout: int = 60) -> None:
    """Poll ICAP service until it responds to OPTIONS request."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with IcapClient(config["host"], config["port"], timeout=5) as client:
                response = client.options(config["service"])
                if response.is_success:
                    return
        except Exception:
            pass
        time.sleep(2)
    raise TimeoutError(f"ICAP service not ready after {timeout} seconds")
```

**Register the marker in `pytest_configure`:**

```python
def pytest_configure(config):
    config.addinivalue_line("markers", "icap: mark test as requiring an ICAP server")
    config.addinivalue_line(
        "markers",
        "icap_server(compose_file, timeout, host, port): configure Docker ICAP server"
    )
```

---

#### 11. Create Documentation Site with MkDocs

**Status:** ❌ Not Done

Set up a documentation site using MkDocs with Material theme for comprehensive project documentation.

**Project structure:**

```
docs/
├── index.md              # Home page (copy of README or custom)
├── getting-started.md    # Installation & quick start
├── user-guide/
│   ├── sync-client.md    # IcapClient usage
│   ├── async-client.md   # AsyncIcapClient usage
│   └── scanning.md       # File/bytes/stream scanning
├── pytest-plugin/
│   ├── installation.md   # Plugin setup
│   ├── fixtures.md       # Available fixtures
│   └── markers.md        # Custom markers
├── api/
│   ├── client.md         # IcapClient API reference
│   ├── async-client.md   # AsyncIcapClient API reference
│   ├── response.md       # IcapResponse API reference
│   └── exceptions.md     # Exception hierarchy
├── development/
│   ├── contributing.md   # Contribution guide
│   ├── testing.md        # Running tests
│   └── docker.md         # Docker setup for testing
└── changelog.md          # Version history
mkdocs.yml                # MkDocs configuration
```

**MkDocs configuration (`mkdocs.yml`):**

```yaml
site_name: py-cap
site_description: Pure Python ICAP client library
site_url: https://captaindriftwood.github.io/py-cap/
repo_url: https://github.com/CaptainDriftwood/py-cap
repo_name: CaptainDriftwood/py-cap

theme:
  name: material
  palette:
    - scheme: default
      primary: indigo
      accent: indigo
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
    - scheme: slate
      primary: indigo
      accent: indigo
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
  features:
    - navigation.tabs
    - navigation.sections
    - navigation.expand
    - content.code.copy
    - content.code.annotate

plugins:
  - search
  - mkdocstrings:
      handlers:
        python:
          options:
            show_source: true
            show_root_heading: true

markdown_extensions:
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.superfences
  - pymdownx.tabbed:
      alternate_style: true
  - admonition
  - pymdownx.details

nav:
  - Home: index.md
  - Getting Started: getting-started.md
  - User Guide:
    - Sync Client: user-guide/sync-client.md
    - Async Client: user-guide/async-client.md
    - Scanning Files: user-guide/scanning.md
  - Pytest Plugin:
    - Installation: pytest-plugin/installation.md
    - Fixtures: pytest-plugin/fixtures.md
    - Markers: pytest-plugin/markers.md
  - API Reference:
    - IcapClient: api/client.md
    - AsyncIcapClient: api/async-client.md
    - IcapResponse: api/response.md
    - Exceptions: api/exceptions.md
  - Development:
    - Contributing: development/contributing.md
    - Testing: development/testing.md
    - Docker Setup: development/docker.md
  - Changelog: changelog.md
```

**Dependencies to add:**

```toml
[project.optional-dependencies]
docs = [
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.0.0",
    "mkdocstrings[python]>=0.24.0",
]
```

**GitHub Actions for docs (`docs.yml`):**

```yaml
name: Deploy Documentation

on:
  push:
    branches: [main, master]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: astral-sh/setup-uv@v5
    - name: Install dependencies
      run: |
        uv python install 3.11
        uv sync --all-extras
        uv pip install mkdocs mkdocs-material mkdocstrings[python]
    - name: Deploy to GitHub Pages
      run: uv run mkdocs gh-deploy --force
```

---

### Low Priority

#### 12. Optimize Fixture Scope

**Status:** ❌ Not Done

`icap_service_config` returns constant values but is function-scoped.

**Recommendation:** Change to session scope:

```python
@pytest.fixture(scope="session")
def icap_service_config() -> Dict[str, Any]:
    """Default ICAP service configuration (session-scoped for performance)."""
    return {
        "host": "localhost",
        "port": 1344,
        "service": "avscan",
    }
```

---

#### 13. Add Configuration via pytest.ini Options

**Status:** ❌ Not Done (Enhancement)

Allow default configuration via pytest.ini/pyproject.toml instead of only markers.

**Recommendation:** Add `pytest_addoption` hook:

```python
def pytest_addoption(parser):
    """Add ICAP plugin configuration options."""
    parser.addini("icap_host", default="localhost", help="Default ICAP server hostname")
    parser.addini("icap_port", default="1344", help="Default ICAP server port")
    parser.addini("icap_service", default="avscan", help="Default ICAP service name")
    parser.addini("icap_timeout", default="10", help="Default timeout in seconds")
```

---

#### 14. Move EICAR Constant

**Status:** ⚠️ Low Priority

`EICAR_TEST_STRING` is in `examples/test_utils.py`. Consider moving to `pycap.constants` or the pytest plugin for better discoverability.

---

#### ~~15. Version Sync~~ ✅ DONE

**Status:** ✅ Complete

Implemented using `importlib.metadata.version()` in `pycap/__init__.py`. Single source of truth is now `pyproject.toml`.

---

#### 16. Add GitHub Templates and Community Files

**Status:** ❌ Not Done

Add standard GitHub community health files for better contributor experience and issue management.

**File structure:**

```
.github/
├── ISSUE_TEMPLATE/
│   ├── bug_report.yml           # Bug report form
│   ├── feature_request.yml      # Feature request form
│   └── config.yml               # Template chooser config
├── PULL_REQUEST_TEMPLATE.md     # PR template
└── CONTRIBUTING.md              # Contribution guidelines
```

**Bug Report Template (`.github/ISSUE_TEMPLATE/bug_report.yml`):**

```yaml
name: Bug Report
description: Report a bug or unexpected behavior
labels: ["bug", "triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for reporting a bug! Please fill out the sections below.

  - type: textarea
    id: description
    attributes:
      label: Description
      description: A clear description of the bug
      placeholder: What happened?
    validations:
      required: true

  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: Minimal code to reproduce the issue
      placeholder: |
        ```python
        from py_cap import IcapClient

        with IcapClient("localhost") as client:
            # Your code here
        ```
    validations:
      required: true

  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What did you expect to happen?
    validations:
      required: true

  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: What actually happened?
    validations:
      required: true

  - type: input
    id: version
    attributes:
      label: py-cap Version
      placeholder: "0.1.0"
    validations:
      required: true

  - type: input
    id: python-version
    attributes:
      label: Python Version
      placeholder: "3.11.0"
    validations:
      required: true

  - type: input
    id: os
    attributes:
      label: Operating System
      placeholder: "Ubuntu 22.04 / macOS 14 / Windows 11"
    validations:
      required: true

  - type: textarea
    id: icap-server
    attributes:
      label: ICAP Server Details
      description: Which ICAP server are you connecting to?
      placeholder: "c-icap with ClamAV, SquidClamav, etc."

  - type: textarea
    id: additional
    attributes:
      label: Additional Context
      description: Any other relevant information (logs, screenshots, etc.)
```

**Feature Request Template (`.github/ISSUE_TEMPLATE/feature_request.yml`):**

```yaml
name: Feature Request
description: Suggest a new feature or enhancement
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for suggesting a feature! Please describe your idea below.

  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: What problem does this feature solve?
      placeholder: "I'm always frustrated when..."
    validations:
      required: true

  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: How would you like this to work?
    validations:
      required: true

  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered
      description: Any alternative solutions or workarounds you've considered?

  - type: textarea
    id: additional
    attributes:
      label: Additional Context
      description: Any other context, mockups, or examples?
```

**Template Chooser Config (`.github/ISSUE_TEMPLATE/config.yml`):**

```yaml
blank_issues_enabled: true
contact_links:
  - name: Documentation
    url: https://captaindriftwood.github.io/py-cap/
    about: Check the documentation for usage guides and API reference
  - name: Discussions
    url: https://github.com/CaptainDriftwood/py-cap/discussions
    about: Ask questions and discuss ideas
```

**Pull Request Template (`.github/PULL_REQUEST_TEMPLATE.md`):**

```markdown
## Description

<!-- Brief description of the changes -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] Test improvements

## Related Issues

<!-- Link any related issues: Fixes #123, Closes #456 -->

## Checklist

- [ ] I have read the [CONTRIBUTING](CONTRIBUTING.md) guidelines
- [ ] My code follows the project's code style (ruff)
- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass locally (`uv run pytest`)
- [ ] I have updated documentation if needed
- [ ] My changes generate no new warnings

## Test Plan

<!-- How did you test these changes? -->

## Screenshots (if applicable)

<!-- Add screenshots for UI changes -->
```

**Contributing Guidelines (`.github/CONTRIBUTING.md`):**

```markdown
# Contributing to py-cap

Thank you for your interest in contributing to py-cap!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/CaptainDriftwood/py-cap.git
   cd py-cap
   ```

2. Install uv (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. Install dependencies:
   ```bash
   uv sync --all-extras
   ```

4. Run tests:
   ```bash
   uv run pytest
   ```

## Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
uv run ruff check .
uv run ruff format .
```

## Running Integration Tests

Integration tests require Docker:

```bash
cd docker && docker compose up -d
uv run pytest -m integration
docker compose down
```

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Make your changes
4. Run tests and linting
5. Commit with a descriptive message
6. Push to your fork
7. Open a Pull Request

## Questions?

Open a [Discussion](https://github.com/CaptainDriftwood/py-cap/discussions) or reach out!
```

---

#### 17. Create Project Logo

**Status:** ❌ Not Done

Create a distinctive logo for the py-cap project to establish brand identity.

**Logo concepts:**

- Python snake + shield (security/antivirus theme)
- Network packet with magnifying glass (content inspection)
- Stylized "ICAP" with Python elements
- Cap/hat icon with Python colors (play on "py-cap" name)

**File locations:**

```
assets/
├── logo.svg              # Vector source (primary)
├── logo.png              # High-res PNG (512x512 or 1024x1024)
├── logo-dark.svg         # Dark theme variant
├── logo-dark.png         # Dark theme PNG
├── favicon.ico           # For documentation site
└── logo-banner.png       # Wide format for README header
```

**Usage locations:**

1. **README.md** - Banner at top of file
   ```markdown
   <p align="center">
     <img src="assets/logo-banner.png" alt="py-cap logo" width="400">
   </p>
   ```

2. **MkDocs** - Add to `mkdocs.yml`:
   ```yaml
   theme:
     logo: assets/logo.svg
     favicon: assets/favicon.ico
   ```

3. **PyPI** - Reference in project description

4. **GitHub** - Repository social preview image (Settings → Social preview)

**Design guidelines:**

- Simple, recognizable at small sizes
- Works in both light and dark modes
- Use Python blue/yellow color palette or security-themed colors
- SVG format for scalability
- Consider accessibility (sufficient contrast)

**Tools for creation:**

- Figma (free tier available)
- Inkscape (open source)
- Adobe Illustrator
- Canva (for quick iterations)
- Hire on Fiverr/99designs for professional result

---

## Package Rename & PyPI Publishing

### Background

The name `pycap` is taken on PyPI by an unrelated package (REDCap API client).

**Chosen name: `py-cap`**

| Context | Name | Example |
|---------|------|---------|
| PyPI / pip install | `py-cap` | `pip install py-cap` |
| Python imports | `py_cap` | `from py_cap import IcapClient` |
| Directory name | `py_cap/` | The actual package folder |
| GitHub repo | `py-cap` | `github.com/CaptainDriftwood/py-cap` |

### Migration Checklist

#### Phase 1: Rename on GitHub
- [ ] Go to `github.com/CaptainDriftwood/pycap` → Settings → General
- [ ] Change "Repository name" from `pycap` to `py-cap`
- [ ] GitHub automatically creates redirects from the old URL

#### Phase 2: Update Local Git Remote
```bash
git remote set-url origin https://github.com/CaptainDriftwood/py-cap.git
```

#### Phase 3: Rename Package Directories

**PyCharm approach (recommended):**
1. Right-click `pycap/` folder → Refactor → Rename (Shift+F6)
2. Rename to `py_cap`
3. Check "Search for references" and "Search in comments and strings"
4. Repeat for `pytest_pycap/` → `pytest_py_cap/`

**Manual approach:**
```bash
mv pycap/ py_cap/
mv pytest_pycap/ pytest_py_cap/
```

#### Phase 4: Update pyproject.toml
- [ ] `name = "pycap"` → `name = "py-cap"`
- [ ] Update `Homepage` URL
- [ ] Update `Repository` URL
- [ ] Update entry point: `pycap = ...` → `py_cap = "pytest_py_cap.plugin"`
- [ ] Update packages: `["py_cap", "pytest_py_cap"]`
- [ ] Update pyright include: `["py_cap"]`

#### Phase 5: Update All Imports
- [ ] `from pycap import ...` → `from py_cap import ...`
- [ ] Check test files
- [ ] Check example files
- [ ] Update README.md

#### Phase 6: Verify and Test
- [ ] Run all tests: `uv run pytest`
- [ ] Run linter: `uv run ruff check .`
- [ ] Build the package: `uv build`

#### Phase 7: Make Repository Public
- [ ] Settings → General → Danger Zone → Change visibility → Make public

#### Phase 8: Set Up PyPI Publishing
- [ ] Add `PYPI_API_TOKEN` to repository secrets
- [ ] Create publish workflow (see GitHub Actions section)

#### Phase 9: First Release
- [ ] Create GitHub release with tag (e.g., `v0.1.0`)
- [ ] Verify package at `https://pypi.org/project/py-cap/`

---

## GitHub Actions Improvements

### Current State

| Workflow | Status | Notes |
|----------|--------|-------|
| `test.yml` | ✅ Good | Matrix testing 3.8-3.14, uses uv |
| `lint.yml` | ✅ Fixed | Now includes `master` branch trigger |
| `typecheck.yml` | ✅ Fixed | Now uses uv and ty type checker |

### Recommended New Workflows

#### 1. Security Scanning (CodeQL)

**Status:** ❌ Not Added

```yaml
# .github/workflows/codeql.yml
name: CodeQL

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]
  schedule:
    - cron: '0 6 * * 1'  # Weekly

permissions:
  security-events: write
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: github/codeql-action/init@v3
      with:
        languages: python
    - uses: github/codeql-action/analyze@v3
```

#### 2. Dependency Review

**Status:** ❌ Not Added

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review

on: [pull_request]

permissions:
  contents: read

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/dependency-review-action@v4
```

#### 3. PyPI Publishing

**Status:** ❌ Not Added

```yaml
# .github/workflows/publish.yml
name: Publish to PyPI

on:
  release:
    types: [published]

permissions:
  contents: read
  id-token: write  # For trusted publishing

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    steps:
    - uses: actions/checkout@v4
    - uses: astral-sh/setup-uv@v5
    - name: Build package
      run: uv build
    - name: Publish to PyPI
      uses: pypa/gh-action-pypi-publish@release/v1
```

#### 4. Code Coverage

**Status:** ❌ Not Added

Add to test.yml:

```yaml
- name: Run tests with coverage
  run: uv run pytest --cov=pycap --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v4
```

#### 5. Release Drafter

**Status:** ❌ Not Added (Optional)

```yaml
# .github/workflows/release-drafter.yml
name: Release Drafter

on:
  push:
    branches: [main, master]

permissions:
  contents: write
  pull-requests: read

jobs:
  update_release_draft:
    runs-on: ubuntu-latest
    steps:
    - uses: release-drafter/release-drafter@v6
```

---

## Code Quality Items

### Potential Bugs Identified (from Copilot Review)

#### 1. Socket Connection Reuse Issue

**Status:** ⚠️ Known Limitation

After a request completes, the socket remains connected but the server may close it. Subsequent calls could fail.

**Current Mitigation:** Context manager pattern disconnects after use. Documentation recommends one connection per operation or using context manager.

**Future Enhancement:** Add connection health check or implement keep-alive handling per RFC 3507 OPTIONS response.

---

#### 2. Thread Safety

**Status:** ⚠️ Known Limitation

`IcapClient` is not thread-safe. Multiple threads sharing a client instance could corrupt socket state.

**Current Mutable State:**

| Attribute | Type | Thread-Safety Risk |
|-----------|------|-------------------|
| `_socket` | `socket.socket` | **High** - sockets are not thread-safe |
| `_connected` | `bool` | **Medium** - race conditions on read/modify |
| `_address`, `_port`, `_timeout` | immutable after init | Low |

**Core Problems:**

1. **Socket interleaving**: If two threads call `scan_bytes()` concurrently, their requests/responses will interleave and corrupt the ICAP protocol
2. **Check-then-act races**: `if not self._connected: self.connect()` pattern is not atomic
3. **State corruption**: `disconnect()` sets `_socket = None` while another thread is mid-read

**Current Mitigation:** Documentation notes this. Users should create separate client instances per thread or use `AsyncIcapClient` for concurrent operations.

**Implementation Options (see Future Enhancements):**

| Approach | Pros | Cons | Best For |
|----------|------|------|----------|
| Lock-based (`threading.RLock`) | Simple, works 3.8-3.14 | Serializes all operations | Low contention apps |
| Thread-local storage | True parallelism, simple mental model | More connections, memory overhead | Thread-pool apps |
| Connection pool | Bounded resources, efficient reuse | More complex, pool exhaustion handling | High-throughput apps |
| Stateless (new socket per op) | Inherently thread-safe | Connection overhead | Low-frequency scanning |

**Python 3.13+ Note:** Free-threaded Python (PEP 703, experimental) disables the GIL. In this mode, explicit locking becomes more critical, not less—the GIL previously "accidentally" serialized some operations.

---

### Best Practices Compliance (Pytest Plugin)

| Practice | Status | Notes |
|----------|--------|-------|
| Entry point registration | ✅ | Correct pyproject.toml format |
| Marker registration | ✅ | Via `pytest_configure()` |
| Fixture cleanup | ✅ | yield + context managers |
| Fixture naming | ✅ | Clear snake_case names |
| Configuration via markers | ✅ | `@pytest.mark.icap(host=..., ssl_context=...)` |
| Framework classifier | ✅ | `"Framework :: Pytest"` present |
| Public API for state | ✅ | `is_connected` property added |
| Fixture scope optimization | ❌ | `icap_service_config` function-scoped |
| Plugin self-tests | ✅ | Pytester tests in `tests/test_pytest_plugin.py` |

---

## Future Enhancements

These are nice-to-have features not blocking release:

### ~~1. ICAP Preview Support~~ ✅ DONE

RFC 3507 preview support implemented. Added `preview` parameter to `respmod()` method with proper 100 Continue handling.

### ~~2. SSL/TLS Support~~ ✅ DONE

SSL/TLS support implemented. Added `ssl_context` parameter to both `IcapClient` and `AsyncIcapClient`. Docker setup includes TLS-enabled server on port 11344.

### 3. Thread Safety & Connection Pooling

For thread-safe and high-throughput applications, consider implementing one or more of these approaches:

#### Option A: Lock-Based Synchronization

Add a `threading.RLock` to serialize all socket operations:

```python
import threading

class IcapClient:
    def __init__(self, ...):
        self._lock = threading.RLock()  # Reentrant for nested calls

    def options(self, service):
        with self._lock:
            # ... entire operation is atomic
```

**Best for:** Applications where thread-safety is needed but concurrent ICAP requests from the same client are rare.

#### Option B: Thread-Local Storage

Use `threading.local()` to give each thread its own client instance:

```python
import threading

_thread_local = threading.local()

def get_client(host, port):
    if not hasattr(_thread_local, 'client'):
        _thread_local.client = IcapClient(host, port)
        _thread_local.client.connect()
    return _thread_local.client
```

**Best for:** Thread-pool based applications (web servers, workers) where each thread handles independent requests.

#### Option C: Connection Pool

Create a pool of `IcapClient` instances that threads borrow and return:

```python
from queue import Queue
from contextlib import contextmanager

class IcapClientPool:
    def __init__(self, host, port, size=10):
        self._pool = Queue(maxsize=size)
        self._host = host
        self._port = port
        for _ in range(size):
            client = IcapClient(host, port)
            client.connect()
            self._pool.put(client)

    def acquire(self, timeout=None):
        return self._pool.get(timeout=timeout)

    def release(self, client):
        self._pool.put(client)

    @contextmanager
    def client(self):
        c = self.acquire()
        try:
            yield c
        finally:
            self.release(c)
```

**Best for:** High-throughput applications with many concurrent scans.

#### Option D: Stateless Client (New Connection Per Operation)

Make the client stateless—each method creates its own socket:

```python
class IcapClient:
    def scan_bytes(self, data, ...):
        with socket.socket(...) as sock:
            sock.connect((self._address, self._port))
            # ... complete operation
```

**Best for:** Low-frequency scanning where simplicity trumps performance.

#### Python Version Compatibility (3.8–3.14)

| Feature | Availability | Notes |
|---------|--------------|-------|
| `threading.Lock` / `RLock` | All versions | Stable, recommended |
| `threading.local()` | All versions | Stable, recommended |
| `queue.Queue` | All versions | For connection pools |
| `contextvars` | 3.7+ | Alternative to thread-local for async-aware code |
| Free-threaded Python (no GIL) | 3.13+ (experimental) | Requires more careful locking |

**Recommendation:** Implement Option A (lock-based) as the default for basic thread-safety, and provide Option C (connection pool) as `IcapClientPool` for high-throughput use cases.

### 4. Retry/Backoff Logic

Network operations could benefit from configurable retry logic with exponential backoff:

```python
def connect(self, retries: int = 3, retry_delay: float = 1.0) -> None:
    """Connect with retry support."""
```

### 5. Response Body Parsing

`IcapResponse.body` contains raw bytes including encapsulated HTTP. Consider parsing into structured fields (modified HTTP headers/body).

---

## PyPI Readiness Checklist

| Item | Status | Action Needed |
|------|--------|---------------|
| `pyproject.toml` | ✅ | Good configuration |
| `README.md` | ✅ | Well documented |
| `LICENSE` | ✅ | MIT LICENSE file added |
| Classifiers | ✅ | Comprehensive (Python 3.8-3.14) |
| Python version | ✅ | 3.8+ good choice |
| Dependencies | ✅ | No runtime deps (pure Python) |
| Entry points | ✅ | pytest plugin registered |
| Version | ✅ | Using `importlib.metadata.version()` |
| Keywords | ✅ | Added to pyproject.toml |
| Package name | ❌ | **Rename to py-cap** |
| Project URLs | ✅ | Homepage, Repository present |
| Issues URL | ❌ | Add Issues URL |
| Changelog URL | ❌ | Add Changelog URL |

---

## References

### Official Documentation

- [pytest - Writing plugins](https://docs.pytest.org/en/stable/how-to/writing_plugins.html)
- [pytest - How to use fixtures](https://docs.pytest.org/en/stable/how-to/fixtures.html)
- [pytest - Writing hook functions](https://docs.pytest.org/en/stable/how-to/writing_hook_functions.html)
- [pytest - Configuration](https://docs.pytest.org/en/stable/reference/customize.html)
- [Python Packaging - Creating plugins](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/)
- [RFC 3507 - ICAP Protocol](https://www.rfc-editor.org/rfc/rfc3507)

### Related PyPI Packages

| Name | Description | Status |
|------|-------------|--------|
| `pycap` | REDCap API client (unrelated) | Active - name conflict |
| `pyicap` | ICAP server framework | April 2017 (stale) |
| `icapclient` | ICAP client in C | Maintained |
| `icapclient3` | Python 3 fork | Active |
| `py-cap` | **Available** | Our target name |