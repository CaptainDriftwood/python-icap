"""Nox configuration for multi-version Python testing."""

import nox

# Use uv for fast environment creation
nox.options.default_venv_backend = "uv"

PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]


@nox.session(python=PYTHON_VERSIONS)
def tests(session: nox.Session) -> None:
    """Run the test suite across Python versions."""
    session.install("-e", ".[dev]")
    session.run("pytest", "-m", "not integration", *session.posargs)


@nox.session(python=PYTHON_VERSIONS)
def lint(session: nox.Session) -> None:
    """Run linting across Python versions."""
    session.install("ruff")
    session.run("ruff", "check", ".")


@nox.session(python="3.12")
def typecheck(session: nox.Session) -> None:
    """Run type checking."""
    session.install("-e", ".[dev]")
    session.run("ty", "check", "py_cap")
