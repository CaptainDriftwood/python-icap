"""Pytest configuration for pycap tests."""

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply timeout to integration tests to allow for Docker startup."""
    for item in items:
        if "integration" in item.keywords:
            # Allow 300s for integration tests (Docker build/startup can be slow)
            item.add_marker(pytest.mark.timeout(300))
