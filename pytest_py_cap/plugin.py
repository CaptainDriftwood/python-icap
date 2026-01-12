"""
Pytest plugin entry point for PyCap.
"""

from pytest_py_cap import (
    async_icap_client,
    icap_client,
    icap_mock,
    icap_response_builder,
    icap_response_clean,
    icap_response_error,
    icap_response_options,
    icap_response_virus,
    icap_service_config,
    mock_async_icap_client,
    mock_icap_client,
    mock_icap_client_connection_error,
    mock_icap_client_timeout,
    mock_icap_client_virus,
    pytest_configure,
    sample_clean_content,
    sample_file,
)

__all__ = [
    "pytest_configure",
    # Live client fixtures
    "async_icap_client",
    "icap_client",
    "icap_service_config",
    "sample_clean_content",
    "sample_file",
    # Response fixtures
    "icap_response_builder",
    "icap_response_clean",
    "icap_response_virus",
    "icap_response_options",
    "icap_response_error",
    # Mock client fixtures
    "mock_icap_client",
    "mock_async_icap_client",
    "mock_icap_client_virus",
    "mock_icap_client_timeout",
    "mock_icap_client_connection_error",
    # Marker-based fixtures
    "icap_mock",
]
