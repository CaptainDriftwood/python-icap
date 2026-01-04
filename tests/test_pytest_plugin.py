"""Tests for the pytest_pycap plugin using pytester."""

pytest_plugins = ["pytester"]


def test_icap_marker_registered(pytester):
    """Verify the icap marker is properly registered."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap
        def test_with_marker():
            pass
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_sample_clean_content_fixture(pytester):
    """Verify sample_clean_content fixture provides bytes."""
    pytester.makepyfile(
        """
        def test_content(sample_clean_content):
            assert isinstance(sample_clean_content, bytes)
            assert len(sample_clean_content) > 0
            assert b"clean" in sample_clean_content.lower()
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_service_config_fixture(pytester):
    """Verify icap_service_config returns expected structure."""
    pytester.makepyfile(
        """
        def test_config(icap_service_config):
            assert isinstance(icap_service_config, dict)
            assert "host" in icap_service_config
            assert "port" in icap_service_config
            assert "service" in icap_service_config
            assert icap_service_config["host"] == "localhost"
            assert icap_service_config["port"] == 1344
            assert icap_service_config["service"] == "avscan"
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_sample_file_fixture(pytester):
    """Verify sample_file fixture creates a temporary file."""
    pytester.makepyfile(
        """
        from pathlib import Path

        def test_file(sample_file):
            assert isinstance(sample_file, Path)
            assert sample_file.exists()
            assert sample_file.is_file()
            content = sample_file.read_bytes()
            assert len(content) > 0
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_marker_with_kwargs(pytester):
    """Verify icap marker accepts configuration kwargs."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap(host="custom-host", port=9999, timeout=30)
        def test_with_custom_config():
            # Just verify the marker is accepted with kwargs
            pass
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_plugin_exports(pytester):
    """Verify the plugin exports expected symbols."""
    pytester.makepyfile(
        """
        import pytest_pycap

        def test_exports():
            assert hasattr(pytest_pycap, "pytest_configure")
            assert hasattr(pytest_pycap, "icap_client")
            assert hasattr(pytest_pycap, "async_icap_client")
            assert hasattr(pytest_pycap, "icap_service_config")
            assert hasattr(pytest_pycap, "sample_clean_content")
            assert hasattr(pytest_pycap, "sample_file")
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_client_fixture_exists(pytester):
    """Verify icap_client fixture is registered (without connecting)."""
    pytester.makepyfile(
        """
        import pytest

        def test_fixture_registered(request):
            # Check that the fixture is registered
            fixture_names = [f for f in request.fixturenames]
            # We can't actually test the fixture without a server,
            # but we can verify it's importable
            from pytest_pycap import icap_client
            assert callable(icap_client)
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_async_icap_client_fixture_exists(pytester):
    """Verify async_icap_client fixture is registered and importable."""
    pytester.makepyfile(
        """
        def test_async_fixture_registered():
            from pytest_pycap import async_icap_client
            # The fixture is wrapped by pytest's decorator,
            # so we just verify it's importable and callable
            assert async_icap_client is not None
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_marker_with_ssl_context(pytester):
    """Verify icap marker accepts ssl_context kwarg."""
    pytester.makepyfile(
        """
        import ssl
        import pytest

        @pytest.mark.icap(host="icap.example.com", ssl_context=ssl.create_default_context())
        def test_with_ssl_context():
            # Just verify the marker is accepted with ssl_context
            pass
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)
