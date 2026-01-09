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


# === Mock Fixture Pytester Tests ===


def test_mock_icap_client_fixture(pytester):
    """Verify mock_icap_client fixture returns clean responses by default."""
    pytester.makepyfile(
        """
        def test_mock_client(mock_icap_client):
            response = mock_icap_client.scan_bytes(b"test content")
            assert response.is_no_modification
            assert response.status_code == 204
            mock_icap_client.assert_called("scan_bytes", times=1)
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_mock_async_icap_client_fixture(pytester):
    """Verify mock_async_icap_client fixture works with async tests."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.asyncio
        async def test_async_mock_client(mock_async_icap_client):
            async with mock_async_icap_client as client:
                response = await client.scan_bytes(b"test content")
                assert response.is_no_modification
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_mock_icap_client_virus_fixture(pytester):
    """Verify mock_icap_client_virus fixture detects viruses."""
    pytester.makepyfile(
        """
        def test_virus_detection(mock_icap_client_virus):
            response = mock_icap_client_virus.scan_bytes(b"malware")
            assert not response.is_no_modification
            assert "X-Virus-ID" in response.headers
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_mock_icap_client_timeout_fixture(pytester):
    """Verify mock_icap_client_timeout fixture raises timeout errors."""
    pytester.makepyfile(
        """
        import pytest
        from pycap.exception import IcapTimeoutError

        def test_timeout(mock_icap_client_timeout):
            with pytest.raises(IcapTimeoutError):
                mock_icap_client_timeout.scan_bytes(b"content")
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_mock_icap_client_connection_error_fixture(pytester):
    """Verify mock_icap_client_connection_error fixture raises connection errors."""
    pytester.makepyfile(
        """
        import pytest
        from pycap.exception import IcapConnectionError

        def test_connection_error(mock_icap_client_connection_error):
            with pytest.raises(IcapConnectionError):
                mock_icap_client_connection_error.scan_bytes(b"content")
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


# === Response Fixture Pytester Tests ===


def test_icap_response_builder_fixture(pytester):
    """Verify icap_response_builder fixture provides a builder instance."""
    pytester.makepyfile(
        """
        from pytest_pycap import IcapResponseBuilder

        def test_builder(icap_response_builder):
            assert isinstance(icap_response_builder, IcapResponseBuilder)
            response = icap_response_builder.virus("Test.Virus").build()
            assert response.headers["X-Virus-ID"] == "Test.Virus"
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_response_clean_fixture(pytester):
    """Verify icap_response_clean fixture provides 204 response."""
    pytester.makepyfile(
        """
        def test_clean_response(icap_response_clean):
            assert icap_response_clean.status_code == 204
            assert icap_response_clean.is_no_modification
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_response_virus_fixture(pytester):
    """Verify icap_response_virus fixture provides virus detection response."""
    pytester.makepyfile(
        """
        def test_virus_response(icap_response_virus):
            assert icap_response_virus.status_code == 200
            assert "X-Virus-ID" in icap_response_virus.headers
            assert "X-Infection-Found" in icap_response_virus.headers
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_icap_response_error_fixture(pytester):
    """Verify icap_response_error fixture provides 500 error response."""
    pytester.makepyfile(
        """
        def test_error_response(icap_response_error):
            assert icap_response_error.status_code == 500
            assert icap_response_error.status_message == "Internal Server Error"
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


# === icap_mock Marker Pytester Tests ===


def test_icap_mock_marker_registered(pytester):
    """Verify icap_mock marker is properly registered."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_mock(response="clean")
        def test_with_marker(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert response.is_no_modification
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_mock_marker_virus_response(pytester):
    """Verify icap_mock marker with response='virus'."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_mock(response="virus", virus_name="Trojan.Test")
        def test_virus(icap_mock):
            response = icap_mock.scan_bytes(b"malware")
            assert not response.is_no_modification
            assert response.headers["X-Virus-ID"] == "Trojan.Test"
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_mock_marker_raises_exception(pytester):
    """Verify icap_mock marker with raises parameter."""
    pytester.makepyfile(
        """
        import pytest
        from pycap.exception import IcapTimeoutError

        @pytest.mark.icap_mock(raises=IcapTimeoutError)
        def test_timeout(icap_mock):
            with pytest.raises(IcapTimeoutError):
                icap_mock.scan_bytes(b"content")
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_mock_marker_per_method_config(pytester):
    """Verify icap_mock marker with per-method configuration."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_mock(
            respmod={"response": "virus"},
            options={"response": "clean"},
        )
        def test_mixed_config(icap_mock):
            # scan_bytes uses respmod, should return virus
            scan_response = icap_mock.scan_bytes(b"content")
            assert not scan_response.is_no_modification

            # options configured with clean returns 204
            options_response = icap_mock.options("avscan")
            assert options_response.is_no_modification
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


# === Mock Client Usage Pytester Tests ===


def test_mock_client_call_recording(pytester):
    """Verify mock client records calls correctly."""
    pytester.makepyfile(
        """
        def test_call_recording(mock_icap_client):
            mock_icap_client.scan_bytes(b"first")
            mock_icap_client.scan_bytes(b"second")
            mock_icap_client.options("avscan")

            assert len(mock_icap_client.calls) == 3
            mock_icap_client.assert_called("scan_bytes", times=2)
            mock_icap_client.assert_called("options", times=1)
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_mock_client_custom_response_configuration(pytester):
    """Verify mock client can be configured with custom responses."""
    pytester.makepyfile(
        """
        from pytest_pycap import IcapResponseBuilder

        def test_custom_config(mock_icap_client):
            # Configure custom virus response
            mock_icap_client.on_respmod(
                IcapResponseBuilder().virus("CustomVirus").build()
            )

            response = mock_icap_client.scan_bytes(b"content")
            assert response.headers["X-Virus-ID"] == "CustomVirus"
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_mock_client_context_manager(pytester):
    """Verify mock client works as context manager."""
    pytester.makepyfile(
        """
        from pytest_pycap import MockIcapClient

        def test_context_manager():
            with MockIcapClient() as client:
                assert client.is_connected
                response = client.scan_bytes(b"test")
                assert response.is_no_modification
            assert not client.is_connected
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_response_builder_fluent_api(pytester):
    """Verify IcapResponseBuilder fluent API works correctly."""
    pytester.makepyfile(
        """
        from pytest_pycap import IcapResponseBuilder

        def test_fluent_builder():
            response = (
                IcapResponseBuilder()
                .with_status(200, "OK")
                .with_header("X-Custom", "value")
                .with_body(b"modified")
                .build()
            )
            assert response.status_code == 200
            assert response.headers["X-Custom"] == "value"
            assert response.body == b"modified"
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_plugin_exports_mock_components(pytester):
    """Verify the plugin exports mock components."""
    pytester.makepyfile(
        """
        import pytest_pycap

        def test_mock_exports():
            assert hasattr(pytest_pycap, "IcapResponseBuilder")
            assert hasattr(pytest_pycap, "MockIcapClient")
            assert hasattr(pytest_pycap, "MockAsyncIcapClient")
            assert hasattr(pytest_pycap, "MockCall")
            assert hasattr(pytest_pycap, "mock_icap_client")
            assert hasattr(pytest_pycap, "mock_async_icap_client")
            assert hasattr(pytest_pycap, "icap_response_builder")
            assert hasattr(pytest_pycap, "icap_mock")
        """
    )
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


# === Stacked icap_response Marker Tests ===


def test_icap_response_marker_registered(pytester):
    """Verify icap_response marker is properly registered."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_response("clean")
        def test_with_marker(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert response.is_no_modification
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_response_marker_virus_preset(pytester):
    """Verify icap_response marker with virus preset."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_response("virus")
        def test_virus_preset(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert not response.is_no_modification
            assert "X-Virus-ID" in response.headers
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_response_marker_virus_with_name(pytester):
    """Verify icap_response marker with custom virus name."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_response("virus", virus_name="Trojan.Custom")
        def test_named_virus(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert response.headers["X-Virus-ID"] == "Trojan.Custom"
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_response_marker_error_preset(pytester):
    """Verify icap_response marker with error preset."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_response("error")
        def test_error_preset(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert response.status_code == 500
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_response_marker_custom_error(pytester):
    """Verify icap_response marker with custom error code."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_response("error", code=503, message="Service Unavailable")
        def test_custom_error(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert response.status_code == 503
            assert response.status_message == "Service Unavailable"
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_stacked_icap_response_markers(pytester):
    """Verify stacked icap_response markers create a sequence."""
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.icap_response("clean")
        @pytest.mark.icap_response("virus")
        @pytest.mark.icap_response("clean")
        def test_sequence(icap_mock):
            r1 = icap_mock.scan_bytes(b"file1")
            assert r1.is_no_modification, "First should be clean"

            r2 = icap_mock.scan_bytes(b"file2")
            assert not r2.is_no_modification, "Second should be virus"
            assert "X-Virus-ID" in r2.headers

            r3 = icap_mock.scan_bytes(b"file3")
            assert r3.is_no_modification, "Third should be clean"
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_stacked_icap_response_markers_exhaustion(pytester):
    """Verify stacked markers raise error when exhausted."""
    pytester.makepyfile(
        """
        import pytest
        from pytest_pycap import MockResponseExhaustedError

        @pytest.mark.icap_response("clean")
        @pytest.mark.icap_response("virus")
        def test_exhaustion(icap_mock):
            icap_mock.scan_bytes(b"file1")  # clean
            icap_mock.scan_bytes(b"file2")  # virus

            with pytest.raises(MockResponseExhaustedError):
                icap_mock.scan_bytes(b"file3")  # exhausted
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_response_marker_with_response_object(pytester):
    """Verify icap_response marker accepts IcapResponse objects."""
    pytester.makepyfile(
        """
        import pytest
        from pytest_pycap import IcapResponseBuilder

        custom_response = IcapResponseBuilder().with_status(418, "I'm a teapot").build()

        @pytest.mark.icap_response(custom_response)
        def test_custom_response(icap_mock):
            response = icap_mock.scan_bytes(b"test")
            assert response.status_code == 418
            assert response.status_message == "I'm a teapot"
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)


def test_icap_response_marker_mixed_presets_and_objects(pytester):
    """Verify stacked markers can mix presets and response objects."""
    pytester.makepyfile(
        """
        import pytest
        from pytest_pycap import IcapResponseBuilder

        custom = IcapResponseBuilder().with_status(418, "I'm a teapot").build()

        @pytest.mark.icap_response("clean")
        @pytest.mark.icap_response(custom)
        @pytest.mark.icap_response("virus", virus_name="Test.Virus")
        def test_mixed(icap_mock):
            r1 = icap_mock.scan_bytes(b"file1")
            assert r1.is_no_modification

            r2 = icap_mock.scan_bytes(b"file2")
            assert r2.status_code == 418

            r3 = icap_mock.scan_bytes(b"file3")
            assert r3.headers["X-Virus-ID"] == "Test.Virus"
        """
    )
    result = pytester.runpytest("--strict-markers")
    result.assert_outcomes(passed=1)
