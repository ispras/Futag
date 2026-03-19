"""Tests for the FuzzDataProviderGenerator class."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.fdp_generator import FuzzDataProviderGenerator


@pytest.fixture
def fdp_generator(tmp_futag_package, tmp_library_root):
    return FuzzDataProviderGenerator(tmp_futag_package, tmp_library_root)


class TestFDPProperties:
    def test_supports_c_false(self, fdp_generator):
        assert fdp_generator.supports_c is False

    def test_needs_buffer_check_false(self, fdp_generator):
        assert fdp_generator.needs_buffer_check is False

    def test_default_headers_includes_fdp(self, fdp_generator):
        assert "fuzzer/FuzzedDataProvider.h" in fdp_generator.default_headers

    def test_harness_preamble_has_provider(self, fdp_generator):
        assert "FuzzedDataProvider" in fdp_generator.harness_preamble


class TestFDPGenBuiltin:
    def test_int_uses_consume_integral(self, fdp_generator):
        result = fdp_generator._gen_builtin("x", {"type_name": "int"})
        assert any("ConsumeIntegral<int>" in line for line in result["gen_lines"])
        assert result["buffer_size"] == []

    def test_float_uses_consume_floating_point(self, fdp_generator):
        result = fdp_generator._gen_builtin("x", {"type_name": "float"})
        assert any("ConsumeFloatingPoint<float>" in line for line in result["gen_lines"])

    def test_double_uses_consume_floating_point(self, fdp_generator):
        result = fdp_generator._gen_builtin("x", {"type_name": "double"})
        assert any("ConsumeFloatingPoint<double>" in line for line in result["gen_lines"])


class TestFDPGenCstring:
    def test_uses_consume_random_length_string(self, fdp_generator):
        result = fdp_generator._gen_cstring("s", {"type_name": "const char *", "local_qualifier": ""}, 1)
        assert any("ConsumeRandomLengthString" in line for line in result["gen_lines"])
        assert result["gen_free"] == []
