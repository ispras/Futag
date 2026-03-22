"""Tests for the Generator class type generation methods."""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.generator import Generator


@pytest.fixture
def generator(tmp_futag_package, tmp_library_root):
    """Create a Generator instance with mock paths."""
    from futag.toolchain import ToolchainConfig
    tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
    return Generator(tmp_library_root, toolchain=tc)


class TestGenBuiltin:
    def test_int_type(self, generator):
        result = generator._gen_builtin("x", {"type_name": "int"})
        assert "gen_lines" in result
        assert "gen_free" in result
        assert "buffer_size" in result
        assert any("memcpy" in line for line in result["gen_lines"])
        assert any("sizeof(int)" in line for line in result["gen_lines"])
        assert result["gen_free"] == []
        assert "sizeof(int)" in result["buffer_size"][0]

    def test_anonymous_namespace_stripped(self, generator):
        result = generator._gen_builtin("x", {"type_name": "(anonymous namespace)::MyType"})
        assert not any("(anonymous namespace)" in line for line in result["gen_lines"])

    def test_float_type(self, generator):
        result = generator._gen_builtin("x", {"type_name": "float"})
        assert any("sizeof(float)" in s for s in result["buffer_size"])


class TestGenCstring:
    def test_basic_cstring(self, generator):
        result = generator._gen_cstring("s", {
            "base_type_name": "char *",
            "type_name": "char *",
            "local_qualifier": ""
        }, 1)
        assert any("malloc" in line for line in result["gen_lines"])
        assert any("memcpy" in line for line in result["gen_lines"])
        assert any("free" in line for line in result["gen_free"])

    def test_const_cstring(self, generator):
        result = generator._gen_cstring("s", {
            "base_type_name": "char *",
            "type_name": "const char *",
            "local_qualifier": "const"
        }, 1)
        # Should have a reference variable
        assert any("rs" in line for line in result["gen_lines"])


class TestGenEnum:
    def test_c_enum(self, generator):
        enum_record = {"name": "Color", "qname": "Color", "enum_values": [
            {"field_name": "RED", "value": 0},
            {"field_name": "GREEN", "value": 1},
        ]}
        result = generator._gen_enum(enum_record, "e", {"type_name": "Color"}, {"compiler": "CC"})
        assert any("enum_index" in line for line in result["gen_lines"])
        assert any("% 2" in line for line in result["gen_lines"])

    def test_cxx_enum(self, generator):
        enum_record = {"name": "Color", "qname": "Color", "enum_values": [
            {"field_name": "RED", "value": 0},
        ]}
        result = generator._gen_enum(enum_record, "e", {"type_name": "Color"}, {"compiler": "CXX"})
        assert any("static_cast" in line for line in result["gen_lines"])


class TestGenArray:
    def test_basic_array(self, generator):
        result = generator._gen_array("arr", {
            "type_name": "int *", "base_type_name": "int", "length": 10
        })
        assert any("malloc" in line for line in result["gen_lines"])
        assert any("10" in line for line in result["gen_lines"])
        assert any("free" in line for line in result["gen_free"])


class TestGenVoid:
    def test_void_pointer(self, generator):
        result = generator._gen_void("v")
        assert any("NULL" in line for line in result["gen_lines"])
        assert result["gen_free"] == []
        assert result["buffer_size"] == []


class TestGenQualifier:
    def test_qualifier(self, generator):
        result = generator._gen_qualifier("q_x", "x", {"type_name": "const int"})
        assert any("q_x" in line and "x" in line for line in result["gen_lines"])


class TestGenPointer:
    def test_pointer(self, generator):
        result = generator._gen_pointer("p_x", "x", {"type_name": "int *"})
        assert any("& x" in line for line in result["gen_lines"])


class TestToolchainIntegration:
    def test_toolchain_kwarg(self, tmp_futag_package, tmp_library_root):
        """Pass toolchain explicitly via keyword arg."""
        from futag.toolchain import ToolchainConfig
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        gen = Generator(tmp_library_root, toolchain=tc)
        assert gen.toolchain is tc
        assert gen.toolchain.clang is not None

    def test_generation_only_mode(self, tmp_library_root):
        """Generation-only: no toolchain, library_root is first arg."""
        gen = Generator(tmp_library_root)
        assert gen.toolchain.clang is None
