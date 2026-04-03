"""Tests for the ToolchainConfig dataclass."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.toolchain import ToolchainConfig
from futag.exceptions import InvalidPathError


class TestFromFutagLlvm:
    def test_valid_path(self, tmp_futag_package):
        """Existing tmp_futag_package fixture creates fake futag-llvm with bin/clang."""
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        assert tc.clang is not None
        assert tc.clang.name == "clang"
        assert tc.clangpp is not None
        assert tc.clangpp.name == "clang++"
        assert tc.scan_build is not None
        assert tc.llvm_profdata is not None
        assert tc.llvm_cov is not None
        assert tc.llvm_symbolizer is not None

    def test_invalid_path_raises(self):
        """Nonexistent directory should raise InvalidPathError."""
        with pytest.raises(InvalidPathError):
            ToolchainConfig.from_futag_llvm("/nonexistent/path")

    def test_missing_clang_raises(self, tmp_path):
        """Directory exists but no bin/clang should raise."""
        d = tmp_path / "empty-llvm"
        d.mkdir()
        with pytest.raises(InvalidPathError):
            ToolchainConfig.from_futag_llvm(str(d))

    def test_afl_none_when_missing(self, tmp_futag_package):
        """AFL++ tools should be None when not present."""
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        assert tc.afl_clang_fast is None
        assert tc.afl_clang_fastpp is None

    def test_svres_none_when_missing(self, tmp_futag_package):
        """svres template should be None when not present."""
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        assert tc.svres_template is None


class TestFromSystem:
    def test_returns_config(self):
        """Should not raise even if tools are not found."""
        tc = ToolchainConfig.from_system()
        assert isinstance(tc, ToolchainConfig)

    def test_custom_clang_path(self, tmp_path):
        """Explicit clang path should be used directly."""
        fake_clang = tmp_path / "my-clang"
        fake_clang.touch()
        fake_clang.chmod(0o755)
        tc = ToolchainConfig.from_system(str(fake_clang))
        assert tc.clang == fake_clang


class TestForGenerationOnly:
    def test_all_none(self):
        """All paths should be None in generation-only mode."""
        tc = ToolchainConfig.for_generation_only()
        assert tc.clang is None
        assert tc.clangpp is None
        assert tc.scan_build is None
        assert tc.llvm_profdata is None
        assert tc.llvm_cov is None
        assert tc.llvm_symbolizer is None
        assert tc.afl_clang_fast is None
        assert tc.afl_clang_fastpp is None
        assert tc.svres_template is None


class TestRequireCompiler:
    def test_raises_when_none_libfuzzer(self):
        """Should raise for LIBFUZZER when clang is None."""
        tc = ToolchainConfig.for_generation_only()
        with pytest.raises(InvalidPathError, match="clang"):
            tc.require_compiler(target_type=0)

    def test_raises_when_none_aflplusplus(self):
        """Should raise for AFLPLUSPLUS when afl-clang-fast is None."""
        tc = ToolchainConfig.for_generation_only()
        with pytest.raises(InvalidPathError, match="afl-clang-fast"):
            tc.require_compiler(target_type=1)

    def test_passes_when_set(self, tmp_futag_package):
        """Should not raise when clang is available."""
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        tc.require_compiler(target_type=0)  # should not raise


class TestRequireScanBuild:
    def test_raises_when_none(self):
        """Should raise when scan-build is None."""
        tc = ToolchainConfig.for_generation_only()
        with pytest.raises(InvalidPathError, match="scan-build"):
            tc.require_scan_build()

    def test_passes_when_set(self, tmp_futag_package):
        """Should not raise when scan-build is available."""
        tc = ToolchainConfig.from_futag_llvm(tmp_futag_package)
        tc.require_scan_build()  # should not raise
