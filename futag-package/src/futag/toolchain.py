# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

"""Toolchain configuration for external tool paths.

Provides a ToolchainConfig dataclass that centralizes all external tool
path resolution. Supports three usage modes:

1. from_futag_llvm() — backward-compatible, uses a compiled futag-llvm directory
2. from_system() — uses system-installed tools via PATH
3. for_generation_only() — no tools needed, only source code generation
"""

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from futag.exceptions import InvalidPathError


@dataclass
class ToolchainConfig:
    """Resolved paths to all external tools FUTAG needs.

    All paths are Optional — None means the tool is not available.
    Use require_compiler() or require_scan_build() before invoking
    a tool to get a clear error message instead of a crash.
    """

    clang: Optional[Path] = None
    clangpp: Optional[Path] = None
    scan_build: Optional[Path] = None
    llvm_profdata: Optional[Path] = None
    llvm_cov: Optional[Path] = None
    llvm_symbolizer: Optional[Path] = None
    intercept_build: Optional[Path] = None
    afl_clang_fast: Optional[Path] = None
    afl_clang_fastpp: Optional[Path] = None
    svres_template: Optional[Path] = None

    @classmethod
    def from_futag_llvm(cls, futag_llvm_package: str) -> "ToolchainConfig":
        """Construct from a futag-llvm directory.

        Validates that the directory exists and contains bin/clang.
        Optional tools (AFL++, svres template) are set only if present.

        Args:
            futag_llvm_package: Path to the compiled futag-llvm directory.

        Raises:
            InvalidPathError: If the directory or bin/clang doesn't exist.
        """
        base = Path(futag_llvm_package).absolute()
        if not base.exists() or not (base / "bin" / "clang").exists():
            raise InvalidPathError(
                f"Invalid futag-llvm path: {futag_llvm_package}")

        afl_base = base / "AFLplusplus" / "usr" / "local" / "bin"
        svres_path = base / "svres-tmpl" / "svres.tmpl"

        return cls(
            clang=base / "bin" / "clang",
            clangpp=base / "bin" / "clang++",
            scan_build=base / "bin" / "scan-build",
            llvm_profdata=base / "bin" / "llvm-profdata",
            llvm_cov=base / "bin" / "llvm-cov",
            llvm_symbolizer=base / "bin" / "llvm-symbolizer",
            intercept_build=base / "bin" / "intercept-build",
            afl_clang_fast=(
                afl_base / "afl-clang-fast"
                if (afl_base / "afl-clang-fast").exists() else None
            ),
            afl_clang_fastpp=(
                afl_base / "afl-clang-fast++"
                if (afl_base / "afl-clang-fast++").exists() else None
            ),
            svres_template=svres_path if svres_path.exists() else None,
        )

    @classmethod
    def from_system(cls, clang_path: str = "") -> "ToolchainConfig":
        """Use system-installed tools discovered via PATH.

        Args:
            clang_path: Explicit path to clang. If empty, searches PATH.

        Returns:
            ToolchainConfig with paths set for tools found on the system.
            Missing tools will have None paths.
        """
        def find(name):
            p = shutil.which(name)
            return Path(p) if p else None

        if clang_path:
            clang = Path(clang_path)
            clangpp = Path(clang_path + "++")
        else:
            clang = find("clang")
            clangpp = find("clang++")

        return cls(
            clang=clang,
            clangpp=clangpp,
            scan_build=find("scan-build"),
            llvm_profdata=find("llvm-profdata"),
            llvm_cov=find("llvm-cov"),
            llvm_symbolizer=find("llvm-symbolizer"),
            intercept_build=find("intercept-build"),
            afl_clang_fast=find("afl-clang-fast"),
            afl_clang_fastpp=find("afl-clang-fast++"),
        )

    @classmethod
    def for_generation_only(cls) -> "ToolchainConfig":
        """Minimal config with all paths set to None.

        Use this when you only need gen_targets() to produce source files
        without compilation. compile_targets() will raise InvalidPathError.
        """
        return cls()

    def require_compiler(self, target_type: int = 0):
        """Validate that a compiler is available for the given target type.

        Args:
            target_type: 0 for LIBFUZZER (needs clang), 1 for AFLPLUSPLUS
                         (needs afl-clang-fast).

        Raises:
            InvalidPathError: If the required compiler is not available.
        """
        if target_type == 0:  # LIBFUZZER
            if not self.clang or not self.clang.exists():
                raise InvalidPathError(
                    "clang compiler not found in toolchain config")
        else:  # AFLPLUSPLUS
            if not self.afl_clang_fast or not self.afl_clang_fast.exists():
                raise InvalidPathError(
                    "afl-clang-fast not found in toolchain config")

    def require_scan_build(self):
        """Validate that scan-build is available.

        Raises:
            InvalidPathError: If scan-build is not available.
        """
        if not self.scan_build or not self.scan_build.exists():
            raise InvalidPathError(
                "scan-build not found in toolchain config")
