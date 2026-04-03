# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

"""Custom exceptions for the Futag package.

Provides a hierarchy of exceptions for structured error handling
instead of sys.exit() calls throughout the codebase.
"""


class FutagError(Exception):
    """Base exception for all Futag errors."""


class InvalidPathError(FutagError):
    """Raised when a required file or directory path is invalid or missing."""


class InvalidConfigError(FutagError):
    """Raised when configuration parameters are invalid (e.g., bad target type)."""


class BuildError(FutagError):
    """Raised when library build or analysis fails."""


class GenerationError(FutagError):
    """Raised when fuzz target generation fails."""


class AnalysisError(FutagError):
    """Raised when analysis result parsing or loading fails."""
