"""Tests for the Futag exception hierarchy."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.exceptions import (
    FutagError, InvalidPathError, InvalidConfigError,
    BuildError, GenerationError, AnalysisError
)


class TestExceptionHierarchy:
    def test_all_inherit_from_futag_error(self):
        assert issubclass(InvalidPathError, FutagError)
        assert issubclass(InvalidConfigError, FutagError)
        assert issubclass(BuildError, FutagError)
        assert issubclass(GenerationError, FutagError)
        assert issubclass(AnalysisError, FutagError)

    def test_futag_error_is_exception(self):
        assert issubclass(FutagError, Exception)

    def test_can_catch_with_base(self):
        with pytest.raises(FutagError):
            raise InvalidPathError("test path")

    def test_message_preserved(self):
        try:
            raise AnalysisError("bad json")
        except FutagError as e:
            assert "bad json" in str(e)
