"""Tests for the preprocessor module."""
import sys
import os
import json
import pathlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestLoadJsonFiles:
    """Test the _load_json_files helper function."""

    def test_skips_empty_files(self, tmp_path):
        """Empty JSON files should be skipped."""
        from futag.preprocessor import _load_json_files
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        results = list(_load_json_files([empty_file], "test"))
        assert results == []

    def test_warns_on_bad_json(self, tmp_path, capsys):
        """Malformed JSON should print warning and continue."""
        from futag.preprocessor import _load_json_files
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json")
        results = list(_load_json_files([bad_file], "test"))
        assert results == []

    def test_yields_valid_json(self, tmp_path):
        """Valid JSON files should be yielded."""
        from futag.preprocessor import _load_json_files
        good_file = tmp_path / "good.json"
        good_file.write_text('{"key": "value"}')
        results = list(_load_json_files([good_file], "test"))
        assert len(results) == 1
        assert results[0] == {"key": "value"}

    def test_skips_none_json(self, tmp_path):
        """JSON files containing null should be skipped."""
        from futag.preprocessor import _load_json_files
        null_file = tmp_path / "null.json"
        null_file.write_text("null")
        results = list(_load_json_files([null_file], "test"))
        assert results == []


class TestParseLocation:
    """Test the _parse_location helper."""

    def test_basic_path(self):
        from futag.preprocessor import _parse_location
        result = _parse_location("/src/test.c:42")
        assert result["file"] == "test.c"
        assert result["line"] == "42"
        assert result["directory"] == "/src"
        assert result["fullpath"] == "/src/test.c"

    def test_path_with_colon(self):
        from futag.preprocessor import _parse_location
        result = _parse_location("/src/C:/test.c:10")
        assert result["line"] == "10"
