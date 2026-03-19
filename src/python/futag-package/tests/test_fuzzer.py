"""Tests for the Fuzzer module."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.fuzzer import BaseFuzzer, Fuzzer, NatchFuzzer


class TestFuzzerClassHierarchy:
    def test_fuzzer_is_base_fuzzer(self):
        assert issubclass(Fuzzer, BaseFuzzer)

    def test_natch_fuzzer_is_base_fuzzer(self):
        assert issubclass(NatchFuzzer, BaseFuzzer)


class TestErrorId:
    def test_deterministic(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        result1 = fuzzer._error_id("test error")
        result2 = fuzzer._error_id("test error")
        assert result1 == result2

    def test_different_inputs_different_ids(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        result1 = fuzzer._error_id("error A")
        result2 = fuzzer._error_id("error B")
        assert result1 != result2


class TestXmlEscape:
    def test_ampersand(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        assert "&amp;" in fuzzer._xml_escape("a & b")

    def test_less_than(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        assert "&lt;" in fuzzer._xml_escape("a < b")

    def test_greater_than(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        assert "&gt;" in fuzzer._xml_escape("a > b")

    def test_quote(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        assert "&quot;" in fuzzer._xml_escape('a "b" c')

    def test_newline(self):
        fuzzer = BaseFuzzer.__new__(BaseFuzzer)
        assert "&#10;" in fuzzer._xml_escape("a\nb")


class TestCorpusArgs:
    def test_fuzzer_returns_empty(self):
        fuzzer = Fuzzer.__new__(Fuzzer)
        assert fuzzer._get_corpus_args(None) == []
