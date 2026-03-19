"""Tests for GeneratorState dataclass."""
import sys
import os

# Add the source directory to the path so we can import futag
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from futag.generator_state import GeneratorState


class TestGeneratorState:
    def test_default_values(self):
        state = GeneratorState()
        assert state.gen_this_function is True
        assert state.gen_lines == []
        assert state.buffer_size == []
        assert state.gen_free == []
        assert state.dyn_cstring_size_idx == 0
        assert state.dyn_cxxstring_size_idx == 0
        assert state.dyn_wstring_size_idx == 0
        assert state.file_idx == 0
        assert state.var_function_idx == 0
        assert state.param_list == []
        assert state.curr_func_log == ""
        assert state.header == []
        assert state.curr_function is None

    def test_save_creates_deep_copy(self):
        state = GeneratorState()
        state.gen_lines = ["line1", "line2"]
        state.dyn_cstring_size_idx = 3

        saved = state.save()

        # Modify original
        state.gen_lines.append("line3")
        state.dyn_cstring_size_idx = 5

        # Saved copy should be unaffected
        assert saved.gen_lines == ["line1", "line2"]
        assert saved.dyn_cstring_size_idx == 3

    def test_reset_clears_all_fields(self):
        state = GeneratorState()
        state.gen_this_function = False
        state.gen_lines = ["code"]
        state.buffer_size = ["sizeof(int)"]
        state.gen_free = ["free(x);"]
        state.dyn_cstring_size_idx = 5
        state.dyn_cxxstring_size_idx = 3
        state.dyn_wstring_size_idx = 2
        state.file_idx = 1
        state.var_function_idx = 4
        state.param_list = ["x", "y"]
        state.curr_func_log = "test log"
        state.header = ["#include <stdio.h>"]
        state.curr_function = {"name": "test"}

        state.reset()

        assert state.gen_this_function is True
        assert state.gen_lines == []
        assert state.buffer_size == []
        assert state.gen_free == []
        assert state.dyn_cstring_size_idx == 0
        assert state.dyn_cxxstring_size_idx == 0
        assert state.dyn_wstring_size_idx == 0
        assert state.file_idx == 0
        assert state.var_function_idx == 0
        assert state.param_list == []
        assert state.curr_func_log == ""
        assert state.header == []
        assert state.curr_function is None

    def test_restore_from_saved(self):
        state = GeneratorState()
        state.gen_lines = ["original"]
        state.dyn_cstring_size_idx = 2

        saved = state.save()

        # Modify state
        state.gen_lines = ["modified"]
        state.dyn_cstring_size_idx = 99

        # Restore
        state.restore_from(saved)

        assert state.gen_lines == ["original"]
        assert state.dyn_cstring_size_idx == 2

    def test_restore_from_is_deep_copy(self):
        state = GeneratorState()
        state.gen_lines = ["line1"]

        saved = state.save()
        state.restore_from(saved)

        # Modifying restored state should not affect saved
        state.gen_lines.append("line2")
        assert saved.gen_lines == ["line1"]

    def test_multiple_save_restore_cycles(self):
        state = GeneratorState()

        # Level 0
        state.gen_lines = ["level0"]
        saved_0 = state.save()

        # Level 1
        state.gen_lines.append("level1")
        saved_1 = state.save()

        # Level 2
        state.gen_lines.append("level2")
        assert state.gen_lines == ["level0", "level1", "level2"]

        # Restore to level 1
        state.restore_from(saved_1)
        assert state.gen_lines == ["level0", "level1"]

        # Restore to level 0
        state.restore_from(saved_0)
        assert state.gen_lines == ["level0"]
