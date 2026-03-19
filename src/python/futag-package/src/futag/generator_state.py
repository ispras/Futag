"""Generator state management for Futag fuzz target generation.

This module provides a dataclass that encapsulates all mutable state used
during the recursive fuzz target generation process. It replaces the previous
approach of 13+ mutable instance variables with manual save/restore methods.
"""

import copy
import dataclasses
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GeneratorState:
    """Encapsulates all mutable state for recursive fuzz target generation.

    During generation, the algorithm recurses over function parameters.
    At each recursion level, state may need to be saved (before trying a
    generation strategy) and restored (if that strategy fails). This dataclass
    provides clean save/restore semantics via deep copy.

    Attributes:
        gen_this_function: Whether the current function can be generated.
        gen_lines: Lines of C/C++ code generated so far.
        buffer_size: Buffer size expressions (strings to concatenate).
        gen_free: Lines of cleanup code (free() calls, file closes).
        dyn_cstring_size_idx: Counter for dynamic C string size variables.
        dyn_cxxstring_size_idx: Counter for dynamic C++ string size variables.
        dyn_wstring_size_idx: Counter for dynamic wide string size variables.
        file_idx: Counter for generated file descriptors.
        var_function_idx: Counter for function-as-parameter variables.
        param_list: List of generated parameter names for the function call.
        curr_func_log: Log text for the current function being generated.
        header: List of header include lines.
        curr_function: The current function dict being processed.
    """

    gen_this_function: bool = True
    gen_lines: List[str] = field(default_factory=list)
    buffer_size: List[str] = field(default_factory=list)
    gen_free: List[str] = field(default_factory=list)
    dyn_cstring_size_idx: int = 0
    dyn_cxxstring_size_idx: int = 0
    dyn_wstring_size_idx: int = 0
    file_idx: int = 0
    var_function_idx: int = 0
    param_list: List[str] = field(default_factory=list)
    curr_func_log: str = ""
    header: List[str] = field(default_factory=list)
    curr_function: Optional[dict] = None

    def save(self) -> "GeneratorState":
        """Create a deep copy of the current state for later restoration.

        Returns:
            A new GeneratorState instance with all fields deep-copied.
        """
        return copy.deepcopy(self)

    def reset(self):
        """Reset all fields to their default values for a new function."""
        self.gen_this_function = True
        self.gen_lines = []
        self.buffer_size = []
        self.gen_free = []
        self.dyn_cstring_size_idx = 0
        self.dyn_cxxstring_size_idx = 0
        self.dyn_wstring_size_idx = 0
        self.file_idx = 0
        self.var_function_idx = 0
        self.param_list = []
        self.curr_func_log = ""
        self.header = []
        self.curr_function = None

    def restore_from(self, saved: "GeneratorState"):
        """Restore state from a previously saved copy.

        Args:
            saved: A GeneratorState previously obtained via save().
        """
        for f in dataclasses.fields(self):
            setattr(self, f.name, copy.deepcopy(getattr(saved, f.name)))
