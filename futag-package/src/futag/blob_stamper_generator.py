# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

# **************************************************
# **      ______  __  __  ______  ___     ______  **
# **     / ____/ / / / / /_  __/ /   |   / ____/  **
# **    / /_    / / / /   / /   / /| |  / / __    **
# **   / __/   / /_/ /   / /   / ___ | / /_/ /    **
# **  /_/      \____/   /_/   /_/  |_| \____/     **
# **                                              **
# **     Fuzz target Automated Generator       **
# **             a tool of ISP RAS                **
# **************************************************
# ** This module is for generating, compiling     **
# ** fuzz-drivers using LibBlobStamper             **
# **************************************************

"""Futag BlobStamper Generator."""

from futag.sysmsg import *
from futag.base_generator import BaseGenerator
from futag.fdp_generator import FuzzDataProviderGenerator


class BlobStamperGenerator(FuzzDataProviderGenerator):
    """Generator using LibBlobStamper (same type generation as FDP).

    Inherits all _gen_* methods from FuzzDataProviderGenerator but:
    - Supports both C and C++ targets (not forced to C++ only)
    - Does not force .cpp extension (uses original source file extension)
    """

    @property
    def supports_c(self) -> bool:
        """Return whether this generator supports C targets."""
        return True  # BlobStamper supports both C and C++

    def _wrapper_file(self, func) -> dict:
        """Return wrapper file metadata, always using .cpp extension."""
        self.target_extension = "cpp"
        return BaseGenerator._wrapper_file(self, func)
