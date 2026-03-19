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
    def supports_c(self):
        return True  # BlobStamper supports both C and C++

    def _wrapper_file(self, func):
        # Don't force .cpp extension like FDP does - use original extension
        self.target_extension = func["location"]["fullpath"].split(".")[-1]
        return BaseGenerator._wrapper_file(self, func)
