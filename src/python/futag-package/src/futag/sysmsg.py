"""
**************************************************
**      ______  __  __  ______  ___     ______  **
**     / ____/ / / / / /_  __/ /   |   / ____/  **
**    / /_    / / / /   / /   / /| |  / / __    **
**   / __/   / /_/ /   / /   / ___ | / /_/ /    **
**  /_/      \____/   /_/   /_/  |_| \____/     **
**                                              **
**     Fuzzing target Automated Generator       **
**             a tool of ISP RAS                **
**************************************************
** This module is for saving constants of Futag **
**************************************************
"""


# constants of Futag
BUILD_PATH = "futag-build"
BUILD_EX_PARAMS = ""
INSTALL_PATH = "futag-install"
ANALYSIS_PATH = "futag-analysis"
FUZZ_DRIVER_PATH = "futag-fuzz-drivers"

# messages of Futag
INVALID_INPUT_PROCESSES = "-- [Futag]: Invalid number of processes for building"
INVALID_FUTAG_PATH = "-- [Futag]: Incorrect path to FUTAG llvm package"
INVALID_FUZZ_DRIVER_PATH = "-- [Futag]: Incorrect path to fuzz-drivers"
INVALID_ANALYSIS_PATH = "-- [Futag]: Incorrect path to analysis folder"
INVALID_ANALYSIS_FILE = "-- [Futag]: Incorrect path to analysis result file"
INVALID_LIBPATH = "-- [Futag]: Incorrect path to the library root"
INVALID_BUILPATH = "-- [Futag]: Incorrect path to the library build path"
INVALID_INSTALLPATH = "-- [Futag]: Incorrect path to the library install path"
LIB_CONFIGURE_FAILED = "--Configure library failed, please build it your own!"
LIB_CONFIGURE_SUCCEEDED = "-- [Futag]: Library was configured successfully!"
LIB_CONFIGURE_COMMAND = "-- [Futag]: Configure command: "
LIB_BUILD_FAILED = "-- [Futag]: Build library failed, please build it your own!"
LIB_BUILD_START = "-- [Futag]: Start building your library!"
LIB_BUILD_SUCCEEDED = "-- [Futag]: Library was built successfully!"
LIB_BUILD_COMMAND = "-- [Futag]: Build command: "
LIB_INSTALL_FAILED = "-- [Futag]: Install library failed, please install it your own!"
LIB_INSTALL_SUCCEEDED = "-- [Futag]: Library was installed successfully!"
LIB_INSTALL_COMMAND = "-- [Futag]: Install command: "
AUTO_BUILD_MSG = "-- [Futag]: Futag is finding for configure or cmake in you library root"
AUTO_BUILD_FAILED = "-- [Futag]: Futag is unable to automatically build your library. Please do it yourself!"
CONFIGURE_FOUND = "-- [Futag]: File configure found, trying to build library with configure... "
CMAKE_FOUND = "-- [Futag]: File CMakeList.txt found, trying to build library with cmake... "

# Constants for generator
GEN_BUILTIN = 0
GEN_STRING = 1
GEN_ENUM = 2
GEN_ARRAY = 3
GEN_VOID = 4
GEN_QUALIFIER = 5
GEN_POINTER = 6
GEN_STRUCT = 7
GEN_INCOMPLETE = 8
GEN_FUNCTION = 9
GEN_INPUT_FILE = 10
GEN_OUTPUT_FILE = 11
GEN_UNKNOWN = 12