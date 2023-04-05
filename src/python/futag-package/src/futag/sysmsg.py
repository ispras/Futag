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
BUILD_PATH = ".futag-build"
BUILD_EX_PARAMS = ""
INSTALL_PATH = ".futag-install"
ANALYSIS_PATH = ".futag-analysis"
DEBUG_FLAGS = "-g -O0"
COMPILER_FLAGS = "-fsanitize=address"
COMPILER_COVERAGE_FLAGS = "-fprofile-instr-generate -fcoverage-mapping "
FUZZ_COMPILER_FLAGS = "-fsanitize=address,fuzzer"
FUZZ_DRIVER_PATH = "futag-fuzz-drivers"
CONTEXT_FUZZ_DRIVER_PATH = "futag-context-fuzz-drivers"
ANALYSIS_FILE_PATH=".futag-analysis/futag-analysis-result.json"
CONTEXT_FILE_PATH=".futag-consumer/futag-contexts.json"
FOR_CONSUMER_FILEPATH=".futag-analysis/futag-4consumer.json"
CONSUMER_REPORT_PATH=".futag-consumer"

# messages of Futag
CMAKE_PATH_ERROR="Please specify other directory for building with cmake."
INVALID_INPUT_PROCESSES = "-- [Futag]: Invalid number of processes for building"
INVALID_FUTAG_PATH = "-- [Futag]: Incorrect path to FUTAG llvm package"
INVALID_FUZZ_DRIVER_PATH = "-- [Futag]: Incorrect path to fuzz-drivers"
INVALID_ANALYSIS_PATH = "-- [Futag]: Incorrect path to analysis folder"
INVALID_ANALYSIS_FILE = "-- [Futag]: Incorrect path to analysis result file"
INVALID_CONTEXT_FILE_PATH = "-- [Futag]: Incorrect path to consumer context file"
INVALID_LIBPATH = "-- [Futag]: Incorrect path to the library root"
INVALID_CONSUMER_PATH = "-- [Futag]: Incorrect path to the consumer program"
INVALID_DB_FILEPATH = "-- [Futag]: analysis result of testing library not found"
INVALID_BUILPATH = "-- [Futag]: Incorrect path to the library build path"
INVALID_INSTALLPATH = "-- [Futag]: Incorrect path to the library install path"
GDB_NOT_FOUND = "-- [Futag]: GDB is not found in your system, Futag can not debug with GDB"
LIB_CONFIGURE_FAILED = "-- [Futag]: Configure library failed, please build it your own!"
LIB_CONFIGURE_SUCCEEDED = "-- [Futag]: Library was configured successfully!"
LIB_ANALYSIS_STARTED = "-- [Futag]: Starting analyzing: "
LIB_ANALYZING_FAILED = "-- [Futag]: Analyzing failed"
LIB_ANALYZING_SUCCEEDED = "-- [Futag]: Analyzing succeeded"
LIB_CONFIGURE_COMMAND = "-- [Futag]: Configure command: "
LIB_BUILD_FAILED = "-- [Futag]: Build library failed, please build it your own!"
LIB_BUILD_START = "-- [Futag]: Start building your library!"
LIB_BUILD_SUCCEEDED = "-- [Futag]: Library was built successfully!"
LIB_ANALYZING_COMMAND = "-- [Futag]: Analyzing command: "
LIB_ANALYZING_FAILED = "-- [Futag]: Analyzing failed!"
LIB_BUILD_COMMAND = "-- [Futag]: Build command: "
LIB_CLEAN_FAILED = "-- [Futag]: Clean library failed, please clean it your own!"
LIB_CLEAN_SUCCEEDED = "-- [Futag]: Clean successfully!"
LIB_INSTALL_FAILED = "-- [Futag]: Install library failed, please install it your own!"
LIB_INSTALL_SUCCEEDED = "-- [Futag]: Library was installed successfully!"
LIB_INSTALL_COMMAND = "-- [Futag]: Install command: "
AUTO_BUILD_MSG = "-- [Futag]: Futag is finding for makefile, configure or cmake in you library root"
AUTO_CONSUMER_BUILD_MSG = "-- [Futag]: Futag is analyzing consumer program for finding context of testing library"
AUTO_BUILD_FAILED = "-- [Futag]: Futag is unable to automatically build your library. Please do it yourself!"
CONFIGURE_FOUND = "-- [Futag]: File configure found, trying to build library with configure... "
CMAKE_FOUND = "-- [Futag]: File CMakeList.txt found, trying to build library with cmake... "
MAKEFILE_FOUND = "-- [Futag]: File Makefile found, trying to build library with make... "
INVALID_TARGET_TYPE = "-- [Futag] Error: Unknown type of fuzz-driver for generating!"

# message for Natch
COULD_NOT_PARSE_NATCH_CALLSTACK = "-- [Futag] Error: Could not parse file!"


# messages for GENERATOR
CANNOT_CREATE_LOG_FILE = "-- [Futag] Error: Can not create log file for function: "
CANNOT_CREATE_WRAPPER_FILE = "-- [Futag] Error: Can not create fuzz-wrapper file for function: "
WRAPPER_FILE_CREATED = "           [*]file fuzz-wrapper was created: "

#messages for ConsumerBuilder:
INVALID_DB_FILEPATH = "-- [Futag] Error: analysis result of testing library not found!"

# Constants for GENERATOR
GEN_BUILTIN   = 0
GEN_CSTRING   = 1
GEN_WSTRING   = 2
GEN_CXXSTRING = 3
GEN_ENUM      = 4
GEN_ARRAY     = 5
GEN_VOID      = 6
GEN_QUALIFIER = 7
GEN_POINTER   = 8
GEN_STRUCT    = 9
GEN_UNION     = 10
GEN_CLASS     = 11
GEN_INCOMPLETE = 12
GEN_FUNCTION  = 13
GEN_INPUT_FILE = 14
GEN_OUTPUT_FILE = 15
GEN_UNKNOWN   = 16
GEN_VARADDR   = 17

# Constants for ParamUsage
FILE_PATH_READ  = 0
FILE_PATH_RW    = 1
FILE_PATH_WRITE = 2
FILE_PATH       = 3
FILE_DESCRIPTOR = 4
SIZE_FIELD      = 5
C_STRING        = 6
UNKNOWN         = 7


# fuzz-driver format
LIBFUZZER = 0
AFLPLUSPLUS = 1

# FutagRecordType
CLASS_RECORD = 0
UNION_RECORD = 1
STRUCT_RECORD = 2
UNKNOW_RECORD = 3

# Function Type
FUNC_CXXMETHOD = 0
FUNC_CONSTRUCTOR = 1
FUNC_DEFAULT_CONSTRUCTOR = 2
FUNC_DESTRUCTOR = 3
FUNC_GLOBAL = 4
FUNC_STATIC = 5
FUNC_UNKNOW_RECORD = 6

# Access type
# A C++ access specifier (public, private, protected), plus the special value "none" which means different things in different contexts.
AS_PUBLIC = 0
AS_PROTECTED = 1
AS_PRIVATE  = 2
AS_NONE  = 3 # for only C

# Storage class
# These are legal on both functions and variables.
SC_NONE = 0
SC_EXTERN = 1
SC_STATIC = 2
SC_PRIVATEEXTERN = 3
# These are only legal on variables.
SC_AUTO = 4
SC_REGISTER = 5

#Contants for ConsumerGenerator:
ARG_INIT_VARREF   = 0
ARG_INIT_CONST    = 1
ARG_INIT_FUNCCALL = 2
ARG_INIT_UNKNOWN  = 3

AFLPLUSPLUS_PREFIX = '''__AFL_FUZZ_INIT();

main() {
// anything else here, e.g. command line arguments, initialization, etc.

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

unsigned char *Fuzz_Data = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT and before __AFL_LOOP!

while (__AFL_LOOP(10000)) {
    int Fuzz_Size = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!
    
    // check for a required/useful minimum input length\n'''
AFLPLUSPLUS_SUFFIX = '''
  }
  return 0;
}'''

LIBFUZZER_PREFIX_C = '''int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){\n'''
LIBFUZZER_PREFIX_CXX = '''extern "C" int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){\n'''
LIBFUZZER_SUFFIX = '''    return 0;\n}'''
