# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.preprocessor import *
from futag.fdp_generator import *
from futag.sysmsg import *
from futag.fuzzer import *
from futag.toolchain import ToolchainConfig

FUTAG_PATH = "../futag-llvm"
lib_path = "json-c-json-c-0.18-20240915"

tc = ToolchainConfig.from_futag_llvm(FUTAG_PATH)
build_test = Builder(
   lib_path,
   clean=True,
   processes=16,
   toolchain=tc,
)
build_test.auto_build()
build_test.analyze()