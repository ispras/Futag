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
generator = FuzzDataProviderGenerator(
    lib_path,
    target_type=LIBFUZZER,
    toolchain=tc,
)

generator.gen_targets()
generator.compile_targets(
    coverage=True,
    keep_failed=True,
    keep_original=True,
)