# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.fuzzer import *
from futag.toolchain import ToolchainConfig

FUTAG_PATH = "/home/futag/Futag/futag-llvm"
lib_path = "."

tc = ToolchainConfig.from_futag_llvm(FUTAG_PATH)
fuzzer = Fuzzer( # модуль для фаззинга
    fuzz_driver_path="futag-fuzz-drivers/",
    toolchain=tc, 
    totaltime=3, # время фаззинга одной обертки
    debug=True,
    gdb=True,
)
fuzzer.fuzz()