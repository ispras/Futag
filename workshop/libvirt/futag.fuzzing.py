# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.preprocessor import *
from futag.generator import * 
from futag.fuzzer import * 

FUTAG_PATH = "/home/thientc/Futag/futag-llvm"
lib_path = "/home/thientc/libvirt"

fuzzer = Fuzzer( # модуль для фаззинга
    FUTAG_PATH,
    fuzz_driver_path="futag-fuzz-drivers/", 
    totaltime=3, # время фаззинга одной обертки
    debug=True,
    gdb=True,
)
fuzzer.fuzz()