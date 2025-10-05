# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.sysmsg import * 
from futag.fuzzer import * 

FUTAG_PATH = "../futag-llvm"
lib_path = "json-c-json-c-0.18-20240915" 

fuzzer = Fuzzer(
    FUTAG_PATH,
    "json-c-json-c-0.18-20240915/futag-fuzz-drivers",
    debug=True,
    svres=True,
    totaltime= 10,
    coverage=True
)
fuzzer.fuzz()