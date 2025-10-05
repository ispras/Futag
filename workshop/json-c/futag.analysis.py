# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.preprocessor import *
from futag.fdp_generator import * 
from futag.sysmsg import * 
from futag.fuzzer import * 

FUTAG_PATH = "/home/futag/Futag/futag-llvm"
lib_path = "json-c-json-c-0.18-20240915" 
build_test = Builder(
   FUTAG_PATH, 
   lib_path,
   clean=True,
   processes=16,
)
build_test.auto_build()
build_test.analyze()