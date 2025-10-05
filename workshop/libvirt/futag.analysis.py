# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.preprocessor import *
from futag.fdp_generator import * 
from futag.fuzzer import * 

FUTAG_PATH = "/home/thientc/Futag/futag-llvm"
lib_path = "/home/thientc/libvirt"
test_build = Builder(
    FUTAG_PATH,
    lib_path,
    clean=False,
    analysis_path='analysis_result',
)
# test_build.auto_build()
test_build.analyze()
