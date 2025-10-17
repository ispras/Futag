# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.preprocessor import *

FUTAG_PATH = "/home/futag/Futag/futag-llvm"
lib_path = "."
test_build = Builder(
    FUTAG_PATH,
    lib_path,
    clean=False,
    analysis_path='futag-analysis',
)
# test_build.auto_build()
test_build.analyze()
