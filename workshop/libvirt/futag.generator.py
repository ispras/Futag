# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.preprocessor import *
from futag.generator import * 
from futag.fuzzer import * 

FUTAG_PATH = "/home/thientc/Futag/futag-llvm"
lib_path = "/home/thientc/libvirt"

generator = Generator(
    FUTAG_PATH,
    lib_path,
    json_file='/home/thientc/libvirt/analysis_result/futag-analysis-result.json',
    build_path='/home/thientc/libvirt/build.meson', #for compile_command.json with cmake
    install_path='/home/thientc/libvirt/build.meson', #for compile_command.json with cmake,
    exclude_headers=["<config.h>"]
)
generator.gen_targets(
    # from_list="futag.functionlist.json",
    max_functions=100,
    max_wrappers=3
)
generator.compile_targets(
    alter_compiler="clang",
    extra_dynamiclink="-lvirt",
    keep_failed=True)
