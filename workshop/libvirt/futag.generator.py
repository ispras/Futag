# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

from futag.generator import * 

FUTAG_PATH = "/home/futag/Futag/futag-llvm"
lib_path = "."

generator = Generator(
    FUTAG_PATH,
    lib_path,
    json_file='/home/futag/libvirt/futag-analysis/futag-analysis-result.json',
    build_path='/home/futag/RPM/BUILD/libvirt-10.7.0/x86_64-alt-linux', #for compile_command.json with cmake
    install_path='/home/futag/RPM/BUILD/libvirt-10.7.0/x86_64-alt-linux', #for compile_command.json with cmake,
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
