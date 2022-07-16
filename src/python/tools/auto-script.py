from futag.generator import *
import sys
import os
import pkg_resources
from subprocess import Popen, PIPE, run, call
from multiprocessing import Pool
from pathlib import Path

if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <path to futag package>')
    exit(1)

futag_package_path = Path(sys.argv[1])
if not futag_package_path.exists():
    print('Specified path to futag package is incorrect')
    exit(1)

# check if futag package is installed
required = {'futag'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if missing:
    print("-- Package 'futag' is not found!")
    print("-- Installing ...")
    p = Popen(
        [
            "pip3",
            "install",
            (futag_package_path /
             "/python/futag-package/dist/futag-0.1.tar.gz").absolute().as_posix()
        ],
        stdout=PIPE,
        stderr=PIPE,
        universal_newlines=True,
    )
    output, errors = p.communicate()
    if errors:
        print(errors)
        exit()

# Delete an existing folder
p = Popen("rm -rf json-c-json-c-0.13.1-20180305", shell=True)
p.wait()

# Untar archive with library sources
p = Popen(["tar", "xf", "json-c-0.13.1-20180305.tar.gz"])
p.wait()

source_path = Path.cwd().absolute() / "json-c-json-c-0.13.1-20180305"

p = Popen("mkdir " + (source_path / "build").as_posix(), shell=True)
p.wait()

p = Popen(
    "mkdir " + (source_path / "build/local-install").as_posix(),
    shell=True)
p.wait()

p = Popen("mkdir " + (source_path / "build/futag-result").as_posix(), shell=True)
p.wait()

# Configure project
os.chdir((source_path / "build").as_posix())
p = Popen(
    "env "
    "CFLAGS=\"-fsanitize=fuzzer-no-link -Wno-error=implicit-const-int-float-conversion\" "
    f"CC=\"{(futag_package_path / 'bin/clang').as_posix()}\" "
    "../configure "
    "--prefix=`pwd`/install ", shell=True)
p.wait()

# Build the library
p = Popen(
    "make -j16 && make install", shell=True)
p.wait()

# Cleanup and checker configuration
p = Popen(
    "make clean && ../configure --prefix=`pwd`/install", shell=True)
p.wait()

# Run checker
p = Popen(
    f"{(futag_package_path / 'bin/scan-build').as_posix()} -analyzer-config futag.FutagFunctionAnalyzer:report_dir=`pwd`/futag-result -enable-checker futag make -j 16", shell=True)
p.wait()

# Merge the results
p = Popen(
    f"python3 {(futag_package_path / 'python/tools/analyzer/analypar.py').as_posix()} ./futag-result", shell=True)
p.wait()

# Compile genearated drivers

g = Generator(
    "futag-fuzz-drivers",
    (source_path / "build/futag-analysis-result.json").as_posix(),
    (futag_package_path).as_posix(),
    (source_path).as_posix()
)
g.gen_targets()
g.compile_targets()
