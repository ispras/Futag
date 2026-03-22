# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

# **************************************************
# **      ______  __  __  ______  ___     ______  **
# **     / ____/ / / / / /_  __/ /   |   / ____/  **
# **    / /_    / / / /   / /   / /| |  / / __    **
# **   / __/   / /_/ /   / /   / ___ | / /_/ /    **
# **  /_/      \____/   /_/   /_/  |_| \____/     **
# **                                              **
# **     Fuzz target Automated Generator       **
# **             a tool of ISP RAS                **
# **************************************************
# **  This preprocessor module is for building,   **
# **  analyzing library                           **
# **************************************************

import json
from json.decoder import JSONDecodeError

import pathlib
import os
import re
import shlex
import sys

import logging

from futag.sysmsg import *
from subprocess import Popen, PIPE

logger = logging.getLogger(__name__)


def delete_folder(pth):
    """
    Function for recursive delete folder
    Parameters
    ----------
    futag_llvm_package: pathlib object
        path to the folder to delete
    """
    for sub in pth.iterdir():
        if sub.is_dir():
            delete_folder(sub)
        else:
            sub.unlink()
    pth.rmdir()


def _scan_build_checker_args(scan_build_path, checker_name=None, analyzer_configs=None):
    """Build the common scan-build checker argument list."""
    args = [scan_build_path.as_posix()]
    for c in DISABLED_CHECKERS:
        args.extend(["-disable-checker", c])
    if checker_name:
        args.extend(["-enable-checker", checker_name])
    for config in (analyzer_configs or []):
        args.extend(["-analyzer-config", config])
    return args


def _run_command(cmd, env=None, msg_prefix="", fail_msg="", succeed_msg="",
                 exit_on_fail=True, capture=True):
    """Run a subprocess command with standardized error handling."""
    kwargs = dict(universal_newlines=True, env=env)
    if capture:
        kwargs.update(stdout=PIPE, stderr=PIPE)
    p = Popen(cmd, **kwargs)
    if msg_prefix:
        logger.debug("%s %s", msg_prefix, " ".join(p.args))
    output, errors = p.communicate()
    if p.returncode:
        if errors:
            logger.error(errors)
        if exit_on_fail and fail_msg:
            sys.exit(fail_msg)
        elif fail_msg:
            logger.error(fail_msg)
    else:
        if output and capture:
            logger.debug(output)
        if succeed_msg:
            logger.info(succeed_msg)
    return p.returncode, output, errors


def _make_build_env(toolchain, flags=None):
    """Create environment dict with compiler paths from toolchain config."""
    env = os.environ.copy()
    env["CC"] = toolchain.clang.as_posix()
    env["CXX"] = toolchain.clangpp.as_posix()
    if flags:
        env["CFLAGS"] = flags
        env["CPPFLAGS"] = flags
        env["LDFLAGS"] = flags
    return env


def _load_json_files(file_list, description=""):
    """Load and yield parsed JSON from all matching files."""
    for jf in file_list:
        if os.stat(jf).st_size == 0:
            continue
        try:
            with open(jf, "r") as f:
                data = json.load(f)
        except JSONDecodeError:
            logger.warning(f"Could not parse JSON in {jf}")
            continue
        if data is None:
            logger.warning(f"loading json from file {jf} failed!")
            continue
        logger.info(f"Analyzing {description} in file {jf} ...")
        yield data


def _parse_location(location_str):
    """Parse 'dir/file.c:line' into a structured dict."""
    parts = location_str.rsplit(":", 1)
    line = parts[-1] if len(parts) > 1 else ""
    fullpath = parts[0]
    p = pathlib.Path(fullpath)
    return {
        "file": p.name,
        "line": line,
        "directory": str(p.parent),
        "fullpath": fullpath,
    }


class _BaseBuilder:
    """Shared base for Builder and ConsumerBuilder."""

    def _validate_common(self, futag_llvm_package, library_root, processes, build_ex_params, toolchain=None):
        """Validate and set common attributes."""
        self.futag_llvm_package = futag_llvm_package
        self.library_root = library_root

        try:
            processes = int(processes)
            if processes < 0:
                sys.exit(INVALID_INPUT_PROCESSES)
        except ValueError:
            sys.exit(INVALID_INPUT_PROCESSES)
        self.processes = processes

        from futag.toolchain import ToolchainConfig
        if toolchain is not None:
            self.toolchain = toolchain
            self.futag_llvm_package = (
                toolchain.clang.parent.parent if toolchain.clang else None)
        elif pathlib.Path(futag_llvm_package).absolute().exists() and (pathlib.Path(futag_llvm_package) / "bin/clang").absolute().exists():
            self.toolchain = ToolchainConfig.from_futag_llvm(futag_llvm_package)
            self.futag_llvm_package = pathlib.Path(
                futag_llvm_package).absolute()
        else:
            sys.exit(INVALID_FUTAG_PATH + futag_llvm_package)

        if pathlib.Path(library_root).absolute().exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            sys.exit(INVALID_LIBPATH)

        self.build_ex_params = build_ex_params

    def _extra_build_params(self):
        """Split build_ex_params safely into a list."""
        if self.build_ex_params:
            return shlex.split(self.build_ex_params)
        return []

    def _scan_build_args(self, checker_name=None, analyzer_configs=None):
        """Build scan-build argument prefix."""
        self.toolchain.require_scan_build()
        return _scan_build_checker_args(
            self.toolchain.scan_build,
            checker_name, analyzer_configs)

    def _make_env(self, with_flags=False):
        """Create build environment with compiler paths from toolchain."""
        return _make_build_env(
            self.toolchain,
            self.flags if with_flags else None)

    def _make_jobs_arg(self):
        """Return ['-jN'] list if processes > 1, else empty list."""
        if self.processes > 1:
            return ["-j" + str(self.processes)]
        return []


class Builder(_BaseBuilder):
    """Futag Builder Class"""

    def __init__(self, futag_llvm_package: str = "", library_root: str = "", flags: str = "", clean: bool = False, intercept: bool = True, build_path: str = BUILD_PATH, install_path: str = INSTALL_PATH, analysis_path: str = ANALYSIS_PATH, processes: int = 4, build_ex_params=BUILD_EX_PARAMS, toolchain=None):
        """Constructor of class Builder

        Args:
            futag_llvm_package (str): path to the futag-llvm package (with binaries, scripts, etc.).
            library_root (str): path to the library root.
            flags (str, optional): flags for compiling.. Defaults to COMPILER_FLAGS.
            clean (bool, optional): Option for deleting futag folders if they are exist, for example futag-build, futag-install, futag-analysis. Defaults to False.
            build_path (str, optional): path to the build directory. Be careful, this directory will be deleted and create again if clean set to True. Defaults to BUILD_PATH.
            install_path (str, optional): path for saving report of analysis. Be careful, this directory will be deleted and create again if clean set to True. Defaults to INSTALL_PATH.
            analysis_path (str, optional): path for saving report of analysis. Be careful, this directory will be deleted and create again if clean set to True. Defaults to ANALYSIS_PATH.
            processes (int, optional): number of processes while building. Defaults to 4.
            build_ex_params (_type_, optional): extra params for building, for example "--with-openssl" for building curl. Defaults to BUILD_EX_PARAMS.

        Raises:
            ValueError: INVALID_FUTAG_PATH: Invalid path of futag-llvm.
            ValueError: INVALID_LIBPATH: Invalid path of library.
            ValueError: INVALID_INPUT_PROCESSES: the input value of "processes" is not a number or negative.
        """

        self._validate_common(futag_llvm_package, library_root, processes, build_ex_params, toolchain=toolchain)

        if (self.library_root / build_path).exists() and clean:
            delete_folder(self.library_root / build_path)

        (self.library_root / build_path).mkdir(parents=True, exist_ok=True)
        self.build_path = self.library_root / build_path

        if (self.library_root / install_path).exists() and clean:
            delete_folder(self.library_root / install_path)

        (self.library_root / install_path).mkdir(parents=True, exist_ok=True)
        self.install_path = self.library_root / install_path

        if (self.library_root / analysis_path).exists() and clean:
            delete_folder(self.library_root / analysis_path)

        (self.library_root / analysis_path).mkdir(parents=True, exist_ok=True)
        self.analysis_path = self.library_root / analysis_path
        if not flags:
            flags = DEBUG_FLAGS + " " + COMPILER_FLAGS + " " + COMPILER_COVERAGE_FLAGS
        self.flags = flags
        self.intercept = intercept

    def auto_build(self) -> bool:
        """ This function tries to automatically build your library. It finds in your library source code whether Makefile, file configure, or CMakeList.txt file exists.

        Returns:
            bool: result of auto build.
        """

        logger.info(AUTO_BUILD_MSG)
        if (self.library_root / "configure").exists():
            logger.info(CONFIGURE_FOUND)
            self.build_configure()
            return True


        # TODO: добавить возможность указать папку cmake!!!
        if (self.library_root / "CMakeLists.txt").exists():
            logger.info(CMAKE_FOUND)
            self.build_cmake()
            return True

        if (self.library_root / "Makefile").exists():
            logger.info(MAKEFILE_FOUND)
            self.build_makefile()
            return True

        if (self.library_root / "meson.build").exists():
            logger.info(CMAKE_FOUND)
            self.build_meson()
            return True

        logger.error(AUTO_BUILD_FAILED)
        return False

    def build_meson(self) -> bool:
        """ This function tries to build your library with cmake.

        Raises:
        Returns:
            bool: result of building with cmake.
        """
        curr_dir = os.getcwd()
        # Configure with meson
        os.chdir(self.library_root.as_posix())
        my_env = self._make_env()
        logger.info(LIB_ANALYSIS_STARTED)
        if self.build_path.resolve() == self.library_root.resolve():
            sys.exit(CMAKE_PATH_ERROR)

        config_cmd = [
            self.toolchain.scan_build.as_posix(),
            "meson",
            f"--prefix={self.install_path.as_posix()}",
            f"{(self.build_path).as_posix()}",
        ]
        if self.build_ex_params:
            config_cmd += self._extra_build_params()

        _run_command(config_cmd, env=my_env, msg_prefix=LIB_CONFIGURE_COMMAND,
                     fail_msg=LIB_CONFIGURE_FAILED, succeed_msg=LIB_CONFIGURE_SUCCEEDED,
                     capture=False)

        # analysis
        os.chdir(self.build_path.as_posix())
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_ANALYZER_CHECKER,
            analyzer_configs=[
                FUTAG_ANALYZER_CHECKER + ":report_dir=" + self.analysis_path.as_posix(),
            ]
        ) + ["ninja"] + self._make_jobs_arg()

        _run_command(analysis_command, env=my_env, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED)

        # Doing ninja install
        _run_command(["ninja", "install"], env=my_env,
                     fail_msg=LIB_INSTALL_FAILED, succeed_msg=LIB_INSTALL_SUCCEEDED,
                     exit_on_fail=False)

        os.chdir(curr_dir)

        return True


    def build_cmake(self) -> bool:
        """ This function tries to build your library with cmake.

        Raises:
            ValueError: LIB_CONFIGURE_FAILED: Futag can not configure library.
            ValueError: LIB_ANALYZING_FAILED: Futag can not analyze library with its own checkers.
            ValueError: LIB_BUILD_FAILED: Futag can not build the library.
            ValueError: LIB_INSTALL_FAILED: Futag can not install the library.

        Returns:
            bool: result of building with cmake.
        """

        # Config with cmake
        my_env = self._make_env()
        logger.info(LIB_ANALYSIS_STARTED)
        if self.build_path.resolve() == self.library_root.resolve():
            sys.exit(CMAKE_PATH_ERROR)

        config_cmd = self._scan_build_args() + [
            "cmake",
            f"-DLLVM_CONFIG_PATH={(self.futag_llvm_package / 'bin/llvm-config').as_posix()}",
            f"-DCMAKE_INSTALL_PREFIX={self.install_path.as_posix()}",
            f"-DCMAKE_EXPORT_COMPILE_COMMANDS=1",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.library_root.as_posix()}"
        ]
        if self.build_ex_params:
            config_cmd += self._extra_build_params()

        _run_command(config_cmd, env=my_env, msg_prefix=LIB_CONFIGURE_COMMAND,
                     fail_msg=LIB_CONFIGURE_FAILED, succeed_msg=LIB_CONFIGURE_SUCCEEDED)

        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        # Doing make for analysis
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_ANALYZER_CHECKER,
            analyzer_configs=[
                FUTAG_ANALYZER_CHECKER + ":report_dir=" + self.analysis_path.as_posix(),
            ]
        ) + ["make"] + self._make_jobs_arg()

        _run_command(analysis_command, env=my_env, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED)

        os.chdir(curr_dir)
        delete_folder(self.build_path)
        (self.build_path).mkdir(parents=True, exist_ok=True)
        os.chdir(self.build_path.as_posix())

        config_cmd = [
            "cmake",
            f"-DLLVM_CONFIG_PATH={(self.futag_llvm_package / 'bin/llvm-config').as_posix()}",
            f"-DCMAKE_INSTALL_PREFIX={self.install_path.as_posix()}",
            f"-DCMAKE_CXX_FLAGS='{self.flags}'",
            f"-DCMAKE_CXX_COMPILER={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            f"-DCMAKE_C_COMPILER={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"-DCMAKE_C_FLAGS='{self.flags}'",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.library_root.as_posix()}",f"-DCMAKE_EXPORT_COMPILE_COMMANDS=1"
        ]

        my_env["CFLAGS"] = self.flags
        my_env["CPPFLAGS"] = self.flags
        my_env["LDFLAGS"] = self.flags

        if self.build_ex_params:
            config_cmd += self._extra_build_params()

        _run_command(config_cmd, env=my_env, msg_prefix=LIB_CONFIGURE_COMMAND,
                     fail_msg=LIB_CONFIGURE_FAILED, succeed_msg=LIB_CONFIGURE_SUCCEEDED)

        os.chdir(self.build_path.as_posix())
        # Doing make for building
        make_command = ["make"] + self._make_jobs_arg() + [
            f"CC={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"CXX={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            f"CFLAGS={self.flags}",
            f"CPPFLAGS={self.flags}",
            f"CXXFLAGS={self.flags}",
            f"LDFLAGS={self.flags}",
        ]

        _run_command(make_command, env=my_env, msg_prefix=LIB_BUILD_COMMAND,
                     fail_msg=LIB_BUILD_FAILED, succeed_msg=LIB_BUILD_SUCCEEDED,
                     exit_on_fail=False)

        # Doing make install
        _run_command(["make", "install"], env=my_env,
                     fail_msg=LIB_INSTALL_FAILED, succeed_msg=LIB_INSTALL_SUCCEEDED,
                     exit_on_fail=False)

        os.chdir(curr_dir)
        return True

    def build_configure(self) -> bool:
        """ This function tries to build your library with configure.

        Raises:
            ValueError: LIB_CONFIGURE_FAILED: Futag can not configure library.
            ValueError: LIB_ANALYZING_FAILED: Futag can not analyze library with its own checkers.
            ValueError: LIB_BUILD_FAILED: Futag can not build the library.
            ValueError: LIB_INSTALL_FAILED: Futag can not install the library.

        Returns:
            bool: result of building with file "configure".
        """
        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        logger.info(LIB_ANALYSIS_STARTED)
        config_cmd = self._scan_build_args() + [
            (self.library_root / "configure").as_posix(),
            f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self._extra_build_params()

        _run_command(config_cmd, msg_prefix=LIB_CONFIGURE_COMMAND,
                     fail_msg=LIB_CONFIGURE_FAILED)

        # Analyzing the library
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_ANALYZER_CHECKER,
            analyzer_configs=[
                FUTAG_ANALYZER_CHECKER + ":report_dir=" + self.analysis_path.as_posix(),
            ]
        ) + ["make"] + self._make_jobs_arg()

        _run_command(analysis_command, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED)

        if self.intercept:
            _run_command(["make", "clean"], capture=True)
            _run_command(["make", "distclean"], capture=True, exit_on_fail=False)

            # Doing make for building
            my_env = self._make_env(with_flags=True)
            my_env["LLVM_CONFIG"] = (
                self.futag_llvm_package / 'bin/llvm-config').as_posix()

            config_cmd = [
                (self.library_root / "configure").as_posix(),
                f"--prefix=" + self.install_path.as_posix(),
            ]
            if self.build_ex_params:
                config_cmd += self._extra_build_params()

            _run_command(config_cmd, env=my_env, msg_prefix=LIB_CONFIGURE_COMMAND,
                         fail_msg=LIB_CONFIGURE_FAILED, succeed_msg=LIB_CONFIGURE_SUCCEEDED)

            make_command = [
                self.toolchain.intercept_build.as_posix(),
                "make",
            ] + self._make_jobs_arg()

            _run_command(make_command, env=my_env, msg_prefix=LIB_BUILD_COMMAND,
                         fail_msg=LIB_BUILD_FAILED, succeed_msg=LIB_BUILD_SUCCEEDED)

        # Doing make install
        _run_command(["make", "install"], msg_prefix="",
                     fail_msg=LIB_INSTALL_FAILED, succeed_msg=LIB_INSTALL_SUCCEEDED)

        os.chdir(curr_dir)
        return True

    def build_makefile(self) -> bool:
        """This function tries to build your library with Makefile.

        Raises:
            ValueError: LIB_ANALYZING_FAILED: Futag can not analyze library with its own checkers.
            ValueError: LIB_BUILD_FAILED: Futag can not build the library.
            ValueError: LIB_INSTALL_FAILED: Futag can not install the library.

        Returns:
            bool: result of building with Makefile.
        """
        curr_dir = os.getcwd()

        logger.info(LIB_ANALYSIS_STARTED)

        # Analyzing the library
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_ANALYZER_CHECKER,
            analyzer_configs=[
                FUTAG_ANALYZER_CHECKER + ":report_dir=" + self.analysis_path.as_posix(),
            ]
        ) + ["make", "-j" + str(self.processes)]

        _run_command(analysis_command, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED,
                     exit_on_fail=False)

        # Doing make for building
        _run_command(["make", "clean"], capture=True, exit_on_fail=False)

        my_env = _make_build_env(self.futag_llvm_package)
        my_env["CFLAGS"] = "'" + self.flags + "'"
        my_env["CPPFLAGS"] = "'" + self.flags + "'"
        my_env["LDFLAGS"] = "'" + self.flags + "'"
        my_env["LLVM_CONFIG"] = (
            self.futag_llvm_package / 'bin/llvm-config').as_posix()

        if self.intercept:
            make_command = [
                self.toolchain.intercept_build.as_posix(),
                "make",
            ]
        else:
            make_command = ["make"]
        make_command += self._make_jobs_arg()

        _run_command(make_command, env=my_env, msg_prefix=LIB_BUILD_COMMAND,
                     fail_msg=LIB_BUILD_FAILED, succeed_msg=LIB_BUILD_SUCCEEDED,
                     exit_on_fail=False)

        # Doing make install
        _run_command(["make", "install", "DESTDIR=" + self.install_path.as_posix()],
                     fail_msg=LIB_INSTALL_FAILED, succeed_msg=LIB_INSTALL_SUCCEEDED,
                     exit_on_fail=False)

        os.chdir(curr_dir)
        return True

    def analyze(self):
        """ This function reads analysis result of Futag checker
        """
        # Find all declaration files in given location
        decl_files = [
            x
            for x in self.analysis_path.glob("**/.declaration-*.futag-analyzer.json")
            if x.is_file()
        ]

        # Find all context files in given location
        context_files = [
            x for x in self.analysis_path.glob("**/.context-*.futag-analyzer.json") if x.is_file()
        ]

        # Find all type_info files in given location
        typeinfo_files = [
            x
            for x in self.analysis_path.glob("**/.types-info-*.futag-analyzer.json")
            if x.is_file()
        ]

        # Find all includes info files in given location
        info_files = [
            x
            for x in self.analysis_path.glob("**/.file-info-*.futag-analyzer.json")
            if x.is_file()
        ]

        # global list of function
        function_list = {} # saving function definitions
        enum_list = []
        typedef_list = []
        record_list = []
        compiled_files = []

        logger.info("Analysing function declarations...")
        for functions in _load_json_files(decl_files, "function declarations"):
            # get global hash of all functions
            for func_hash in functions:
                if func_hash not in function_list:
                    function_list[func_hash] = functions[func_hash]

        logger.info("Analysing contexts...")
        for contexts in _load_json_files(context_files, "context"):
            # get global hash of all functions
            global_hash = [x for x in function_list]
            # iterate function hash for adding to global hash list
            for func_hash in contexts:
                if func_hash in global_hash:
                    target_list = [
                        x["target_func_hash"] + x["target_func_loc"]
                        for x in function_list[func_hash]["call_contexts"]
                    ]
                    for call_xref in contexts[func_hash]["call_contexts"]:
                        if not call_xref["target_func_hash"] + call_xref["target_func_loc"] in target_list:
                            function_list[func_hash]["call_contexts"].append(
                                call_xref)
                else:
                    logger.warning("%s not found in global hash list!", func_hash)

        logger.info("Analysing data types ...")

        for types in _load_json_files(typeinfo_files, "data types"):
            for enum_it in types["enums"]:
                exist = False
                for enum_exist_it in enum_list:
                    if enum_it["hash"] == enum_exist_it["hash"]:
                        exist = True
                        break
                if not exist:
                    enum_list.append(enum_it)

            for record in types["records"]:
                exist = False
                for record_iter in record_list:
                    if record["qname"] == record_iter["qname"]:
                        if len(record["fields"]) > len(record_iter["fields"]):
                            record_iter["fields"] = record["fields"]
                        exist = True
                        break
                if not exist:
                    record_list.append(record)

            for typedef_it in types["typedefs"]:
                exist = False
                for typedef_exist_it in typedef_list:
                    if typedef_it["qname"] == typedef_exist_it["qname"]:
                        exist = True
                        break
                if not exist:
                    typedef_list.append(typedef_it)

        logger.info("Analysing header files and compiler options...")

        match_include = r"^\s*#include\s*([<\"][//_\-\w.<>]+[>\"])\s*$"
        for infofile in info_files:
            if os.stat(infofile).st_size == 0:
                continue
            try:
                with open(infofile, "r") as f:
                    compiled_file = json.load(f)
            except JSONDecodeError:
                logger.warning(f"Could not parse JSON in {infofile}")
                continue

            if not compiled_file or not compiled_file['file']:
                logger.warning(f"loading json from file {infofile} failed!")
                continue
            else:
                logger.info(f"Analyzing headers in file {infofile} ...")
            code = []
            if os.path.exists(compiled_file['file']):
                logger.info("Getting info from file %s ...", compiled_file['file'])
                with open(compiled_file['file'], "r", errors="ignore") as f:
                    code = f.readlines()
            headers = []
            include_paths = []
            for line in code:
                include = re.match(match_include, line)
                if include:
                    header = include.group(1)
                    for i in compiled_file['includes']:
                        if header[1:-1].split("/")[-1] == i.split('/')[-1] and header[1:-1] in i:
                            headers.append(header)
                            p = pathlib.Path(header[1:-1])
                            if p and header[0] != '<' and p.absolute().parents[0].as_posix() not in include_paths:
                                include_paths.append(p.absolute().parents[0].as_posix())

            compiled_files.append({
                "filename": compiled_file['file'],
                "headers": headers,
                "include_paths": include_paths,
                "compiler_opts": compiled_file['compiler_opts'],
            })

        functions_w_contexts = []
        functions_4_consumer = []
        for func in function_list:
            contexts = []
            for f in function_list:
                for call_func in function_list[f]["call_contexts"]:
                    if call_func["target_func_hash"] == function_list[func]["hash"]:
                        contexts.append(call_func)
            location = _parse_location(function_list[func]["location"])

            fs = {
                "name": function_list[func]["name"],
                "qname": function_list[func]["qname"],
                "hash": function_list[func]["hash"],
                "is_simple": function_list[func]["is_simple"],
                "func_type": function_list[func]["func_type"],
                "access_type": function_list[func]["access_type"],
                "storage_class": function_list[func]["storage_class"],
                "parent_hash": function_list[func]["parent_hash"],
                "return_type": function_list[func]["return_type"],
                "gen_return_type": function_list[func]["gen_return_type"],
                "params": function_list[func]["params"],
                "fuzz_it": function_list[func]["fuzz_it"],
                "contexts": contexts,
                "location": location,
            }

            functions_w_contexts.append(fs)

            fdecl = {
                "name": function_list[func]["name"],
                "qname": function_list[func]["qname"],
                "is_simple": function_list[func]["is_simple"],
                "return_type": function_list[func]["return_type"],
                "params": function_list[func]["params"],
                "location": location,
            }
            functions_4_consumer.append(fdecl)
        result = {
            "functions": functions_w_contexts,
            "enums": enum_list,
            "records": record_list,
            "typedefs": typedef_list,
            "compiled_files": compiled_files,
        }
        with open(self.analysis_path / "futag-analysis-result.json", "w") as f:
            json.dump(result, f)
        result_4_consumer = {
            "functions": functions_4_consumer,
            "enums": enum_list,
            "records": record_list,
            "typedefs": typedef_list,
        }
        with open(self.analysis_path / "futag-4consumer.json", "w") as f:
            json.dump(result_4_consumer, f)

        logger.info("Total functions: %s", str(len(result["functions"])))
        logger.info("Total functions for consumer programs: %s", str(len(result_4_consumer["functions"])))
        logger.info("Total enums: %s", str(len(result["enums"])))
        logger.info("Total records: %s", str(len(result["records"])))
        logger.info("Total typedefs: %s", str(len(result["typedefs"])))
        logger.info("Analysis result: %s", (self.analysis_path /
              "futag-analysis-result.json").as_posix())


class ConsumerBuilder(_BaseBuilder):
    """Futag Builder Class for Consumer programs"""

    def __init__(self, futag_llvm_package: str = "", library_root: str = "", consumer_root: str = "", flags: str = "", clean: bool = False, build_path: str = BUILD_PATH, consumer_report_path: str = CONSUMER_REPORT_PATH, db_filepath: str = FOR_CONSUMER_FILEPATH, processes: int = 4, build_ex_params=BUILD_EX_PARAMS, toolchain=None):
        """Constructor of class Consumer Builder

        Args:
            futag_llvm_package (str): path to the futag-llvm package (with binaries, scripts, etc.).
            library_root (str): path to the library root.
            consumer_root (str): path to the consumer program.
            flags (str, optional): flags for compiling.. Defaults to COMPILER_FLAGS.
            clean (bool, optional): Option for deleting futag folders if they are exist, for example futag-build, futag-consumer-analysis. Defaults to False.
            build_path (str, optional): path to the build directory. Be careful, this directory will be deleted and create again if clean set to True. Defaults to BUILD_PATH.
            consumer_report_path (str, optional): path for saving report of analysis. Be careful, this directory will be deleted and create again if clean set to True. Defaults to CONSUMER_REPORT_PATH.
            db_filepath (str, optional): path of analysis result of testing library. Defaults to DB_FILEPATH.
            processes (int, optional): number of processes while building. Defaults to 4.
            build_ex_params (_type_, optional): extra params for building, for example "--with-openssl" for building curl. Defaults to BUILD_EX_PARAMS.

        Raises:
            ValueError: INVALID_FUTAG_PATH: Invalid path of futag-llvm.
            ValueError: INVALID_LIBPATH: Invalid path of library.
            ValueError: INVALID_INPUT_PROCESSES: the input value of "processes" is not a number or negative.
        """

        self.consumer_root = consumer_root
        self._validate_common(futag_llvm_package, library_root, processes, build_ex_params, toolchain=toolchain)

        if pathlib.Path(consumer_root).absolute().exists():
            self.consumer_root = pathlib.Path(self.consumer_root).absolute()
        else:
            sys.exit(INVALID_CONSUMER_PATH)

        if (self.consumer_root / build_path).exists() and clean:
            delete_folder(self.consumer_root / build_path)

        (self.consumer_root / build_path).mkdir(parents=True, exist_ok=True)
        self.build_path = self.consumer_root / build_path

        if not pathlib.Path(self.library_root / db_filepath).absolute().exists():
            sys.exit(INVALID_DB_FILEPATH)

        self.db_filepath = pathlib.Path(self.library_root / db_filepath).absolute()

        if (self.library_root / consumer_report_path).exists() and clean:
            delete_folder(self.library_root / consumer_report_path)

        (self.library_root / consumer_report_path).mkdir(parents=True, exist_ok=True)
        self.consumer_report_path = self.library_root / consumer_report_path
        if not flags:
            flags = DEBUG_FLAGS + " " + COMPILER_FLAGS
        self.flags = flags

    def _consumer_analyzer_configs(self):
        """Return analyzer config args for consumer checker."""
        return [
            FUTAG_CONSUMER_ANALYZER_CHECKER + ":consumer_report_path=" + self.consumer_report_path.as_posix(),
            FUTAG_CONSUMER_ANALYZER_CHECKER + ":db_filepath=" + self.db_filepath.as_posix(),
        ]

    def auto_build(self) -> bool:
        """ This function tries to automatically build your library. It finds in your library source code whether Makefile, file configure, or CMakeList.txt file exists.

        Returns:
            bool: result of auto build.
        """

        logger.info(AUTO_CONSUMER_BUILD_MSG)
        logger.info("Testing library: %s", self.library_root.as_posix())
        logger.info("Consumer program: %s", self.consumer_root.as_posix())
        logger.info("Analysis result: %s", self.consumer_report_path.as_posix())
        if (self.consumer_root / "configure").exists():
            logger.info(CONFIGURE_FOUND)
            self.build_configure()
            return True

        # TODO: добавить возможность указать папку cmake!!!
        if (self.consumer_root / "CMakeLists.txt").exists():
            logger.info(CMAKE_FOUND)
            self.build_cmake()
            return True

        if (self.consumer_root / "Makefile").exists():
            logger.info(MAKEFILE_FOUND)
            self.build_makefile()
            return True

        logger.error(AUTO_BUILD_FAILED)
        return False

    def build_cmake(self) -> bool:
        """ This function tries to build your library with cmake.

        Raises:
            ValueError: LIB_CONFIGURE_FAILED: Futag can not configure library.
            ValueError: LIB_ANALYZING_FAILED: Futag can not analyze library with its own checkers.
            ValueError: LIB_BUILD_FAILED: Futag can not build the library.
            ValueError: LIB_INSTALL_FAILED: Futag can not install the library.

        Returns:
            bool: result of building with cmake.
        """

        # Config with cmake
        my_env = self._make_env()
        logger.info(LIB_ANALYSIS_STARTED)
        if self.build_path.resolve() == self.consumer_root.resolve():
            sys.exit(CMAKE_PATH_ERROR)

        config_cmd = self._scan_build_args() + [
            "cmake",
            f"-DLLVM_CONFIG_PATH={(self.futag_llvm_package / 'bin/llvm-config').as_posix()}",
            f"-DCMAKE_EXPORT_COMPILE_COMMANDS=1",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.consumer_root.as_posix()}"
        ]
        if self.build_ex_params:
            config_cmd += self._extra_build_params()

        _run_command(config_cmd, env=my_env, msg_prefix=LIB_CONFIGURE_COMMAND,
                     fail_msg=LIB_CONFIGURE_FAILED, succeed_msg=LIB_CONFIGURE_SUCCEEDED)

        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        # Doing make for analysis
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_CONSUMER_ANALYZER_CHECKER,
            analyzer_configs=self._consumer_analyzer_configs(),
        ) + ["make"] + self._make_jobs_arg()

        _run_command(analysis_command, env=my_env, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED,
                     exit_on_fail=False)

        os.chdir(curr_dir)
        return True

    def build_configure(self) -> bool:
        """ This function tries to build your library with configure.

        Raises:
            ValueError: LIB_CONFIGURE_FAILED: Futag can not configure library.
            ValueError: LIB_ANALYZING_FAILED: Futag can not analyze library with its own checkers.
            ValueError: LIB_BUILD_FAILED: Futag can not build the library.
            ValueError: LIB_INSTALL_FAILED: Futag can not install the library.

        Returns:
            bool: result of building with file "configure".
        """

        curr_dir = os.getcwd()
        os.chdir(self.consumer_root.as_posix())
        logger.info(LIB_ANALYSIS_STARTED)

        config_cmd = self._scan_build_args() + [
            (self.consumer_root / "configure").as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self._extra_build_params()

        _run_command(config_cmd, msg_prefix=LIB_CONFIGURE_COMMAND,
                     fail_msg=LIB_CONFIGURE_FAILED)

        # Analyzing the library
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_CONSUMER_ANALYZER_CHECKER,
            analyzer_configs=self._consumer_analyzer_configs(),
        ) + ["make"] + self._make_jobs_arg()

        _run_command(analysis_command, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED,
                     exit_on_fail=False)

        os.chdir(curr_dir)
        return True

    def build_makefile(self) -> bool:
        """This function tries to build your library with Makefile.

        Raises:
            ValueError: LIB_ANALYZING_FAILED: Futag can not analyze library with its own checkers.
            ValueError: LIB_BUILD_FAILED: Futag can not build the library.
            ValueError: LIB_INSTALL_FAILED: Futag can not install the library.

        Returns:
            bool: result of building with Makefile.
        """

        logger.info(LIB_ANALYSIS_STARTED)

        # Analyzing the library
        analysis_command = self._scan_build_args(
            checker_name=FUTAG_CONSUMER_ANALYZER_CHECKER,
            analyzer_configs=self._consumer_analyzer_configs(),
        ) + ["make", "-j" + str(self.processes)]

        _run_command(analysis_command, msg_prefix=LIB_ANALYZING_COMMAND,
                     fail_msg=LIB_ANALYZING_FAILED, succeed_msg=LIB_ANALYZING_SUCCEEDED,
                     exit_on_fail=False)

        return True

    def analyze(self):
        """ This function reads context analysis result of Futag Consumer checker
        """
        # Find all declaration files in given location
        context_files = [
            x
            for x in self.consumer_report_path.glob("**/_*.json")
            if x.is_file()
        ]
        contexts = []
        for context in _load_json_files(context_files, "consumer context"):
            contexts.append(context)

        with open(self.consumer_report_path / "futag-contexts.json", "w") as f:
            json.dump(contexts, f)
