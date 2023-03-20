"""
**************************************************
**      ______  __  __  ______  ___     ______  **
**     / ____/ / / / / /_  __/ /   |   / ____/  **
**    / /_    / / / /   / /   / /| |  / / __    **
**   / __/   / /_/ /   / /   / ___ | / /_/ /    **
**  /_/      \____/   /_/   /_/  |_| \____/     **
**                                              **
**     Fuzzing target Automated Generator       **
**             a tool of ISP RAS                **
**************************************************
**  This preprocessor module is for building,   **
**  analyzing library                           **
**************************************************
"""
import json
import pathlib
import os
import re
import sys

from futag.sysmsg import *
from subprocess import Popen, PIPE


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


class Builder:
    """Futag Builder Class"""

    def __init__(self, futag_llvm_package: str, library_root: str, flags: str = "", clean: bool = False, build_path: str = BUILD_PATH, install_path: str = INSTALL_PATH, analysis_path: str = ANALYSIS_PATH, processes: int = 4, build_ex_params=BUILD_EX_PARAMS):
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

        self.futag_llvm_package = futag_llvm_package
        self.library_root = library_root

        try:
            processes = int(processes)
            if processes < 0:
                sys.exit(INVALID_INPUT_PROCESSES)
        except ValueError:
            print(INVALID_INPUT_PROCESSES)
        self.processes = processes

        if pathlib.Path(futag_llvm_package).absolute().exists() and (pathlib.Path(futag_llvm_package) / "bin/clang").absolute().exists():
            self.futag_llvm_package = pathlib.Path(
                self.futag_llvm_package).absolute()
        else:
            sys.exit(INVALID_FUTAG_PATH, futag_llvm_package)

        if pathlib.Path(library_root).absolute().exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            sys.exit(INVALID_LIBPATH)

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
            flags = DEBUG_FLAGS + " " + COMPILER_FLAGS
        self.flags = flags
        self.build_ex_params = build_ex_params

    def auto_build(self) -> bool:
        """ This function tries to automatically build your library. It finds in your library source code whether Makefile, file configure, or CMakeList.txt file exists.

        Returns:
            bool: result of auto build.
        """

        print(AUTO_BUILD_MSG)
        if (self.library_root / "configure").exists():
            print(CONFIGURE_FOUND)
            self.build_configure()
            return True

        # TODO: добавить возможность указать папку cmake!!!
        if (self.library_root / "CMakeLists.txt").exists():
            print(CMAKE_FOUND)
            self.build_cmake()
            return True

        if (self.library_root / "Makefile").exists():
            print(MAKEFILE_FOUND)
            self.build_makefile()
            return True

        print(AUTO_BUILD_FAILED)
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
        my_env = os.environ.copy()
        print(LIB_ANALYSIS_STARTED)
        if self.build_path.resolve() == self.library_root.resolve():
            sys.exit(CMAKE_PATH_ERROR)

        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        config_cmd = [
            (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "cmake",
            f"-DLLVM_CONFIG_PATH={(self.futag_llvm_package / 'bin/llvm-config').as_posix()}",
            f"-DCMAKE_INSTALL_PREFIX={self.install_path.as_posix()}",
            # f"-DCMAKE_EXPORT_COMPILE_COMMANDS=1",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.library_root.as_posix()}"
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_CONFIGURE_FAILED)
        else:
            print(LIB_CONFIGURE_SUCCEEDED)
        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        # Doing make for analysis
        analysis_command = [
            (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "-enable-checker",
            "futag.FutagAnalyzer",
            "-analyzer-config",
            "futag.FutagAnalyzer:report_dir=" + self.analysis_path.as_posix(),
            "make",
        ]
        if self.processes > 1:
            analysis_command = analysis_command + ["-j" + str(self.processes)]

        p = Popen(analysis_command, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)
        print(LIB_ANALYZING_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_ANALYZING_FAILED)
        else:
            print(LIB_ANALYZING_SUCCEEDED)

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
            f"-S{self.library_root.as_posix()}"
        ]

        # my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        # my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        my_env["CFLAGS"] = self.flags
        my_env["CPPFLAGS"] = self.flags
        my_env["LDFLAGS"] = self.flags

        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_CONFIGURE_FAILED)
        else:
            print(output)
            print(LIB_CONFIGURE_SUCCEEDED)

        os.chdir(self.build_path.as_posix())
        # Doing make for building
        make_command = [
            (self.futag_llvm_package / "bin/intercept-build").as_posix(),
            "make",]
        if self.processes > 1:
            make_command = make_command + ["-j" + str(self.processes)]
        make_command = make_command + [
            f"CC={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"CXX={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            f"CFLAGS={self.flags}",
            f"CPPFLAGS={self.flags}",
            f"CXXFLAGS={self.flags}",
            f"LDFLAGS={self.flags}",
        ]
        p = Popen(make_command, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)
                #   universal_newlines=True)

        print(LIB_BUILD_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            print(LIB_BUILD_FAILED)
        else:
            print(output)
            print(LIB_BUILD_SUCCEEDED)

        # Doing make install
        p = Popen([
            "make",
            "install",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)

        output, errors = p.communicate()
        if p.returncode:
            print(LIB_INSTALL_COMMAND, " ".join(p.args))
            print(errors)
            print(LIB_INSTALL_FAILED)
        else:
            print(output)
            print(LIB_INSTALL_SUCCEEDED)

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

        print(LIB_ANALYSIS_STARTED)
        config_cmd = [
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            (self.library_root / "configure").as_posix(),
            f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE,
                  stderr=PIPE, universal_newlines=True)

        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_CONFIGURE_FAILED)

        # Analyzing the library
        analysis_command = [
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "-enable-checker",
            "futag.FutagAnalyzer",
            "-analyzer-config",
            "futag.FutagAnalyzer:report_dir=" + self.analysis_path.as_posix(),
            "make",]
        if self.processes > 1:
            analysis_command = analysis_command + ["-j" + str(self.processes)]

        p = Popen(analysis_command, stdout=PIPE,
                  stderr=PIPE, universal_newlines=True)

        print(LIB_ANALYZING_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_ANALYZING_FAILED)
        else:
            print(LIB_ANALYZING_SUCCEEDED)

        p = Popen([
            "make",
            "clean",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        output, errors = p.communicate()

        p = Popen([
            "make",
            "distclean",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        output, errors = p.communicate()
        # Doing make for building

        my_env = os.environ.copy()
        my_env["CFLAGS"] = self.flags
        my_env["CPPFLAGS"] = self.flags
        my_env["LDFLAGS"] = self.flags
        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        
        my_env["LLVM_CONFIG"] = (
            self.futag_llvm_package / 'bin/llvm-config').as_posix()
        config_cmd = [
            (self.library_root / "configure").as_posix(),
            f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)

        output, errors = p.communicate()
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        if p.returncode:
            print(errors)
            sys.exit(LIB_CONFIGURE_FAILED)
        else:
            print(output)
            print(LIB_CONFIGURE_SUCCEEDED)

        make_command = [
            (self.futag_llvm_package / "bin/intercept-build").as_posix(),
            "make",
        ]
        if self.processes > 1:
            make_command = make_command + ["-j" + str(self.processes)]
        make_command = make_command + [
            f"CC={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"CXX={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            f"CFLAGS={self.flags}",
            f"CPPFLAGS={self.flags}",
            f"CXXFLAGS={self.flags}",
            f"LDFLAGS={self.flags}",
        ]
        p = Popen(make_command, stdout=PIPE,
                  stderr=PIPE, universal_newlines=True, env=my_env)

        print(LIB_BUILD_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_BUILD_FAILED)
        else:
            print(output)
            print(LIB_BUILD_SUCCEEDED)

        # Doing make install
        p = Popen([
            "make",
            "install",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        output, errors = p.communicate()
        if p.returncode:
            print(LIB_INSTALL_COMMAND, " ".join(p.args))
            print(errors)
            sys.exit(LIB_INSTALL_FAILED)
        else:
            print(output)
            print(LIB_INSTALL_SUCCEEDED)

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

        print(LIB_ANALYSIS_STARTED)

        # Analyzing the library
        p = Popen([
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "-enable-checker",
            "futag.FutagAnalyzer",
            "-analyzer-config",
            "futag.FutagAnalyzer:report_dir=" + self.analysis_path.as_posix(),
            "make",
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        print(LIB_ANALYZING_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            # sys.exit(LIB_ANALYZING_FAILED)
        else:
            print(LIB_ANALYZING_SUCCEEDED)

        # Doing make for building
        p = Popen([
            "make",
            "clean",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        output, errors = p.communicate()

        my_env = os.environ.copy()
        my_env["CFLAGS"] = "'" + self.flags + "'"
        my_env["CPPFLAGS"] = "'" + self.flags + "'"
        my_env["LDFLAGS"] = "'" + self.flags + "'"
        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        my_env["LLVM_CONFIG"] = (
            self.futag_llvm_package / 'bin/llvm-config').as_posix()
        make_command = [
            (self.futag_llvm_package / "bin/intercept-build").as_posix(),
            "make",
        ]
        if self.processes > 1:
            make_command = make_command + ["-j" + str(self.processes)]
        make_command = make_command + [
            f"CC={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"CXX={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            f"CFLAGS={self.flags}",
            f"CPPFLAGS={self.flags}",
            f"CXXFLAGS={self.flags}",
            f"LDFLAGS={self.flags}",
        ]
        p = Popen(make_command, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)

        print(LIB_BUILD_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            # sys.exit(LIB_BUILD_FAILED)
        else:
            print(output)
            print(LIB_BUILD_SUCCEEDED)

        # Doing make install
        p = Popen([
            "make",
            "install",
            "DESTDIR=" + self.install_path.as_posix(),
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        output, errors = p.communicate()
        if p.returncode:
            print(LIB_INSTALL_COMMAND, " ".join(p.args))
            print(errors)
            # sys.exit(LIB_INSTALL_FAILED)
        else:
            print(output)
            print(LIB_INSTALL_SUCCEEDED)

        os.chdir(curr_dir)
        return True

    def analyze(self):
        """ This function reads analysis result of Futag checker
        """
        # Find all declaration files in given location
        decl_files = [
            x
            for x in self.analysis_path.glob("**/declaration-*.futag-analyzer.json")
            if x.is_file()
        ]

        # Find all context files in given location
        context_files = [
            x for x in self.analysis_path.glob("**/context-*.futag-analyzer.json") if x.is_file()
        ]

        # Find all type_info files in given location
        typeinfo_files = [
            x
            for x in self.analysis_path.glob("**/types-info-*.futag-analyzer.json")
            if x.is_file()
        ]

        # Find all includes info files in given location
        info_files = [
            x
            for x in self.analysis_path.glob("**/file-info-*.futag-analyzer.json")
            if x.is_file()
        ]

        # global list of function
        function_list = {} # saving function definitions
        enum_list = []
        typedef_list = []
        record_list = []
        compiled_files = []

        print("")
        print(" -- [Futag]: Analysing fuction declarations...")
        for jf in decl_files:
            functions = json.load(open(jf.as_posix()))
            if functions is None:
                print(" -- [Futag]: Warning: loading json from file %s failed!" %
                      (jf.as_posix()))
                continue
            else:
                print(" -- [Futag]: Analyzing file %s ..." %
                      (jf.as_posix()))
            # get global hash of all functions
            global_hash = [x for x in function_list]
            # iterate function hash for adding to global hash list
            for hash in functions:
                if not hash in global_hash:
                    function_list[hash] = functions[hash]

        for jf in context_files:
            contexts = json.load(open(jf.as_posix()))
            if contexts is None:
                print(" -- [Futag]: Warning: loading json from file %s failed!" %
                      (jf.as_posix()))
                continue
            # get global hash of all functions
            global_hash = [x for x in function_list]
            # iterate function hash for adding to global hash list
            for hash in contexts:
                if hash in global_hash:
                    target_list = [
                        x["target_func_hash"] + x["target_func_loc"]
                        for x in function_list[hash]["call_contexts"]
                    ]
                    for call_xref in contexts[hash]["call_contexts"]:
                        if not call_xref["target_func_hash"] + call_xref["target_func_loc"] in target_list:
                            function_list[hash]["call_contexts"].append(
                                call_xref)
                else:
                    print(" -- %s not found in global hash list!" % (hash))

        print("")
        print(" -- [Futag]: Analysing data types ...")

        for jf in typeinfo_files:
            types = json.load(open(jf.as_posix()))
            if types is None:
                print(" -- [Futag]: Warning: loading json from file %s failed!" %
                      (jf.as_posix()))
                continue
            else:
                print(" -- [Futag]: Analyzing file %s ..." % (jf.as_posix()))
            # get global hash of all functions
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

        print("")
        print(" -- [Futag]: Analysing header files and compiler options...")

        match_include = "^\s*#include\s*([<\"][//_\-\w.<>]+[>\"])\s*$"
        for infofile in info_files:
            compiled_file = json.load(open(infofile.as_posix()))
            if not compiled_file or not compiled_file['file']:
                print(" -- [Futag]: Warning: loading json from file %s failed!" %
                      (jf.as_posix()))
                continue
            else:
                print(" -- [Futag]: Analyzing file %s ..." %
                      (infofile.as_posix()))
            code = []
            if os.path.exists(compiled_file['file']):
                print(" -- [Futag]: Getting info from file %s ..." %
                      (compiled_file['file']))
                with open(compiled_file['file'], "r", errors="ignore") as f:
                    code = f.readlines()
            headers = []
            for line in code:
                include = re.match(match_include, line)
                if include:
                    header = include.group(1)
                    for i in compiled_file['includes']:
                        if header[1:-1].split("/")[-1] == i.split('/')[-1] and header[1:-1] in i:
                            headers.append(header)

            compiled_files.append({
                "filename": compiled_file['file'],
                "headers": headers,
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
            local_list = function_list[func]["location"].split(":")
            line = local_list[-1]
            local_list.pop()
            fullpath = ":".join(local_list)
            local_list = fullpath.split("/")
            file = local_list[-1]
            local_list.pop()
            directory = "/".join(local_list)
            location = {
                "file": file,
                "line": line,
                "directory": directory,
                "fullpath": fullpath,

            }
            
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
        json.dump(result, open(
            (self.analysis_path / "futag-analysis-result.json").as_posix(), "w"))
        result_4_consumer = {
            "functions": functions_4_consumer,
            "enums": enum_list,
            "records": record_list,
            "typedefs": typedef_list,
        }
        json.dump(result_4_consumer, open(
            (self.analysis_path / "futag-4consumer.json").as_posix(), "w"))

        print("Total functions: ", str(len(result["functions"])))
        print("Total functions for consumer programs: ", str(len(result_4_consumer["functions"])))
        print("Total enums: ", str(len(result["enums"])))
        print("Total records: ", str(len(result["records"])))
        print("Total typedefs: ", str(len(result["typedefs"])))
        print("Analysis result: ", (self.analysis_path /
              "futag-analysis-result.json").as_posix())


class ConsumerBuilder:
    """Futag Builder Class for Consumer programs"""

    def __init__(self, futag_llvm_package: str, library_root: str, consumer_root: str, flags: str = "", clean: bool = False, build_path: str = BUILD_PATH, consumer_report_path: str = CONSUMER_REPORT_PATH, db_filepath: str = FOR_CONSUMER_FILEPATH, processes: int = 4, build_ex_params=BUILD_EX_PARAMS):
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

        self.futag_llvm_package = futag_llvm_package
        self.library_root = library_root
        self.consumer_root = consumer_root

        try:
            processes = int(processes)
            if processes < 0:
                sys.exit(INVALID_INPUT_PROCESSES)
        except ValueError:
            print(INVALID_INPUT_PROCESSES)
        self.processes = processes

        if pathlib.Path(futag_llvm_package).absolute().exists() and (pathlib.Path(futag_llvm_package) / "bin/clang").absolute().exists():
            self.futag_llvm_package = pathlib.Path(
                self.futag_llvm_package).absolute()
        else:
            sys.exit(INVALID_FUTAG_PATH, futag_llvm_package)

        if pathlib.Path(library_root).absolute().exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            sys.exit(INVALID_LIBPATH)

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
        self.build_ex_params = build_ex_params

    def auto_build(self) -> bool:
        """ This function tries to automatically build your library. It finds in your library source code whether Makefile, file configure, or CMakeList.txt file exists.

        Returns:
            bool: result of auto build.
        """

        print(AUTO_CONSUMER_BUILD_MSG)
        print("-- [Futag]: Testing library: ", self.library_root.as_posix())
        print("-- [Futag]: Consumer program: ", self.consumer_root.as_posix())
        print("-- [Futag]: Analysis result: ", self.consumer_report_path.as_posix())
        print("")
        if (self.consumer_root / "configure").exists():
            print(CONFIGURE_FOUND)
            self.build_configure()
            return True

        # TODO: добавить возможность указать папку cmake!!!
        if (self.consumer_root / "CMakeLists.txt").exists():
            print(CMAKE_FOUND)
            self.build_cmake()
            return True

        if (self.consumer_root / "Makefile").exists():
            print(MAKEFILE_FOUND)
            self.build_makefile()
            return True

        print(AUTO_BUILD_FAILED)
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
        my_env = os.environ.copy()
        print(LIB_ANALYSIS_STARTED)
        if self.build_path.resolve() == self.consumer_root.resolve():
            sys.exit(CMAKE_PATH_ERROR)

        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        config_cmd = [
            (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "cmake",
            f"-DLLVM_CONFIG_PATH={(self.futag_llvm_package / 'bin/llvm-config').as_posix()}",
            # f"-DCMAKE_EXPORT_COMPILE_COMMANDS=1",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.consumer_root.as_posix()}"
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_CONFIGURE_FAILED)
        else:
            print(LIB_CONFIGURE_SUCCEEDED)
        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        # Doing make for analysis
        analysis_command = [
            (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "-enable-checker",
            "futag.FutagConsumerAnalyzer",
            "-analyzer-config",
            "futag.FutagConsumerAnalyzer:consumer_report_path=" + self.consumer_report_path.as_posix(),
            "-analyzer-config",
            "futag.FutagConsumerAnalyzer:db_filepath=" + self.db_filepath.as_posix(),
            "make",
        ]
        if self.processes > 1:
            analysis_command = analysis_command + ["-j" + str(self.processes)]

        p = Popen(analysis_command, stdout=PIPE, stderr=PIPE,
                  universal_newlines=True, env=my_env)
        print(LIB_ANALYZING_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_ANALYZING_FAILED)
        else:
            print(LIB_ANALYZING_SUCCEEDED)
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
        print(LIB_ANALYSIS_STARTED)
        config_cmd = [
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            (self.consumer_root / "configure").as_posix(),
            # f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE,
                  stderr=PIPE, universal_newlines=True)

        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_CONFIGURE_FAILED)

        # Analyzing the library
        analysis_command = [
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "-enable-checker",
            "futag.FutagConsumerAnalyzer",
            "-analyzer-config",
            "futag.FutagConsumerAnalyzer:consumer_report_path=" + self.consumer_report_path.as_posix(),
            "-analyzer-config",
            "futag.FutagConsumerAnalyzer:db_filepath=" + self.db_filepath.as_posix(),
            "make",]
        if self.processes > 1:
            analysis_command = analysis_command + ["-j" + str(self.processes)]

        p = Popen(analysis_command, stdout=PIPE,
                  stderr=PIPE, universal_newlines=True)

        print(LIB_ANALYZING_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            sys.exit(LIB_ANALYZING_FAILED)
        else:
            print(LIB_ANALYZING_SUCCEEDED)

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
        
        print(LIB_ANALYSIS_STARTED)

        # Analyzing the library
        p = Popen([
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-disable-checker",
            "core",
            "-disable-checker",
            "security",
            "-disable-checker",
            "unix",
            "-disable-checker",
            "deadcode",
            "-disable-checker",
            "nullability",
            "-disable-checker",
            "cplusplus",
            "-enable-checker",
            "futag.FutagConsumerAnalyzer",
            "-analyzer-config",
            "futag.FutagConsumerAnalyzer:consumer_report_path=" + self.consumer_report_path.as_posix(),
            "-analyzer-config",
            "futag.FutagConsumerAnalyzer:db_filepath=" + self.db_filepath.as_posix(),
            "make",
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        print(LIB_ANALYZING_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            # sys.exit(LIB_ANALYZING_FAILED)
        else:
            print(LIB_ANALYZING_SUCCEEDED)

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
        for jf in context_files:
            context = json.load(open(jf.as_posix()))
            if context is None:
                print(" -- [Futag]: Warning: file %s empty!" %
                      (jf.as_posix()))
                continue
            # get global hash of all functions
            contexts.append(context)

        json.dump(contexts, open(
            (self.consumer_report_path / "futag-contexts.json").as_posix(), "w"))

        print("-- [Futag] Context analysis result: ", (self.consumer_report_path / "futag-contexts.json").as_posix())