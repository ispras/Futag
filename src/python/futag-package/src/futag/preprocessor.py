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
import copy
import os

from futag.sysmsg import *

from subprocess import Popen, PIPE, call
from multiprocessing import Pool
from typing import List

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

    def __init__(self, futag_llvm_package: str, library_root: str, clean: bool = False, build_path: str = BUILD_PATH, install_path: str = INSTALL_PATH, analysis_path: str = ANALYSIS_PATH, processes: int =16, build_ex_params=BUILD_EX_PARAMS):
        """
        Parameters
        ----------
        futag_llvm_package: str
            (*required) path to the futag llvm package (with binaries, scripts, etc)
        library_root: str
            (*required) path to the library root
        clean: bool
            Option for deleting futag folders if they are exist (futag-build, futag-install, futag-analysis)
        build_path: str
            path to the build directory. This directory will be deleted and create again if clean set to True.
        install_path: str
            path to the install directory. Be careful, this directory will be deleted and create again if clean set to True.
        analysis_path: str
            path for saving report of analysis. This directory will be deleted and create again if clean set to True.
        processes: int
            number of processes while building.
        build_ex_params: str
            extra params for building, for example "--with-openssl" for building curl
        """

        # self.target_project_archive = target_project_archive
        self.futag_llvm_package = futag_llvm_package
        self.library_root = library_root

        try:
            processes = int(processes)
            if processes < 0:
                raise ValueError(INVALID_INPUT_PROCESSES)
        except ValueError:
            print(INVALID_INPUT_PROCESSES)
        self.processes = processes

        if pathlib.Path(futag_llvm_package).absolute().exists() and (pathlib.Path(futag_llvm_package) / "bin/clang").absolute().exists():
            self.futag_llvm_package = pathlib.Path(
                self.futag_llvm_package).absolute()
        else:
            raise ValueError(INVALID_FUTAG_PATH, futag_llvm_package)

        if pathlib.Path(library_root).absolute().exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            raise ValueError(INVALID_LIBPATH)

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

        self.flags = "-fsanitize=address -g -O0 "
        self.coverage_flags = "-fsanitize=address -g -O0 -fprofile-instr-generate -fcoverage-mapping "
        self.build_ex_params = build_ex_params

    def auto_build(self) -> int:
        """
        This function tries to automatically build your library.
        It finds in your library source code whether configure file or CMakeList.txt file exists.
        """

        print(AUTO_BUILD_MSG)
        if (self.library_root / "configure").exists():
            print(CONFIGURE_FOUND)
            self.build_configure()
            return 1

        # TODO: добавить возможность указать папку cmake!!!
        if (self.library_root / "CMakeLists.txt").exists():
            print(CMAKE_FOUND)
            self.build_cmake()
            return 1

        print(AUTO_BUILD_FAILED)
        return 0

    def build_cmake(self) -> int:
        """
        This function tries to build your library with cmake.
        """
        # Config with cmake
        my_env = os.environ.copy()
        my_env["CFLAGS"] = self.flags
        my_env["CPPFLAGS"] = self.flags
        my_env["LDFLAGS"] = self.flags
        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        config_cmd = [
            (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "cmake",
            f"-DCMAKE_INSTALL_PREFIX={self.install_path.as_posix()}",
            f"-DCMAKE_CXX_FLAGS='{self.flags}'",
            # f"-DCMAKE_CXX_COMPILER={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            # f"-DCMAKE_C_COMPILER={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"-DCMAKE_C_FLAGS='{self.flags}'",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.library_root.as_posix()}"
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            raise ValueError(LIB_CONFIGURE_FAILED)
        else:
            print(LIB_CONFIGURE_SUCCEEDED)
        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        # Doing make for analysis
        p = Popen([
            (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "-enable-checker",
            "futag.FutagFunctionAnalyzer",
            "-analyzer-config",
            "futag.FutagFunctionAnalyzer:report_dir=" + self.analysis_path.as_posix(),
            "make",
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)
        print(LIB_BUILD_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            raise ValueError(LIB_BUILD_FAILED)
        else:
            print(LIB_BUILD_SUCCEEDED)
        
        # Doing make clean
        p = Popen([
            "make",
            "clean",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            print(LIB_CLEAN_FAILED)
        else:
            print(LIB_CLEAN_SUCCEEDED)

        os.chdir(curr_dir)
        config_cmd = [
            # (self.futag_llvm_package / "bin/scan-build").as_posix(),
            "cmake",
            f"-DCMAKE_INSTALL_PREFIX={self.install_path.as_posix()}",
            f"-DCMAKE_CXX_FLAGS='{self.coverage_flags}'",
            f"-DCMAKE_CXX_COMPILER={(self.futag_llvm_package / 'bin/clang++').as_posix()}",
            f"-DCMAKE_C_COMPILER={(self.futag_llvm_package / 'bin/clang').as_posix()}",
            f"-DCMAKE_C_FLAGS='{self.coverage_flags}'",
            f"-B{(self.build_path).as_posix()}",
            f"-S{self.library_root.as_posix()}"
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            raise ValueError(LIB_CONFIGURE_FAILED)
        else:
            print(LIB_CONFIGURE_SUCCEEDED)
        
        os.chdir(self.build_path.as_posix())
        # Doing make for building
        my_env = os.environ.copy()
        my_env["CFLAGS"] = self.coverage_flags
        my_env["CPPFLAGS"] = self.coverage_flags
        my_env["LDFLAGS"] = self.coverage_flags

        p = Popen([
            "make",
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)

        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            print(LIB_BUILD_FAILED)
        else:
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
            print(LIB_INSTALL_SUCCEEDED)

        os.chdir(curr_dir)
        return 0

    def build_configure(self) -> int:
        """
        This function tries to build your library with configure.
        """
        curr_dir = os.getcwd()
        os.chdir(self.build_path.as_posix())

        my_env = os.environ.copy()
        # my_env["CFLAGS"] = self.flags
        # my_env["CPPFLAGS"] = self.flags
        # my_env["LDFLAGS"] = self.flags
        # my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        # my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        
        config_cmd = [
            # (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            (self.library_root / "configure").as_posix(),
            f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            raise ValueError(LIB_CONFIGURE_FAILED)
        else:
            print(LIB_CONFIGURE_SUCCEEDED)

        # Build the library
        p = Popen([
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-enable-checker",
            "futag.FutagFunctionAnalyzer",
            "-analyzer-config",
            "futag.FutagFunctionAnalyzer:report_dir=" + self.analysis_path.as_posix(),
            "make",
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)
        
        print(LIB_BUILD_COMMAND, " ".join(p.args))
        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            raise ValueError(LIB_BUILD_FAILED)
        else:
            print(LIB_BUILD_SUCCEEDED)

            
        os.chdir(curr_dir)
        delete_folder(self.build_path)
        (self.build_path).mkdir(parents=True, exist_ok=True)
        os.chdir(self.build_path.as_posix())
        # Doing make for building

        my_env = os.environ.copy()
        my_env["CFLAGS"] = self.coverage_flags
        my_env["CPPFLAGS"] = self.coverage_flags
        my_env["LDFLAGS"] = self.coverage_flags
        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()

        config_cmd = [
            (self.library_root / "configure").as_posix(),
            f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)

        output, errors = p.communicate()
        print(LIB_CONFIGURE_COMMAND, " ".join(p.args))
        if p.returncode:
            print(errors)
            raise ValueError(LIB_CONFIGURE_FAILED)
        else:
            print(LIB_CONFIGURE_SUCCEEDED)

        p = Popen([
            "make",
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)

        output, errors = p.communicate()
        if p.returncode:
            print(errors)
            print(LIB_BUILD_FAILED)
        else:
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
            raise ValueError(LIB_INSTALL_FAILED)
        else:
            print(LIB_INSTALL_SUCCEEDED)
            
        os.chdir(curr_dir)
        return 0

    def gen_build_script_configure(self, script_path: str = "") -> int:
        """
        This function export build script with configure for svace.
        """
        curr_dir = os.getcwd()
        if not script_path:
            script_path = curr_dir + "/svace-build.sh"
                
        build_script = open ( script_path, "w")
        build_script.write('#!/bin/bash')

        os.chdir(self.build_path.as_posix())
        build_script.write("cd " + self.build_path.as_posix() + "\n")
        my_env = os.environ.copy()
        my_env["CFLAGS"] = self.flags
        my_env["CPPFLAGS"] = self.flags
        my_env["CC"] = (self.futag_llvm_package / 'bin/clang').as_posix()
        my_env["CXX"] = (self.futag_llvm_package / 'bin/clang++').as_posix()
        
        build_script.write("export CFLAGS=\"" + self.flags + "\"\n")
        build_script.write("export CPPFLAGS=\"" + self.flags + "\"\n")
        build_script.write("export CC=" + (self.futag_llvm_package / 'bin/clang').as_posix() + "\n")
        build_script.write("export CXX=" + (self.futag_llvm_package / 'bin/clang++').as_posix() + "\n")

        config_cmd = [
            (self.library_root / "configure").as_posix(),
            f"--prefix=" + self.install_path.as_posix(),
        ]
        if self.build_ex_params:
            config_cmd += self.build_ex_params.split(" ")
        p = Popen(config_cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, env=my_env)
        
        build_script.write(" ".join(p.args))
        build_script.write("\n")

        # Build the library
        p = Popen([
            (self.futag_llvm_package / 'bin/scan-build').as_posix(),
            "-enable-checker",
            "futag.FutagFunctionAnalyzer",
            "-analyzer-config",
            "futag.FutagFunctionAnalyzer:report_dir=" + self.analysis_path.as_posix(),
            "make",
            "-f",
            (self.build_path / "Makefile").as_posix(),
            "-j" + str(self.processes)
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        
        build_script.write(" ".join(p.args))
        build_script.write("\n")

        # Doing make install
        p = Popen([
            "make",
            "-f",
            (self.build_path / "Makefile").as_posix(),
            "install",
        ], stdout=PIPE, stderr=PIPE, universal_newlines=True)

        build_script.write(" ".join(p.args))
        build_script.write("\n")
        build_script.close()
        os.chdir(curr_dir)
        return 0

    def analyze(self):
        """
        This function reads analysis result of Futag checker
        """
        decl_files = [
            x
            for x in self.analysis_path.glob("**/declaration-*.futag-function-analyzer")
            if x.is_file()
        ]

        # Find all context files in given location
        context_files = [
            x for x in self.analysis_path.glob("**/context-*.futag-function-analyzer") if x.is_file()
        ]

        # Find all type_info files in given location
        typeinfo_files = [
            x
            for x in self.analysis_path.glob("**/types-info-*.futag-function-analyzer")
            if x.is_file()
        ]

        # Find all includes info files in given location
        includesinfo_files = [
            x
            for x in self.analysis_path.glob("**/includes-info-*.futag-function-analyzer")
            if x.is_file()
        ]

        # global list of function
        function_list = {}
        enum_list = []
        typedef_list = []
        struct_list = []
        includes_dict = {}

        for jf in decl_files:
            functions = json.load(open(jf.as_posix()))
            if functions is None:
                print(" -- Warning: loading json from file %s failed!" %
                      (jf.as_posix()))
                continue
            # get global hash of all functions
            global_hash = [x for x in function_list]
            if not functions:
                continue
            # iterate function hash for adding to global hash list
            for hash in functions:
                if not hash in global_hash:
                    function_list[hash] = functions[hash]

        for jf in context_files:
            contexts = json.load(open(jf.as_posix()))
            if contexts is None:
                print(" -- Warning: loading json from file %s failed!" %
                      (jf.as_posix()))
                continue
            # get global hash of all functions
            global_hash = [x for x in function_list]

            # iterate function hash for adding to global hash list
            for hash in contexts:
                if hash in global_hash:
                    called_from_list = [
                        x["called_from"] + x["called_from_func_name"]
                        for x in function_list[hash]["call_contexts"]
                    ]
                    for call_xref in contexts[hash]["call_contexts"]:
                        if (
                            not call_xref["called_from"] +
                                call_xref["called_from_func_name"]
                            in called_from_list
                        ):
                            function_list[hash]["call_contexts"].append(
                                call_xref)
                else:
                    print(" -- %s not found in global hash list!" % (hash))

        for jf in typeinfo_files:
            types = json.load(open(jf.as_posix()))
            # get global hash of all functions
            for enum_it in types["enums"]:
                exist = False
                for enum_exist_it in enum_list:
                    if enum_it["enum_name"] == enum_exist_it["enum_name"]:
                        exist = True
                        break
                if not exist:
                    enum_list.append(enum_it)

            for struct_it in types["structs"]:
                exist = False
                for struct_exist_it in struct_list:
                    if struct_it["struct_name"] == struct_exist_it["struct_name"]:
                        if len(struct_it["struct_fields"]) > len(struct_exist_it["struct_fields"]):
                            struct_exist_it["struct_fields"] = struct_it["struct_fields"]
                        exist = True
                        break
                if not exist:
                    struct_list.append(struct_it)

            for typedef_it in types["typedefs"]:
                exist = False
                for typedef_exist_it in typedef_list:
                    if typedef_it["typename"] == typedef_exist_it["typename"]:
                        exist = True
                        break
                if not exist:
                    typedef_list.append(typedef_it)

        cwd = None
        for incf in includesinfo_files:
            includes = json.load(open(incf.as_posix()))
            includes_dict[includes['file']] = includes['includes']

            # # Just to make sure, that the cwd is the same for every file
            # if cwd is not None:
            #     assert(cwd == includes['cwd'])
            # else:
            #     cwd = includes['cwd']

        functions_w_contexts = []
        functions_w_contexts_set = set()
        for func in function_list:
            contexts = []
            for f in function_list:
                for call_func in function_list[f]["call_contexts"]:
                    if call_func["called_from_func_name"] == function_list[func]["func_name"]:
                        contexts.append(call_func)
            fs = {
                "func_name": function_list[func]["func_name"],
                "return_type": function_list[func]["return_type"],
                "return_type_pointer": function_list[func]["return_type_pointer"],
                "params": function_list[func]["params"],
                "fuzz_it": function_list[func]["fuzz_it"],
                "contexts": contexts,
                "location": function_list[func]["location"],
                "compiler_opts": function_list[func]["compiler_opts"],
                "LOC": function_list[func]["LOC"],

            }
            functions_w_contexts.append(fs)

        result = {
            "functions": functions_w_contexts,
            "enums": enum_list,
            "structs": struct_list,
            "typedefs": typedef_list,
            "includes": includes_dict,
            "cwd": cwd
        }
        json.dump(result, open(
            (self.analysis_path / "futag-analysis-result.json").as_posix(), "w"))

        print("Total functions: ", str(len(result["functions"])))
        print("Total enums: ", str(len(result["enums"])))
        print("Total structs: ", str(len(result["structs"])))
        print("Total typedefs: ", str(len(result["typedefs"])))
        print("Analysis result: ", (self.analysis_path /
              "futag-analysis-result.json").as_posix())
