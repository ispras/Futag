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
**      This module is for fuzzing              **
**************************************************
"""

import os
import sys
import re

from hashlib import md5
from pathlib import Path
from subprocess import Popen, PIPE, call, run
from multiprocessing import Pool
from futag.sysmsg import *


class Fuzzer:
    """Futag Fuzzer"""

    def __init__(self, futag_llvm_package: str, fuzz_driver_path: str = FUZZ_DRIVER_PATH, leak: bool = False, debug: bool = False, svres: bool = False, gdb: bool = False, fork: int = 1, timeout: int = 10, totaltime: int = 300, memlimit: int = 2048, coverage: bool = False, introspect: bool = False):
        """
        Parameters
        ----------
        futag_llvm_package: str
            path to the futag llvm package (with binaries, scripts, etc)
        fuzz_driver_path : str
            location of fuzz-drivers, default to "futag-fuzz-drivers"
        """

        self.futag_llvm_package = futag_llvm_package
        self.fuzz_driver_path = fuzz_driver_path

        if Path(self.futag_llvm_package).exists():
            self.futag_llvm_package = Path(self.futag_llvm_package).absolute()
        else:
            raise ValueError(INVALID_FUTAG_PATH)

        if Path(self.fuzz_driver_path).exists():
            self.fuzz_driver_path = Path(self.fuzz_driver_path).absolute()
        else:
            raise ValueError(INVALID_FUZZ_DRIVER_PATH)
        
        self.svres = svres
        self.leak = leak
        self.debug = debug
        self.gdb = gdb
        self.fork = fork
        self.timeout = timeout
        self.totaltime = totaltime
        self.memlimit = memlimit
        self.coverage = coverage
        self.introspect = introspect
        self.backtraces = []  # backtraces list
        # Set for backtrace's hashes. If current backtrace's hash is not in set then add this backtrace to backtraces list, otherwise this backtrace will be passed
        self.backtrace_hashes = (
            set()
        )  

    def Printer(data):
        sys.stdout.write("\r\x1b[K" + data.__str__())
        sys.stdout.flush()

    def futag_escape(str):
        str = str.replace("&", "&amp;")
        str = str.replace("<", "&lt;")
        str = str.replace(">", "&gt;")
        str = str.replace('"', "&quot;")
        str = str.replace("\n", " ")
        return str


    def get_backtrace_hash(backtrace):
        '''
        # Format of backtrace:
        # backtrace= {
        #     "warnClass" : warnClass,
        #     "warnID": md5(warnClass+msg),
        #     "msg" : msg,
        #     "crash_line" : crash_line,
        #     "crash_file" : crash_file,
        #     "role_traces" : [{
        #         "role": role,
        #         "stack": {
        #             "function": trace.group(2),
        #             "file": trace.group(3),
        #             "location" : {
        #                 "line": location.group(1),
        #                 "col" : location.group(2)
        #             },
        #             "info" : ""
        #         }
        #     }]
        # }
        #
        # HASH = warnID + role_traces["stack"]["file"] + role_traces["stack"]["location"]["line"] + role_traces["stack"]["file"]["col"]
        '''
        input_str = ""
        for r in backtrace["role_traces"]:
            for s in r["stack"]:
                input_str += (
                    str(s["file"]) + str(s["location"]["line"]) + str(s["location"]["col"])
                )
        return hash(str(backtrace["warnID"]) + input_str)

    def fuzz(self):
        symbolizer = self.futag_llvm_package / "bin/llvm-symbolizer"
        print(self.fuzz_driver_path.as_posix())
        generated_functions = [x for x in self.fuzz_driver_path.iterdir() if x.is_dir()]
        for dir in generated_functions:
            for x in [t for t in dir.glob("*.out") if t.is_file()]:
                print("Fuzzing " + x.stem + "... \n")
                my_env = os.environ.copy()
                if self.leak:
                    my_env["ASAN_OPTIONS"] = "allocator_may_return_null=1"
                else:
                    my_env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1"
                my_env["ASAN_SYMBOLIZER_PATH"] = symbolizer.as_posix()
                if self.coverage:
                    my_env["LLVM_PROFILE_FILE"] = x.as_posix() + ".profraw"
                if self.fork > 0:
                    # 1. Execute binary with -fork=4  -ignore_crashes=1 -max_total_time=10
                    # 2. Find all crash-* leak-* ... in artifact folder
                    # 3. Execute binary with these artifacts and save to log
                    # 4. With received log, parse to get traceback
                    # 5. Debug with GDB
                    execute_command = [
                        x.as_posix(),
                        "-fork=" + str(self.fork),
                        "-ignore_crashes=1",
                        "-timeout=" + str(self.timeout),
                        "-rss_limit_mb=" + str(self.memlimit),
                        "-max_total_time=" + str(self.totaltime),
                        "-artifact_prefix=" + dir.as_posix() + "/",
                    ]
                    if self.debug:
                        print("\n-- [futag] FUZZING:" + " ".join(execute_command))

                    # print(" ".join(execute_command))
                    p = call(
                        execute_command,
                        stdout=PIPE,
                        stderr=PIPE,
                        universal_newlines=True,
                        env=my_env,
                    )

                    # 2. Find all crash-* leak-* ... in artifact folder
                    # print(dir.as_posix())
                    crashes_files = [x for x in dir.glob("**/crash-*") if x.is_file()]
                    for cr in crashes_files:
                        getlog_command = [x.as_posix(), cr.as_posix()]
                        crashlog_filename = dir.as_posix() + "/" + cr.stem + ".log"
                        crashlog_file = open(crashlog_filename, "w")
                        p = Popen(
                            getlog_command,
                            stdout=PIPE,
                            stderr=crashlog_file,
                            universal_newlines=True,
                            env=my_env,
                        )
                        output, errors = p.communicate()
                        crashlog_file.close()
                else:
                    execute_command = [
                        x.as_posix(),
                        "-timeout=" + str(self.timeout),
                        "-rss_limit_mb=" + str(self.memlimit),
                        "-max_total_time=" + str(self.totaltime),
                        "-artifact_prefix=" + dir.as_posix() + "/",
                    ]
                    if self.debug:
                        print("\n-- [futag] FUZZING:" + " ".join(execute_command))

                    errorlog_filename = dir.as_posix() + "/" + x.stem + ".log"
                    errorlog_file = open(errorlog_filename, "w")
                    p = Popen(
                        execute_command,
                        stdout=PIPE,
                        stderr=errorlog_file,
                        universal_newlines=True,
                        env=my_env,
                    )
                    output, errors = p.communicate()
                    errorlog_file.close()

                if self.coverage:
                    llvm_profdata = self.futag_llvm_package / "bin/llvm-profdata"
                    llvm_profdata_command = [
                        llvm_profdata.as_posix(),
                        "merge",
                        "-sparse",
                        x.as_posix() + ".profraw",
                        "-o",
                        x.as_posix() + ".profdata",
                    ]
                    if self.debug:
                        print(" ".join(llvm_profdata_command))
                    p = call(
                        llvm_profdata_command,
                        stdout=PIPE,
                        stderr=PIPE,
                        universal_newlines=True,
                        env=my_env,
                    )

                    llvm_cov = self.futag_llvm_package / "bin/llvm-cov"
                    llvm_cov_report = [
                        llvm_cov.as_posix(),
                        "report",
                        x.as_posix(),
                        "-instr-profile=" + x.as_posix() + ".profdata",
                    ]
                    if self.debug:
                        print(" ".join(llvm_cov_report))
                    p = run(llvm_cov_report)

                    llvm_cov_show = [
                        llvm_cov.as_posix(),
                        "show",
                        x.as_posix(),
                        "-instr-profile=" + x.as_posix() + ".profdata",
                    ]

                    cov_filename = x.as_posix() + ".cov"
                    cov_file = open(cov_filename, "w")
                    p = Popen(
                        llvm_cov_show,
                        stdout=cov_file,
                        stderr=PIPE,
                        universal_newlines=True,
                        env=my_env,
                    )
                    output, errors = p.communicate()
                    cov_file.close()

        template_file = self.futag_llvm_package / "svres-tmpl/svres.tmpl"
        warning_info_text = ""
        warning_info_path = Path.cwd().absolute() / "warning_info.svres"
        warning_info_ex_text = ""
        warning_info_ex_path = Path.cwd().absolute() / "warning_info_ex.svres"

        if warning_info_path.exists() and warning_info_ex_path.exists():
            with open("warning_info.svres", "r") as warning_info:
                warning_info_text = warning_info.read()
            with open("warning_info_ex.svres", "r") as warning_info_ex:
                warning_info_ex_text = warning_info_ex.read()
            with template_file.open() as tmpl:
                lines = tmpl.read()
            lines = lines.replace("WARNING_INFO", warning_info_text)
            lines = lines.replace("WARNINGINFO_EXPLAINATION", warning_info_ex_text)
            warning_info_path.unlink()
            warning_info_ex_path.unlink()
            with open("futag.svres", "w") as svres:
                svres.write(lines)
            print("-- [futag] Please import file futag.svres to Svace project to view result!")
        print("============ FINISH ============")
