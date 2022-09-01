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

from shutil import which
from hashlib import md5
from pathlib import Path
from subprocess import Popen, PIPE, call, run, TimeoutExpired
from multiprocessing import Pool
from futag.sysmsg import *


class Fuzzer:
    """Futag Fuzzer"""

    def __init__(self, futag_llvm_package: str, fuzz_driver_path: str = FUZZ_DRIVER_PATH, debug: bool = False, gdb: bool = False, svres: bool = False, fork: int = 1, totaltime: int = 300, timeout: int = 10, memlimit: int = 2048, coverage: bool = False, leak: bool = False, introspect: bool = False):
        """
        Parameters
        ----------
        futag_llvm_package: str
            path to the futag llvm package (with binaries, scripts, etc)
        fuzz_driver_path: str
            location of fuzz-drivers, default "futag-fuzz-drivers"
        debug: bool = False
            print debug infomation while fuzzing, default False
        gdb: bool = False
            debug crashes with GDB, default False
        svres: bool = False
            generate svres file for Svace (if you have Svace), default False
        fork: int = 1
            fork mode of libFuzzer (https://llvm.org/docs/LibFuzzer.html#fork-mode), default 1 - no fork mode
        totaltime: int = 300
            total time of fuzzing one fuzz-driver, default 300 seconds
        timeout: int = 10
            if an fuzz-drive takes longer than this timeout, the process is treated as a failure case, default 10 seconds
        memlimit: int = 2048
            option for rss_limit_mb of libFuzzer - Memory usage limit in Mb, default 2048 Mb, Use 0 to disable the limit.
        coverage: bool = False
            option for showing coverage of fuzzing, default False.
        leak: bool = False
            detecting memory leak, default False
        introspect: bool = False
            option for integrate with fuzz-introspector (to be add soon).

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
        if self.gdb and which("gdb") is None:
            raise ValueError(GDB_NOT_FOUND)

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

    def get_id_from_error(self, error_string):
        error_id = 0
        for c in error_string:
            error_id += ord(c)
        return str(error_id)

    def Printer(self, data):
        sys.stdout.write("\r\x1b[K" + data.__str__())
        sys.stdout.flush()

    def futag_escape(self, str):
        str = str.replace("&", "&amp;")
        str = str.replace("<", "&lt;")
        str = str.replace(">", "&gt;")
        str = str.replace('"', "&quot;")
        str = str.replace("\n", " ")
        return str

    def get_backtrace_hash(self, backtrace):
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
                    str(s["file"]) + str(s["location"]["line"]) +
                    str(s["location"]["col"])
                )
        return hash(str(backtrace["warnID"]) + input_str)

    def libFuzzerLog_parser(self, fuzz_driver: str, libFuzzer_log: str, gdb: bool = False):
        """
        Parameters
        ----------
        fuzz_driver: str
            path to the fuzz-driver
        libFuzzer_log: str
            path of libFuzzer log
        gdb: bool = False
            option for parsing with GDB
        """

        # Thank https://regex101.com/
        # match_error = "^==\d*==ERROR: (\w*): (.*)$"
        match_error = "^==\d*==ERROR: (\w*): (.*) on.*$"
        match_libFuzzer = "^==\d*== ERROR: (\w*): (.*)$"
        match_summary = "^SUMMARY: \w*: (.*)$"
        match_traceback = (
            "^ *#(\d*) \d.\w* in ([\w:_\[\]()&<> *,]*) ([\/\w\d\-._]*):(\d*:?\d*)$"
        )
        match_tracepass = "^ *#(\d*) \d.\w* in ([\w:_\[\]()&<> *,]*) ([\(\)+\/\w\d\-._]*)$"
        match_location = "(\d*):(\d*)"
        match_exc_trace = "^.*\/llvm-11.1.0\/.*$"
        match_exc_trace2 = "^.*libc-start.c.*$"
        match_exc_trace3 = "^.*compiler-rt/lib/.*$"
        match_exc_trace4 = "^.*LLVMFuzzerTestOneInput.*$"
        # match_artifacts = "^artifact_prefix.*Test unit written to (.*)$"
        match_artifacts = "^Running: (.*)$"
        match_oom = "out-of-memory"

        backtrace = {}
        parsing_error = False
        stack = []
        info = ""
        warnClass = ""
        msg = ""
        role_traces = []
        role = ""
        crash_file = ""
        crash_line = 0
        artifact_file = ""
        with open(libFuzzer_log, "r", errors="ignore") as f:
            lines = f.readlines()
        if self.gdb:
            print("-- [Futag] crash log:\n", "".join(lines))
        for l in lines:
            artifact = re.match(match_artifacts, l)
            if artifact:
                artifact_file = artifact.group(1)
            error = re.match(match_error, l)
            # if not error:
            #     error = re.match(match_libFuzzer, l)
            if error:
                parsing_error = True
                warnClass = error.group(1)
                msg = error.group(2)
                continue
            summary = re.match(match_summary, l)
            if summary:
                parsing_error = False
                if role_traces:
                    backtrace = {
                        "warnClass": warnClass,
                        "warnID": self.get_id_from_error(
                            warnClass + msg + crash_file + str(crash_line)
                        ),
                        "msg": msg,
                        "crash_line": crash_line,
                        "crash_file": crash_file,
                        "role_traces": role_traces,
                    }
                    crash_file = ""
                    crash_line = 0
                    role_traces = []
            if parsing_error:
                trace = re.match(match_traceback, l)
                if trace:
                    if re.match(match_exc_trace, l):
                        continue
                    if re.match(match_exc_trace2, l):
                        continue
                    if re.match(match_exc_trace3, l):
                        continue
                    # if re.match(match_exc_trace4, l):
                    #     continue
                    location = re.match(match_location, trace.group(4))
                    if location:
                        if not crash_line:
                            crash_line = location.group(1)
                        location = {"line": location.group(
                            1), "col": location.group(2)}
                    else:
                        location = {"line": trace.group(4), "col": "0"}
                        if not crash_line:
                            crash_line = trace.group(4)
                    if not crash_file:
                        crash_file = trace.group(3)
                    stack.insert(
                        0,
                        {
                            "function": trace.group(2),
                            "file": trace.group(3),
                            "location": location,
                            "info": "",
                        },
                    )
                    info = "Next: "
                else:
                    if re.match(match_tracepass, l):
                        continue
                    empty_line = re.match("^$", l)
                    if not empty_line:
                        role = l
                    else:
                        if stack:
                            role_traces.append({"role": role, "stack": stack})
                            stack = []
                            role = ""
        if not backtrace:
            return
        if gdb:
            """
            Execute gdb for 3 times:
            - First time for setting breakpoints and output all args, variables
            - Second time for getting type of args, variables
            - Third time for getting value
            """

            match_variable = "^([a-zA-Z_0-9]*) = .*$"
            match_empty = "^(.*) = 0x[0-9]$"
            match_full_ff = "^(.*) = 0x[0-9]$"
            match_error_gdb = "^([a-zA-Z_0-9]*) = .*(<error:).*$"
            match_pointer = "^([a-zA-Z_0-9]*) = 0x.*$"
            match_normal = "^(.*) = .*$"
            if backtrace["role_traces"]:
                count_role_traces = 0

                # !setting breakpoints and output all args, variables

                with open(".gdbinit", "w") as gdbinit:
                    gdbinit.write("file " + fuzz_driver + "\n")
                    gdbinit.write("set args " + artifact_file + "\n")
                    gdbinit.write("set pagination off" + "\n")
                    gdbinit.write("set logging off" + "\n")

                    for trace in backtrace["role_traces"]:
                        count_role_traces += 1
                        count_stack = 0
                        for stack in trace["stack"]:
                            count_stack += 1
                            gdbinit.write(
                                "set logging file trace_"
                                + str(count_role_traces)
                                + "_"
                                + str(count_stack)
                                + "\n"
                            )
                            gdbinit.write("set logging overwrite on \n")
                            gdbinit.write(
                                "b "
                                + stack["file"]
                                + ":"
                                + stack["location"]["line"]
                                + "\n"
                            )
                            if count_stack == 1:
                                gdbinit.write("r" + "\n")
                            else:
                                gdbinit.write("c" + "\n")
                            gdbinit.write("set logging on" + "\n")
                            gdbinit.write("info args" + "\n")
                            gdbinit.write("info local" + "\n")
                            gdbinit.write("set logging off" + "\n")
                    gdbinit.write("quit\n")

                # https://undo.io/resources/gdb-watchpoint/here-quick-way-pretty-print-structures-gdb/
                try:
                    run([
                        "gdb",
                        "-q",
                        "-iex",
                        "set auto-load safe-path .",
                    ],
                        # stdout=PIPE,
                        # stderr=PIPE,
                        check=True,
                        universal_newlines=True,
                        timeout=10,
                    )
                except Exception:
                    print("-- [Futag] Debug with GDB: set breakpoints failed!")
                # !getting type of args, variables
                count_role_traces = 0
                with open(".gdbinit", "w") as gdbinit:
                    gdbinit.write("file " + fuzz_driver + "\n")
                    gdbinit.write("set args " + artifact_file + "\n")
                    gdbinit.write("set pagination off" + "\n")
                    gdbinit.write("set logging off" + "\n")

                    for trace in backtrace["role_traces"]:
                        count_role_traces += 1
                        count_stack = 0
                        for stack in trace["stack"]:
                            count_stack += 1
                            gdbinit.write(
                                "set logging file types_"
                                + str(count_role_traces)
                                + "_"
                                + str(count_stack)
                                + "\n"
                            )
                            gdbinit.write("set logging overwrite on \n")
                            gdbinit.write(
                                "b "
                                + stack["file"]
                                + ":"
                                + stack["location"]["line"]
                                + "\n"
                            )
                            if count_stack == 1:
                                gdbinit.write("r" + "\n")
                            else:
                                gdbinit.write("c" + "\n")
                            gdbinit.write("set logging on" + "\n")
                            # read trace file for variables
                            if Path("trace_" + str(count_role_traces) + "_" + str(count_stack)).exists():
                                with open(
                                    "trace_" + str(count_role_traces) +
                                    "_" + str(count_stack),
                                    "r",
                                ) as info_file:
                                    lines = info_file.readlines()

                            for line in lines:
                                # match variable
                                variable = re.match(match_variable, line)
                                var_name = ""
                                is_pointer = False
                                if variable:
                                    var_name = variable.group(1)
                                    gdbinit.write('echo ' + var_name + ': \n')
                                    gdbinit.write("ptype " + var_name + "\n")
                                    gdbinit.write("echo \n")
                            gdbinit.write("set logging off" + "\n")
                    gdbinit.write("quit\n")

                try:
                    run([
                            "gdb",
                            "-q",
                            "-iex",
                            "set auto-load safe-path .",
                        ],
                        # stdout=PIPE,
                        # stderr=PIPE,
                        check=True,
                        universal_newlines=True,
                        timeout=10,
                    )
                except Exception:
                    print(
                        "-- [Futag] Debug with GDB: get types of variables failed!")
                
                count_role_traces = 0
                with open(".gdbinit", "w") as gdbinit:
                    gdbinit.write("file " + fuzz_driver + "\n")
                    gdbinit.write("set args " + artifact_file + "\n")
                    gdbinit.write("set pagination off" + "\n")
                    gdbinit.write("set logging off" + "\n")

                    for trace in backtrace["role_traces"]:
                        count_role_traces += 1
                        count_stack = 0
                        for stack in trace["stack"]:
                            count_stack += 1
                            gdbinit.write(
                                "set logging file values_"
                                + str(count_role_traces)
                                + "_"
                                + str(count_stack)
                                + "\n"
                            )
                            gdbinit.write("set logging overwrite on \n")
                            gdbinit.write(
                                "b "
                                + stack["file"]
                                + ":"
                                + stack["location"]["line"]
                                + "\n"
                            )
                            if count_stack == 1:
                                gdbinit.write("r" + "\n")
                            else:
                                gdbinit.write("c" + "\n")
                            gdbinit.write("set logging on" + "\n")
                            # read trace file for variables
                            lines = []
                            types = []
                            if Path("trace_" + str(count_role_traces) + "_" + str(count_stack)).exists():
                                with open(
                                    "trace_" + str(count_role_traces) +
                                    "_" + str(count_stack),
                                    "r",
                                ) as info_file:
                                    lines = info_file.readlines()

                            if Path("types_" + str(count_role_traces) + "_" + str(count_stack)).exists():
                                with open(
                                    "types_" + str(count_role_traces) +
                                    "_" + str(count_stack),
                                    "r",
                                ) as types_file:
                                    types = types_file.readlines()

                            for line in lines:
                                # match variable
                                variable = re.match(match_variable, line)
                                var_name = ""
                                is_pointer = False
                                if variable:
                                    var_name = variable.group(1)
                                    pointer = re.match(match_pointer, line)
                                    if pointer:
                                        is_pointer = True
                                    if re.match(match_empty, line):
                                        is_pointer = False
                                    if re.match(match_error_gdb, line):
                                        is_pointer = False
                                    gdbinit.write(
                                        'output "value of ' + var_name + ':" \n')
                                    if is_pointer:
                                        check_void = False
                                        for t in types:

                                            split_types = t.split(':')
                                            if len(split_types) < 2:
                                                continue
                                            var_name_in_types = split_types[0]
                                            var_type_in_types = split_types[1].split(" = ")[
                                                1].strip()
                                            if var_name_in_types == var_name and var_type_in_types == "void *":
                                                check_void = True
                                        if not check_void:
                                            gdbinit.write(
                                                "output *" + var_name + " \n")
                                            gdbinit.write('output "; "' + "\n")
                                    else:
                                        gdbinit.write(
                                            "output " + var_name + " \n")
                                        gdbinit.write('output "; "' + "\n")
                            gdbinit.write("set logging off" + "\n")
                    gdbinit.write("quit\n")
                # p = Popen(
                try:
                    run(
                        [
                            "gdb",
                            "-q",
                            "-iex",
                            "set auto-load safe-path .",
                        ],
                        # stdout=PIPE,
                        # stderr=PIPE,
                        check=True,
                        universal_newlines=True,
                        timeout=10,
                    )
                    # output, errors = p.communicate()
                except:
                    print("-- [Futag] Debug with GDB: get values failed!")
                count_role_traces = 0
                for trace in backtrace["role_traces"]:
                    count_role_traces += 1
                    count_stack = 0
                    for stack in trace["stack"]:
                        count_stack += 1
                        info = ""
                        if Path("values_" + str(count_role_traces) + "_" + str(count_stack)).exists():
                            with open(
                                "values_" + str(count_role_traces) +
                                "_" + str(count_stack), "r"
                            ) as info_file:
                                lines = info_file.read()

                            for line in lines:
                                info += self.futag_escape(line)
                        stack["info"] = info
        hash_backtrace = self.get_backtrace_hash(backtrace)
        if not hash_backtrace in self.backtrace_hashes:
            self.backtrace_hashes.add(hash_backtrace)
            curren_explanation = ""
            with open("warning_info.svres", "a") as warning_info:
                warning_info.write(
                    '<WarnInfo id="'
                    + backtrace["warnID"]
                    + '" warnClass="'
                    + backtrace["warnClass"]
                    + '" line="'
                    + str(backtrace["crash_line"])
                    + '" file="'
                    + backtrace["crash_file"]
                    + '" msg="'
                    + backtrace["msg"]
                    + '" status="Default" details="" comment="" function="" mtid="" tool="" lang="" flags="0" tags=""/>'
                )

                for r in backtrace["role_traces"]:
                    loc_info = ""
                    for s in r["stack"]:
                        loc_info += (
                            '<LocInfo file="'
                            + s["file"]
                            + '" line="'
                            + s["location"]["line"]
                            + '" spec="false" info="'
                            + s["info"]
                            + '" col="'
                            + s["location"]["col"]
                            + '"/>'
                        )
                    curren_explanation += (
                        '<RoleTraceInfo role="'
                        + r["role"]
                        + '"><locations>'
                        + loc_info
                        + "</locations></RoleTraceInfo>"
                    )
            with open("warning_info_ex.svres", "a") as warning_info_ex:
                warning_info_ex.write(
                    '<WarnInfoEx id="'
                    + backtrace["warnID"]
                    + '" zRate="0.0"><traces>'
                    + curren_explanation
                    + '</traces><userAttributes class="tree-map"><entry><string>.comment</string><string></string></entry><entry><string>.status</string><string>Default</string></entry></userAttributes></WarnInfoEx>'
                )
            os.system("rm -f values_*")
            os.system("rm -f types_*")
            os.system("rm -f trace_*")

    def fuzz(self):
        symbolizer = self.futag_llvm_package / "bin/llvm-symbolizer"
        generated_functions = [
            x for x in self.fuzz_driver_path.iterdir() if x.is_dir()]
        # for dir in generated_functions:
        for func_dir in generated_functions:
            self.backtraces = []
            fuzz_driver_dirs = [x for x in func_dir.iterdir() if x.is_dir()]
            for dir in fuzz_driver_dirs:
                for x in [t for t in dir.glob("*.out") if t.is_file()]:
                    print("\n-- [Futag] FUZZING driver: " + x.stem + "... \n")
                    my_env = os.environ.copy()
                    if self.leak:
                        my_env["ASAN_OPTIONS"] = "allocator_may_return_null=1"
                    else:
                        my_env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1"
                    my_env["ASAN_SYMBOLIZER_PATH"] = symbolizer.as_posix()
                    if self.coverage:
                        my_env["LLVM_PROFILE_FILE"] = x.as_posix() + ".profraw"
                    if self.fork > 1:
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
                    else:
                        execute_command = [
                            x.as_posix(),
                            "-timeout=" + str(self.timeout),
                            "-rss_limit_mb=" + str(self.memlimit),
                            "-max_total_time=" + str(self.totaltime),
                            "-artifact_prefix=" + dir.as_posix() + "/",
                        ]
                    if self.debug:
                        print("-- [Futag] FUZZING command:" +
                              " ".join(execute_command))

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
                    crashes_files = [x for x in dir.glob(
                        "**/crash-*") if x.is_file()]
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
                        if self.gdb:
                            print(
                                "-- [Futag]: Parsing crashes with GDB: ", x.as_posix())
                            self.libFuzzerLog_parser(
                                x.as_posix(), crashlog_filename, True)
                        else:
                            print(
                                "-- [Futag]: Parsing crash without GDB: ", x.as_posix())
                            self.libFuzzerLog_parser(
                                x.as_posix(), crashlog_filename, False)

                    # if self.coverage:
                    #     llvm_profdata = self.futag_llvm_package / "bin/llvm-profdata"
                    #     llvm_profdata_command = [
                    #         llvm_profdata.as_posix(),
                    #         "merge",
                    #         "-sparse",
                    #         x.as_posix() + ".profraw",
                    #         "-o",
                    #         x.as_posix() + ".profdata",
                    #     ]
                    #     if self.debug:
                    #         print(" ".join(llvm_profdata_command))
                    #     p = call(
                    #         llvm_profdata_command,
                    #         stdout=PIPE,
                    #         stderr=PIPE,
                    #         universal_newlines=True,
                    #         env=my_env,
                    #     )

                    #     llvm_cov = self.futag_llvm_package / "bin/llvm-cov"
                    #     llvm_cov_report = [
                    #         llvm_cov.as_posix(),
                    #         "report",
                    #         x.as_posix(),
                    #         "-instr-profile=" + x.as_posix() + ".profdata",
                    #     ]
                    #     if self.debug:
                    #         print(" ".join(llvm_cov_report))
                    #     p = run(llvm_cov_report)

                    #     llvm_cov_show = [
                    #         llvm_cov.as_posix(),
                    #         "show",
                    #         x.as_posix(),
                    #         "-instr-profile=" + x.as_posix() + ".profdata",
                    #     ]

                    #     cov_filename = x.as_posix() + ".cov"
                    #     cov_file = open(cov_filename, "w")
                    #     p = Popen(
                    #         llvm_cov_show,
                    #         stdout=cov_file,
                    #         stderr=PIPE,
                    #         universal_newlines=True,
                    #         env=my_env,
                    #     )
                    #     output, errors = p.communicate()
                    #     cov_file.close()
        if self.coverage:
            profdata_files = [x.as_posix() for x in self.fuzz_driver_path.glob("**/*.profraw") if x.is_file()]
            object_list = [x.as_posix()[:-8] for x in self.fuzz_driver_path.glob("**/*.profraw") if x.is_file()]
            object_files =[]
            for o in object_list:
                object_files += ["-object", o]

            llvm_profdata = self.futag_llvm_package / "bin/llvm-profdata"
            llvm_profdata_command = [
                    llvm_profdata.as_posix(),
                    "merge",
                    "-sparse"
                ] + profdata_files + [
                    "-o",
                    (self.fuzz_driver_path / "futag-fuzz-result.profdata").as_posix(),
                ]
            if self.debug:
                print(" ".join(llvm_profdata_command))
            p = call(
                llvm_profdata_command,
                stdout=PIPE,
                stderr=PIPE,
            )

            llvm_cov = self.futag_llvm_package / "bin/llvm-cov"
            llvm_cov_report = [
                llvm_cov.as_posix(),
                "report",
            ]+ object_files + [
                "-instr-profile=" + (self.fuzz_driver_path / "futag-fuzz-result.profdata").as_posix()
            ]
            if self.debug:
                print(" ".join(llvm_cov_report))
            cov_report_filename = (self.fuzz_driver_path / "futag-coverage-report.txt").as_posix()
            cov_report_file = open(cov_report_filename, "w")
            p = Popen(
                llvm_cov_report,
                stdout=cov_report_file,
                stderr=PIPE,
            )

            
            llvm_cov_show = [
                llvm_cov.as_posix(),
                "show",
                "-format=html",
                "-instr-profile=" + (self.fuzz_driver_path / "futag-fuzz-result.profdata").as_posix(),
            ] + object_files

            cov_filename = (self.fuzz_driver_path / "futag-coverage-result.html").as_posix()
            cov_file = open(cov_filename, "w")
            p = Popen(
                llvm_cov_show,
                stdout=cov_file,
                stderr=PIPE,
            )
            if self.debug:
                print(" ".join(llvm_cov_show))

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
            lines = lines.replace(
                "WARNINGINFO_EXPLAINATION", warning_info_ex_text)
            warning_info_path.unlink()
            warning_info_ex_path.unlink()
            with open((self.fuzz_driver_path / "futag.svres").as_posix(), "w") as svres:
                svres.write(lines)
            print("-- [Futag] Please import file ", (self.fuzz_driver_path /
                  "futag.svres").as_posix(), " to Svace project to view result!")
        print("============ FINISH ============")
