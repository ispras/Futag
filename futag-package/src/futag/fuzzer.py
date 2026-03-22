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
# **      This module is for fuzzing              **
# **************************************************

import os
import sys
import re
import tempfile

from shutil import which
from pathlib import Path
from subprocess import Popen, PIPE, call, run
import logging

from futag.sysmsg import *
from futag import setup_console_logging

logger = logging.getLogger(__name__)

# Regex patterns for crash log parsing
RE_ERROR = r"^==\d*==ERROR: (\w*): (.*) on.*$"
RE_LIBFUZZER_ERROR = r"^==\d*== ERROR: (\w*): (.*)$"
RE_SUMMARY = r"^SUMMARY: \w*: (.*)$"
RE_TRACEBACK = r"^ *#(\d*) \d.\w* in ([\w:_\[\]()&<> *,]*) ([\/\w\d\-._]*):(\d*:?\d*)$"
RE_TRACEPASS = r"^ *#(\d*) \d.\w* in ([\w:_\[\]()&<> *,]*) ([\(\)+\/\w\d\-._]*)$"
RE_LOCATION = r"(\d*):(\d*)"
RE_EXC_TRACE_LLVM = r"^.*\/llvm-11.1.0\/.*$"
RE_EXC_TRACE_LIBC = r"^.*libc-start.c.*$"
RE_EXC_TRACE_RT = r"^.*compiler-rt/lib/.*$"
RE_ARTIFACTS = r"^Running: (.*)$"

# GDB variable matching patterns
RE_GDB_VARIABLE = r"^([a-zA-Z_0-9]*) = .*$"
RE_GDB_EMPTY = r"^(.*) = 0x[0-9]$"
RE_GDB_ERROR = r"^([a-zA-Z_0-9]*) = .*(<error:).*$"
RE_GDB_POINTER = r"^([a-zA-Z_0-9]*) = 0x.*$"

# Default fuzzing parameters
DEFAULT_TOTAL_TIME = 300
DEFAULT_TIMEOUT = 10
DEFAULT_MEMLIMIT = 2048
DEFAULT_FORK = 1
GDB_TIMEOUT = 10


class BaseFuzzer:
    """Base class containing all shared fuzzing logic."""

    def __init__(self, fuzz_driver_path: str = FUZZ_DRIVER_PATH, debug: bool = False, gdb: bool = False, svres: bool = False, fork: int = 1, totaltime: int = 300, timeout: int = 10, memlimit: int = 2048, coverage: bool = False, leak: bool = False, introspect: bool = False, source_path: str = "", toolchain=None, log_to_console: bool = True) -> None:
        """Initialize the BaseFuzzer with fuzzing configuration.

        Args:
            fuzz_driver_path: Location of fuzz-drivers, default "futag-fuzz-drivers".
            debug: Print debug information while fuzzing, default False.
            gdb: Debug crashes with GDB, default False.
            svres: Generate svres file for Svace, default False.
            fork: Fork mode of libFuzzer, default 1 (no fork mode).
            totaltime: Total time of fuzzing one fuzz-driver in seconds, default 300.
            timeout: If a fuzz-driver takes longer than this timeout, the process is treated as a failure case, default 10.
            memlimit: Memory usage limit in Mb (rss_limit_mb), 0 to disable, default 2048.
            coverage: Show coverage of fuzzing, default False.
            leak: Detect memory leaks, default False.
            introspect: Integrate with fuzz-introspector, default False.
            source_path: Path to source code for coverage reports, default "".
            toolchain: ToolchainConfig instance. If None, uses generation-only mode.
            log_to_console: Show log messages in the console, default True.
        """
        setup_console_logging(log_to_console)
        self.fuzz_driver_path = fuzz_driver_path
        self.source_path = source_path

        from futag.toolchain import ToolchainConfig
        if toolchain is not None:
            self.toolchain = toolchain
        else:
            self.toolchain = ToolchainConfig.for_generation_only()

        if Path(self.fuzz_driver_path).exists():
            self.fuzz_driver_path = Path(self.fuzz_driver_path).absolute()
        else:
            sys.exit(INVALID_FUZZ_DRIVER_PATH)

        self.svres = svres
        self.leak = leak
        self.debug = debug
        self.gdb = gdb
        if self.gdb and which("gdb") is None:
            sys.exit(GDB_NOT_FOUND)

        self.fork = fork
        self.timeout = timeout
        self.totaltime = totaltime
        self.memlimit = memlimit
        self.coverage = coverage
        self.introspect = introspect
        self.backtraces = []  # backtraces list
        # Set for backtrace's hashes. If current backtrace's hash is not in set
        # then add this backtrace to backtraces list, otherwise this backtrace
        # will be passed
        self.backtrace_hashes = set()

    def _error_id(self, error_string: str) -> str:
        """Compute a simple numeric ID from an error string by summing character ordinals.

        Args:
            error_string: The error description string to convert.

        Returns:
            A string representation of the computed numeric ID.
        """
        error_id = 0
        for c in error_string:
            error_id += ord(c)
        return str(error_id)

    def _printer(self, data: str) -> None:
        """Print data to stdout with carriage return and line clear escape sequence.

        Args:
            data: The data to print.
        """
        sys.stdout.write("\r\x1b[K" + data.__str__())
        sys.stdout.flush()

    def _xml_escape(self, s: str) -> str:
        """Escape special XML characters and newlines in a string.

        Args:
            s: The string to escape.

        Returns:
            The XML-escaped string.
        """
        s = s.replace("&", "&amp;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        s = s.replace('"', "&quot;")
        s = s.replace("\n", " ")
        return s

    def _get_backtrace_hash(self, backtrace: dict) -> int:
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

    def _parse_crash_log(self, crashlog_path: str) -> tuple:
        """Parse a libFuzzer crash log file and extract stack trace information.

        Args:
            crashlog_path: Path to the crash log file to parse.

        Returns:
            A tuple of (backtrace, artifact_file) where backtrace is a dict
            containing structured crash information or an empty dict if no
            crash was found, and artifact_file is the path to the crash artifact.
        """
        with open(crashlog_path, "r", errors="ignore") as f:
            lines = f.readlines()
        if self.gdb:
            logger.debug("crash log:\n%s", "".join(lines))

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

        for l in lines:
            artifact = re.match(RE_ARTIFACTS, l)
            if artifact:
                artifact_file = artifact.group(1)
            error = re.match(RE_ERROR, l)
            if error:
                parsing_error = True
                warnClass = error.group(1)
                msg = error.group(2)
                continue
            summary = re.match(RE_SUMMARY, l)
            if summary:
                parsing_error = False
                if role_traces:
                    backtrace = {
                        "warnClass": warnClass,
                        "warnID": self._error_id(
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
                trace = re.match(RE_TRACEBACK, l)
                if trace:
                    if re.match(RE_EXC_TRACE_LLVM, l):
                        continue
                    if re.match(RE_EXC_TRACE_LIBC, l):
                        continue
                    if re.match(RE_EXC_TRACE_RT, l):
                        continue
                    location = re.match(RE_LOCATION, trace.group(4))
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
                    if re.match(RE_TRACEPASS, l):
                        continue
                    empty_line = re.match("^$", l)
                    if not empty_line:
                        role = l
                    else:
                        if stack:
                            role_traces.append({"role": role, "stack": stack})
                            stack = []
                            role = ""

        return backtrace, artifact_file

    def _run_gdb_debug(self, fuzz_driver: str, artifact_file: str, backtrace: dict, tmpdir: str) -> dict:
        """Run GDB to collect detailed crash information including types and values.

        Creates a .gdbinit in tmpdir and runs GDB in three passes:
        Pass 1: Set breakpoints, output all args/variables.
        Pass 2: Get types of args/variables.
        Pass 3: Get values.

        Args:
            fuzz_driver: Path to the fuzz-driver executable.
            artifact_file: Path to the crash artifact file.
            backtrace: The backtrace dict from _parse_crash_log to augment.
            tmpdir: Temporary directory for GDB init and log files.

        Returns:
            The updated backtrace dict with variable info populated.
        """
        gdbinit_path = os.path.join(tmpdir, ".gdbinit")

        if not backtrace["role_traces"]:
            return backtrace

        count_role_traces = 0

        # --- Pass 1: setting breakpoints and output all args, variables ---
        with open(gdbinit_path, "w") as gdbinit:
            gdbinit.write("file " + fuzz_driver + "\n")
            gdbinit.write("set args " + artifact_file + "\n")
            gdbinit.write("set pagination off" + "\n")
            gdbinit.write("set logging off" + "\n")

            for trace in backtrace["role_traces"]:
                count_role_traces += 1
                count_stack = 0
                for stack_entry in trace["stack"]:
                    count_stack += 1
                    gdbinit.write(
                        "set logging file "
                        + os.path.join(tmpdir, "trace_"
                        + str(count_role_traces)
                        + "_"
                        + str(count_stack))
                        + "\n"
                    )
                    gdbinit.write("set logging overwrite on \n")
                    gdbinit.write(
                        "b "
                        + stack_entry["file"]
                        + ":"
                        + stack_entry["location"]["line"]
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

        try:
            run([
                "gdb",
                "-q",
                "-iex",
                "set auto-load safe-path " + tmpdir,
            ],
                check=True,
                universal_newlines=True,
                timeout=GDB_TIMEOUT,
                cwd=tmpdir,
            )
        except Exception as e:
            logger.error("Debug with GDB: set breakpoints failed! %s", e)

        # --- Pass 2: getting type of args, variables ---
        count_role_traces = 0
        with open(gdbinit_path, "w") as gdbinit:
            gdbinit.write("file " + fuzz_driver + "\n")
            gdbinit.write("set args " + artifact_file + "\n")
            gdbinit.write("set pagination off" + "\n")
            gdbinit.write("set logging off" + "\n")

            for trace in backtrace["role_traces"]:
                count_role_traces += 1
                count_stack = 0
                for stack_entry in trace["stack"]:
                    count_stack += 1
                    gdbinit.write(
                        "set logging file "
                        + os.path.join(tmpdir, "types_"
                        + str(count_role_traces)
                        + "_"
                        + str(count_stack))
                        + "\n"
                    )
                    gdbinit.write("set logging overwrite on \n")
                    gdbinit.write(
                        "b "
                        + stack_entry["file"]
                        + ":"
                        + stack_entry["location"]["line"]
                        + "\n"
                    )
                    if count_stack == 1:
                        gdbinit.write("r" + "\n")
                    else:
                        gdbinit.write("c" + "\n")
                    gdbinit.write("set logging on" + "\n")
                    # read trace file for variables
                    trace_file_path = os.path.join(
                        tmpdir, "trace_" + str(count_role_traces) + "_" + str(count_stack))
                    lines = []
                    if Path(trace_file_path).exists():
                        with open(trace_file_path, "r") as info_file:
                            lines = info_file.readlines()

                    for line in lines:
                        variable = re.match(RE_GDB_VARIABLE, line)
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
                "set auto-load safe-path " + tmpdir,
            ],
                check=True,
                universal_newlines=True,
                timeout=GDB_TIMEOUT,
                cwd=tmpdir,
            )
        except Exception as e:
            logger.error("Debug with GDB: get types of variables failed! %s", e)

        # --- Pass 3: getting values ---
        count_role_traces = 0
        with open(gdbinit_path, "w") as gdbinit:
            gdbinit.write("file " + fuzz_driver + "\n")
            gdbinit.write("set args " + artifact_file + "\n")
            gdbinit.write("set pagination off" + "\n")
            gdbinit.write("set logging off" + "\n")

            for trace in backtrace["role_traces"]:
                count_role_traces += 1
                count_stack = 0
                for stack_entry in trace["stack"]:
                    count_stack += 1
                    gdbinit.write(
                        "set logging file "
                        + os.path.join(tmpdir, "values_"
                        + str(count_role_traces)
                        + "_"
                        + str(count_stack))
                        + "\n"
                    )
                    gdbinit.write("set logging overwrite on \n")
                    gdbinit.write(
                        "b "
                        + stack_entry["file"]
                        + ":"
                        + stack_entry["location"]["line"]
                        + "\n"
                    )
                    if count_stack == 1:
                        gdbinit.write("r" + "\n")
                    else:
                        gdbinit.write("c" + "\n")
                    gdbinit.write("set logging on" + "\n")
                    # read trace file for variables
                    trace_file_path = os.path.join(
                        tmpdir, "trace_" + str(count_role_traces) + "_" + str(count_stack))
                    types_file_path = os.path.join(
                        tmpdir, "types_" + str(count_role_traces) + "_" + str(count_stack))
                    lines = []
                    types = []
                    if Path(trace_file_path).exists():
                        with open(trace_file_path, "r") as info_file:
                            lines = info_file.readlines()

                    if Path(types_file_path).exists():
                        with open(types_file_path, "r") as types_file:
                            types = types_file.readlines()

                    for line in lines:
                        variable = re.match(RE_GDB_VARIABLE, line)
                        if variable:
                            var_name = variable.group(1)
                            is_pointer = False
                            pointer = re.match(RE_GDB_POINTER, line)
                            if pointer:
                                is_pointer = True
                            if re.match(RE_GDB_EMPTY, line):
                                is_pointer = False
                            if re.match(RE_GDB_ERROR, line):
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

        try:
            run(
                [
                    "gdb",
                    "-q",
                    "-iex",
                    "set auto-load safe-path " + tmpdir,
                ],
                check=True,
                universal_newlines=True,
                timeout=GDB_TIMEOUT,
                cwd=tmpdir,
            )
        except Exception as e:
            logger.error("Debug with GDB: get values failed! %s", e)

        # Read back values into backtrace
        count_role_traces = 0
        for trace in backtrace["role_traces"]:
            count_role_traces += 1
            count_stack = 0
            for stack_entry in trace["stack"]:
                count_stack += 1
                info = ""
                values_file_path = os.path.join(
                    tmpdir, "values_" + str(count_role_traces) + "_" + str(count_stack))
                if Path(values_file_path).exists():
                    with open(values_file_path, "r") as info_file:
                        lines = info_file.read()
                    for line in lines:
                        info += self._xml_escape(line)
                stack_entry["info"] = info

        return backtrace

    def _write_svres(self, backtrace: dict) -> None:
        """Write a single crash backtrace entry to the svres XML file.

        Writes XML svres output for a backtrace, deduplicating by hash.
        Appends warning info to warning_info.svres and explanation to
        warning_info_ex.svres.

        Args:
            backtrace: The structured backtrace dict to write.
        """
        hash_backtrace = self._get_backtrace_hash(backtrace)
        if hash_backtrace in self.backtrace_hashes:
            return
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

    def _parse_libfuzzer_log(self, fuzz_driver: str, libFuzzer_log: str, gdb: bool = False) -> None:
        """Orchestrator: parse crash log, optionally debug with GDB, write svres.

        Args:
            fuzz_driver: Path to the fuzz-driver executable.
            libFuzzer_log: Path of libFuzzer log file.
            gdb: Option for parsing with GDB. Defaults to False.
        """
        backtrace, artifact_file = self._parse_crash_log(libFuzzer_log)

        if not backtrace:
            return

        if gdb:
            with tempfile.TemporaryDirectory() as tmpdir:
                backtrace = self._run_gdb_debug(
                    fuzz_driver, artifact_file, backtrace, tmpdir)

        self._write_svres(backtrace)

    def _get_corpus_args(self, target_path) -> list:
        """Override in subclass to provide corpus path args."""
        return []

    def _build_single_coverage(self, object_file: str, path: str) -> None:
        """Build coverage report for a single fuzz-driver using llvm-profdata and llvm-cov.

        Args:
            object_file: Path to the instrumented object file.
            path: Directory path for the coverage HTML output.
        """
        my_env = os.environ.copy()
        my_env["LLVM_PROFILE_FILE"] = object_file + ".profraw"
        llvm_profdata = self.toolchain.llvm_profdata
        llvm_cov = self.toolchain.llvm_cov

        ## Merge profraw file
        llvm_profdata_command = [
            llvm_profdata.as_posix(),
            "merge",
            "-sparse",
            object_file + ".profraw",
            "-o",
            object_file + ".profdata",
        ]
        call(
            llvm_profdata_command,
            stdout=PIPE,
            stderr=PIPE,
            universal_newlines=True,
            env=my_env,
        )

        llvm_cov_report = [
            llvm_cov.as_posix(),
            "report",
            "-instr-profile",
            object_file + ".profdata",
            "--object",
            object_file,
        ]
        with open(object_file + ".coverage.csv", "w") as cov_file:
            p = Popen(
                llvm_cov_report,
                stdout=cov_file,
                stderr=PIPE,
                universal_newlines=True,
                env=my_env,
            )
            p.wait()

        llvm_cov_show = [
            llvm_cov.as_posix(),
            "show",
            "-format=html",
            "-instr-profile",
            object_file + ".profdata",
        ] + [
            "-output-dir=" + path
        ] + [
            "-object",
            object_file,
        ] + [self.source_path]

        Popen(
            llvm_cov_show,
            stderr=PIPE,
        ).wait()
        os.rename(path + "/index.html", object_file + ".html")

        if self.debug:
            logger.debug(" ".join(llvm_profdata_command))
            logger.debug(" ".join(llvm_cov_report))
            logger.debug(" ".join(llvm_cov_show))

    def _build_overall_coverage(self, path) -> None:
        """Build an overall coverage report by merging all profraw files.

        Args:
            path: Path object to the fuzz-driver directory containing profraw files.
        """
        my_env = os.environ.copy()
        profdata_files = [x.as_posix() for x in path.glob("**/*.profraw") if x.is_file()]
        object_list = [x.as_posix()[:-8] for x in path.glob("**/*.profraw") if x.is_file()]
        object_files = []
        for o in object_list:
            object_files += ["-object", o]

        llvm_profdata = self.toolchain.llvm_profdata
        llvm_cov = self.toolchain.llvm_cov

        llvm_profdata_command = [
            llvm_profdata.as_posix(),
            "merge",
            "-sparse"
        ] + profdata_files + [
            "-o",
            (path / "futag-fuzz-result.profdata").as_posix(),
        ]

        call(
            llvm_profdata_command,
            stdout=PIPE,
            stderr=PIPE,
        )
        source_path = [self.source_path]
        llvm_cov_report = [
            llvm_cov.as_posix(),
            "report",
        ] + object_files + [
            "-instr-profile=" + (self.fuzz_driver_path / "futag-fuzz-result.profdata").as_posix()
        ] + source_path

        cov_report_filename = (self.fuzz_driver_path / "futag-coverage-report.csv").as_posix()
        with open(cov_report_filename, "w") as cov_report_file:
            p = Popen(
                llvm_cov_report,
                stdout=cov_report_file,
                stderr=PIPE,
                universal_newlines=True,
                env=my_env,
            )
            p.wait()

        llvm_cov_show = [
            llvm_cov.as_posix(),
            "show",
            "-format=html",
            "-instr-profile=" + (self.fuzz_driver_path / "futag-fuzz-result.profdata").as_posix(),
        ] + ["-output-dir=" + (self.fuzz_driver_path).as_posix()] + object_files + source_path

        Popen(
            llvm_cov_show,
            stderr=PIPE,
        )

        if self.debug:
            logger.debug(" ".join(llvm_cov_show))
            logger.debug(" ".join(llvm_cov_report))
            logger.debug(" ".join(llvm_profdata_command))

    def _finalize_svres(self) -> None:
        """Write the closing XML tags to the svres file.

        Reads warning_info.svres and warning_info_ex.svres, merges them
        into the svres template, writes the final futag.svres file, and
        removes the intermediate files.
        """
        template_file = self.toolchain.svres_template
        if template_file is None:
            logger.warning("svres template not available, skipping svres finalization")
            return
        warning_info_text = ""
        warning_info_path = Path.cwd().absolute() / "warning_info.svres"
        warning_info_ex_text = ""
        warning_info_ex_path = Path.cwd().absolute() / "warning_info_ex.svres"

        if warning_info_path.exists() and warning_info_ex_path.exists():
            with open(warning_info_path, "r") as warning_info:
                warning_info_text = warning_info.read()
            with open(warning_info_ex_path, "r") as warning_info_ex:
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
            logger.info("Please import file %s to Svace project to view result!", (self.fuzz_driver_path /
                  "futag.svres").as_posix())

    def fuzz(self, extra_param: str = "") -> None:
        """Helper for automatic fuzzing.

        Args:
            extra_param: Extra params for fuzzing. Defaults to "".
        """
        symbolizer = self.toolchain.llvm_symbolizer
        generated_functions = [
            x for x in (self.fuzz_driver_path / "succeeded").iterdir() if x.is_dir()]
        for func_dir in generated_functions:
            self.backtraces = []
            fuzz_driver_dirs = [x for x in func_dir.iterdir() if x.is_dir()]
            for dir in fuzz_driver_dirs:
                for x in [t for t in dir.glob("*.out") if t.is_file()]:
                    logger.info("FUZZING driver: %s...", x.stem)
                    my_env = os.environ.copy()
                    if not self.leak:
                        my_env["ASAN_OPTIONS"] = "detect_leaks=0"

                    my_env["ASAN_SYMBOLIZER_PATH"] = symbolizer.as_posix()
                    if self.coverage:
                        my_env["LLVM_PROFILE_FILE"] = x.as_posix() + ".profraw"

                    corpus_args = self._get_corpus_args(x)

                    if self.fork > 1:
                        execute_command = [
                            x.as_posix(),
                        ] + corpus_args + [
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
                        ] + corpus_args + [
                            "-timeout=" + str(self.timeout),
                            "-rss_limit_mb=" + str(self.memlimit),
                            "-max_total_time=" + str(self.totaltime),
                            "-artifact_prefix=" + dir.as_posix() + "/",
                        ]
                    if extra_param:
                        execute_command = execute_command + extra_param.split(" ")
                    if self.debug:
                        logger.debug("FUZZING command: %s", " ".join(execute_command))
                    call(
                        execute_command,
                        stdout=PIPE,
                        stderr=PIPE,
                        universal_newlines=True,
                        env=my_env,
                    )

                    # Find all crash-* files in artifact folder
                    crashes_files = [c for c in dir.glob(
                        "**/crash-*") if c.is_file()]
                    for cr in crashes_files:
                        getlog_command = [x.as_posix(), cr.as_posix()]
                        crashlog_filename = dir.as_posix() + "/" + cr.stem + ".log"
                        with open(crashlog_filename, "w") as crashlog_file:
                            p = Popen(
                                getlog_command,
                                stdout=PIPE,
                                stderr=crashlog_file,
                                universal_newlines=True,
                                env=my_env,
                            )
                            p.communicate()
                        if self.gdb:
                            logger.info("Parsing crashes with GDB: %s", x.as_posix())
                            self._parse_libfuzzer_log(
                                x.as_posix(), crashlog_filename, True)
                        else:
                            logger.info("Parsing crash without GDB: %s", x.as_posix())
                            self._parse_libfuzzer_log(
                                x.as_posix(), crashlog_filename, False)
                    # build single coverage
                    if self.coverage:
                        self._build_single_coverage(x.as_posix(), dir.as_posix())

        # build overall coverage
        if self.coverage:
            self._build_overall_coverage(self.fuzz_driver_path)

        # generate svres file
        self._finalize_svres()
        logger.info("============ FINISH ============")


class Fuzzer(BaseFuzzer):
    """Futag Fuzzer"""

    def __init__(self, fuzz_driver_path: str = FUZZ_DRIVER_PATH, debug: bool = False, gdb: bool = False, svres: bool = False, fork: int = 1, totaltime: int = 300, timeout: int = 10, memlimit: int = 2048, coverage: bool = False, leak: bool = False, introspect: bool = False, source_path: str = "", toolchain=None, log_to_console: bool = True) -> None:
        """Initialize the Fuzzer.

        Args:
            fuzz_driver_path: Location of fuzz-drivers, default "futag-fuzz-drivers".
            debug: Print debug information while fuzzing, default False.
            gdb: Debug crashes with GDB, default False.
            svres: Generate svres file for Svace, default False.
            fork: Fork mode of libFuzzer, default 1 (no fork mode).
            totaltime: Total time of fuzzing one fuzz-driver in seconds, default 300.
            timeout: If a fuzz-driver takes longer than this timeout, the process is treated as a failure case, default 10.
            memlimit: Memory usage limit in Mb (rss_limit_mb), 0 to disable, default 2048.
            coverage: Show coverage of fuzzing, default False.
            leak: Detect memory leaks, default False.
            introspect: Integrate with fuzz-introspector, default False.
            source_path: Path to source code for coverage reports, default "".
            toolchain: ToolchainConfig instance. If None, uses generation-only mode.
            log_to_console: Show log messages in the console, default True.
        """
        super().__init__(
            fuzz_driver_path=fuzz_driver_path,
            debug=debug,
            gdb=gdb,
            svres=svres,
            fork=fork,
            totaltime=totaltime,
            timeout=timeout,
            memlimit=memlimit,
            coverage=coverage,
            leak=leak,
            introspect=introspect,
            source_path=source_path,
            toolchain=toolchain,
            log_to_console=log_to_console,
        )

    def _get_corpus_args(self, target_path) -> list:
        """Fuzzer does not add corpus path args."""
        return []


class NatchFuzzer(BaseFuzzer):
    """Futag Fuzzer for Natch"""

    def __init__(self, fuzz_driver_path: str = FUZZ_DRIVER_PATH, debug: bool = False, gdb: bool = False, svres: bool = False, fork: int = 1, totaltime: int = 300, timeout: int = 10, memlimit: int = 2048, coverage: bool = False, leak: bool = False, introspect: bool = False, toolchain=None, log_to_console: bool = True) -> None:
        """Initialize the NatchFuzzer.

        Args:
            fuzz_driver_path: Location of fuzz-drivers, default "futag-fuzz-drivers".
            debug: Print debug information while fuzzing, default False.
            gdb: Debug crashes with GDB, default False.
            svres: Generate svres file for Svace, default False.
            fork: Fork mode of libFuzzer, default 1 (no fork mode).
            totaltime: Total time of fuzzing one fuzz-driver in seconds, default 300.
            timeout: If a fuzz-driver takes longer than this timeout, the process is treated as a failure case, default 10.
            memlimit: Memory usage limit in Mb (rss_limit_mb), 0 to disable, default 2048.
            coverage: Show coverage of fuzzing, default False.
            leak: Detect memory leaks, default False.
            introspect: Integrate with fuzz-introspector, default False.
            log_to_console: Show log messages in the console, default True.
        """
        super().__init__(
            fuzz_driver_path=fuzz_driver_path,
            debug=debug,
            gdb=gdb,
            svres=svres,
            fork=fork,
            totaltime=totaltime,
            timeout=timeout,
            memlimit=memlimit,
            coverage=coverage,
            leak=leak,
            introspect=introspect,
            source_path="",
            toolchain=toolchain,
            log_to_console=log_to_console,
        )

    def _get_corpus_args(self, target_path) -> list:
        """NatchFuzzer adds corpus path to the execute command."""
        corpus_path = (target_path.parents[3] / "Natch_corpus" / target_path.parents[1].stem.replace("anonymous_", ""))
        return [corpus_path.as_posix()]
