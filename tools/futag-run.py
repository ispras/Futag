#===-- futag-run.py -------*- Python script -*-===//
#
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
#

import sys
import os
import re
import argparse
from pathlib import Path
from subprocess import Popen, PIPE, run, call
from multiprocessing import Pool
import signal
# signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

# sys.excepthook = lambda exctype, exc, traceback: print(
#     "{}: {}".format(exctype.__name__, exc))

print("************************************************")
print("*      ______  __  __  ______  ___     ______  *")
print("*     / ____/ / / / / /_  __/ /   |   / ____/  *")
print("*    / /_    / / / /   / /   / /| |  / / __    *")
print("*   / __/   / /_/ /   / /   / ___ | / /_/ /    *")
print("*  /_/      \____/   /_/   /_/  |_| \____/     *")
print("*                                              *")
print("*     Fuzzing target Automated Generator       *")
print("*             a tool of ISP RAS                *")
print("*                                              *")
print("************************************************")
print("* This script is used for running fuzz targets *")
print("************************************************")
print("")


backtraces = []  # bactraces list
backtrace_hashes = set()  # Set for backtrace's hashes. If current bactrace's hash is not in set then add this backtrace to bactraces list, otherwise this backtrace will be passed


def Printer(data):
    sys.stdout.write("\r\x1b[K"+data.__str__())
    sys.stdout.flush()


def worker(bgen_args):
    p = Popen(bgen_args, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output, errors = p.communicate()

    if args.debug:
        print("\n-- [futag] COMPILING COMMAND:" + " ".join(bgen_args))
        if errors:
            print("\n-- [futag] ERROR:" + errors)


def get_id_from_error(error_string):
    error_id = 0
    for c in error_string:
        error_id += ord(c)
    return str(error_id)


def futag_escape(str):
    str = str.replace("&", "&amp;")
    str = str.replace("<", "&lt;")
    str = str.replace(">", "&gt;")
    str = str.replace("\"", "&quot;")
    str = str.replace("\n", " ")
    return str


def get_backtrace_hash(backtrace):
    # backtrace= {
    #     "warnClass" : warnClass,
    #     "warnID": get_id_from_error(warnClass+msg),
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
    input_str = ""
    for r in backtrace["role_traces"]:
        for s in r["stack"]:
            input_str += str(s["file"]) + str(s["location"]
                                              ["line"]) + str(s["location"]["col"])
    return hash(str(backtrace["warnID"]) + input_str)


def libFuzzerLog_parser(fuzzer_file, libFuzzer_log, debug):
    # Thank https://regex101.com/
    # match_error = "^==\d*==ERROR: (\w*): (.*)$"
    match_error = "^==\d*==ERROR: (\w*): (.*) on.*$"
    match_libFuzzer = "^==\d*== ERROR: (\w*): (.*)$"
    match_summary = "^SUMMARY: \w*: (.*)$"
    match_traceback = "^ *#(\d*) \d.\w* in ([\w:_\[\]()&<> *,]*) ([\/\w\d\-._]*):(\d*:?\d*)$"
    match_tracepass = "^ *#(\d*) \d.\w* in ([\w:_\[\]()&<> *,]*) ([\(\)+\/\w\d\-._]*)$"
    match_location = "(\d*):(\d*)"
    match_exc_trace = "^.*\/llvm-11.1.0\/.*$"
    match_exc_trace2 = "^.*libc-start.c.*$"
    match_exc_trace3 = "^.*ExecuteCallback.*compiler-rt/lib/fuzzer/FuzzerLoop.cpp.*$"
    # match_exc_trace3 = "^.*LLVMFuzzerTestOneInput.*$"
    match_artifacts = "^artifact_prefix.*Test unit written to (.*)$"
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
    with open(libFuzzer_log, 'r', errors='ignore') as f:
        lines = f.readlines()

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
                    "warnID": get_id_from_error(warnClass+msg+crash_file+str(crash_line)),
                    "msg": msg,
                    "crash_line": crash_line,
                    "crash_file": crash_file,
                    "role_traces": role_traces
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
                location = re.match(match_location, trace.group(4))
                if location:
                    if not crash_line:
                        crash_line = location.group(1)
                    location = {
                        "line": location.group(1),
                        "col": location.group(2)
                    }
                else:
                    location = {
                        "line": trace.group(4),
                        "col": "0"
                    }
                    if not crash_line:
                        crash_line = trace.group(4)
                if not crash_file:
                    crash_file = trace.group(3)
                stack.insert(0, {
                    "function": trace.group(2),
                    "file": trace.group(3),
                    "location": location,
                    "info": ""
                })
                info = "Next: "
            else:
                if re.match(match_tracepass, l):
                    continue
                empty_line = re.match("^$", l)
                if not empty_line:
                    role = l
                else:
                    if stack:
                        role_traces.append({
                            "role": role,
                            "stack": stack
                        })
                        stack = []
                        role = ""
    if not backtrace:
        return
    # print(backtrace)
    if debug:
        match_variable = "^([a-zA-Z_0-9]*) = .*$"
        match_empty = "^(.*) = 0x[0-9]$"
        match_full_ff = "^(.*) = 0x[0-9]$"
        match_error_gdb = "^([a-zA-Z_0-9]*) = .*(<error:).*$"
        match_pointer = "^([a-zA-Z_0-9]*) = 0x.*$"
        match_normal = "^(.*) = .*$"
        if backtrace["role_traces"]:
            count_role_traces = 0
            with open('.gdbinit', 'w') as gdbinit:
                gdbinit.write("file " + fuzzer_file + "\n")
                gdbinit.write("set args " + artifact_file + "\n")
                gdbinit.write("set pagination off" + "\n")
                gdbinit.write("set logging off" + "\n")

                for trace in backtrace["role_traces"]:
                    count_role_traces += 1
                    count_stack = 0
                    for stack in trace["stack"]:
                        count_stack += 1
                        gdbinit.write(
                            "set logging file trace_" + str(count_role_traces) + "_" + str(count_stack) + "\n")
                        gdbinit.write("set logging overwrite on \n")
                        gdbinit.write(
                            "b " + stack["file"] + ":" + stack["location"]["line"] + "\n")
                        if count_stack == 1:
                            gdbinit.write("r" + "\n")
                        else:
                            gdbinit.write("c" + "\n")
                        gdbinit.write("set logging on" + "\n")
                        gdbinit.write("info args" + "\n")
                        gdbinit.write("info local" + "\n")
                        gdbinit.write("set logging off" + "\n")
                gdbinit.write("quit")

            # https://undo.io/resources/gdb-watchpoint/here-quick-way-pretty-print-structures-gdb/
            p = Popen([
                "gdb",
                "-q",
                "-iex",
                "set auto-load safe-path .",
            ], stdout=PIPE, stderr=PIPE, universal_newlines=True, timeout=30)
            output, errors = p.communicate()

            count_role_traces = 0
            with open('.gdbinit', 'w') as gdbinit:
                gdbinit.write("file " + fuzzer_file + "\n")
                gdbinit.write("set args " + artifact_file + "\n")
                gdbinit.write("set pagination off" + "\n")
                gdbinit.write("set logging off" + "\n")

                for trace in backtrace["role_traces"]:
                    count_role_traces += 1
                    count_stack = 0
                    for stack in trace["stack"]:
                        count_stack += 1
                        gdbinit.write(
                            "set logging file values_" + str(count_role_traces) + "_" + str(count_stack) + "\n")
                        gdbinit.write("set logging overwrite on \n")
                        gdbinit.write(
                            "b " + stack["file"] + ":" + stack["location"]["line"] + "\n")
                        if count_stack == 1:
                            gdbinit.write("r" + "\n")
                        else:
                            gdbinit.write("c" + "\n")
                        gdbinit.write("set logging on" + "\n")
                        # read trace file for variables
                        with open("trace_" + str(count_role_traces) + "_" + str(count_stack), 'r') as info_file:
                            lines = info_file.readlines()

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
                                    "output \"value of " + var_name + ":\" \n")
                                if is_pointer:
                                    gdbinit.write(
                                        "output *" + var_name + " \n")
                                    gdbinit.write("output \"; \"" + "\n")
                                else:
                                    gdbinit.write("output " + var_name + " \n")
                                    gdbinit.write("output \"; \"" + "\n")
                        gdbinit.write("set logging off" + "\n")
                gdbinit.write("quit")
            p = Popen([
                "gdb",
                "-q",
                "-iex",
                "set auto-load safe-path .",
            ], stdout=PIPE, stderr=PIPE, universal_newlines=True, timeout=30)
            output, errors = p.communicate()

            count_role_traces = 0
            for trace in backtrace["role_traces"]:
                count_role_traces += 1
                count_stack = 0
                for stack in trace["stack"]:
                    count_stack += 1
                    info = ""
                    with open("values_" + str(count_role_traces) + "_" + str(count_stack), 'r') as info_file:
                        lines = info_file.read()

                    for line in lines:
                        info += futag_escape(line)
                    stack["info"] = info
    hash_backtrace = get_backtrace_hash(backtrace)
    if not hash_backtrace in backtrace_hashes:
        backtrace_hashes.add(hash_backtrace)
        curren_explanation = ""
        with open('warning_info.svres', 'a') as warning_info:
            warning_info.write("<WarnInfo id=\""+backtrace["warnID"]+"\" warnClass=\"" + backtrace["warnClass"] + "\" line=\"" + str(backtrace["crash_line"]) + "\" file=\"" +
                               backtrace["crash_file"] + "\" msg=\""+backtrace["msg"]+"\" status=\"Default\" details=\"\" comment=\"\" function=\"\" mtid=\"\" tool=\"\" lang=\"\" flags=\"0\" tags=\"\"/>")

            for r in backtrace["role_traces"]:
                loc_info = ""
                for s in r["stack"]:
                    loc_info += "<LocInfo file=\""+s["file"]+"\" line=\""+s["location"]["line"] + \
                        "\" spec=\"false\" info=\"" + \
                        s["info"]+"\" col=\""+s["location"]["col"]+"\"/>"
                curren_explanation += "<RoleTraceInfo role=\"" + \
                    r["role"]+"\"><locations>"+loc_info + \
                    "</locations></RoleTraceInfo>"
        with open('warning_info_ex.svres', 'a') as warning_info_ex:
            warning_info_ex.write("<WarnInfoEx id=\""+backtrace["warnID"]+"\" zRate=\"0.0\"><traces>" + curren_explanation +
                                  "</traces><userAttributes class=\"tree-map\"><entry><string>.comment</string><string></string></entry><entry><string>.status</string><string>Default</string></entry></userAttributes></WarnInfoEx>")
        os.system("rm -f values_*")
        os.system("rm -f trace_*")


parser = argparse.ArgumentParser(
    description='[Futag]-- [futag] Script for auto compiling,debugging and gathering result.')

parser.add_argument(
    "-p",
    "--package",
    type=lambda p: Path(p).absolute(),
    # by default futag-package is in the parent directory
    default=Path(__file__).parent.parent.absolute() ,
    help="path to futag, by default futag is in the same folder of this script ",
)

parser.add_argument(
    "-x", 
    "--target", 
    default="libFuzzer",
    help="type of targets for generating (libFuzzer or Crusher), default is libFuzzer"
)
parser.add_argument(
    "-i",
    "--include",
    default="include",
    help="paths for including when compiling"
)

parser.add_argument(
    "-a",
    "--static_path",
    help="path to folder of installed libraries"
)

parser.add_argument(
    "-asan",
    "--futag_asan",
    action='store_true',
    help="Compile with futag ASAN"
)

parser.add_argument(
    "-s",
    "--syslibs",
    default="",
    help="list of system libs for compiling"
)

parser.add_argument(
    "-so",
    "--objects",
    default="",
    help="list of object files for compiling"
)

parser.add_argument(
    '-gdb',
    '--gdb_debug',
    action='store_true',
    help="Option for debugging with gdb"
)

parser.add_argument(
    '-d',
    '--debug',
    action='store_true',
    help="Option for viewing debugging info while compiling "
)

parser.add_argument(
    '-f',
    '--fork',
    type=int,
    default=0,
    help="Fork option for libFuzzer"
)

parser.add_argument(
    '-to',
    '--timeout',
    type=int,
    default=10,
    help="Time out for fuzzing"
)
parser.add_argument(
    '-tt',
    '--max_total_time',
    type=int,
    default=30,
    help="Max total time out for fuzzing"
)
parser.add_argument(
    '-o',
    '--output',
    default="futag-targets",
    help="Folder for generating fuzz-targets"
)

parser.add_argument(
    '-m',
    '--memlimit',
    type=int,
    default=2048,
    help="Memory limit for fuzzing"
)

parser.add_argument(
    '-k',
    '--makefile',
    action='store_true',
    help="Option for exporting list of compiling commands to Makefile.futag"
)

parser.add_argument(
    '-0c',
    '--nocompiling',
    action='store_true',
    help="Option for fuzzing without compiling"
)

parser.add_argument(
    '-0f',
    '--nofuzzing',
    action='store_true',
    help="Option for executing without fuzzing"
)

parser.add_argument(
    '-c',
    '--coverage',
    action='store_true',
    help="Option for counting coverage"
)

parser.add_argument(
    'header',
    type=lambda p: Path(p).absolute(),
    help="Header file for fuzzing"
)

args = parser.parse_args()

if not args.header.exists():
    parser.error("The header file \"%s\" does not exist!" % args.header)
    exit()

print(args.package.as_posix())

if not ((args.package / "bin/clang").exists() and (args.package / "bin/futag-gen4libfuzzer" ).exists() and (args.package / "bin/futag-gen4crusher" ).exists()):
    parser.error(
        "The path to folder of futag package %s does not exist!" % args.package)
    exit()

if ((args.target != "libFuzzer") and (args.target !="Crusher") ):
    parser.error(
        "Unknown what type of targets (%s) for generating!" % args.target)
    exit()

futag_header_file = Path.cwd().absolute() / "futagheader.h"
futag_header = open(futag_header_file.as_posix(), "w")
futag_header.write("#include \""+args.header.as_posix()+"\"")
futag_header.close()

targets_folder = Path.cwd().absolute() / args.output

static_libs = []
if(args.static_path):
    paths = args.static_path.split(' ')
    for p in paths:
        for alib in [x.as_posix() for x in Path(p).absolute().glob('**/*.a') if x.is_file()]:
            static_libs.append(alib)
# share_libs = []
# if(args.share_path):
#     share_libs = [x.as_posix() for x in args.share_path.glob('**/*.so') if x.is_file()]

includes = [Path(inc).absolute().as_posix() for inc in args.include.split(' ') if inc]
extra_args = ["--extra-arg=-I" + inc for inc in includes if inc]

compiler = args.package / "bin/clang"

if(args.target == "libFuzzer"):
    futag_gen4lib = args.package / "bin/futag-gen4libfuzzer"
else:
    futag_gen4lib = args.package / "bin/futag-gen4crusher"


# Generating fuzz-targets for all function in testing header
generate_command = [futag_gen4lib.as_posix()]

for e in extra_args:
    generate_command.append(e)

if args.output:
    generate_command.append("--folder")
    generate_command.append(args.output)

generate_command.append(futag_header_file.as_posix())
generate_command.append("--")

if args.debug:
    print( " ".join(generate_command))

p = Popen(generate_command, stdout=PIPE, stderr=PIPE, universal_newlines=True)
output, errors = p.communicate()
if args.debug:
    print(" ".join(generate_command))
    if(errors):
        print(errors)

# Getting result of generation
func_list = [x for x in targets_folder.iterdir() if x.is_dir()]
targets_list = [x for x in targets_folder.glob('**/*.cc') if x.is_file()]

if not len(func_list):
    sys.exit('No targets has been generated. Quit...')

print("-- [futag] Generated " + str(len(targets_list)) +
      " fuzz-targets for " + str(len(func_list)) + " functions!")


if not args.nocompiling:
    compile_list = []
    clean_list = []
    makefile_list = []
    if(args.target == "libFuzzer"):
        makefile_compiler_flags = "-ferror-limit=1 -g -O0 -fsanitize=address,undefined,fuzzer -fprofile-instr-generate -fcoverage-mapping"
    else:
        makefile_compiler_flags = "-ferror-limit=1 -g -O0 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping"
    makefile_compiler_include = " ".join(["-I" + inc for inc in includes if inc])
    makefile_static_list = " "
    makefile_syslibs = args.syslibs

    if (static_libs):
        makefile_static_list += "-Wl,--start-group "
        for i in static_libs:
            makefile_static_list += i
        if args.futag_asan:
            makefile_static_list += (args.package / "lib/clang/11.1.0/lib/linux/libclang_rt.asan-x86_64.a").as_posix()
        makefile_static_list +=" -Wl,--end-group"

    Printer("-- [futag] Compiling...")
    # Compile each target with input parameters: include, static libs (libpath), syslibs
    for dir in func_list:
        for x in [t for t in dir.glob('*.cc') if t.is_file()]:
            if(args.target == "libFuzzer"):
                compile_command=[
                    compiler.as_posix(),
                    "-ferror-limit=1",
                    "-g",
                    "-O0",
                    "-fsanitize=address,fuzzer",
                    "-fprofile-instr-generate",
                    "-fcoverage-mapping"
                ]
            else:
                compile_command=[
                    compiler.as_posix(),
                    "-ferror-limit=1",
                    "-g",
                    "-O0",
                    "-fsanitize=address",
                    "-fprofile-instr-generate",
                    "-fcoverage-mapping"
                ]
            
            for i in includes:
                compile_command.append("-I"+i)
            if (args.objects):
                for i in args.objects.split(' '):
                    compile_command.append(i)

            compile_command.append(x.as_posix())
            compile_command.append("-o")
            if(args.target == "libFuzzer"):
                compile_command.append(dir.as_posix() + '/' + x.stem + ".libFuzzer.out")
            else:
                compile_command.append(dir.as_posix() + '/' + x.stem + ".Crusher.out")
            makefile_list.append([x.as_posix(), dir.as_posix() + '/' + x.stem + ".out"])
            clean_list.append(dir.as_posix() + '/' + x.stem + ".out")
            if (static_libs):
                compile_command.append("-Wl,--start-group")
                for i in static_libs:
                    compile_command.append(i)
                if args.futag_asan:
                    compile_command.append(
                        (args.package / "lib/clang/11.1.0/lib/linux/libclang_rt.asan-x86_64.a").as_posix())
                compile_command.append("-Wl,--end-group")
            # if (share_libs):
            #     compile_command.append("-Wl,--start-group")
            #     for i in share_libs:
            #         compile_command.append(i)
            #     compile_command.append("-Wl,--end-group")

            if (args.syslibs):
                for i in args.syslibs.split(' '):
                    compile_command.append(i)
            compile_list.append(compile_command)


    if (args.makefile and len(compile_list) > 0):
        makefile = open('Makefile.futag', 'w') 
        makefile.write("#************************************************\n")
        makefile.write("#*      ______  __  __  ______  ___     ______  *\n")
        makefile.write("#*     / ____/ / / / / /_  __/ /   |   / ____/  *\n")
        makefile.write("#*    / /_    / / / /   / /   / /| |  / / __    *\n")
        makefile.write("#*   / __/   / /_/ /   / /   / ___ | / /_/ /    *\n")
        makefile.write("#*  /_/      \____/   /_/   /_/  |_| \____/     *\n")
        makefile.write("#*                                              *\n")
        makefile.write("#*     Fuzzing target Automated Generator       *\n")
        makefile.write("#*             a tool of ISP RAS                *\n")
        makefile.write("#*                                              *\n")
        makefile.write("#************************************************\n")
        makefile.write("#* This script is used for running fuzz targets *\n")
        makefile.write("#************************************************\n")
        makefile.write("\n")
        makefile.write("COMPILER="+compiler.as_posix()+"\n")
        makefile.write("FLAGS=" + makefile_compiler_flags+"\n") 
        makefile.write("INCLUDE="+makefile_compiler_include+"\n") 
        makefile.write("STATIC_LIBS="+makefile_static_list+"\n") 
        makefile.write("LIBS="+makefile_syslibs+"\n") 

        makefile.write("default: \n")
        for c in makefile_list:
            makefile.write("\t" + "${COMPILER} ${FLAGS} ${INCLUDE} " + c[0] + " -o " + c[1] + " ${STATIC_LIBS} ${LIBS}\n")
        makefile.write("clean: \n")
        for c in makefile_list:
            makefile.write("\trm " + c[1] + "\n")
        makefile.close()

    multi = 1
    if (args.fork > 1) and (args.target == "libFuzzer"):
        multi = args.fork

    with Pool(multi) as p:
        p.map(worker, compile_list)

    # Getting result of compilation
    compile_targets_list = [
        x for x in targets_folder.glob('**/*.out') if x.is_file()]
    print("done! (compiled " + str(len(compile_targets_list)) +
        " from " + str(len(targets_list)) + " targets)")

if args.nofuzzing:
    exit()
if (args.target == "Crusher"):
    exit()

symbolizer = args.package / "bin/llvm-symbolizer"

for dir in func_list:
    for x in [t for t in dir.glob('*.libFuzzer.out') if t.is_file()]:
        print("Fuzzing " + x.stem + "... \n")
        my_env = os.environ.copy()
        my_env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1"
        my_env["ASAN_SYMBOLIZER_PATH"] = symbolizer.as_posix()
        if args.coverage:
            my_env["LLVM_PROFILE_FILE"] = x.as_posix()+".profraw"
        if args.fork > 0:
            # 1. Execute binary with -fork=4  -ignore_crashes=1 -max_total_time=10
            # 2. Find all crash-* leak-* ... in artifact folder
            # 3. Execute binary with these artifacts and save to log
            # 4. With received log, parse to get traceback
            # 5. Debug with GDB
            execute_command = [
                x.as_posix(),
                "-fork="+str(args.fork),
                "-ignore_crashes=1",
                "-timeout="+str(args.timeout),
                "-rss_limit_mb="+str(args.memlimit),
                "-max_total_time="+str(args.max_total_time),
                "-artifact_prefix=" + dir.as_posix() + '/',
            ]
            if args.debug:
                print("\n-- [futag] FUZZING:" + " ".join(execute_command))

            # print(" ".join(execute_command))
            p = call(execute_command, stdout=PIPE, stderr=PIPE,
                     universal_newlines=True, env=my_env)
            
            # 2. Find all crash-* leak-* ... in artifact folder
            # print(dir.as_posix())
            crashes_files = [x for x in dir.glob('**/crash-*') if x.is_file()]
            for cr in crashes_files:
                getlog_command = [
                    x.as_posix(),
                    cr.as_posix()
                ]
                crashlog_filename = dir.as_posix() + '/' + cr.stem + ".log"
                crashlog_file = open(crashlog_filename, "w")
                p = Popen(getlog_command, stdout=PIPE, stderr=crashlog_file,
                          universal_newlines=True, env=my_env)
                output, errors = p.communicate()
                crashlog_file.close()
                if args.gdb_debug:
                    libFuzzerLog_parser(x.as_posix(), crashlog_filename, 1)
                else:
                    libFuzzerLog_parser(x.as_posix(), crashlog_filename, 0)
        else:
            execute_command = [
                x.as_posix(),
                "-timeout="+str(args.timeout),
                "-rss_limit_mb="+str(args.memlimit),
                "-max_total_time="+str(args.max_total_time),
                "-artifact_prefix=" + dir.as_posix() + '/',
            ]
            if args.debug:
                print("\n-- [futag] FUZZING:" + " ".join(execute_command))

            errorlog_filename = dir.as_posix() + '/' + x.stem + ".log"
            errorlog_file = open(errorlog_filename, "w")
            p = Popen(execute_command, stdout=PIPE, stderr=errorlog_file,
                      universal_newlines=True, env=my_env)
            output, errors = p.communicate()
            errorlog_file.close()
            if args.gdb_debug:
                libFuzzerLog_parser(x.as_posix(), errorlog_filename, 1)
            else:
                libFuzzerLog_parser(x.as_posix(), errorlog_filename, 0)
        if args.coverage:
            llvm_profdata = args.package / "bin/llvm-profdata"
            llvm_profdata_command = [
                llvm_profdata.as_posix(),
                "merge",
                "-sparse",
                x.as_posix()+".profraw",
                "-o",
                x.as_posix()+".profdata",
            ]
            if args.debug:
                print(" ".join(llvm_profdata_command))
            p = call(llvm_profdata_command, stdout=PIPE, stderr=PIPE,
                        universal_newlines=True, env=my_env)

            llvm_cov = args.package / "bin/llvm-cov"
            llvm_cov_report = [
                llvm_cov.as_posix(),
                "report",
                x.as_posix(),
                "-instr-profile="+x.as_posix()+".profdata"
            ]
            if args.debug:
                print(" ".join(llvm_cov_report))
            p = run(llvm_cov_report)

            llvm_cov_show = [
                llvm_cov.as_posix(),
                "show",
                x.as_posix(),
                "-instr-profile="+x.as_posix()+".profdata"
            ]

            cov_filename = x.as_posix() + ".cov"
            cov_file = open(cov_filename, "w")
            p = Popen(llvm_cov_show, stdout=cov_file, stderr=PIPE,
                        universal_newlines=True, env=my_env)
            output, errors = p.communicate()
            cov_file.close()

template_file = args.package / "tools/svace.svres.tmpl"
warning_info_text = ""
warning_info_path = Path.cwd().absolute() / "warning_info.svres"
warning_info_ex_text = ""
warning_info_ex_path = Path.cwd().absolute() / "warning_info_ex.svres"

if(warning_info_path.exists() and warning_info_ex_path.exists()):
    with open("warning_info.svres", 'r') as warning_info:
        warning_info_text = warning_info.read()
    with open("warning_info_ex.svres", 'r') as warning_info_ex:
        warning_info_ex_text = warning_info_ex.read()
    with template_file.open() as tmpl:
        lines = tmpl.read()
    lines = lines.replace("WARNING_INFO", warning_info_text)
    lines = lines.replace("WARNINGINFO_EXPLAINATION", warning_info_ex_text)
    warning_info_path.unlink()
    warning_info_ex_path.unlink()
    # os.system("rm warning_info.svres")
    # os.system("rm warning_info_ex.svres")
    with open('futag.svres', 'w') as svres:
        svres.write(lines)
    print(
        "-- [futag] Please import file futag.svres to Svace project to view result!")
print("============ FINISH ============")
