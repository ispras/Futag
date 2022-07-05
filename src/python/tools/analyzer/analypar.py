# ===-- combine.py -------*- Python script -*-===//
#
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
#
# This tool is for combining results of futag-analysis

import json
import argparse
from pathlib import Path


parser = argparse.ArgumentParser(
    description="[Analypar]-- combine.py - A script for combining futag-analysis results."
)

parser.add_argument(
    "location", type=lambda p: Path(p).absolute(), help="folder of analysis results"
)

args = parser.parse_args()

if not args.location.exists():
    parser.error('The path "%s" does not exist!' % args.location)
    exit()

# Find all declaration files in given location
decl_files = [
    x
    for x in args.location.glob("**/declaration-*.futag-function-analyzer")
    if x.is_file()
]

# Find all context files in given location
context_files = [
    x for x in args.location.glob("**/context-*.futag-function-analyzer") if x.is_file()
]

# Find all type_info files in given location
typeinfo_files = [
    x
    for x in args.location.glob("**/types-info-*.futag-function-analyzer")
    if x.is_file()
]

# Find all includes info files in given location
includesinfo_files = [
    x
    for x in args.location.glob("**/includes-info-*.futag-function-analyzer")
    if x.is_file()
]

# global list of function
function_list = {}
enum_list = []
typedef_list = []
struct_list = []
includes_dict = {}

for jf in decl_files:
    # print(jf.as_posix())
    functions = json.load(open(jf.as_posix()))
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
        print(" -- Error: loading json from file: %s" % (jf.as_posix()))
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
                    function_list[hash]["call_contexts"].append(call_xref)
        else:
            print(" -- %s not found in global hash list!" % (hash))

# json.dump(function_list, open("function-analysis.json", "w"))
# functions = json.load(open("function-analysis.json"))

for jf in typeinfo_files:
    # print(jf.as_posix())
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

    # Just to make sure, that the cwd is the same for every file
    if cwd is not None:
        assert(cwd == includes['cwd'])
    else:
        cwd = includes['cwd']


def count_volume(func, called_functions, functions):
    # print("-- recursive analyzing function: %s" % ( func["func_name"]))
    # print("-- called function list: " + "; ".join(called_functions))
    if func["func_name"] in called_functions:
        # print("-- -- already called: %s" % (func["func_name"]))
        return 0
    called_functions.add(func["func_name"])
    total_line = 0
    for call_func in func["call_contexts"]:
        found = ""
        for f in functions:
            if call_func["called_from_func_name"] == functions[f]["func_name"]:
                found = functions[f]
        if found == "":
            return 0
        total_line += found["LOC"]
        total_line += count_volume(found, called_functions, functions)
        # print("-- total = " + str(total_line))

    return func["LOC"] + total_line


functions_w_contexts = []
functions_w_contexts_set = set()
for func in function_list:
    # if not function_list[func]["fuzz_it"]:
    #     continue
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
json.dump(result, open("futag-analysis-result.json", "w"))

count = 0
f_without_context = []
for f in functions_w_contexts:
    if not len(f["contexts"]):
        count += 1
        f_without_context.append(f)

json.dump(f_without_context, open("functions-without-context.json", "w"))

print("Total functions: " + str(len(result["functions"])))
print("Total enums: " + str(len(result["enums"])))
print("Total structs: " + str(len(result["structs"])))
print("Total typedefs: " + str(len(result["typedefs"])))
print("Analysis result: futag-analysis-result.json")
