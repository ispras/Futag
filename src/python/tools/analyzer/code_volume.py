# ===-- code_volume.py -------*- Python script -*-===//
#
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
#
# This tool is for counting volume of executed code

import sys
import os
import json
import argparse
from pathlib import Path


parser = argparse.ArgumentParser(
    description="[Analypar]-- code_vol_count.py - A script for counting code volume of futag targets. Input of this script is the json-output-file of combine.py"
)

parser.add_argument(
    "combined_file", type=lambda p: Path(p).absolute(), help="file of analysis results"
)

args = parser.parse_args()

if not args.combined_file.exists():
    parser.error('The path "%s" does not exist!' % args.combined_file)
    exit()

# Get all function declarations in json file
functions = json.load(open(args.combined_file.as_posix()))
called_functions = set()
files_of_code = set()
execute_volume = 0
total_line = 0
print("Total function for analyzing: " + str(len(functions)))
c = 0
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

result = []
for func in functions:
    c = c + 1
    # print("-- analyzing %sth function: %s" % (str(c), functions[func]['func_name']))
    called_functions = set()
    # add current function name as first function call
    called_functions.add(functions[func]["func_name"])
    
    curr_file = functions[func]["location"].split(":")[0]
    if curr_file not in files_of_code:
        if os.path.isfile(curr_file):
            with open(curr_file, 'r') as fp:
                total_line += len(fp.readlines())
            files_of_code.add(curr_file)
    execute_volume = functions[func]["LOC"]
    for call_func in functions[func]["call_contexts"]:
        found = ""
        for f in functions:
            if call_func["called_from_func_name"] == functions[f]["func_name"]:
                found = functions[f]
        if found == "":
            print("-- Error: function %s is not found in functions list!" %
                  (call_func["called_from_func_name"]))
            continue

        execute_volume += count_volume(found,
                                       called_functions, functions)
    # print("execute volume of current function: %s" % (str(execute_volume)))
    result.append(
        {
            "name": functions[func]['func_name'],
            "called_functions": "; ".join(called_functions),
            "exec_volume": execute_volume
        }
    )

json.dump(result, open("volume-exec.json", "w"))
print(total_line)