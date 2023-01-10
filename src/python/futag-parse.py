# Futag-tests (https://github.com/thientc/Futag-tests): testing repository for Futag.
# This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).

import argparse
import json
from pathlib import Path
from futag.generator import *
from futag.sysmsg import *

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
print("*    This script is used for generating        *")
print("*        fuzz targets from traceback           *")
print("************************************************")
print("")


parser = argparse.ArgumentParser(
    description='[Futag]-- [futag] Script for auto compiling,debugging and gathering result.')

parser.add_argument(
    "callstack",
    type=lambda p: Path(p).absolute(),
    help="json file from Natch",
)

parser.add_argument(
    "Futag",
    type=lambda p: Path(p).absolute(),
    help="path to folder of Futag package",
)

parser.add_argument(
    "libpath",
    type=lambda p: Path(p).absolute(),
    help="path to library",
)

args = parser.parse_args()

if not args.callstack.exists():
    parser.error("File \"%s\" does not exist!" % args.callstack)

if not args.Futag.exists() or not (args.Futag / "bin/clang").absolute().exists():
    parser.error("Invalid path to Futag!")

if not args.libpath.exists():
    parser.error("Invalid path to library!")

natch = json.load(open(args.callstack.as_posix()))
if not natch:
    raise ValueError(COULD_NOT_PARSE_NATCH_CALLSTACK)

# get the line number 
natch_location_split = natch["location"].split(":")
line = natch_location_split[-1]

# get the file name 
natch_location_split.pop()
path = ":".join(natch_location_split)
file = path.split("/")[-1]

location = {
        "file": file,
        "line": line
    }

callstacks = []
for cs in  natch["callstack"]:
    tmp_callstack = []
    for c in cs:
        # get the line number 
        callstack_location_split = c["location"].split(":")
        if not callstack_location_split:
            break
        line = callstack_location_split[-1]
        callstack_location_split.pop()

        # get the file name 
        path = ":".join(callstack_location_split)
        file = path.split("/")[-1]

        tmp_callstack.append({
            "function_name": c["function_name"],
            "location":{
                "file": file,
                "line": line
            }
        })
    callstacks.append(tmp_callstack)
target = {
    "qname": natch["function_qualified_name"],
    "location": location,
    "callstack": callstacks
}
json.dump(target, open("target_from_callstack.json", "w"))