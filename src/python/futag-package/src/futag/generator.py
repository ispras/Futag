import json
import pathlib
import copy
import os

from subprocess import Popen, PIPE
from multiprocessing import Pool
from typing import List


class Generator:
    """Futag Generator"""

    # def __init__(self, output_path: str, json_file: str, target_project_archive: str, futag_package_path: str, library_root: str):
    def __init__(self, output_path: str, json_file: str, futag_package_path: str, library_root: str):
        """
        Parameters
        ----------
        output_path : str
            where to save fuzz-drivers
        json_file: str
            path to the futag-analysis-result.json file
        target_project_archive: str
            path to the compiled and packed project
        futag_package_path: str
            path to the futag package (with binaries, scripts, etc)
        library_root: str
            path to the library root
        """

        self.output_path = None  # Path for saving fuzzing drivers
        self.json_file = json_file
        # self.target_project_archive = target_project_archive
        self.futag_package_path = futag_package_path
        self.library_root = library_root
        self.target_library = None

        self.gen_func_params = []
        self.gen_free = []
        self.gen_this_function = True
        self.buf_size_arr = []
        self.dyn_size = 0

        # if pathlib.Path(self.target_project_archive).exists():
        #     self.target_project_archive = pathlib.Path(self.target_project_archive).absolute()
        # else:
        #     raise ValueError('Incorrect path to compiled target project')

        if pathlib.Path(self.futag_package_path).exists():
            self.futag_package_path = pathlib.Path(self.futag_package_path).absolute()
        else:
            raise ValueError('Incorrect path to FUTAG package')

        if pathlib.Path(self.library_root).exists():
            self.library_root = pathlib.Path(self.library_root).absolute()
        else:
            raise ValueError('Incorrect path to the library root')

        if pathlib.Path(json_file).exists():
            self.json_file = json_file
            f = open(json_file)
            if not f.closed:
                self.target_library = json.load(f)

            # create directory for function targets if not exists
            if not pathlib.Path(output_path).exists():
                (pathlib.Path(".") / output_path).mkdir(parents=True, exist_ok=True)

            self.output_path = pathlib.Path(output_path).absolute()

    def gen_header(self, target_function_fname):
        header = [
            "#include <stdio.h>\n",
            "#include <stddef.h>\n",
            "#include <stdlib.h>\n",
            "#include <string.h>\n",
            "#include <stdint.h>\n"
        ]
        for h in self.target_library['includes'].get(target_function_fname, []):
            header.append(f'#include "{h}"\n')
        return header

    def gen_builtin(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                type_name + " " + var_name + ";\n",
                "memcpy(&"+var_name+", pos, sizeof(" + type_name + "));\n",
                "pos += sizeof(" + type_name + ");\n"
            ],
            "gen_free": []
        }

    def gen_size(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                type_name + " " + var_name +
                " = (" + type_name + ") dyn_size;\n",
            ],
            "gen_free": []
        }

    def gen_string(self, type_name, var_name, parent_type):
        if (len(parent_type) > 0):
            return {
                # char  * var_0 = (char  *) malloc(sizeof(char )*(futag_cstr_size + 1));
                "gen_lines": [
                    "//GEN_STRING\n",
                    parent_type + " r" + var_name + " = (" + parent_type + ") " +
                    "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(r" + var_name+", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(r" + var_name+", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    type_name + " " + var_name + "= r" + var_name + ";\n"
                ],
                "gen_free": [
                    "if (dyn_size > 0 && strlen(" + var_name + \
                    ") > 0) free(" + var_name + ");\n"
                ]
            }
        return {
            # char  * var_0 = (char  *) malloc(sizeof(char )*(futag_cstr_size + 1));
            "gen_lines": [
                "//GEN_STRING\n",
                type_name + " " + var_name + " = (" + type_name + ") " +
                "malloc(sizeof(" + type_name + ") * dyn_size + 1);\n",
                "memset(" + var_name+", 0, sizeof(" + \
                type_name + ") * dyn_size + 1);\n",
                "memcpy(" + var_name+", pos, sizeof(" + \
                type_name + ") * dyn_size );\n",
                "pos += sizeof(" + type_name + ") * dyn_size ;\n"
            ],
            "gen_free": [
                "if (dyn_size > 0 && strlen(" + var_name + \
                ") > 0) free(" + var_name + ");\n"
            ]
        }

    def gen_enum(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_ENUM\n"
            ],
            "gen_free": []
        }

    def gen_array(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_ARRAY\n"
            ],
            "gen_free": []
        }

    def gen_void(self, var_name):
        return {
            "gen_lines": [
                "//GEN_VOID\n"
            ],
            "gen_free": []
        }

    def gen_qualifier(self, type_name, var_name, parent_type):
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                parent_type + " u" + var_name + ";\n",
                "memcpy(&u"+var_name+", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " var_name = u" + var_name + ";\n"
            ],
            "gen_free": []
        }

    def gen_pointer(self, type_name, var_name, parent_type):
        return {
            "gen_lines": [
                "//GEN_POINTER\n",
                parent_type + " r" + var_name + ";\n",
                "memcpy(&r" + var_name + ", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " " + var_name + "= &r" + var_name + ";\n"
            ],
            "gen_free": []
        }

    def gen_struct(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_STRUCT\n"
            ],
            "gen_free": []
        }

    # def gen_incomplete(type_name, var_buf, var_size, ):
    #     # find in
    #     return {
    #         "gen_lines": [],
    #         "free_line": []
    #     }

    def gen_input_file(self, var_name):
        return {
            "gen_lines": [
                "//GEN_INPUT_FILE\n",
                "const char* " + var_name + " = \"futag_input_file\";\n",
                "FILE *fp = fopen(" + var_name + ",\"w\");\n",
                "if (fp != NULL) { return 0; }\n",
                "fwrite(pos, 1, dyn_size, fp);\n",
                "fclose(fp);\n",
                "pos += dyn_size;\n"
            ],
            "gen_free": []
        }

    def gen_output_file(self, var_name):
        return {
            "gen_lines": [
                "//GEN_OUTPUT_FILE\n"
            ],
            "gen_free": []
        }

    def gen_function(type_name, var_buf, var_size, ):
        return {
            "gen_lines": [
                "//GEN_FUNCTION\n"
            ],
            "gen_free": []
        }

    def check_gen_function(self, function):
        """ Check if we can initialize argument as function call """
        return True

    def gen_var_function(self, func, var_name):
        """ Initialize for argument of function call """
        curr_gen_func_params = []
        curr_gen_free = []
        curr_buf_size_arr = []
        curr_dyn_size = 0
        # static_buffer_size = 0
        # dynamic_buffer_size = 0
        param_list = []
        for arg in func["params"]:
            param_list.append("f_" + arg["param_name"])
            if arg["generator_type"] == 0:
                if arg["param_usage"] == "SIZE_FIELD":
                    print("GEN_SIZE")
                    var_curr_gen = self.gen_size(
                        arg["param_type"], "f_" + arg["param_name"])
                else:
                    print("GEN_BUILTIN")
                    var_curr_gen = self.gen_builtin(
                        arg["param_type"], "f_" + arg["param_name"])
                if not var_curr_gen:
                    return None

                curr_gen_func_params += var_curr_gen["gen_lines"]
                curr_buf_size_arr.append("sizeof(" + arg["param_type"]+")")

            if arg["generator_type"] == 1:
                if(arg["param_usage"] == "FILE_PATH"):
                    print("GEN_FILE_PATH")
                    var_curr_gen = self.gen_input_file(
                        "f_" + arg["param_name"])
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None

                    curr_gen_func_params += var_curr_gen["gen_lines"]
                    curr_buf_size_arr.append("sizeof(" + arg["param_type"]+")")
                    # self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")
                else:
                    print("GEN_STRING")
                    var_curr_gen = self.gen_string(
                        arg["param_type"],
                        "f_" + arg["param_name"],
                        arg["parent_type"])
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None

                    curr_gen_func_params += var_curr_gen["gen_lines"]
                    curr_gen_free += var_curr_gen["gen_free"]
            # if arg["generator_type"] == 2:
            #     self.gen_this_function = False

        function_call = "//GEN_VAR_FUNCTION\n    " + func["return_type"] + " " + var_name + \
            " = " + func["func_name"] + \
            "(" + ",".join(param_list)+");\n"
        curr_gen_func_params.append(function_call)
        return {
            "gen_lines": curr_gen_func_params,
            "gen_free": curr_gen_free,
            "dyn_size": curr_dyn_size,
            "buf_size_arr": curr_buf_size_arr,
        }

    def gen_target_function(self, func, param_id):
        if param_id == len(func['params']):
            # generate file name
            file_index = 0
            # A short tale how I tried to debug "undefined reference to" for 4
            # hours. If clang sees .cc extension it somehow assumes that it
            # works with c++ (even if we use clang and not clang++) thus
            # when I've tried to link with pure C library I wasn't able to do so.
            # One extra char and whole day worth of debugging.
            # God, I love C!
            file_name = func["func_name"] + ".c"

            # if not (self.output_path / func["func_name"]).exist():
            if not (self.output_path / func["func_name"]).exists():
                (self.output_path / func["func_name"]
                 ).mkdir(parents=True, exist_ok=True)
            while (self.output_path / func["func_name"] / file_name).exists():
                file_name = func["func_name"] + str(file_index) + ".c"
                file_index += 1
            print("-- Generate function \"" + func["func_name"] + "\": ...")
            curr_buffer_size = 0
            full_path = (self.output_path /
                         func["func_name"] / file_name).as_posix()
            f = open(full_path, 'w')
            if f.closed:
                return None

            for line in self.gen_header(func["location"].split(':')[0]):
                f.write(line)
            f.write('\n')

            # target_func_types = ','.join([param['param_type'] for param in func['params']])
            # f.write(
            #     f"extern \"C\" {func['return_type']} {func['func_name']}({target_func_types});\n\n"
            # )

            f.write(
                "int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size)\n")
            f.write("{\n")

            if self.dyn_size > 0:
                # if len(self.buf_size_arr) > 0:
                f.write("    if (Fuzz_Size < " + str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write(") return 0;\n")
                f.write(
                    "    int dyn_size = (int) ((Fuzz_Size - (" +
                    str(self.dyn_size))
                if self.buf_size_arr:
                    f.write(" + " + "+".join(self.buf_size_arr))
                f.write("))/" + str(self.dyn_size) + ");\n")
            else:
                if len(self.buf_size_arr) > 0:
                    f.write("    if (Fuzz_Size < ")
                    f.write("+".join(self.buf_size_arr))
                    f.write(") return 0;\n")

            f.write("    uint8_t * pos = Fuzz_Data;\n")
            for line in self.gen_func_params:
                f.write("    " + line)

            # generate function call
            if func["return_type"] != "void":
                f.write("    " + func["return_type"] +
                        " futag_target = " + func["func_name"] + "(")
                param_list = []
                for arg in func["params"]:
                    param_list.append(arg["param_name"] + " ")
                f.write(",".join(param_list))
                f.write(");\n")
            else:
                f.write("futag_target = " + func["func_name"] + "(")
                param_list = []
                for arg in func["params"]:
                    param_list.append(arg["param_name"] + " ")
                f.write(",".join(param_list))
                f.write(");\n")

            if func["return_type_pointer"]:
                f.write("    if(futag_target) free(futag_target);\n")

            for line in self.gen_free:
                f.write("    " + line)

            f.write("    return 0;\n")
            f.write("}")
            f.close()
            return None

        curr_param = func["params"][param_id]

        if curr_param["generator_type"] == 0:  # GEN_BUILTIN
            if curr_param["param_usage"] == "SIZE_FIELD":
                print("GEN_SIZE")
                curr_gen = self.gen_size(
                    curr_param["param_type"], curr_param["param_name"])
            else:
                print("GEN_BUILTIN")
                curr_gen = self.gen_builtin(
                    curr_param["param_type"], curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False
                return None

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 1:  # GEN_STRING
            if(curr_param["param_usage"] == "FILE_PATH" or curr_param["param_name"] == "filename"):
                print("GEN_FILE_PATH")
                curr_gen = self.gen_input_file(curr_param["param_name"])
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                # self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")
            else:
                print("GEN_STRING")
                curr_gen = self.gen_string(
                    curr_param["param_type"],
                    curr_param["param_name"],
                    curr_param["parent_type"])
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 2:  # GEN_ENUM

            print("GEN_ENUM")
            curr_gen = self.gen_enum(
                curr_param["param_type"], curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 3:  # GEN_ARRAY
            print("GEN_ARRAY")
            curr_gen = self.gen_array(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 4:  # GEN_VOID
            print("GEN_VOID")
            curr_gen = self.gen_void(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 5:  # GEN_QUALIFIER
            print("GEN_QUALIFIER")
            curr_gen = self.gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 6:  # GEN_POINTER
            print("GEN_POINTER")
            curr_gen = self.gen_pointer(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 7:  # GEN_STRUCT
            print("GEN_STRUCT")
            curr_gen = self.gen_struct(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 8:  # GEN_INCOMPLETE
            print("GEN_INCOMPLETE")
            # iterate all possible variants for generating
            old_func_params = copy.copy(self.gen_func_params)
            old_gen_free = copy.copy(self.gen_free)
            old_dyn_size = copy.copy(self.dyn_size)
            old_buf_size_arr = copy.copy(self.buf_size_arr)
            curr_gen = False
            for f in self.target_library['functions']:
                if f["return_type"] == curr_param["param_type"] and f["func_name"] != func["func_name"]:
                    # check for function call with simple data type!!!
                    check_params = True
                    for arg in f["params"]:
                        if arg["generator_type"] not in [0, 1]:
                            check_params = False
                            break
                    if not check_params:
                        continue

                    curr_gen = self.gen_var_function(
                        f, curr_param["param_name"])
                    self.gen_func_params += curr_gen["gen_lines"]
                    self.gen_free += curr_gen["gen_free"]
                    self.dyn_size += curr_gen["dyn_size"]
                    self.buf_size_arr += curr_gen["buf_size_arr"]
                    param_id += 1
                    self.gen_target_function(func, param_id)

                    param_id -= 1

                    self.gen_func_params = copy.copy(old_func_params)
                    self.gen_free = copy.copy(old_gen_free)
                    self.dyn_size = copy.copy(old_dyn_size)
                    self.buf_size_arr = copy.copy(old_buf_size_arr)

            # curr_gen = self.gen_incomplete(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

        if curr_param["generator_type"] == 9:  # GEN_FUNCTION
            print("GEN_FUNCTION")
            # return null pointer to function?
            curr_gen = self.gen_function(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 10:  # GEN_INPUT_FILE
            print("GEN_INPUT_FILE")
            curr_gen = self.gen_input_file(curr_param["param_name"])
            self.dyn_size += 1
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 11:  # GEN_OUTPUT_FILE
            print("GEN_OUTPUT_FILE")
            curr_gen = self.gen_output_file(curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"]+")")

            param_id += 1
            self.gen_target_function(func, param_id)

        if curr_param["generator_type"] == 12:  # GEN_UNKNOWN
            print("GEN_UNKNOWN")
            self.gen_this_function = False
            return None

    def gen_targets(self):
        for func in self.target_library["functions"]:
            if(func["fuzz_it"]):
                self.gen_func_params = []
                self.gen_free = []
                self.gen_this_function = True
                self.buf_size_arr = []
                self.dyn_size = 0
                print("Generating fuzz-driver for function: " +
                      func["func_name"])
                self.gen_target_function(func, 0)

    def compile_targets(self):
        '''Tries to compile all fuzz-drivers inside targets directory
        '''
        include_subdir: List[pathlib.Path] = [x for x in (self.library_root).iterdir() if x.is_dir()]
        include_subdir = include_subdir + \
            [x for x in (self.library_root / "build").iterdir() if x.is_dir()]
        include_subdir = include_subdir + \
            [x for x in (self.library_root / "build/install").iterdir() if x.is_dir()]
        include_subdir = include_subdir + \
            [x for x in (self.library_root / "build/install/include").iterdir() if x.is_dir()]
        generated_functions = [x for x in self.output_path.iterdir() if x.is_dir()]

        for dir in generated_functions:
            # Extract compiler cwd, to resolve relative includes
            compilation_cwd = pathlib.Path(self.target_library['cwd'])
            current_func = [f for f in self.target_library['functions'] if f['func_name'] == dir.name][0]
            current_func_compilation_opts = current_func['compiler_opts'].split(' ')
            # Extract all include locations from compilation options
            include_paths: List[pathlib.Path] = map(
                pathlib.Path,
                map(
                    current_func_compilation_opts.__getitem__,
                    [i + 1 for i, x in enumerate(current_func_compilation_opts) if x == '-I']
                ))

            resolved_include_paths: List[pathlib.Path] = []
            for include_path in include_paths:
                if include_path.is_absolute():
                    resolved_include_paths.append(include_path)
                else:
                    # Resolve relative include paths (e.g. in this case: -I.. -I.)
                    resolved_include_paths.append((compilation_cwd / include_path).resolve())

            for target_src in [t for t in dir.glob("*.c") if t.is_file()]:
                compiler_path = self.futag_package_path / "bin/clang"

                compiler_flags = [
                    compiler_path.as_posix(),
                    "-fsanitize=fuzzer",
                    target_src.as_posix()
                ]
                for i in include_subdir:
                    compiler_flags.append("-I" + i.as_posix())
                for i in resolved_include_paths:
                    compiler_flags.append("-I" + i.as_posix())

                compiler_flags.append("-o")
                compiler_flags.append(dir.as_posix() + "/" + target_src.stem + ".out")
                compiler_flags.append("-Wl,--start-group")
                for target_lib in [u for u in (self.library_root / "build/install/lib").glob("*.a") if u.is_file()]:
                    compiler_flags.append(target_lib.as_posix())
                compiler_flags.append("-Wl,--end-group")

                # TODO: multiprocess compilation
                p = Popen(
                    compiler_flags,
                    # stdout=PIPE,
                    # stderr=PIPE,
                    universal_newlines=True,
                )
                print(format(p.args))
                exit_code = p.wait()

                if exit_code == 0:
                    print(f'Target: {target_src.stem} compiled successfully')
                else:
                    print(f'Compilation failed for target: {target_src.stem}')
