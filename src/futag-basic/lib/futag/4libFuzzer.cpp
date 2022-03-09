//===-- Basic.cpp -------*- C++ -*-===//
//
// This file is distributed under the GPL v3 license
// (https://www.gnu.org/licenses/gpl-3.0.en.html).
//

/***********************************************/
/*      ______  __  __  ______  ___     ______ */
/*     / ____/ / / / / /_  __/ /   |   / ____/ */
/*    / /_    / / / /   / /   / /| |  / / __   */
/*   / __/   / /_/ /   / /   / ___ | / /_/ /   */
/*  /_/      \____/   /_/   /_/  |_| \____/    */
/*                                             */
/*     Fuzzing target Automated Generator      */
/*             a tool of ISP RAS               */
/*                                             */
/***********************************************/

#include "futag/4libFuzzer.h"

#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "futag/Basic.h"
#include "clang/AST/Type.h"
#include "clang/Tooling/Tooling.h"

using namespace std;
using namespace llvm;
using namespace clang;
using namespace tooling;
using namespace futag;
namespace futag {
void gen_wrapper_4libFuzzer(ofstream *fuzz_file, vector<string> include_headers,
                            futag::genstruct *generator) {

  unsigned char count = 0;
  string total_size = "";
  for (auto s : generator->size_limit) {
    total_size += s;
    count++;
    if (count < generator->size_limit.size()) {
      total_size += " + ";
    }
  }
  if (!total_size.length())
    return;

  *fuzz_file << "#include <stdio.h>\n";
  *fuzz_file << "#include <stdlib.h>\n";
  *fuzz_file << "#include <stdint.h>\n";
  *fuzz_file << "#include <stddef.h>\n";
  *fuzz_file << "#include <string.h>\n";
  *fuzz_file << "#include <cstring>\n";

  for (vector<string>::iterator it = include_headers.begin();
       it != include_headers.end(); ++it) {
    *fuzz_file << *it + " \n";
  }

  // Beging writing libfuzzer function
  *fuzz_file << "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, "
                "size_t Size) {\n";

  *fuzz_file << "    if(Size <= " + total_size + ") return 0;\n";
  *fuzz_file << "    uint8_t * pos = (uint8_t *) Data;\n\n";
  vector<string>::iterator l;

  if (generator->cstring_count > 0) {
    *fuzz_file
        << "    unsigned int futag_cstr_size = (unsigned int) ((Size - (" +
               total_size + "))/" + to_string(generator->cstring_count) +
               "); \n";
  }

  for (l = generator->gen4types.begin(); l != generator->gen4types.end(); l++) {
    *fuzz_file << "    " << *l;
  }

  if (generator->return_qualtype.getAsString() != "void") {
    *fuzz_file << "    " << generator->return_qualtype.getAsString()
               << " fuzz_target = " + generator->function_name + "(";
  } else {
    *fuzz_file << "    " + generator->function_name + "(";
  }

  count = 0;
  for (l = generator->args_list.begin(); l != generator->args_list.end(); l++) {
    count++;
    *fuzz_file << *l;
    if (count < generator->args_list.size()) {
      *fuzz_file << ", ";
    }
  }

  *fuzz_file << ");\n";
  for (l = generator->free_vars.begin(); l != generator->free_vars.end(); l++) {
    *fuzz_file << "    " << *l;
  }
  if (generator->return_qualtype.getAsString() == "void" ||
      futag::getQualTypeDetail(generator->return_qualtype).generator_type ==
          GEN_STRUCT ||
      futag::getQualTypeDetail(generator->return_qualtype).generator_type ==
          GEN_ENUM) {
    *fuzz_file << "    return 0;\n";
  } else {

    *fuzz_file << "    if(fuzz_target) {\n";

    if (generator->return_qualtype->isPointerType()) {
      if (generator->return_qualtype->getPointeeType().hasLocalQualifiers()) {
        std::string rt_str = generator->return_qualtype.getAsString();
        std::string qualifier = generator->return_qualtype->getPointeeType()
                                    .getLocalQualifiers()
                                    .getAsString();
        size_t index = 0;
        index = rt_str.find(qualifier, index);
        rt_str.replace(index, qualifier.length(), "");
        *fuzz_file << "        free( (" + rt_str + ") fuzz_target);\n";
      } else {
        *fuzz_file << "        free(fuzz_target);\n";
      }
    }
    *fuzz_file << "        return 0;\n";
    *fuzz_file << "    } else {\n";
    *fuzz_file << "        return 1;\n";
    *fuzz_file << "    }\n";
  }
  *fuzz_file << "}\n";

  return;
}
} // namespace futag