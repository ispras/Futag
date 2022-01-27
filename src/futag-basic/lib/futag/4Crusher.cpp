//===-- Basic.cpp -------*- C++ -*-===//
//
// This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
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

#include "futag/4Crusher.h"

#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "clang/AST/Type.h"
#include "clang/Tooling/Tooling.h"
#include "futag/Basic.h"

using namespace std;
using namespace llvm;
using namespace clang;
using namespace tooling;
using namespace futag;
namespace futag {

void gen_wrapper_4Crusher(ofstream *fuzz_file, vector<string> include_headers,
                          futag::genstruct *generator) {
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
  *fuzz_file << "int main(int argc, char* argv[]) {\n";
  *fuzz_file << "    if (argc < 2) return 1;\n";
  *fuzz_file << "    char *buffer = NULL;\n";
  *fuzz_file << "    FILE *fp = fopen(argv[1], \"r\");\n";
  *fuzz_file << "    if (fp != NULL) {\n";
  *fuzz_file << "        //Find end of file\n";
  *fuzz_file << "        if (fseek(fp, 0L, SEEK_END) == 0) {\n";
  *fuzz_file << "            long bufsize = ftell(fp);\n";
  *fuzz_file << "            if (bufsize == -1) { return 1; };\n";
  *fuzz_file << "            buffer = (char *) malloc(sizeof(char) * (bufsize + 1));\n";
  *fuzz_file << "            if (fseek(fp, 0L, SEEK_SET) != 0) { return 1;};\n";
  *fuzz_file << "            size_t newLen = fread(buffer, sizeof(char), bufsize, fp);\n";
  *fuzz_file << "            if ( ferror( fp ) != 0 ) { return 1;}\n";
  *fuzz_file << "            else { buffer[newLen++] = '\\0'; }\n";
  *fuzz_file << "            if(newLen <= ";
  unsigned char count = 0;
  string total_size = "";
  for (auto s : generator->size_limit) {
    total_size += s;
    count++;
    if (count < generator->size_limit.size()) {
      total_size += " + ";
    }
  }
  *fuzz_file << total_size;
  *fuzz_file << ") return 0;\n";
  *fuzz_file << "            char * pos = buffer;\n\n";
  vector<string>::iterator l;

  if (generator->cstring_count > 0) {
    *fuzz_file << "            unsigned int futag_cstr_size = (unsigned int) "
                  "((bufsize - (" +
                      total_size + "))/" + to_string(generator->cstring_count) +
                      "); \n";
  }

  for (l = generator->gen4types.begin(); l != generator->gen4types.end(); l++) {
    *fuzz_file << "            " << *l;
  }

  *fuzz_file << "            " + generator->function_name + "(";

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
    *fuzz_file << "            " << *l;
  }
  *fuzz_file << "        }\n";
  *fuzz_file << "       fclose(fp);\n";
  *fuzz_file << "    }\n";
  
  *fuzz_file << "    free(buffer);\n";
  *fuzz_file << "    return 0;\n";
  *fuzz_file << "}";
  return;
}
// void gen_wrapper_4Crusher_cplusplus(ofstream *fuzz_file, vector<string> include_headers,
//                           futag::genstruct *generator) {
//   *fuzz_file << "#include <stdint.h>\n";
//   *fuzz_file << "#include <stddef.h>\n";
//   *fuzz_file << "#include <string.h>\n";
//   *fuzz_file << "#include <cstring>\n";
//   *fuzz_file << "#include <fstream>\n\n";
//   for (vector<string>::iterator it = include_headers.begin();
//        it != include_headers.end(); ++it) {
//     *fuzz_file << *it + " \n";
//   }

//   // Beging writing libfuzzer function
//   *fuzz_file << "int main(int argc, char* argv[]) {\n";
//   *fuzz_file << "    if (argc < 2) return 0;\n";
//   *fuzz_file << "    std::ifstream crusher_input; \n";
//   *fuzz_file << "    crusher_input.open(argv[1], std::ifstream::in);\n";
//   *fuzz_file << "    if (crusher_input.is_open()) {\n";
//   *fuzz_file << "        char* buffer;\n";
//   *fuzz_file << "        size_t buffer_length;\n";
//   *fuzz_file << "        // get length of file\n";
//   *fuzz_file << "        crusher_input.seekg(0, crusher_input.end);\n";
//   *fuzz_file << "        buffer_length = crusher_input.tellg();\n";
//   *fuzz_file << "        crusher_input.seekg(0, crusher_input.beg);\n";
//   *fuzz_file << "        buffer = new char (buffer_length +1);\n";
//   *fuzz_file << "        crusher_input.read(buffer, buffer_length);\n";
//   *fuzz_file << "        crusher_input.close();\n";
//   *fuzz_file << "        if(buffer_length <= ";
//   unsigned char count = 0;
//   string total_size = "";
//   for (auto s : generator->size_limit) {
//     total_size += s;
//     count++;
//     if (count < generator->size_limit.size()) {
//       total_size += " + ";
//     }
//   }
//   *fuzz_file << total_size;
//   *fuzz_file << ") return 0;\n";
//   *fuzz_file << "        char * pos = buffer;\n\n";
//   vector<string>::iterator l;

//   if (generator->cstring_count > 0) {
//     *fuzz_file << "        unsigned int futag_cstr_size = (unsigned int) "
//                   "((buffer_length - (" +
//                       total_size + "))/" + to_string(generator->cstring_count) +
//                       "); \n";
//   }

//   for (l = generator->gen4types.begin(); l != generator->gen4types.end(); l++) {
//     *fuzz_file << "        " << *l;
//   }

//   *fuzz_file << "        " + generator->function_name + "(";

//   count = 0;
//   for (l = generator->args_list.begin(); l != generator->args_list.end(); l++) {
//     count++;
//     *fuzz_file << *l;
//     if (count < generator->args_list.size()) {
//       *fuzz_file << ", ";
//     }
//   }

//   *fuzz_file << ");\n";
//   for (l = generator->free_vars.begin(); l != generator->free_vars.end(); l++) {
//     *fuzz_file << "        " << *l;
//   }
//   *fuzz_file << "    }\n";
//   *fuzz_file << "    return 0;\n";
//   *fuzz_file << "}";
//   return;
// }
}  // namespace futag