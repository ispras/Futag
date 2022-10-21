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

#ifndef FUTAG_BASIC_H
#define FUTAG_BASIC_H

#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "clang/AST/Type.h"
#include "clang/Tooling/Tooling.h"

#include <map>
#include <string>

using namespace std;
using namespace llvm;
using namespace clang;

namespace futag {

class FutagType {
public:
  enum Type { CONST_VAL, DECL_REF, FUNCTION_CALL_RESULT, UNKNOWN };

  static const std::map<Type, std::string> c_typesToNames;
  static const std::map<std::string, Type> c_namesToTypes;

  static inline std::string TypeToString(Type type) {
    return c_typesToNames.at(type);
  }

  static std::string ConstValStr() { return TypeToString(CONST_VAL); }

  static std::string DeclRefStr() { return TypeToString(DECL_REF); }

  static std::string FuncCallResStr() {
    return TypeToString(FUNCTION_CALL_RESULT);
  }

  static std::string UnknownStr() { return TypeToString(UNKNOWN); }

  static Type NameToType(std::string type) { return c_namesToTypes.at(type); }
};

char *replace_char(char *str, char find, char replace);

bool dir_exists(const char *path);

// Create directory for fuzz-targets
const char *create_target_dir(string dir_name);

// Generate function file name with suffix of parameters
const char *get_function_filename(string name, vector<string> params);

// Generate target filename and try to open file, if not - return empty string
const char *get_target_file(string dir_name, const char *function_filename);

string trim(string str);

vector<string> explode(string line, char delimiter);

// * Data types followed by: https://en.cppreference.com/w/c/language/type
typedef enum {
  _BUILTIN,     // 0: All basic types: int, float, double,...
  _STRING,      // 1: char *, const char *
  _ENUM,        // 2
  _ARRAY,       // 3
  _VOIDP,       // 4
  _QUALIFIER,   // 5: const, volatile, and restrict qualifiers
  _POINTER,     // 6
  _STRUCT,      // 7
  _INCOMPLETE,  // 8
  _FUNCTION,    // 9
  _INPUT_FILE,  // 10
  _OUTPUT_FILE, // 11
  _UNKNOWN,     // 12
} DataType;

typedef enum {
  _CLASS_RECORD,
  _UNION_RECORD,
  _STRUCT_RECORD,
  _UNKNOW_RECORD
} RecordType;

typedef enum {
  _FUNC_CXXMETHOD,
  _FUNC_CONSTRUCTOR,
  _FUNC_DEFAULT_CONSTRUCTOR,
  _FUNC_DESTRUCTOR,
  _FUNC_GLOBAL,
  _FUNC_STATIC,
  _FUNC_UNKNOW_RECORD
} FunctionType;

typedef struct {
  DataType generator_type;
  bool is_pointer = false;
  uint64_t array_size = 0; // for saving the size of array, for example int[30]
  std::string type_name = "";
  std::string parent_type = "";
  std::string parent_gen = ""; // save the function name for generating if
                               // generator_type == GEN_STRUCT
} DataTypeDetail;

DataTypeDetail getDataTypeDetail(QualType type);

} // namespace futag

#endif // FUTAG_BASIC_H