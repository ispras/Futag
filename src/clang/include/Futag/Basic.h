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

namespace futag
{

  class FutagType
  {
  public:
    enum Type
    {
      CONST_VAL,
      DECL_REF,
      FUNCTION_CALL_RESULT,
      UNKNOWN
    };

    static const std::map<Type, std::string> c_typesToNames;
    static const std::map<std::string, Type> c_namesToTypes;

    static inline std::string TypeToString(Type type)
    {
      return c_typesToNames.at(type);
    }

    static std::string ConstValStr() { return TypeToString(CONST_VAL); }

    static std::string DeclRefStr() { return TypeToString(DECL_REF); }

    static std::string FuncCallResStr()
    {
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

  // Function for check if current type is simple type: a type or its qualified, pointee type is builtin
  bool isSimpleType(QualType type);
  bool isSimpleRecord(const RecordDecl *rd);
  bool isSimpleFunction(const FunctionDecl *fd);

  // * Data types followed by: https://en.cppreference.com/w/c/language/type
  typedef enum
  {
    _BUILTIN,     // 0: All basic types: int, float, double,...
    _STRING,      // 1: char *, const char *
    _ENUM,        // 2
    _ARRAY,       // 3
    _VOIDP,       // 4
    _QUALIFIER,   // 5: const, volatile, and restrict qualifiers
    _POINTER,     // 6
    _STRUCT,      // 7
    _UNION,       // 8
    _CLASS,       // 9
    _INCOMPLETE,  // 10
    _FUNCTION,    // 11
    _INPUT_FILE,  // 12
    _OUTPUT_FILE, // 13
    _UNKNOWN,     // 14
  } FutagDataType;

  typedef enum
  {
    _CLASS_RECORD,
    _UNION_RECORD,
    _STRUCT_RECORD,
    _UNKNOW_RECORD
  } FutagRecordType;

  typedef enum
  {
    _FUNC_CXXMETHOD,
    _FUNC_CONSTRUCTOR,
    _FUNC_DEFAULT_CONSTRUCTOR,
    _FUNC_DESTRUCTOR,
    _FUNC_GLOBAL,
    _FUNC_STATIC,
    _FUNC_UNKNOW_RECORD
  } FunctionType;

  typedef struct
  {
    FutagDataType generator_type;
    bool is_pointer = false;
    uint64_t array_size = 0; // for saving the size of array, for example int[30]
    std::string type_name = "";
    std::string parent_type = "";
    std::string parent_gen = ""; // save the function name for generating if
                                 // generator_type == GEN_STRUCT
  } DataTypeDetail;

  DataTypeDetail getDataTypeDetail(QualType type);
  typedef vector<DataTypeDetail> DecomposedType;

  typedef enum
  {
    F_BUILTIN,        // 0: All basic types: int, float, double,...
    F_STRING,         // 1: char *, const char *
    F_ENUM,           // 2
    F_ARRAY,          // 3
    F_VOIDP,          // 4
    F_QUALIFIER,      // 5: const, volatile, and restrict qualifiers
    F_POINTER,        // 6
    F_STRUCT,         // 7
    F_UNION,          // 8
    F_CLASS,          // 9
    F_INCOMPLETE,     // 10
    F_FUNCTION,       // 11
    F_INPUT_CXXFILE,  // 12
    F_OUTPUT_CXXFILE, // 13
    F_CXXFILE,        // 14
    F_CFILE,          // 15
    F_UNKNOWN,        // 16
  } FutagGenType;

  typedef struct
  {
    FutagGenType gen_type;
    std::string base_type_name; // Unqualified type or Element type of array or Pointee type
    std::string curr_type_name; // current type
    std::string local_qualifier;
    uint64_t length; // Length of array
  } GenFieldInfo;

  vector<GenFieldInfo> getGenField(QualType type);
  vector<GenFieldInfo> getGenType(QualType type);

  std::string GetFutagGenTypeFromIdx(FutagGenType idx);

} // namespace futag

#endif // FUTAG_BASIC_H