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

using namespace std;
using namespace llvm;
using namespace clang;

namespace futag {

typedef enum {
  OBJECT_TYPE,
  FUNCTION_TYPE,
  INCOMPLETE_TYPE,
} TypePartition;

typedef enum {
  GEN_BUILTIN,
  GEN_STRING,
  GEN_ENUM,
  GEN_ARRAY,
  GEN_VOID,
  GEN_QUALIFIER,
  GEN_POINTER,
  GEN_STRUCT,
  GEN_INCOMPLETE,
  GEN_FUNCTION,
  GEN_INPUT_FILE,
  GEN_OUTPUT_FILE,
  GEN_UNKNOWN,
} GenType;

typedef struct {
  string type_name;
  string parent_qualifier;
  TypePartition partition;
  GenType generator_type;
  bool is_pointer = false;
  uint64_t array_size;
  string gen_var_function = ""; // save the function name for generating if
                                // generator_type == GEN_FUNCTION
  string gen_var_struct = "";   // save the function name for generating if
                                // generator_type == GEN_STRUCT
} QualTypeDetail;

typedef struct {
  vector<QualTypeDetail> sequence;
} TypeSequence;

typedef struct {
  string name;
  unsigned char size;
  vector<string> items;
} EnumDetail;

typedef struct {
  string name;
  string decl_name;
} TypedefDetail;

typedef struct {
  string name;
  bool genok;
  futag::TypeSequence return_type;
  QualType return_qualtype;
  vector<futag::TypeSequence> params;
} FunctionDetail;

typedef struct {
  string name;
  futag::TypeSequence type;
} FuncParam;

typedef struct {
  string name;
  futag::TypeSequence type_sequence;
} StructFieldDetail;

typedef struct {
  string name;
  bool incomplete;
  vector<futag::StructFieldDetail> fields;
} StructDetail;

typedef struct {
} FutagTaget;

typedef struct {
  vector<TypedefDetail> typedefdecl_list;
  vector<string> gen4types;
  vector<string> size_limit;
  vector<string> args_list;
  vector<string> free_vars;
  string function_name;
  QualType return_qualtype;
  int cstring_count;
} genstruct;

struct argu {
  string type;
  string name;
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

vector<FunctionDetail>
searchInReturnType(QualTypeDetail type_detail,
                   vector<FunctionDetail> funcdecl_list,
                   vector<futag::StructDetail> struct_decl_list);
FunctionDetail *
searchParamInReturnType(futag::TypeSequence *param,
                        vector<FunctionDetail> *funcdecl_list,
                        vector<futag::StructDetail> *struct_decl_list);
FunctionDetail *
searchParamTypeInReturnType(futag::QualTypeDetail *paramType,
                            vector<FunctionDetail> *funcdecl_list,
                            vector<futag::StructDetail> *struct_decl_list);

futag::QualTypeDetail *
findTypeDetailByName(string type_name, vector<futag::QualTypeDetail> type_list);

futag::QualTypeDetail *
findTypeDetailInTypedef(futag::QualTypeDetail type,
                        vector<futag::TypedefDetail> typedefdecl_list,
                        vector<futag::QualTypeDetail> type_list);

QualTypeDetail getQualTypeDetail(QualType type);

futag::TypeSequence getTypeSequenceFromQualType(QualType type);

void printQualTypeSequence(futag::TypeSequence qd);

void gen_var_function_by_name(string var_name, string function_name,
                              vector<futag::FunctionDetail> *funcdecl_list,
                              vector<futag::EnumDetail> *enumdecl_list,
                              futag::genstruct *generator);

string gen_enum_value(unsigned char random_value, EnumDetail enum_detail);

void gen_builtin(string var_name, QualTypeDetail type,
                 futag::genstruct *generator);

void gen_string(string var_name, QualTypeDetail type,
                futag::genstruct *generator);

void gen_string_4Crusher(string var_name, QualTypeDetail type,
                         futag::genstruct *generator);

void gen_enum(string var_name, QualTypeDetail type,
              vector<futag::EnumDetail> *enumdecl_list,
              futag::genstruct *generator);

void gen_qualifier(string var_name, string last_var_name, QualTypeDetail type,
                   futag::genstruct *generator);

void gen_pointer(string var_name, string last_var_name, QualTypeDetail type,
                 futag::genstruct *generator);

void gen_array(string var_name, QualTypeDetail type,
               futag::genstruct *generator);
void gen_struct(string var_name, StructDetail _struct,
                futag::genstruct *generator);
void gen_struct_by_name(string var_name, string struct_name,
                        vector<futag::StructDetail> *struct_decl_list,
                        vector<futag::EnumDetail> *enumdecl_list,
                        futag::genstruct *generator);
bool check_enumtype(QualType qt, vector<futag::TypedefDetail> typedefdecl_list);

// * Data types followed by: https://en.cppreference.com/w/c/language/type
typedef enum {
  _BUILTIN,    // 0: All basic types: int, float, double,...
  _STRING,     // 1: char *, const char *
  _ENUM,       // 2
  _ARRAY,      // 3
  _VOIDP,      // 4
  _QUALIFIER,  // 5: const, volatile, and restrict qualifiers
  _POINTER,    // 6
  _STRUCT,     // 7
  _INCOMPLETE, // 8
  _FUNCTION,   // 9
  _INPUT_FILE, //10
  _OUTPUT_FILE,//11
  _UNKNOWN,    // 12
} DataType;

typedef struct {
  DataType generator_type;
  bool is_pointer = false;
  uint64_t array_size = 0; // for saving the size of array, for example int[30]
  std::string type_name = "";
  std::string parent_type = "";
  std::string gen_var_struct = ""; // save the function name for generating if
                                   // generator_type == GEN_STRUCT
} DataTypeDetail;

DataTypeDetail getDataTypeDetail(QualType type);

} // namespace futag

#endif // FUTAG_BASIC_H