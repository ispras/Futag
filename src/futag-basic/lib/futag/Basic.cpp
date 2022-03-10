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

#include "futag/Basic.h"

#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "clang/AST/Type.h"
#include "clang/Tooling/Tooling.h"

using namespace std;
using namespace llvm;
using namespace clang;
using namespace tooling;
using namespace futag;

namespace futag {

char *replace_char(char *str, char find, char replace) {
  char *current_pos = strchr(str, find);
  while (current_pos) {
    *current_pos = replace;
    current_pos = strchr(current_pos, find);
  }
  return str;
}

bool dir_exists(const char *path) {
  struct stat info;

  if (stat(path, &info) != 0)
    return false;
  else if (info.st_mode & S_IFDIR)
    return true;
  else
    return false;
}

// Create directory for fuzz-targets
const char *create_target_dir(string dir_name) {
  char *cdir_name = new char[dir_name.length() + 1];
  strcpy(cdir_name, dir_name.c_str());
  if (!dir_exists(cdir_name)) {
    mkdir(cdir_name, 0755);
  }
  return cdir_name;
}

// Generate function file name with suffix of parameters
const char *get_function_filename(string name, vector<string> params) {
  int size = 0;
  char delimiter[] = ".";

  const char *func_name = name.c_str();

  size += strlen(func_name);
  vector<string>::iterator j;
  for (j = params.begin(); j != params.end(); j++) {
    size += strlen(delimiter);
    size += j->length();
  }
  char *function_filename = (char *)malloc(size + 1);
  strcpy(function_filename, func_name);

  for (j = params.begin(); j != params.end(); j++) {
    string tmp = *j;
    char *tmp_param = new char[tmp.length() + 1];
    strcpy(tmp_param, tmp.c_str());

    char *param = futag::replace_char(tmp_param, ' ', '_');
    strcat(function_filename, delimiter);
    strcat(function_filename, param);
  }
  return function_filename;
}

// Generate target filename and try to open file, if not - return empty string
// ("")
const char *get_target_file(string dir_name, const char *function_filename) {
  char *cdir_name = new char[dir_name.length() + 1];
  strcpy(cdir_name, dir_name.c_str());

  char delimiter[] = "/";
  char *dir_path = (char *)malloc(
      strlen(cdir_name) + strlen(function_filename) + strlen(delimiter) + 1);
  strcpy(dir_path, cdir_name);

  strcat(dir_path, delimiter);
  strcat(dir_path, function_filename);
  if (!dir_exists(dir_path)) {
    mkdir(dir_path, 0755);
  }
  char extension[] = ".cc";
  char *file_full_path =
      (char *)malloc(strlen(dir_path) + strlen(delimiter) +
                     strlen(function_filename) + strlen(extension) + 1);
  strcpy(file_full_path, dir_path);
  strcat(file_full_path, delimiter);
  strcat(file_full_path, function_filename);
  strcat(file_full_path, extension);

  //   ofstream fuzz_target_file;
  //   fuzz_target_file.open(file_full_path);

  //   if (!fuzz_target_file.is_open()) {
  //     return "";
  //   }
  //   fuzz_target_file.close();
  return file_full_path;
}

string trim(string str) {
  while (str[0] == ' ' && str.length() > 0) {
    str = str.substr(1, str.length());
  }
  while (str[str.length() - 1] == ' ' && str.length() > 0) {
    str = str.substr(0, str.length() - 1);
  }
  return str;
}

vector<string> explode(string line, char delimiter) {
  vector<string> result;

  string copy_line = line;
  size_t pos = copy_line.find_first_of(delimiter);

  while (pos != string::npos) {
    string tmp = copy_line.substr(0, pos);
    result.insert(result.end(), trim(tmp));
    copy_line = copy_line.substr(pos + 1);
    pos = copy_line.find_first_of(delimiter);
  }
  result.insert(result.end(), trim(copy_line));
  return result;
}

vector<futag::FunctionDetail> searchInReturnType(
    futag::QualTypeDetail type_detail,
    vector<futag::FunctionDetail> funcdecl_list,
    vector<futag::StructDetail> struct_decl_list) {
  vector<futag::FunctionDetail> result_list;
  for (vector<futag::FunctionDetail>::iterator f_iter = funcdecl_list.begin();
       f_iter != funcdecl_list.end(); ++f_iter) {
    bool found = false;
    for (vector<futag::QualTypeDetail>::iterator r_iter =
             f_iter->return_type.sequence.begin();
         r_iter != f_iter->return_type.sequence.end(); ++r_iter) {
      if (r_iter->type_name == type_detail.type_name) {
        found = true;
        break;
      }
    }

    for (vector<futag::TypeSequence>::iterator p_iter = f_iter->params.begin();
         p_iter != f_iter->params.end(); ++p_iter) {
      if (p_iter->sequence[p_iter->sequence.size() - 1].generator_type ==
              futag::GEN_INCOMPLETE ||
          p_iter->sequence[p_iter->sequence.size() - 1].generator_type ==
              futag::GEN_UNKNOWN) {
        found = false;
        break;
      }
      if (p_iter->sequence[p_iter->sequence.size() - 1].generator_type ==
          futag::GEN_STRUCT) {
        vector<string> type_split = futag::explode(
            p_iter->sequence[p_iter->sequence.size() - 1].type_name, ' ');
        for (vector<futag::StructDetail>::iterator s_iter =
                 struct_decl_list.begin();
             s_iter != struct_decl_list.end(); ++s_iter) {
          if (type_split[1] != s_iter->name) continue;

          if (!s_iter->incomplete) {
            found = false;
          }
        }
      }
    }
    if (found) {
      result_list.insert(result_list.end(), *f_iter);
    }
  }
  return result_list;
}

FunctionDetail *searchParamTypeInReturnType(
    futag::QualTypeDetail *paramType,
    vector<futag::FunctionDetail> *funcdecl_list,
    vector<futag::StructDetail> *struct_decl_list) {
  for (vector<futag::FunctionDetail>::iterator f_iter = funcdecl_list->begin();
       f_iter != funcdecl_list->end(); ++f_iter) {
    if (paramType->type_name == f_iter->return_type.sequence[0].type_name &&
        f_iter->genok) {
      bool genok = true;
      for (vector<futag::TypeSequence>::iterator p_iter =
               f_iter->params.begin();
           p_iter != f_iter->params.end(); ++p_iter) {
        if (p_iter->sequence[p_iter->sequence.size() - 1].generator_type ==
                futag::GEN_INCOMPLETE ||
            p_iter->sequence[p_iter->sequence.size() - 1].generator_type ==
                futag::GEN_UNKNOWN) {
          genok = false;
          break;
        }
        if (p_iter->sequence[p_iter->sequence.size() - 1].generator_type ==
            futag::GEN_STRUCT) {
          vector<string> type_split = futag::explode(
              p_iter->sequence[p_iter->sequence.size() - 1].type_name, ' ');
          for (vector<futag::StructDetail>::iterator s_iter =
                   struct_decl_list->begin();
               s_iter != struct_decl_list->end(); ++s_iter) {
            if (type_split[1] != s_iter->name) continue;
            if (s_iter->incomplete) {
              genok = false;
            } else {
              genok = true;
              break;
            }
          }
        }
        if (!genok) {
          break;
        }
      }
      if (genok) {
        return &*f_iter;
      }
    }
  }
  return NULL;
}

futag::QualTypeDetail *findTypeDetailByName(
    string type_name, vector<futag::QualTypeDetail> type_list) {
  for (vector<futag::QualTypeDetail>::iterator t_iter = type_list.begin();
       t_iter != type_list.end(); ++t_iter) {
    if (t_iter->type_name == type_name) {
      return &(*t_iter);
    }
  }
  return nullptr;
}

futag::QualTypeDetail *findTypeDetailInTypedef(
    futag::QualTypeDetail type, vector<futag::TypedefDetail> typedefdecl_list,
    vector<futag::QualTypeDetail> type_list) {
  for (vector<futag::TypedefDetail>::iterator td_iter =
           typedefdecl_list.begin();
       td_iter != typedefdecl_list.end(); ++td_iter) {
    if (td_iter->decl_name == type.type_name) {
      return findTypeDetailByName(td_iter->name, type_list);
    }
  }
  return nullptr;
}

QualTypeDetail getQualTypeDetail(QualType type) {
  QualTypeDetail qual_type_detail;
  qual_type_detail.array_size = 1;
  qual_type_detail.type_name = type.getAsString();
  qual_type_detail.parent_qualifier = "";
  qual_type_detail.generator_type = futag::GEN_UNKNOWN;
  if (!type->isIncompleteOrObjectType()) {
    qual_type_detail.partition = futag::FUNCTION_TYPE;
    qual_type_detail.generator_type = futag::GEN_UNKNOWN;
    return qual_type_detail;
  } else {
    if (type->isIncompleteType()) {
      qual_type_detail.partition = futag::INCOMPLETE_TYPE;
      qual_type_detail.generator_type = futag::GEN_INCOMPLETE;
    } else {
      qual_type_detail.partition = futag::OBJECT_TYPE;
    }
  }
  if (type.getAsString() == "char *" || type.getAsString() == "const char *" ||
      type.getAsString() == "const unsigned char *" ||
      type.getAsString() == "unsigned char *") {
    qual_type_detail.generator_type = futag::GEN_STRING;
    if (type.getAsString() == "const char *" ||
        type.getAsString() == "const unsigned char *") {
      qual_type_detail.parent_qualifier = "const";
    }
    return qual_type_detail;
  }
  if (type.hasLocalQualifiers()) {
    qual_type_detail.generator_type = futag::GEN_QUALIFIER;
    qual_type_detail.parent_qualifier = type.getLocalQualifiers().getAsString();
    return qual_type_detail;
  }
  if (type.getAsString() == "void *" || type.getAsString() == "const void *") {
    qual_type_detail.generator_type = futag::GEN_UNKNOWN;
    return qual_type_detail;
  }
  if (type.getCanonicalType().getAsString() == "void" ||
      type.getCanonicalType().getAsString() == "void *") {
    qual_type_detail.generator_type = futag::GEN_UNKNOWN;
    return qual_type_detail;
  }
  if (type->isBuiltinType()) {
    qual_type_detail.generator_type = futag::GEN_BUILTIN;
    return qual_type_detail;
  }
  if (type.getAsString().find("enum ") != std::string::npos &&
      type.getAsString().find("enum ") == 0) {
    qual_type_detail.generator_type = futag::GEN_ENUM;

    return qual_type_detail;
  }
  if (type->isPointerType()) {
    if (!type->getPointeeType()->isIncompleteOrObjectType()) {
      qual_type_detail.generator_type = futag::GEN_VOID;
      return qual_type_detail;
    }
    qual_type_detail.generator_type = futag::GEN_POINTER;
    qual_type_detail.is_pointer = true;
    return qual_type_detail;
  }
  if (type->isConstantArrayType()) {
    auto t = dyn_cast<ConstantArrayType>(type);
    if (!t) {
      qual_type_detail.generator_type = futag::GEN_BUILTIN;
      return qual_type_detail;
    }
    qual_type_detail.type_name =
        type->getAsArrayTypeUnsafe()->getElementType().getAsString();
    qual_type_detail.generator_type = futag::GEN_ARRAY;
    qual_type_detail.array_size = t->getSize().getSExtValue();
    return qual_type_detail;
  }
  vector<string> type_split = futag::explode(qual_type_detail.type_name, ' ');
  if (std::find(type_split.begin(), type_split.end(), "struct") !=
      type_split.end()) {
    qual_type_detail.generator_type = futag::GEN_STRUCT;
    return qual_type_detail;
  }

  return qual_type_detail;
}

futag::TypeSequence getTypeSequenceFromQualType(QualType type) {
  int init_types[] = {futag::GEN_STRING, futag::GEN_BUILTIN, futag::GEN_ENUM,
                      futag::GEN_VOID, futag::GEN_ARRAY};
  futag::TypeSequence return_type;
  QualTypeDetail type_detail = futag::getQualTypeDetail(type);
  return_type.sequence.insert(return_type.sequence.end(), type_detail);
  if (std::find(init_types, init_types + 5, type_detail.generator_type) !=
      init_types + 5) {
    return return_type;
  }
  while (type->isPointerType()) {
    type = type->getPointeeType();
    QualTypeDetail type_detail = futag::getQualTypeDetail(type);
    return_type.sequence.insert(return_type.sequence.end(), type_detail);
    if (std::find(init_types, init_types + 3, type_detail.generator_type) !=
        init_types + 3) {
      return return_type;
    }
  }
  if (type.hasLocalQualifiers()) {
    type = type.getLocalUnqualifiedType();
    QualTypeDetail type_detail = futag::getQualTypeDetail(type);
    return_type.sequence.insert(return_type.sequence.end(), type_detail);
    if (std::find(init_types, init_types + 3, type_detail.generator_type) !=
        init_types + 3) {
      return return_type;
    }
  }
  QualType canonical_type = type.getCanonicalType();
  if (canonical_type.getAsString() != type.getAsString()) {
    QualTypeDetail type_detail = futag::getQualTypeDetail(canonical_type);
    return_type.sequence.insert(return_type.sequence.end(), type_detail);
    if (std::find(init_types, init_types + 3, type_detail.generator_type) !=
        init_types + 3) {
      return return_type;
    }
  }
  while (canonical_type->isPointerType()) {
    canonical_type = canonical_type->getPointeeType();
    QualTypeDetail type_detail = futag::getQualTypeDetail(canonical_type);
    return_type.sequence.insert(return_type.sequence.end(), type_detail);
    if (std::find(init_types, init_types + 3, type_detail.generator_type) !=
        init_types + 3) {
      return return_type;
    }
  }
  if (canonical_type.hasLocalQualifiers()) {
    canonical_type = canonical_type.getLocalUnqualifiedType();
    QualTypeDetail type_detail = futag::getQualTypeDetail(canonical_type);
    return_type.sequence.insert(return_type.sequence.end(), type_detail);
    if (std::find(init_types, init_types + 3, type_detail.generator_type) !=
        init_types + 3) {
      return return_type;
    }
  }
  return return_type;
}

void printQualTypeSequence(futag::TypeSequence qd) {
  for (vector<futag::QualTypeDetail>::iterator qt_iter = qd.sequence.begin();
       qt_iter != qd.sequence.end(); ++qt_iter) {
    llvm::outs() << " type \"" << qt_iter->type_name << "\", partition: ";
    switch (qt_iter->partition) {
      case futag::FUNCTION_TYPE:
        llvm::outs() << "FUNCTION_TYPE";
        break;
      case futag::INCOMPLETE_TYPE:
        llvm::outs() << "INCOMPLETE_TYPE";
        break;
      case futag::OBJECT_TYPE:
        llvm::outs() << "OBJECT_TYPE";
        break;
    }
    llvm::outs() << ", ";

    switch (qt_iter->generator_type) {
      case futag::GEN_BUILTIN:
        llvm::outs() << "GEN_BUILTIN";
        break;
      case futag::GEN_STRING:
        llvm::outs() << "GEN_STRING";
        break;
      case futag::GEN_ENUM:
        llvm::outs() << "GEN_ENUM";
        break;
      case futag::GEN_VOID:
        llvm::outs() << "GEN_VOID";
        break;
      case futag::GEN_QUALIFIER:
        llvm::outs() << "GEN_QUALIFIER";
        break;
      case futag::GEN_POINTER:
        llvm::outs() << "GEN_POINTER";
        break;
      case futag::GEN_STRUCT:
        llvm::outs() << "GEN_STRUCT";
        break;
      case futag::GEN_INCOMPLETE:
        llvm::outs() << "GEN_INCOMPLETE";
        break;
      case futag::GEN_FUNCTION:
      case futag::GEN_UNKNOWN:
        llvm::outs() << "GEN_UNKNOWN";
        break;
      case futag::GEN_ARRAY:
        llvm::outs() << "GEN_ARRAY";
        break;
    }
    llvm::outs() << ", " << qt_iter->parent_qualifier << "; ";
  }
  llvm::outs() << "\n";
}

void gen_var_function_by_name(string var_name, string function_name,
                              vector<futag::FunctionDetail> *funcdecl_list,
                              vector<futag::EnumDetail> *enumdecl_list,
                              futag::genstruct *generator) {
  futag::FunctionDetail *fd;
  for (vector<futag::FunctionDetail>::iterator f_iter = funcdecl_list->begin();
       f_iter != funcdecl_list->end(); ++f_iter) {
    if (function_name == f_iter->name) {
      fd = &*f_iter;
      break;
    }
  }

  unsigned int index = 0;
  string arg_lines = "";
  for (vector<futag::TypeSequence>::iterator field = fd->params.begin();
       field != fd->params.end(); ++field) {
    string last_var_name = "";
    for (vector<futag::QualTypeDetail>::reverse_iterator f_iter =
             field->sequence.rbegin();
         f_iter != field->sequence.rend(); ++f_iter) {
      if (f_iter->generator_type == futag::GEN_BUILTIN) {
        gen_builtin(var_name + "_" + to_string(index), *f_iter, generator);
        last_var_name = var_name + "_" + to_string(index);
      }
      if (f_iter->generator_type == futag::GEN_STRING) {
        gen_string(var_name + "_" + to_string(index), *f_iter, generator);
        last_var_name = var_name + "_" + to_string(index);
      }
      if (f_iter->generator_type == futag::GEN_ENUM) {
        gen_enum(var_name, *f_iter, enumdecl_list, generator);
        last_var_name = var_name;
      }
      if (f_iter->generator_type == futag::GEN_QUALIFIER) {
        gen_qualifier("q_" + last_var_name, last_var_name, *f_iter, generator);
        last_var_name = "q_" + last_var_name;
      }
      if (f_iter->generator_type == futag::GEN_POINTER) {
        gen_pointer("p_" + last_var_name, last_var_name, *f_iter, generator);
        last_var_name = "p_" + last_var_name;
      }
      if (f_iter->generator_type == futag::GEN_ARRAY) {
        gen_array(var_name + "_" + to_string(index), *f_iter, generator);
        last_var_name = var_name + "_" + to_string(index);
      }
    }
    index++;
    arg_lines += last_var_name;
    if (index != fd->params.size()) {
      arg_lines += ", ";
    }
  }
  string gen_line = fd->return_type.sequence[0].type_name + " " + var_name +
                    " = " + fd->name + "(" + arg_lines + "); \n";

  generator->gen4types.insert(generator->gen4types.end(), gen_line);

  if (fd->return_type.sequence[0].is_pointer) {
    gen_line = "if(!" + var_name + "){\n";
    // while (generator->free_vars.size() > 0) {
    //   gen_line +=
    //       "    " + generator->free_vars[generator->free_vars.size() - 1] + "\n";
    //   generator->free_vars.pop_back();
    // }
    for (vector<string>::iterator l = generator->free_vars.begin();
         l != generator->free_vars.end(); l++) {
      gen_line += "    " + *l + "\n";
    }
    gen_line += "        return 1;\n    }\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    if (fd->return_type.sequence[0].generator_type == futag::GEN_QUALIFIER) {
      std::string rt_str = fd->return_type.sequence[0].type_name;
      std::string qualifier = fd->return_type.sequence[0].parent_qualifier;
      size_t index = 0;
      index = rt_str.find(qualifier, index);
      rt_str.replace(index, qualifier.length(), "");
      gen_line =  "free( (" + rt_str + ") " + var_name + ");\n";
    } else {
      gen_line = "free(" + var_name + ");\n";
    }
    generator->free_vars.push_back(gen_line);
  }
}

void gen_builtin(string var_name, QualTypeDetail type,
                 futag::genstruct *generator) {
  string gen_line;
  //   llvm::outs() << type.type_name << "\n";
  gen_line = type.type_name + " " + var_name + "; \n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);

  gen_line =
      "memcpy(&" + var_name + ", pos, sizeof(" + type.type_name + "));\n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  gen_line = "pos += sizeof(" + type.type_name + ");\n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  generator->size_limit.insert(generator->size_limit.end(),
                               "sizeof(" + type.type_name + ")");
}

void gen_string(string var_name, QualTypeDetail type,
                futag::genstruct *generator) {
  string gen_line;
  vector<string> type_split = futag::explode(type.type_name, ' ');
  if (type_split[0] == "const") {
    string real_type = "";
    for (vector<string>::iterator i_iter = type_split.begin() + 1;
         i_iter != type_split.end() - 1; ++i_iter) {
      real_type += *i_iter + " ";
    }
    gen_line = real_type + " * " + var_name + " = (" + real_type +
               " *) malloc(sizeof(" + real_type + ")*(futag_cstr_size + 1));\n";
    //    " *) malloc(futag_cstr_size + 1);  \n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "std::memset(" + var_name + ", 0, futag_cstr_size + 1);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "memcpy(" + var_name + ", pos, futag_cstr_size);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "pos += futag_cstr_size;\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);
    gen_line = type.type_name + " q" + var_name + " = " + var_name + ";\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "free (" + var_name + ");\n";
    generator->free_vars.insert(generator->free_vars.begin(), gen_line);
  } else {
    gen_line = type.type_name + " " + var_name + " = (" + type.type_name +
               " *) malloc(sizeof(" + type.type_name +
               ")*(futag_cstr_size + 1));\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "std::memset(" + var_name + ", 0, futag_cstr_size + 1);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "memcpy(" + var_name + ", pos, futag_cstr_size);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "pos += futag_cstr_size;\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);
    gen_line = "free(" + var_name + ");\n";
    generator->free_vars.insert(generator->free_vars.begin(), gen_line);
  }

  generator->size_limit.insert(generator->size_limit.end(), "1");
  generator->cstring_count++;
}
// TODO: fix for Crusher
void gen_string_4Crusher(string var_name, QualTypeDetail type,
                         futag::genstruct *generator) {
  string gen_line;
  vector<string> type_split = futag::explode(type.type_name, ' ');
  if (type_split[0] == "const") {
    string real_type = "";
    for (vector<string>::iterator i_iter = type_split.begin() + 1;
         i_iter != type_split.end() - 1; ++i_iter) {
      real_type += *i_iter + " ";
    }
    gen_line = real_type + " * " + var_name + " = (" + real_type +
               "* ) malloc(sizeof(" + real_type +
               ")*(futag_cstr_size + 1));  \n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "std::memset(" + var_name + ", 0, futag_cstr_size + 1);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "memcpy(" + var_name + ", pos, futag_cstr_size);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "pos += futag_cstr_size;\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);
    gen_line = type.type_name + " q" + var_name + " = " + var_name + ";\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "free(" + var_name + ");\n";
    generator->free_vars.insert(generator->free_vars.begin(), gen_line);
  } else {
    gen_line = type.type_name + " " + var_name + " = (" + type.type_name +
               ") malloc(sizeof(" + type.type_name +
               ")*(futag_cstr_size + 1));  \n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "std::memset(" + var_name + ", 0, futag_cstr_size + 1);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "memcpy(" + var_name + ", pos, futag_cstr_size);\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);

    gen_line = "pos += futag_cstr_size;\n";
    generator->gen4types.insert(generator->gen4types.end(), gen_line);
    gen_line = "if (futag_cstr_size > 0 && strlen(" + var_name +
               ") > 0) delete [] " + var_name + ";\n";
    generator->free_vars.insert(generator->free_vars.begin(), gen_line);
  }

  generator->size_limit.insert(generator->size_limit.end(), "1");
  generator->cstring_count++;
}

void gen_enum(string var_name, QualTypeDetail type,
              vector<futag::EnumDetail> *enumdecl_list,
              futag::genstruct *generator) {
  futag::EnumDetail *ed;
  bool found = false;
  for (vector<futag::EnumDetail>::iterator e_iter = enumdecl_list->begin();
       e_iter != enumdecl_list->end(); ++e_iter) {
    if (type.type_name == "enum " + e_iter->name) {
      ed = &*e_iter;
      found = true;
      break;
    }
  }
  if (!found) {
    return;
  }
  string gen_line = "unsigned char index_" + var_name + ";\n ";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  gen_line = "memcpy(&index_" + var_name + ", pos, sizeof(unsigned char));\n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  gen_line = "pos += sizeof(unsigned char);\n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  generator->size_limit.insert(generator->size_limit.end(),
                               "sizeof(unsigned char)");

  gen_line = "unsigned char enum_index = index_" + var_name + "%" +
             to_string(ed->size) + ";\n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  gen_line =
      type.type_name + " " + var_name + "= " + ed->name + "(enum_index);\n ";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
}

void gen_qualifier(string var_name, string last_var_name, QualTypeDetail type,
                   futag::genstruct *generator) {
  string gen_line;
  gen_line = type.type_name + " " + var_name + " = " + last_var_name + "; \n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
}

void gen_pointer(string var_name, string last_var_name, QualTypeDetail type,
                 futag::genstruct *generator) {
  string gen_line;
  gen_line = type.type_name + " " + var_name + " = &" + last_var_name + "; \n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
}

void gen_array(string var_name, QualTypeDetail type,
               futag::genstruct *generator) {
  string gen_line;
  gen_line = type.type_name + " " + var_name + "[" +
             to_string(type.array_size) + "]" + ";\n";

  generator->gen4types.insert(generator->gen4types.end(), gen_line);

  gen_line = "memcpy(" + var_name + ", pos, " + to_string(type.array_size) +
             "*sizeof(" + type.type_name + "));\n";

  generator->gen4types.insert(generator->gen4types.end(), gen_line);

  gen_line = "pos += " + to_string(type.array_size) + "*sizeof(" +
             type.type_name + ");\n";
  generator->size_limit.insert(
      generator->size_limit.end(),
      to_string(type.array_size) + "*sizeof(" + type.type_name + ")");
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
}

void gen_struct_by_name(string var_name, string struct_name,
                        vector<futag::StructDetail> *struct_decl_list,
                        vector<futag::EnumDetail> *enumdecl_list,
                        futag::genstruct *generator) {
  futag::StructDetail *sd;
  for (vector<futag::StructDetail>::iterator s_iter = struct_decl_list->begin();
       s_iter != struct_decl_list->end(); ++s_iter) {
    if (struct_name == s_iter->name) {
      sd = &*s_iter;
      break;
    }
  }
  string gen_line;
  gen_line = sd->name + " " + var_name + "; \n";
  generator->gen4types.insert(generator->gen4types.end(), gen_line);
  for (auto field : sd->fields) {
    string last_var_name = "";
    for (vector<futag::QualTypeDetail>::reverse_iterator f_iter =
             field.type_sequence.sequence.rbegin();
         f_iter != field.type_sequence.sequence.rend(); ++f_iter) {
      if (f_iter->generator_type == futag::GEN_BUILTIN) {
        gen_builtin(var_name + "_" + field.name, *f_iter, generator);
        last_var_name = var_name + "_" + field.name;
      }
      if (f_iter->generator_type == futag::GEN_STRING) {
        gen_string(var_name + "_" + field.name, *f_iter, generator);
        last_var_name = var_name + "_" + field.name;
      }
      if (f_iter->generator_type == futag::GEN_ENUM) {
        gen_enum(var_name, *f_iter, enumdecl_list, generator);
        last_var_name = var_name + "_" + field.name;
      }
      if (f_iter->generator_type == futag::GEN_QUALIFIER) {
        gen_qualifier("q" + last_var_name, last_var_name, *f_iter, generator);

        last_var_name = "q" + last_var_name;
      }
      if (f_iter->generator_type == futag::GEN_POINTER) {
        gen_pointer("p" + last_var_name, last_var_name, *f_iter, generator);
        last_var_name = "p" + last_var_name;
      }
      if (f_iter->generator_type == futag::GEN_ARRAY) {
        gen_array(var_name + "_" + field.name, *f_iter, generator);
        last_var_name = var_name + "_" + field.name;
      }
    }
    if (field.type_sequence.sequence[0].generator_type == futag::GEN_ARRAY) {
      gen_line =
          "memcpy(" + var_name + "." + field.name + ", " + last_var_name +
          ", " + to_string(field.type_sequence.sequence[0].array_size) +
          "*sizeof(" + field.type_sequence.sequence[0].type_name + "));\n\n";
    } else {
      gen_line = var_name + "." + field.name + " = " + last_var_name + ";\n\n";
    }

    generator->gen4types.insert(generator->gen4types.end(), gen_line);
  }
}

bool check_enumtype(QualType qt,
                    vector<futag::TypedefDetail> typedefdecl_list) {
  for (auto td : typedefdecl_list) {
    if (td.name == qt.getAsString()) {
      vector<string> type_split = futag::explode(td.decl_name, ' ');
      if (std::find(type_split.begin(), type_split.end(), "enum") !=
          type_split.end()) {
        return true;
      }
    }
  }
  return false;
}
}  // namespace futag
