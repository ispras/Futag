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

#include "Futag/Basic.h"

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

DataTypeDetail getDataTypeDetail(QualType type) {
  DataTypeDetail qual_type_detail;
  qual_type_detail.array_size = 1;
  qual_type_detail.type_name = type.getAsString();
  qual_type_detail.generator_type = DataType::_UNKNOWN;

  if (type.getCanonicalType().getAsString() == "void *" ||
      type.getCanonicalType().getAsString() == "const void *") {
    qual_type_detail.generator_type = DataType::_VOIDP;
    return qual_type_detail;
  }

  if (type.getCanonicalType().getAsString() == "char *" ||
      type.getCanonicalType().getAsString() == "const char *" ||
      type.getCanonicalType().getAsString() == "const unsigned char *" ||
      type.getCanonicalType().getAsString() == "unsigned char *") {
    qual_type_detail.parent_type = "";
    qual_type_detail.generator_type = DataType::_STRING;
    vector<string> type_split = futag::explode(type.getAsString(), ' ');
    if (type_split[0] == "const") {
      qual_type_detail.parent_type = type_split[1];
    }
    return qual_type_detail;
  }

  if (type.hasLocalQualifiers()) {
    qual_type_detail.generator_type = DataType::_QUALIFIER;
    qual_type_detail.parent_type = type.getUnqualifiedType().getAsString();
    if(qual_type_detail.parent_type == "const char *" || qual_type_detail.parent_type == "const unsigned char *")
    {
      qual_type_detail.parent_gen = "string";
      return qual_type_detail;
    }
    if(type.getUnqualifiedType()->isIncompleteType())
    {
      qual_type_detail.parent_gen = "incomplete";
      return qual_type_detail;
    }
    return qual_type_detail;
  }

  if (type->isBuiltinType()) {
    qual_type_detail.generator_type = DataType::_BUILTIN;
    return qual_type_detail;
  }
  
  if (!type->isIncompleteOrObjectType()) {
    qual_type_detail.generator_type = DataType::_FUNCTION;
    return qual_type_detail;
  } else {
    if (type->isIncompleteType()) {
      qual_type_detail.generator_type = DataType::_INCOMPLETE;
    }
  }

  if (type.getAsString().find("enum ") != std::string::npos &&
      type.getAsString().find("enum ") == 0) {
    qual_type_detail.generator_type = DataType::_ENUM;
    return qual_type_detail;
  }

  if (type->isPointerType()) {
    if (type->getPointeeType()->isIncompleteType()) {
      qual_type_detail.generator_type = DataType::_INCOMPLETE;
      return qual_type_detail;
    } else {
      if (type->getPointeeType()->isBuiltinType()) {
        qual_type_detail.generator_type = DataType::_POINTER;
        qual_type_detail.is_pointer = true;
        qual_type_detail.parent_type = type->getPointeeType().getAsString();
        return qual_type_detail;
      } else {
        vector<string> type_split =
            futag::explode(qual_type_detail.type_name, ' ');
        if (std::find(type_split.begin(), type_split.end(), "struct") !=
            type_split.end()) {
          qual_type_detail.generator_type = DataType::_INCOMPLETE;
          return qual_type_detail;
        }
      }
    }

    qual_type_detail.generator_type = DataType::_UNKNOWN;
    return qual_type_detail;
  }

  if (type->isConstantArrayType()) {
    auto t = dyn_cast<ConstantArrayType>(type);
    if (!t) {
      qual_type_detail.generator_type = DataType::_BUILTIN;
      return qual_type_detail;
    }
    qual_type_detail.type_name =
        type->getAsArrayTypeUnsafe()->getElementType().getAsString();
    qual_type_detail.generator_type = DataType::_ARRAY;
    qual_type_detail.array_size = t->getSize().getSExtValue();
    return qual_type_detail;
  }

  vector<string> type_split = futag::explode(qual_type_detail.type_name, ' ');
  if (std::find(type_split.begin(), type_split.end(), "struct") !=
      type_split.end()) {
    qual_type_detail.generator_type = DataType::_STRUCT;
    return qual_type_detail;
  }
  return qual_type_detail;
}
} // namespace futag
