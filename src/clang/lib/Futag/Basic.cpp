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

/// @brief
/// @param type
/// @return
bool isSimpleType(QualType type) {
  // dereference pointer
  while (type->isPointerType()) {
    type = type->getPointeeType();
  }
  if (type.getAsString() == "string" || type.getAsString() == "std::string" ||
      type.getAsString() == "wstring" || type.getAsString() == "std::wstring") {
    return true;
  }
  if (type->isBuiltinType()) {
    llvm::outs() << " type: " << type.getAsString() << " is built-in type\n";
    // if type of a variable after dereference is void - it's somehow a pointer
    // to a function, so it's not simple!
    if (type.getAsString() == "void" || type.getAsString() == "const void") {
      return false;
    }
    return true;
  }

  // if the type is a enum or its size is known by compiler -> it's simple
  if (type->isEnumeralType()) {
    return true;
  }
  if (type->isFunctionType()) {
    return true;
  }

  if (type->isIncompleteType()) {
    return false;
  }

  if (type.getAsString() == "ofstream" || type.getAsString() == "ifstream" ||
      type.getAsString() == "fstream" ||
      type.getAsString() == "std::ofstream" ||
      type.getAsString() == "std::ifstream" ||
      type.getAsString() == "std::fstream" || type.getAsString() == "FILE") {
    return true;
  }

  // If a type is a record type (union, struct, class) - it's not simple!
  if (type->isRecordType()) {
    return false;
  }

  if (const auto *DT = dyn_cast<DecayedType>(type)) {
    if (const auto *AT = dyn_cast<ArrayType>(
            DT->getOriginalType()->getCanonicalTypeInternal())) {
      if (AT->getElementType()->isBuiltinType()) {
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  return false;
}

bool isSimpleRecord(const RecordDecl *rd) {
  bool simple = true;
  for (auto it = rd->field_begin(); it != rd->field_end(); it++) {
    if (!isSimpleType(it->getType())) {
      simple = false;
      break;
    }
  }
  return simple;
}
bool isSimpleFunction(const FunctionDecl *fd) {
  bool simple = true;
  for (size_t i = 0; i < fd->getNumParams(); ++i) {
    auto param_type = fd->parameters()[i]->getType();
    if (param_type->isRecordType()) {
      auto rd = param_type->getAsRecordDecl();
      if (rd && !isSimpleRecord(rd)) {
        simple = false;
        break;
      }
    } else {
      if (!isSimpleType(param_type)) {
        simple = false;
        break;
      }
    }
  }
  return simple;
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
  qual_type_detail.generator_type = FutagDataType::_UNKNOWN;

  if (type.getCanonicalType().getAsString() == "void *" ||
      type.getCanonicalType().getAsString() == "const void *") {
    qual_type_detail.generator_type = FutagDataType::_VOIDP;
    return qual_type_detail;
  }

  if (type.getCanonicalType().getAsString() == "char *" ||
      type.getCanonicalType().getAsString() == "const char *" ||
      type.getCanonicalType().getAsString() == "const unsigned char *" ||
      type.getCanonicalType().getAsString() == "unsigned char *") {
    qual_type_detail.parent_type = "";
    qual_type_detail.generator_type = FutagDataType::_STRING;
    // vector<string> type_split = futag::explode(type.getAsString(), ' ');
    if (type.getCanonicalType().getAsString() == "const char *") {
      qual_type_detail.parent_type = "char *";
    }
    if (type.getCanonicalType().getAsString() == "const unsigned char *") {
      qual_type_detail.parent_type = "unsigned char *";
    }
    return qual_type_detail;
  }

  if (type.hasLocalQualifiers()) {
    auto unqualifiedType = type.getUnqualifiedType();
    qual_type_detail.generator_type = FutagDataType::_QUALIFIER;
    qual_type_detail.parent_type = unqualifiedType.getAsString();
    if (qual_type_detail.parent_type == "const char *" ||
        qual_type_detail.parent_type == "const unsigned char *") {
      qual_type_detail.parent_gen = "string";
      return qual_type_detail;
    }
    if (type.getUnqualifiedType()->isIncompleteType()) {
      qual_type_detail.parent_gen = "incomplete";
      return qual_type_detail;
      qual_type_detail.parent_gen = "incomplete";
      return qual_type_detail;
    }
    return qual_type_detail;
  }

  if (type->isRecordType()) {
    const Type *ty = type.getTypePtr();
    const RecordDecl *rd = ty->castAs<RecordType>()->getDecl();
    if (rd->isStruct()) {
      qual_type_detail.generator_type = FutagDataType::_STRUCT;
    }
    if (rd->isUnion()) {
      qual_type_detail.generator_type = FutagDataType::_UNION;
    }
    if (rd->isClass()) {
      qual_type_detail.generator_type = FutagDataType::_CLASS;
    }
  }
  if (type->isBuiltinType()) {
    qual_type_detail.generator_type = FutagDataType::_BUILTIN;
    return qual_type_detail;
  }

  if (!type->isIncompleteOrObjectType()) {
    qual_type_detail.generator_type = FutagDataType::_FUNCTION;
    return qual_type_detail;
  } else {
    if (type->isIncompleteType()) {
      qual_type_detail.generator_type = FutagDataType::_INCOMPLETE;
    }
  }

  if (type->isEnumeralType()) {
    qual_type_detail.generator_type = FutagDataType::_ENUM;
    return qual_type_detail;
  }

  if (type->isPointerType()) {
    if (type->getPointeeType()->isBuiltinType()) {
      qual_type_detail.generator_type = FutagDataType::_POINTER;
      qual_type_detail.is_pointer = true;
      qual_type_detail.parent_type = type->getPointeeType().getAsString();
      return qual_type_detail;
    } else {
      qual_type_detail.generator_type = FutagDataType::_INCOMPLETE;
      return qual_type_detail;
    }
  }

  if (type->isConstantArrayType()) {
    auto t = dyn_cast<ConstantArrayType>(type);
    if (!t) {
      qual_type_detail.generator_type = FutagDataType::_BUILTIN;
      return qual_type_detail;
    }
    qual_type_detail.type_name =
        type->getAsArrayTypeUnsafe()->getElementType().getAsString();
    qual_type_detail.generator_type = FutagDataType::_ARRAY;
    qual_type_detail.array_size = t->getSize().getSExtValue();
    return qual_type_detail;
  }

  // vector<string> type_split = futag::explode(qual_type_detail.type_name, '
  // '); if (std::find(type_split.begin(), type_split.end(), "struct") !=
  //     type_split.end())
  // {
  //   qual_type_detail.generator_type = FutagDataType::_STRUCT;
  //   return qual_type_detail;
  // }
  return qual_type_detail;
}

/// @brief This function decomposes abilities of <b>record's field</b>
/// generation supposed that the type isSimpleType(). For example, type "const
/// int * i" is followed by: FutagGenType::F_POINTER, FutagGenType::F_QUALIFIER,
/// FutagGenType::F_BUILTIN. Don't edit the check sequence if you don't
/// understand the whole code
/// @param type
/// @return vector<GenFieldInfo>
vector<GenFieldInfo> getGenField(QualType type) {
  vector<GenFieldInfo> result = {};
  do {
    QualType canonical_type = type.getCanonicalType();
    GenFieldInfo gen_field;
    gen_field.curr_type_name = type.getAsString();
    gen_field.base_type_name = "";
    gen_field.length = 0;
    gen_field.local_qualifier = "";
    gen_field.gen_type = FutagGenType::F_UNKNOWN;

    // Check for string
    if (canonical_type.getAsString() == "char *" ||
        canonical_type.getAsString() == "const char *" ||
        canonical_type.getAsString() == "const unsigned char *" ||
        canonical_type.getAsString() == "unsigned char *" ||
        canonical_type.getAsString() == "wstring" ||
        canonical_type.getAsString() == "std::wstring" ||
        canonical_type.getAsString() == "string" ||
        canonical_type.getAsString() == "std::string") {
      if (canonical_type.getAsString() == "const char *") {
        gen_field.base_type_name = "char *";
        gen_field.local_qualifier = "const";
      }
      if (canonical_type.getAsString() == "const  char *") {
        gen_field.base_type_name = "unsigned char *";
        gen_field.local_qualifier = "const";
      }
      gen_field.length = 0;
      gen_field.gen_type = FutagGenType::F_STRING;
      result.push_back(gen_field);
      return result;
    }
    // Check for file type of C
    if (type.getAsString() == "FILE *") {
      gen_field.gen_type = FutagGenType::F_CFILE; // Read
      result.push_back(gen_field);
      return result;
    }

    // Check for array type
    if (const auto *DT = dyn_cast<DecayedType>(type)) {
      if (const auto *AT = dyn_cast<ArrayType>(
              DT->getOriginalType()->getCanonicalTypeInternal())) {
        if (AT->getElementType()->isBuiltinType()) {
          gen_field.base_type_name = AT->getElementType().getAsString();
          gen_field.gen_type = FutagGenType::F_ARRAY;
          if (const auto *CAT = dyn_cast<ConstantArrayType>(AT)) {
            gen_field.length = CAT->getSize().getZExtValue();
          }
          result.push_back(gen_field);
          return result;
        }
      }
    }

    // dereference pointer
    if (type->isPointerType()) {
      gen_field.base_type_name = type->getPointeeType().getAsString();
      gen_field.gen_type = FutagGenType::F_POINTER;
      result.push_back(gen_field);

      type = type->getPointeeType();
      gen_field.curr_type_name = type.getAsString();
      gen_field.base_type_name = "";
      gen_field.length = 0;
      gen_field.local_qualifier = "";
      gen_field.gen_type = FutagGenType::F_UNKNOWN;
    }

    // check for qualifier
    if (type.hasLocalQualifiers()) {
      gen_field.local_qualifier = type.getLocalQualifiers().getAsString();
      gen_field.base_type_name = type.getLocalUnqualifiedType().getAsString();
      gen_field.gen_type = FutagGenType::F_QUALIFIER;
      result.push_back(gen_field);
      type = type.getLocalUnqualifiedType();
    }

    // check for built-in type
    if (type->isBuiltinType()) {
      gen_field.gen_type = FutagGenType::F_BUILTIN;
      result.push_back(gen_field);
      return result;
    }

    // check for enum type
    if (type->isEnumeralType()) {
      gen_field.gen_type = FutagGenType::F_ENUM;
      result.push_back(gen_field);
      return result;
    }

    // check for function type
    if (type->isFunctionType()) {
      gen_field.gen_type = FutagGenType::F_FUNCTION;
      result.push_back(gen_field);
      return result;
    }

    // check for file type
    if (type.getAsString() == "ofstream" ||
        type.getAsString() == "std::ofstream") {
      gen_field.gen_type = FutagGenType::F_OUTPUT_CXXFILE; // Write
      result.push_back(gen_field);
      return result;
    }
    if (type.getAsString() == "ifstream" ||
        type.getAsString() == "std::ifstream") {
      gen_field.gen_type = FutagGenType::F_INPUT_CXXFILE; // Read
      result.push_back(gen_field);
      return result;
    }
    if (type.getAsString() == "fstream" ||
        type.getAsString() == "std::fstream") {
      gen_field.gen_type = FutagGenType::F_CXXFILE;
      result.push_back(gen_field);
      return result;
    }
    if (type.getAsString() == "FILE") {
      gen_field.gen_type = FutagGenType::F_CFILE;
      result.push_back(gen_field);
      return result;
    }

  } while (type->isPointerType());

  return result;
}

// /// @brief This function decomposes abilities of <b>parameter's type</b>
// /// generation. For example, type "const int * i" is followed by:
// /// FutagGenType::F_POINTER, FutagGenType::F_QUALIFIER,
// FutagGenType::F_BUILTIN
// /// @param type
// /// @return
// vector<GenFieldInfo> getGenType(QualType type) {
//   vector<GenFieldInfo> result = {};
//   GenFieldInfo gen_field;
//   do {
//     QualType canonical_type;
//     canonical_type = type.getCanonicalType();
//     gen_field.curr_type_name = type.getAsString();
//     gen_field.base_type_name = "";
//     gen_field.length = 0;
//     gen_field.local_qualifier = "";
//     gen_field.gen_type = FutagGenType::F_UNKNOWN;
//     // dereference pointer
//     if (type->isPointerType()) {
//       if (canonical_type.getAsString() == "char *" ||
//           canonical_type.getAsString() == "const char *" ||
//           canonical_type.getAsString() == "const unsigned char *" ||
//           canonical_type.getAsString() == "unsigned char *") {
//         if (canonical_type.getAsString() == "const char *") {
//           gen_field.base_type_name = "char *";
//           gen_field.local_qualifier = "const";
//         }
//         if (canonical_type.getAsString() == "const  char *") {
//           gen_field.base_type_name = "unsigned char *";
//           gen_field.local_qualifier = "const";
//         }
//         gen_field.length = 0;
//         gen_field.gen_type = FutagGenType::F_STRING;
//         result.push_back(gen_field);
//         return result;
//       }
//       GenFieldInfo gen_field_pointer;
//       gen_field_pointer.curr_type_name = type.getAsString();
//       gen_field_pointer.base_type_name =
//       type->getPointeeType().getAsString(); gen_field_pointer.length = 0;
//       gen_field_pointer.local_qualifier = "";
//       gen_field_pointer.gen_type = FutagGenType::F_POINTER;
//       result.push_back(gen_field_pointer);
//       // gen_field.base_type_name = type->getPointeeType().getAsString();
//       // gen_field.length = 0;
//       // gen_field.local_qualifier = "";
//       // gen_field.gen_type = FutagGenType::F_POINTER;
//       // result.push_back(gen_field);
//       llvm::outs() << "added pointer!!!! \n";
//       type = type->getPointeeType();
//       gen_field.gen_type = FutagGenType::F_UNKNOWN;
//     }

//     if (type.hasLocalQualifiers()) {
//       gen_field.local_qualifier = type.getLocalQualifiers().getAsString();
//       gen_field.base_type_name =
//       type.getLocalUnqualifiedType().getAsString(); gen_field.gen_type =
//       FutagGenType::F_QUALIFIER; result.push_back(gen_field); type =
//       type.getLocalUnqualifiedType();
//     }
//     if (type->isBuiltinType()) {
//       gen_field.gen_type = FutagGenType::F_BUILTIN;
//       result.push_back(gen_field);
//       return result;
//     }
//     if (type->isEnumeralType()) {
//       gen_field.gen_type = FutagGenType::F_ENUM;
//       result.push_back(gen_field);
//       return result;
//     }

//     if (const auto *DT = dyn_cast<DecayedType>(type)) {
//       if (const auto *AT = dyn_cast<ArrayType>(
//               DT->getOriginalType()->getCanonicalTypeInternal())) {
//         if (AT->getElementType()->isBuiltinType()) {
//           gen_field.base_type_name = AT->getElementType().getAsString();
//           gen_field.gen_type = FutagGenType::F_ARRAY;
//           if (const auto *CAT = dyn_cast<ConstantArrayType>(AT)) {
//             gen_field.length = CAT->getSize().getZExtValue();
//           }
//           result.push_back(gen_field);
//           return result;
//         }
//       }
//     }

//     // Check for FILE type, iostream, fstream
//     if (type.getAsString() == "ofstream" ||
//         type.getAsString() == "std::ofstream") {
//       gen_field.gen_type = FutagGenType::F_OUTPUT_CXXFILE;
//       result.push_back(gen_field);
//       return result;
//     }
//     if (type.getAsString() == "ifstream" ||
//         type.getAsString() == "std::ifstream") {
//       gen_field.gen_type = FutagGenType::F_INPUT_CXXFILE;
//       result.push_back(gen_field);
//       return result;
//     }
//     if (type.getAsString() == "fstream" ||
//         type.getAsString() == "std::fstream") {
//       gen_field.gen_type = FutagGenType::F_CXXFILE;
//       result.push_back(gen_field);
//       return result;
//     }
//     if (type.getAsString() == "FILE") {
//       gen_field.gen_type = FutagGenType::F_CFILE;
//       result.push_back(gen_field);
//       return result;
//     }
//     llvm::outs() << "checked and added unknown!!!!"
//                  << futag::GetFutagGenTypeFromIdx(gen_field.gen_type) << "
//                  \n";
//     result.push_back(gen_field);
//   } while (!type->isPointerType());
//   return result;
// }

const std::map<FutagType::Type, std::string> FutagType::c_typesToNames = {
    {FutagType::CONST_VAL, "CONST_VAL"},
    {FutagType::DECL_REF, "DECL_REF"},
    {FutagType::FUNCTION_CALL_RESULT, "FUNCTION_CALL_RESULT"},
    {FutagType::UNKNOWN, "UNKNOWN"}};

const std::map<std::string, FutagType::Type> FutagType::c_namesToTypes = {
    {"CONST_VAL", FutagType::CONST_VAL},
    {"DECL_REF", FutagType::DECL_REF},
    {"FUNCTION_CALL_RESULT", FutagType::FUNCTION_CALL_RESULT},
    {"UNKNOWN", FutagType::UNKNOWN}};

std::string GetFutagGenTypeFromIdx(FutagGenType idx) {
  switch (idx) {
  case FutagGenType::F_BUILTIN:
    return "_BUILTIN";
    break;

  case FutagGenType::F_STRING:
    return "_STRING";
    break;

  case FutagGenType::F_ENUM:
    return "_ENUM";
    break;

  case FutagGenType::F_ARRAY:
    return "_ARRAY";
    break;

  case FutagGenType::F_VOIDP:
    return "_VOIDP";
    break;

  case FutagGenType::F_QUALIFIER:
    return "_QUALIFIER";
    break;

  case FutagGenType::F_POINTER:
    return "_POINTER";
    break;

  case FutagGenType::F_STRUCT:
    return "_STRUCT";
    break;

  case FutagGenType::F_UNION:
    return "_UNION";
    break;

  case FutagGenType::F_CLASS:
    return "_CLASS";
    break;

  case FutagGenType::F_INCOMPLETE:
    return "_INCOMPLETE";
    break;

  case FutagGenType::F_FUNCTION:
    return "_FUNCTION";
    break;

  case FutagGenType::F_INPUT_CXXFILE:
    return "_INPUT_CXXFILE";
    break;

  case FutagGenType::F_OUTPUT_CXXFILE:
    return "_OUTPUT_CXXFILE";
    break;

  case FutagGenType::F_CXXFILE:
    return "_CXXFILE";
    break;

  case FutagGenType::F_CFILE:
    return "_CFILE";
    break;

  default:
    return "_UNKNOWN";
    break;
  }
}

} // namespace futag
