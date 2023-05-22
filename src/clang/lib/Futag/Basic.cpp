/**
 * @file Basic.cpp
 * @author Tran Chi Thien (thientcgithub@gmail.com)
 * @brief
 ************************************************
 *      ______  __  __  ______  ___     ______  *
 *     / ____/ / / / / /_  __/ /   |   / ____/  *
 *    / /_    / / / /   / /   / /| |  / / __    *
 *   / __/   / /_/ /   / /   / ___ | / /_/ /    *
 *  /_/      \____/   /_/   /_/  |_| \____/     *
 *                                              *
 *     Fuzzing target Automated Generator       *
 *             a tool of ISP RAS                *
 ************************************************
 *
 * @version 2.0.4
 * @date 2023-04-17
 *
 * @copyright This file is distributed under the GPL v3 license
 *
 */

#include "Futag/Basic.h"
#include <algorithm>
#include <fstream>
#include <string>
#include <sys/stat.h>

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

/**
 * @brief This function decomposes abilities of <b>record's field</b> generation
 * supposed that the type isSimpleType(). For example, type "const int * i" is
 * followed by: FutagGenType::F_POINTER,
 * FutagGenType::F_QUALIFIER,FutagGenType::F_BUILTIN. Don't edit the check
 * sequence if you don't understand the whole code. Useful
 * link: https://c-faq.com/decl/spiral.anderson.html
 *
 * @param type
 * @return vector<GenTypeInfo>
 */
vector<GenTypeInfo> getGenField(QualType type) {
    vector<GenTypeInfo> result = {};
    QualType canonical_type = type.getCanonicalType();
    GenTypeInfo gen_list;
    gen_list.type_name = type.getAsString();
    gen_list.base_type_name = "";
    gen_list.length = 0;
    gen_list.local_qualifier = "";
    gen_list.gen_type = FutagGenType::F_UNKNOWN;

    do {
        // Check for string
        if (std::find(str_types.begin(), str_types.end(),
                      type.getCanonicalType().getAsString()) !=
            str_types.end()) {
            gen_list.base_type_name = "char *";
            if (type.getCanonicalType().getAsString() == "unsigned char *" || type.getCanonicalType().getAsString() == "const unsigned char *" ){
                gen_list.base_type_name = "unsigned char *";
            }
            if (std::find(wchar_str_types.begin(), wchar_str_types.end(),
                          type.getCanonicalType().getAsString()) !=
                wchar_str_types.end()) {
                gen_list.base_type_name = "wchar_t *";
            }
            if (std::find(const_str_types.begin(), const_str_types.end(),
                          type.getCanonicalType().getAsString()) !=
                const_str_types.end()) {
                gen_list.local_qualifier = "const";
                if (canonical_type.getAsString() == "const unsigned char *") {
                    gen_list.base_type_name = "unsigned char *";
                }
                if (canonical_type.getAsString() == "const wchar_t *" ||
                    canonical_type.getAsString() == "const wchar_t *const") {
                    gen_list.base_type_name = "wchar_t *";
                }
            }
            gen_list.gen_type = FutagGenType::F_CSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "wstring" ||
            type.getAsString() == "std::wstring" ||
            type.getAsString() == "string" ||
            type.getAsString() == "std::string") {
            gen_list.gen_type = FutagGenType::F_CXXSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }

        if (type.getAsString() == "const char *&" || type.getCanonicalType().getAsString() == "const char *&") {
            gen_list.base_type_name = "const char *";
            gen_list.gen_type = FutagGenType::F_REFSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "char *&" || type.getCanonicalType().getAsString() == "char *&") {
            gen_list.base_type_name = "char *";
            gen_list.gen_type = FutagGenType::F_REFSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }
        
        // Check for file type of C
        if (type.getAsString() == "FILE *") {
            gen_list.gen_type = FutagGenType::F_CFILE; // Read
            result.insert(result.begin(), gen_list);
            return result;
        }

        // Check for array type
        if (const auto *DT = dyn_cast<DecayedType>(type)) {
            if (const auto *AT = dyn_cast<ArrayType>(
                    DT->getOriginalType()->getCanonicalTypeInternal())) {
                if (AT->getElementType()->isBuiltinType()) {
                    gen_list.base_type_name =
                        AT->getElementType().getAsString();
                    gen_list.gen_type = FutagGenType::F_ARRAY;
                    if (const auto *CAT = dyn_cast<ConstantArrayType>(AT)) {
                        gen_list.length = CAT->getSize().getZExtValue();
                    }
                    result.insert(result.begin(), gen_list);
                    return result;
                }
            }
        }

        // dereference pointer
        if (type->isPointerType()) {
            gen_list.base_type_name = type->getPointeeType().getAsString();
            gen_list.gen_type = FutagGenType::F_POINTER;
            result.insert(result.begin(), gen_list);
            type = type->getPointeeType();
            gen_list.type_name = type.getAsString();
            gen_list.base_type_name = "";
            gen_list.gen_type = FutagGenType::F_UNKNOWN;
        }

        // check for qualifier
        if (type.hasLocalQualifiers()) {
            gen_list.local_qualifier = type.getLocalQualifiers().getAsString();
            gen_list.base_type_name =
                type.getLocalUnqualifiedType().getAsString();
            gen_list.gen_type = FutagGenType::F_QUALIFIER;
            result.insert(result.begin(), gen_list);
            type = type.getLocalUnqualifiedType();
            auto gen_list_child = getGenType(type);
            for (auto g : gen_list_child) {
                result.insert(result.begin(), g);
            }
            return result;
        }

        // check for built-in type
        if (type->isBuiltinType()) {
            gen_list.gen_type = FutagGenType::F_BUILTIN;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // check for enum type
        if (type->isEnumeralType()) {
            gen_list.gen_type = FutagGenType::F_ENUM;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // check for function type
        if (type->isFunctionType()) {
            gen_list.gen_type = FutagGenType::F_FUNCTION;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // check for file type
        if (type.getAsString() == "ofstream" ||
            type.getAsString() == "std::ofstream") {
            gen_list.gen_type = FutagGenType::F_OUTPUT_CXXFILE; // Write
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "ifstream" ||
            type.getAsString() == "std::ifstream") {
            gen_list.gen_type = FutagGenType::F_INPUT_CXXFILE; // Read
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "fstream" ||
            type.getAsString() == "std::fstream") {
            gen_list.gen_type = FutagGenType::F_CXXFILE;
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "FILE") {
            gen_list.gen_type = FutagGenType::F_CFILE;
            result.insert(result.begin(), gen_list);
            return result;
        }

    } while (type->isPointerType());

    return result;
}

/**
 * @brief This function decomposes abilities of <b>function's argument</b>
 * generation. For example, type "const int * i" is followed by:
 * FutagGenType::F_POINTER, FutagGenType::F_QUALIFIER,FutagGenType::F_BUILTIN.
 * Don't edit the check sequence if you don't understand the whole code. Useful
 * link: https://c-faq.com/decl/spiral.anderson.html
 *
 * @param type
 * @return vector<GenTypeInfo>
 *
 */
vector<GenTypeInfo> getGenType(QualType type) {
    vector<GenTypeInfo> result = {};
    QualType canonical_type = type.getCanonicalType();
    GenTypeInfo gen_list;
    gen_list.type_name = type.getAsString();
    gen_list.base_type_name = "";
    gen_list.length = 0;
    gen_list.local_qualifier = "";
    gen_list.gen_type = FutagGenType::F_UNKNOWN;

    do {
        // Check for string
        if (std::find(str_types.begin(), str_types.end(),
                      type.getCanonicalType().getAsString()) !=
            str_types.end()) {
            gen_list.gen_type = FutagGenType::F_CSTRING;
            gen_list.base_type_name = "char *";
            if (type.getCanonicalType().getAsString() == "unsigned char *" || type.getCanonicalType().getAsString() == "const unsigned char *" ){
                gen_list.base_type_name = "unsigned char *";
            }
            if (std::find(wchar_str_types.begin(), wchar_str_types.end(),
                          type.getCanonicalType().getAsString()) !=
                wchar_str_types.end()) {
                gen_list.base_type_name = "wchar_t *";
                gen_list.gen_type = FutagGenType::F_WSTRING;
            }
            if (std::find(const_str_types.begin(), const_str_types.end(),
                          type.getCanonicalType().getAsString()) !=
                const_str_types.end()) {
                gen_list.local_qualifier = "const";
                if (canonical_type.getAsString() == "const unsigned char *") {
                    gen_list.base_type_name = "unsigned char *";
                }
                if (canonical_type.getAsString() == "const wchar_t *" ||
                    canonical_type.getAsString() == "const wchar_t *const") {
                    gen_list.base_type_name = "wchar_t *";
                    gen_list.gen_type = FutagGenType::F_WSTRING;
                }
            }

            result.insert(result.begin(), gen_list);
            return result;
        }

        if (type.getAsString() == "wstring" ||
            type.getAsString() == "std::wstring" ||
            type.getAsString() == "string" ||
            type.getAsString() == "std::string") {
            gen_list.gen_type = FutagGenType::F_CXXSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }

        if (type.getAsString() == "const char *&" || type.getCanonicalType().getAsString() == "const char *&") {
            gen_list.base_type_name = "const char *";
            gen_list.gen_type = FutagGenType::F_REFSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "char *&" || type.getCanonicalType().getAsString() == "char *&") {
            gen_list.base_type_name = "char *";
            gen_list.gen_type = FutagGenType::F_REFSTRING;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // Check for file type of C
        if (type.getAsString() == "FILE *") {
            gen_list.gen_type = FutagGenType::F_CFILE; // Read
            result.insert(result.begin(), gen_list);
            return result;
        }

        if (type.getAsString() == "void" || type.getAsString() == "void *" ||
            type.getAsString() == "const void *") {
            gen_list.gen_type = FutagGenType::F_VOIDP;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // Check for array type
        if (const auto *DT = dyn_cast<DecayedType>(type)) {
            if (const auto *AT = dyn_cast<ArrayType>(
                    DT->getOriginalType()->getCanonicalTypeInternal())) {
                if (AT->getElementType()->isBuiltinType()) {
                    gen_list.base_type_name =
                        AT->getElementType().getAsString();
                    gen_list.gen_type = FutagGenType::F_ARRAY;
                    if (const auto *CAT = dyn_cast<ConstantArrayType>(AT)) {
                        gen_list.length = CAT->getSize().getZExtValue();
                    }
                    result.insert(result.begin(), gen_list);
                    return result;
                }
            }
        }

        // dereference pointer
        if (type->isPointerType()) {
            gen_list.base_type_name = type->getPointeeType().getAsString();
            gen_list.gen_type = FutagGenType::F_POINTER;
            result.insert(result.begin(), gen_list);
            type = type->getPointeeType();
            gen_list.type_name = type.getAsString();
            gen_list.base_type_name = "";
            gen_list.gen_type = FutagGenType::F_UNKNOWN;
        }

        // check for qualifier
        if (type.hasLocalQualifiers()) {
            gen_list.local_qualifier = type.getLocalQualifiers().getAsString();
            gen_list.base_type_name =
                type.getLocalUnqualifiedType().getAsString();
            gen_list.gen_type = FutagGenType::F_QUALIFIER;
            result.insert(result.begin(), gen_list);
            type = type.getLocalUnqualifiedType();
            auto gen_list_child = getGenType(type);
            for (auto g : gen_list_child) {
                result.insert(result.begin(), g);
            }
            return result;
        }

        // check for built-in type
        if (type->isBuiltinType()) {
            gen_list.gen_type = FutagGenType::F_BUILTIN;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // check for enum type
        if (type->isEnumeralType()) {
            gen_list.gen_type = FutagGenType::F_ENUM;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // check for function type
        if (type->isFunctionType()) {
            gen_list.gen_type = FutagGenType::F_FUNCTION;
            result.insert(result.begin(), gen_list);
            return result;
        }

        // check for file type
        if (type.getAsString() == "ofstream" ||
            type.getAsString() == "std::ofstream") {
            gen_list.gen_type = FutagGenType::F_OUTPUT_CXXFILE; // Write
            result.insert(result.begin(), gen_list);
            return result;
        }

        if (type.getAsString() == "ifstream" ||
            type.getAsString() == "std::ifstream") {
            gen_list.gen_type = FutagGenType::F_INPUT_CXXFILE; // Read
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "fstream" ||
            type.getAsString() == "std::fstream") {
            gen_list.gen_type = FutagGenType::F_CXXFILE;
            result.insert(result.begin(), gen_list);
            return result;
        }
        if (type.getAsString() == "FILE") {
            gen_list.gen_type = FutagGenType::F_CFILE;
            result.insert(result.begin(), gen_list);
            return result;
        }
        // If a type is a record type (union, struct, class) - it's not simple!
        if (type->isRecordType()) {
            auto *recorddecl = type->getAsRecordDecl();
            if (recorddecl->isClass()) {
                gen_list.gen_type = FutagGenType::F_CLASS;
            }
            if (recorddecl->isUnion()) {
                gen_list.gen_type = FutagGenType::F_UNION;
            }
            if (recorddecl->isStruct()) {
                gen_list.gen_type = FutagGenType::F_STRUCT;
            }
            gen_list.type_name = type.getAsString();
            result.insert(result.begin(), gen_list);
            return result;
        }

    } while (type->isPointerType());

    return result;
}

/**
 * @brief This function checks if a type is simple: Built-in type, string, enum,
 * or input, output stream/file
 *
 * @param type
 * @return true
 * @return false
 */
bool isSimpleType(QualType type) {
    vector<FutagGenType> SimpleList{F_BUILTIN, F_CSTRING, F_WSTRING, F_CXXSTRING, F_ENUM, F_ARRAY, F_REFSTRING, F_CFILE, F_CXXFILE, F_INPUT_CXXFILE, F_OUTPUT_CXXFILE};

    auto gen_type_list = getGenType(type);
    if (!gen_type_list.size()) return false;
    FutagGenType gen_type = gen_type_list.front().gen_type;
    if(std::find(SimpleList.begin(), SimpleList.end(), gen_type) != SimpleList.end()){
        return true;
    }
    return false;
    // dereference pointer
    while (type->isPointerType()) {
        type = type->getPointeeType();
    }
    if (type.getAsString() == "string" || type.getAsString() == "std::string" ||
        type.getAsString() == "wstring" ||
        type.getAsString() == "std::wstring") {
        return true;
    }
    if (type->isBuiltinType()) {
        //  " type: " << type.getAsString() << " is built-in type\n";
        // if type of a variable after dereference is void - it's somehow a
        // pointer to a function, so it's not simple!
        if (type.getAsString() == "void" ||
            type.getAsString() == "const void") {
            return false;
        }
        return true;
    }

    // if the type is a enum or its size is known by compiler -> it's simple
    if (type->isEnumeralType()) {
        return true;
    }

    if (type->isFunctionType()) {
        return false;
        // return true;
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

/**
 * @brief
 *
 * @param rd
 * @return true
 * @return false
 */
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

/**
 * @brief
 *
 * @param fd
 * @return true
 * @return false
 */
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

/**
 * @brief
 *
 * @param path
 * @return true
 * @return false
 */
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

/**
 * @brief Get the FutagGenType string from index
 *
 * @param idx
 * @return std::string
 */
std::string GetFutagGenTypeFromIdx(FutagGenType idx) {
    switch (idx) {
    case FutagGenType::F_BUILTIN:
        return "_BUILTIN";
        break;

    case FutagGenType::F_CSTRING:
        return "_CSTRING";
        break;

    case FutagGenType::F_WSTRING:
        return "_WSTRING";
        break;

    case FutagGenType::F_CXXSTRING:
        return "_CXXSTRING";
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
