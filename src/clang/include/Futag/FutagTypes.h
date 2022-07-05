#ifndef FUTAG_TYPES_H
#define FUTAG_TYPES_H

#include <map>
#include <string>

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
} // namespace futag

#endif