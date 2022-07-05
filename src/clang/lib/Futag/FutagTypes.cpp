#include "Futag/FutagTypes.h"

namespace futag {

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

} // namespace futag