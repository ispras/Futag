#ifndef FUTAG_ARGUMENTS_USAGE_H
#define FUTAG_ARGUMENTS_USAGE_H

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

// For open consts (O_RDWR, ...)
#include <fcntl.h>

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace futag {
class ArgumentsUsage {
public:
  enum class ArgumentType {
    SIZE_FIELD = 0,
    // Everything related to FD's
    FILE_DESCRIPTOR,

    // Everything related to FilePath's
    // @TODO: Probably it's much better, to move it to separate enum
    // and work with the file flags from the generator
    // @TODO: Currently we are ignoreing specific open modes (e.g. append)
    FILE_PATH,
    FILE_PATH_READ,
    FILE_PATH_WRITE,
    FILE_PATH_RW,

    // Everything else
    C_STRING, // Null-terminated C-string
    UNKNOWN,
    LAST
  };

  // @TODO: we should add some kind of priority to the deduced argument types
  // E.g. we might have a conflict if similar sequence of calls is executed:
  //   >> open(path) -> strcpy(buffer, path)
  // After execution, path will be marked as C_STRING, which isn't the best
  // type, as FILE_PATH would be much more informative.
  enum class ArgumentTypePriority {
    // From the most important to the least
    FILE_PATH_READ = 0,
    FILE_PATH_RW,
    FILE_PATH_WRITE,
    FILE_PATH,

    FILE_DESCRIPTOR,
    SIZE_FIELD,
    C_STRING,
    UNKNOWN,
    LAST,
  };

  static_assert((int)ArgumentType::LAST == (int)ArgumentTypePriority::LAST, "");

  using AT = ArgumentType;
  using ATP = ArgumentTypePriority;

  // Converts elements from ArgumentType enum to string
  static std::string ArgumentTypeToStr(ArgumentType argType) {
    switch (argType) {
    case AT::SIZE_FIELD:
      return "SIZE_FIELD";
    case AT::FILE_DESCRIPTOR:
      return "FILE_DESCRIPTOR";
    case AT::FILE_PATH:
      return "FILE_PATH";
    case AT::FILE_PATH_READ:
      return "FILE_PATH_READ";
    case AT::FILE_PATH_WRITE:
      return "FILE_PATH_WRITE";
    case AT::FILE_PATH_RW:
      return "FILE_PATH_RW";
    case AT::C_STRING:
      return "C_STRING";
    case AT::UNKNOWN:
      return "UNKNOWN";
    default:
      return "UNKNOWN";
    }

    return "UNKNOWN";
  }

  ArgumentType DetermineFileModeOpen(uint32_t argumentIdx,
                                     const CallExpr *callExpr) {
    ArgumentType currentArgType = AT::FILE_PATH;
    int32_t openModeInt;

    // Try to get open's open mode as an integer flag
    if (const auto *openMode = dyn_cast<clang::IntegerLiteral>(
            callExpr->getArg(argumentIdx + 1)->IgnoreCasts())) {
      openModeInt = openMode->getValue().getSExtValue();
    } else {
      return currentArgType;
    }

    if (openModeInt == O_WRONLY) {
      currentArgType = AT::FILE_PATH_WRITE;
    } else if (openModeInt == O_RDONLY) {
      currentArgType = AT::FILE_PATH_READ;
    } else if (openModeInt == O_RDWR) {
      currentArgType = AT::FILE_PATH_RW;
    }

    return currentArgType;
  }

  ArgumentType DetermineFileModeFopen(uint32_t argumentIdx,
                                      const CallExpr *callExpr) {
    ArgumentType currentArgType = AT::FILE_PATH;
    std::string fopenModeStr;

    // Try to get fopen's open mode as a astring literal
    if (const auto *fopenMode = dyn_cast<clang::StringLiteral>(
            callExpr->getArg(argumentIdx + 1)->IgnoreCasts())) {
      fopenModeStr = fopenMode->getBytes().str();
    } else {
      return currentArgType;
    }

    if (fopenModeStr == "r+" || fopenModeStr == "w+" || fopenModeStr == "a+") {
      currentArgType = AT::FILE_PATH_RW;
    } else if (fopenModeStr == "r") {
      currentArgType = AT::FILE_PATH_READ;
    } else if (fopenModeStr == "a" || fopenModeStr == "w") {
      currentArgType = AT::FILE_PATH_WRITE;
    }

    return currentArgType;
  }

  // Currently it is a POC, but it is really easy to extend to support a lot of
  // other functions, and even load them from json/yaml scheme, ...
  ArgumentType DetermineArgumentType(std::string functionName,
                                     uint32_t argumentIdx,
                                     const CallExpr *callExpr) {
    if (fuctionArgsToTypes.find(functionName) != fuctionArgsToTypes.end()) {
      AT currentArgType = fuctionArgsToTypes.at(functionName).at(argumentIdx);

      // Parse fopen/open flags and try to determine in which mode the file is
      // opened (read/write)
                    
          if (currentArgType == AT::FILE_PATH && functionName == "open") {
        currentArgType = DetermineFileModeOpen(argumentIdx, callExpr);
      } else if (currentArgType == AT::FILE_PATH &&
                 functionName == "fopen") {
        currentArgType = DetermineFileModeFopen(argumentIdx, callExpr);
      }
      return currentArgType;
    }

    return AT::UNKNOWN;
  }

  std::string DetermineArgumentTypeStr(std::string functionName,
                                       uint32_t argumentIdx, const CallExpr *callExpr) {
    return ArgumentTypeToStr(DetermineArgumentType(functionName, argumentIdx, callExpr));
  }

private:
  // @TODO:
  // - We should implement AST use-def chains
  // - We should implement recursive paramters deduction
  // - We should add support for return types
  const std::unordered_map<std::string, std::vector<ArgumentType>>
      fuctionArgsToTypes = {
          {"open", {AT::FILE_PATH, AT::UNKNOWN}},
          {"fopen", {AT::FILE_PATH, AT::UNKNOWN}},
          {"write", {AT::FILE_DESCRIPTOR, AT::UNKNOWN, AT::SIZE_FIELD}},
          // Currently I've replaced all C_STRING with UNKNOWN, to
          // avoid (for now) arguments priority problem.
          {"strncpy", {AT::C_STRING, AT::C_STRING, AT::SIZE_FIELD}},
          {"strcpy", {AT::C_STRING, AT::C_STRING}},
          {"strcmp", {AT::C_STRING, AT::C_STRING}},
          {"strlen", {AT::C_STRING}},
          {"strncmp", {AT::C_STRING, AT::C_STRING, AT::SIZE_FIELD}},
          {"malloc", {AT::SIZE_FIELD}},
          {"calloc", {AT::SIZE_FIELD, AT::UNKNOWN,}},
          {"realloc", {AT::UNKNOWN, AT::SIZE_FIELD}},
          {"close", {AT::FILE_DESCRIPTOR}},
          {"memchr", {AT::UNKNOWN, AT::UNKNOWN, AT::SIZE_FIELD}},
          {"memcmp", {AT::UNKNOWN, AT::UNKNOWN, AT::SIZE_FIELD}},
          {"memcpy", {AT::UNKNOWN, AT::UNKNOWN, AT::SIZE_FIELD}},
          {"memmove", {AT::UNKNOWN, AT::UNKNOWN, AT::SIZE_FIELD}},
          {"memset", {AT::UNKNOWN, AT::UNKNOWN, AT::SIZE_FIELD}},
          {"puts", {AT::C_STRING}},
  };
};
} // namespace futag

#endif