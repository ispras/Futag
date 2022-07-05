#ifndef FUTAG_UTILS_H
#define FUTAG_UTILS_H

#include "clang/AST/Decl.h"
#include "clang/AST/ODRHash.h"
#include "clang/AST/Stmt.h"

#include <algorithm>
#include <iterator>
#include <random>
#include <string>

using namespace clang;

namespace futag {
namespace consts {

const std::string cDot = "./";
const std::string cAlphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
} // namespace consts

namespace utils {

class Random {
private:
  std::random_device mRandomDev;
  std::default_random_engine mRandomEngine;

public:
  Random() : mRandomDev{}, mRandomEngine{mRandomDev()} {}

  std::string GenerateRandomString(const std::string &tCharset,
                                   uint32_t tLength) {
    std::uniform_int_distribution<> dist{0,
                                         static_cast<int>(tCharset.size() - 1)};

    std::string randomString;
    randomString.reserve(tLength);

    std::generate_n(std::back_inserter(randomString), tLength,
                    [&]() { return tCharset[dist(mRandomEngine)]; });

    return randomString;
  }
};

class PathProcessor {
public:
  // This function tries to create a substring starting from the last ../ or ./
  // sequence
  // @WARNING: This function "fails" on this testcase: "../../dir1/../file1.c"
  // -> "file1.c"
  //           But I'm assuming, that we don't ever have real paths with .. in
  //           them
  // "../../dir1/file1.c"    -> "dir1/file1.c"
  // "dir1/file1.c"          -> "dir1/file1.c"
  // "./file1.c"             -> "file1.c"
  // ".././file1.c"          -> "file1.c"
  // "../file1.c"            -> "file1.c"
  static std::string RemoveUnnecessaryPathComponents(std::string &&path) {
    auto pos = std::find_end(path.begin(), path.end(), consts::cDot.cbegin(),
                             consts::cDot.cend());

    if (pos == path.end()) {
      return path;
    }

    return path.substr(std::distance(std::begin(path), pos) +
                           consts::cDot.size(),
                       path.size());
  }
};

// @TODO: Potentially it is better (for performance) to implement additional
// method
//   inside FunctionDecl class, thus the calculated ODRHash value will be
//   cached?
class ODRHashCalculator {
public:
  static unsigned CalculateHash(const FunctionDecl *func,
                                bool skipBody = true) {
    class ODRHash Hash;
    Hash.AddFunctionDecl(func, skipBody);
    return Hash.CalculateHash();
  }
};

} // namespace utils
} // namespace futag

#endif
