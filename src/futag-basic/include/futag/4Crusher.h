//===-- Basic.cpp -------*- C++ -*-===//
//
// This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
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

#ifndef FUTAG_4CRUSHER_H
#define FUTAG_4CRUSHER_H

#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "clang/AST/Type.h"
#include "clang/Tooling/Tooling.h"
#include "futag/Basic.h"

using namespace std;
using namespace llvm;
using namespace clang;

namespace futag {

void gen_wrapper_4Crusher(ofstream *fuzz_file, vector<string> include_headers,
                          futag::genstruct *generator);

}  // namespace futag

#endif  // FUTAG_4CRUSHER_H