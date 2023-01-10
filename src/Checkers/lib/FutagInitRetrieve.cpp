//== FutagInitRetrieve.cpp ----------------------------------- -*- C++
//-*--=//
//
//===----------------------------------------------------------------------===//
//
// This module tries to collect some useful information to use with futag
// while generating libfuzzer targets.
//
//===----------------------------------------------------------------------===//

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Futag/Basic.h"
#include "Futag/MatchFinder.h"
#include "Futag/Utils.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/Tooling/Tooling.h"

using namespace llvm;
using namespace clang;
using namespace ento;
using namespace nlohmann;
using namespace futag;
using namespace clang::ast_matchers;

//===----------------------------------------------------------------------===//
// Checker to analyze function declarations
//===----------------------------------------------------------------------===//
namespace {
AST_MATCHER(BinaryOperator, isAssignmentOp) { return Node.isAssignmentOp(); }

AST_MATCHER(UnaryOperator, isIncrementDecrementOp) {
  return Node.isIncrementDecrementOp();
}

class FutagInitRetrieve : public Checker<check::ASTDecl<FunctionDecl>> {
public:
  string TargetFunction = "";
  string TargetFile = "";
  unsigned int TargetLine = 0;
  string ConsummerFunction = "";
  string ConsummerFile = "";
  unsigned int ConsummerLine = 0;
  void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const;
};

} // namespace

void FutagInitRetrieve::checkASTDecl(const FunctionDecl *func,
                                  AnalysisManager &Mgr, BugReporter &BR) const {
  if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc()) ||
      !func->hasBody()) {
    return;
  }
  MatchFinder Finder;

  if (func->getNameAsString() != this->ConsummerFunction)
    return;

  Stmt *CurrentNode = func->getBody();


}

void ento::registerFutagInitRetrieve(CheckerManager &Mgr) {
  auto *Chk = Mgr.registerChecker<FutagInitRetrieve>();
  Chk->TargetFunction = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
      Mgr.getCurrentCheckerName(), "TargetFunction"));
  Chk->TargetFile = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
      Mgr.getCurrentCheckerName(), "TargetFile"));
  Chk->TargetLine = Mgr.getAnalyzerOptions().getCheckerIntegerOption(
      Mgr.getCurrentCheckerName(), "TargetLine");
  
  Chk->FuncConsummerFunctionName = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
      Mgr.getCurrentCheckerName(), "ConsummerFunction"));
  Chk->ConsummerFile = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
      Mgr.getCurrentCheckerName(), "ConsummerFile"));
  Chk->ConsummerLine = Mgr.getAnalyzerOptions().getCheckerIntegerOption(
      Mgr.getCurrentCheckerName(), "ConsummerLine");
}

bool ento::shouldRegisterFutagInitRetrieve(const CheckerManager &mgr) {
  return true;
}
