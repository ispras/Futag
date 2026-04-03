//== FutagCatchInfo.cpp ----------------------------------- -*- C++
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

class FutagCatchInfo : public Checker<check::ASTDecl<FunctionDecl>> {
  public:
    string FuncName = "";
    unsigned int BeginLine = 0;
    unsigned int EndLine = 0;
    void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                      BugReporter &BR) const;
};

} // namespace

/**
 * @brief 
 * 
 * @param func 
 * @param Mgr 
 * @param BR 
 */
void FutagCatchInfo::checkASTDecl(const FunctionDecl *func,
                                  AnalysisManager &Mgr, BugReporter &BR) const {
    if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc()) ||
        !func->hasBody()) {
        return;
    }
    MatchFinder Finder;

    if (func->getNameAsString() != this->FuncName)
        return;
    clang::LangOptions lo;
    string out_str;
    llvm::raw_string_ostream outstream(out_str);

    // auto MatchFuncCall = stmt().bind("stmt");
    auto MatchFuncCall = declRefExpr().bind("declRefExpr");
    Stmt *CurrentNode = func->getBody();
    futag::FutagCatchInfoCallBack statementMatchCallBack{Mgr, func, BeginLine,
                                                         EndLine};
    llvm::outs() << "-- Begin line: " << statementMatchCallBack.BeginLine
                 << "\n";
    llvm::outs() << "-- End line: " << statementMatchCallBack.EndLine << "\n";

    Finder.addMatcher(MatchFuncCall, &statementMatchCallBack);
    Finder.futagMatchAST(Mgr.getASTContext(), CurrentNode);
}

void ento::registerFutagCatchInfo(CheckerManager &Mgr) {
    auto *Chk = Mgr.registerChecker<FutagCatchInfo>();
    Chk->FuncName = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
        Mgr.getCurrentCheckerName(), "FuncName"));
    Chk->BeginLine = Mgr.getAnalyzerOptions().getCheckerIntegerOption(
        Mgr.getCurrentCheckerName(), "BeginLine");
    Chk->EndLine = Mgr.getAnalyzerOptions().getCheckerIntegerOption(
        Mgr.getCurrentCheckerName(), "EndLine");
}

bool ento::shouldRegisterFutagCatchInfo(const CheckerManager &mgr) {
    return true;
}
