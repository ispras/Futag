//== FutagContextConsumer.cpp ----------------------------------- -*- C++
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

class FutagContextConsumer : public Checker<check::ASTDecl<FunctionDecl>> {
public:
  string FuncName = "";
  unsigned int LineNumber = 0;
  unsigned int ColNumber = 0;
  void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const;
};

} // namespace

void FutagContextConsumer::checkASTDecl(const FunctionDecl *func,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc()) ||
      !func->hasBody()) {
    return;
  }
  MatchFinder Finder;

  if (func->getNameAsString() != this->FuncName)
    return;
  auto MatchFuncCall =
      stmt(eachOf(futag::ifs, futag::whiles, futag::compounds, futag::decls,
                  futag::bop, futag::uop, futag::ret))
          .bind("stmt");
  Stmt *CurrentNode = func->getBody();
  // llvm::outs() << "-- >> Dump: ";
  clang::LangOptions lo;
  string out_str;
  llvm::raw_string_ostream outstream(out_str);
  // CurrentNode->printPretty(outstream, NULL, PrintingPolicy(lo));
  // llvm::outs() << out_str << "\n";
  // CurrentNode->dump();
  futag::FutagContextConsumerCallBack functionCallCallBack{
      Mgr, func, LineNumber, ColNumber};
  Finder.addMatcher(MatchFuncCall, &functionCallCallBack);
  Finder.futagMatchAST(Mgr.getASTContext(), CurrentNode);
  llvm::outs() << "-- Line number: " << functionCallCallBack.lineNo << "\n";
  llvm::outs() << "-- Col number: " << functionCallCallBack.colNo << "\n";
  // llvm::outs()<<functionCallCallBack.stmt_map[CurrentNode]->dump();
  llvm::outs() << "----- slicing statement: ";
  functionCallCallBack.slicingStmt->printPretty(outstream, NULL,
                                                PrintingPolicy(lo));
  llvm::outs() << out_str << "\n";
  // std::map<const Stmt *, Statement *>::iterator it;
  // llvm::outs() << "-map: \n";
  // for (it = functionCallCallBack.stmt_map.begin();
  //      it != functionCallCallBack.stmt_map.end(); it++) {
  //   clang::LangOptions lo;
  //   std::string out_str;
  //   llvm::raw_string_ostream outstream(out_str);
  //   it->first->printPretty(outstream, NULL, PrintingPolicy(lo));
  //   llvm::outs() << "-- map item: " << out_str << ':' <<
  //   it->second->nameAsString()
  //                << "\n";
  // }

  // llvm::outs()<< "----- slicing: ";
  // functionCallCallBack.stmt_map[CurrentNode]->slice(functionCallCallBack.stmt_map[functionCallCallBack.slicingStmt],
  // false); llvm::outs() <<
  // functionCallCallBack.stmt_map[CurrentNode]->dumpDot(Mgr.getSourceManager(),
  // true);

  // dump useful info
  if (functionCallCallBack.slicingStmt != nullptr) {
    llvm::errs() << "slicing statement is:\n";
    functionCallCallBack.slicingStmt->dumpColor();
  } else {
    llvm::errs() << "You've given invalid location for slicing var, since I've "
                    "found no variable there.\n";
    return;
  }
  llvm::errs() << "With control edges, but no data dependence edges:\n";
  llvm::errs() << functionCallCallBack.stmt_map[CurrentNode]->dump();
  functionCallCallBack.stmt_map[CurrentNode]->setDataEdges();
  llvm::errs() << "With data dependence edges too:\n";
  llvm::errs() << functionCallCallBack.stmt_map[CurrentNode]->dump();
  functionCallCallBack.dumpDots();
}

void ento::registerFutagContextConsumer(CheckerManager &Mgr) {
  auto *Chk = Mgr.registerChecker<FutagContextConsumer>();
  Chk->FuncName = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
      Mgr.getCurrentCheckerName(), "FuncName"));
  Chk->LineNumber = Mgr.getAnalyzerOptions().getCheckerIntegerOption(
      Mgr.getCurrentCheckerName(), "LineNumber");
  Chk->ColNumber = Mgr.getAnalyzerOptions().getCheckerIntegerOption(
      Mgr.getCurrentCheckerName(), "ColNumber");
}

bool ento::shouldRegisterFutagContextConsumer(const CheckerManager &mgr) {
  return true;
}
