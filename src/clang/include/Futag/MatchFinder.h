#ifndef FUTAG_MATCHFINDER_H
#define FUTAG_MATCHFINDER_H

#include "nlohmann/json.hpp"
#include "clang/AST/ComputeDependence.h"
#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "Futag/Utils.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace nlohmann;
using namespace ento;
using namespace llvm;

namespace futag {

// Class for matching binaryOperator
class FutagMatchBinaryOperatorCallBack : public MatchFinder::MatchCallback {
public:
  //   AnalysisManager &Mgr;
  virtual void run(const MatchFinder::MatchResult &Result);
};

// Class for matching Variable Declaration
class FutagMatchVarDeclCallBack : public MatchFinder::MatchCallback {
public:
  //   AnalysisManager &Mgr;
  virtual void run(const MatchFinder::MatchResult &Result);
};

// Class for matching CallExpression
class FutagMatchCallExprCallBack : public MatchFinder::MatchCallback {
public:
  FutagMatchCallExprCallBack(json &currentContext, AnalysisManager &Mgr,
                             Stmt *CurrentNode, const FunctionDecl *CurrFunc)
      : Mgr{Mgr}, CurrentNode{CurrentNode}, CurrFunc{CurrFunc},
        currentContext{currentContext} {}
  AnalysisManager &Mgr;         // For passing the AnalysisManager
  Stmt *CurrentNode;            // For passing the current node for searching
  const FunctionDecl *CurrFunc; // Current analyzed function
  virtual void run(const MatchFinder::MatchResult &Result);

private:
  // All different functions that handles specific types
  bool HandleLiterals(const clang::Expr* implicitArg, json& currArgumentContext);
  void HandleDeclRefExpr(const DeclRefExpr* arg, json& currArgumentContext);
  void HandleCharacterLiteral(const CharacterLiteral* arg, json& currArgumentContext);
  void HandleFixedPointLiteral(const FixedPointLiteral* arg, json& currArgumentContext);
  void HandleFloatingLiteral(const FloatingLiteral* arg, json& currArgumentContext);
  void HandleImaginaryLiteral(const ImaginaryLiteral* arg, json& currArgumentContext);
  void HandleIntegerLiteral(const IntegerLiteral* arg, json& currArgumentContext);
  void HandleStringLiteral(const clang::StringLiteral* arg, json& currArgumentContext);
  
  void HandleCallExpr(const CallExpr* arg, json& currArgumentContext);

  json &currentContext;
};

// Processes all call expressions inside specific function to
// determine callee arguments types
class FutagArgumentUsageDeterminer : public MatchFinder::MatchCallback {
public:
  FutagArgumentUsageDeterminer(json &currentParamContext, AnalysisManager &Mgr, Stmt *CurrentNode, const FunctionDecl *CurrFunc)
      : Mgr{Mgr}, CurrentNode{CurrentNode}, CurrFunc{CurrFunc},
        currentParamContext{currentParamContext} {}
  AnalysisManager &Mgr;
  Stmt *CurrentNode;            // For passing the current node for searching
  const FunctionDecl *CurrFunc; // Currently analyzed function
  virtual void run(const MatchFinder::MatchResult &Result);

private:
  json &currentParamContext;
};

} // namespace futag

#endif