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
AST_MATCHER(BinaryOperator, isAssignmentOp) { return Node.isAssignmentOp(); }

AST_MATCHER(UnaryOperator, isIncrementDecrementOp) {
    return Node.isIncrementDecrementOp();
}

std::string getFile(const Stmt *stmt, SourceManager *sm);

// Class for matching binaryOperator of function argument
class FutagMatchVarDeclArgCallBack : public MatchFinder::MatchCallback {
  public:
    FutagMatchVarDeclArgCallBack(AnalysisManager &Mgr, Stmt *curr_node,
                                 const DeclRefExpr *arg, json &curr_arg_context)
        : Mgr{Mgr}, curr_node{curr_node}, arg{arg}, curr_arg_context{
                                                        curr_arg_context} {}
    AnalysisManager &Mgr; // For passing the AnalysisManager
    Stmt *curr_node;      // For passing the current node for searching
    json &curr_arg_context;
    const DeclRefExpr *arg;
    virtual void run(const MatchFinder::MatchResult &Result);
};

// Class for matching binaryOperator of function argument
class FutagMatchBinOperatorArgCallBack : public MatchFinder::MatchCallback {
  public:
    FutagMatchBinOperatorArgCallBack(AnalysisManager &Mgr, Stmt *curr_node,
                                     const DeclRefExpr *arg,
                                     json &curr_arg_context)
        : Mgr{Mgr}, curr_node{curr_node}, arg{arg}, curr_arg_context{
                                                        curr_arg_context} {}
    AnalysisManager &Mgr; // For passing the AnalysisManager
    Stmt *curr_node;      // For passing the current node for searching
    json &curr_arg_context;
    const DeclRefExpr *arg;
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
    FutagMatchCallExprCallBack(json &curr_context, AnalysisManager &Mgr,
                               Stmt *curr_node,
                               const FunctionDecl *consummer_func)
        : curr_context{curr_context}, Mgr{Mgr}, curr_node{curr_node},
          consummer_func{consummer_func} {}
    AnalysisManager &Mgr; // For passing the AnalysisManager
    Stmt *curr_node;      // For passing the current node for searching
    const FunctionDecl *consummer_func; // Current analyzed function
    virtual void run(const MatchFinder::MatchResult &Result);

  private:
    // All different functions that handles specific types
    bool HandleLiterals(const clang::Expr *implicitArg, json &curr_arg_context);
    void HandleDeclRefExpr(const DeclRefExpr *arg, json &curr_arg_context);
    void HandleCharacterLiteral(const CharacterLiteral *arg,
                                json &curr_arg_context);
    void HandleFixedPointLiteral(const FixedPointLiteral *arg,
                                 json &curr_arg_context);
    void HandleFloatingLiteral(const FloatingLiteral *arg,
                               json &curr_arg_context);
    void HandleImaginaryLiteral(const ImaginaryLiteral *arg,
                                json &curr_arg_context);
    void HandleIntegerLiteral(const IntegerLiteral *arg,
                              json &curr_arg_context);
    void HandleStringLiteral(const clang::StringLiteral *arg,
                             json &curr_arg_context);

    void HandleCallExpr(const CallExpr *arg, json &curr_arg_context);

    json &curr_context;
};

// Processes all call expressions inside specific function to
// determine callee arguments types
class FutagArgUsageDeterminer : public MatchFinder::MatchCallback {
  public:
    FutagArgUsageDeterminer(json &curr_param_context, AnalysisManager &Mgr,
                            Stmt *curr_node, const FunctionDecl *consummer_func)
        : Mgr{Mgr}, curr_node{curr_node}, consummer_func{consummer_func},
          curr_param_context{curr_param_context} {}
    AnalysisManager &Mgr;
    Stmt *curr_node; // For passing the current node for searching
    const FunctionDecl *consummer_func; // Currently analyzed function
    virtual void run(const MatchFinder::MatchResult &Result);

  private:
    json &curr_param_context;
};

class FutagCatchInfoCallBack : public MatchFinder::MatchCallback {
  public:
    FutagCatchInfoCallBack(AnalysisManager &Mgr, const FunctionDecl *func,
                           unsigned int BeginLine, unsigned int EndLine)
        : Mgr{Mgr}, func{func}, BeginLine{BeginLine}, EndLine{EndLine} {}

    ~FutagCatchInfoCallBack();

    AnalysisManager &Mgr;
    const FunctionDecl *func; // For passing the current node for searching
    virtual void run(const MatchFinder::MatchResult &Result);
    // tool params
    const std::string funcName;
    unsigned int BeginLine = 0;
    unsigned int EndLine = 0;
    SourceManager *sm = nullptr;
    std::vector<unsigned int> decl_hash_list{};
    std::vector<const DeclRefExpr *> decl_ref_list{};
};

} // namespace futag

#endif