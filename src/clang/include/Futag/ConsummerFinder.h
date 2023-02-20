#ifndef FUTAG_MATCHFINDER_H
#define FUTAG_MATCHFINDER_H

#include "Futag/Utils.h"
#include "nlohmann/json.hpp"
#include "clang/AST/ComputeDependence.h"
#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/Support/Process.h"
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;
using namespace nlohmann;
using namespace ento;
using namespace llvm;

namespace futag {

// Struct for edges of graph
struct FutagEdge {
    unsigned int node_f;
    unsigned int node_t;
    inline bool operator==(const FutagEdge &rhs) {
        return this->node_f == rhs.node_f && this->node_t == rhs.node_t;
    };
    inline bool operator==(const FutagEdge *rhs) {
        return this->node_f == rhs->node_f && this->node_t == rhs->node_t;
    };
};
typedef std::vector<FutagEdge> FutagGraph;

typedef std::vector<int> FutagPath;

// Class for matching CallExpression
class FutagMatchConsummerCallExprCallBack : public MatchFinder::MatchCallback {
  public:
    FutagMatchConsummerCallExprCallBack(
        AnalysisManager &Mgr, const FunctionDecl *consummer_func,
        std::vector<const CallExpr *> &matched_call_expr, const json &analysis_jdb)
        : Mgr{Mgr},                       // Analysis manager
          consummer_func{consummer_func}, // Function
          matched_call_expr{
              matched_call_expr},       // result - matched call expressions
          analysis_jdb{analysis_jdb} {} // Analysis database

    AnalysisManager &Mgr; // For passing the AnalysisManager
    const FunctionDecl *consummer_func; // Current analyzed function
    virtual void run(const MatchFinder::MatchResult &Result);

  private:
    utils::Random rand{};
    // All different functions that handles specific types
    bool HandleLiterals(const clang::Expr *implicitArg, json &curr_arg_context);
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
    void FindPathInCFG(const CFGBlock *stmt_block, std::vector<unsigned> &path,
                       std::vector<std::vector<unsigned>> &all_path);

    void HandleCallExpr(const CallExpr *arg, json &curr_arg_context);

    void HandleDeclRefExpr(const DeclRefExpr *arg, json &curr_arg_context);

    std::vector<const CallExpr *> &matched_call_expr;
    const json &analysis_jdb;
};
} // namespace futag

#endif