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

/**
 * @brief This struct for saving found callExpr
 *
 */
struct FutagCodeLoc {
    unsigned int line;
    unsigned int col;
    std::string file;
};

typedef std::vector<const CallExpr *> FutagCallContext;

// Enum of argument generating type
typedef enum { ArgVarRef, ArgConstValue, ArgFuncCall, ArgUnknown,  ArgConstValueSTR} ArgInitType;

// Struct for generating argument
struct FutagInitArg {
    ArgInitType init_type;
    std::string value = ""; // name of variable if init_type is ArgVarRef,
                            //  const value if init_type is ArgConstValue,
                            //  str of callexpr if init_type is ArgFuncCall
    CallExpr *func_call = NULL;
    ValueDecl *var_decl = NULL;
};
// Struct for an init call_expression
struct FutagInitCallExpr {
    unsigned int block_id;
    const CallExpr *call;
};

struct FutagCallExprInfo {
    const CallExpr *call_expr;
    std::string qname;
    std::string name;
    std::string str_stmt;
    std::vector<FutagInitArg> args;
    unsigned int cfg_block_ID;
    FutagCodeLoc location;
};

struct FutagInitVarDeclCallExpr {
    // const VarDecl *var_decl;
    std::string var_name;
    FutagCallExprInfo call_expr_info;
};

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

typedef std::vector<unsigned int> FutagPath;

futag::FutagCallExprInfo GetCallExprSimpleInfo( //
    const CallExpr *call_expr,                  //
    clang::CFGStmtMap *cfg_stmt_map,            //
    AnalysisManager &Mgr);
bool HandleLiterals(const Expr *arg, FutagInitArg &curr_init_arg);
futag::FutagCallExprInfo GetCallExprInfo( //
    const CallExpr *call_expr,            //
    clang::CFGStmtMap *cfg_stmt_map,      //
    AnalysisManager &Mgr,                 //
    const json &analysis_jdb,             //
    std::vector<FutagInitVarDeclCallExpr> &init_calls);

void SearchModifyingCallExprInBlock(
    AnalysisManager &Mgr,
    std::string var_name,            // current argument for search
    Stmt *curr_search_node,          // current node for search
    clang::CFGStmtMap *cfg_stmt_map, // map for matching found callexpr
    FutagPath &curr_context_path,    // current path for adding node to path
    futag::FutagPath::iterator &curr_analyzed_pos, // for checking reverse match
    futag::FutagPath &curr_analyzed_path,          // for checking reverse match
    std::vector<FutagInitVarDeclCallExpr> &init_calls, //
    std::vector<FutagCallExprInfo> &modifying_calls,   //
    const json &analysis_jdb);

void SearchVarDeclInBlock(
    AnalysisManager &Mgr,
    FutagInitArg iter_arg,           // current argument for search
    Stmt *curr_search_node,          // current node for search
    clang::CFGStmtMap *cfg_stmt_map, // map for matching found callexpr
    FutagPath &curr_context_path,    // current path for adding node to path
    futag::FutagPath::iterator &curr_analyzed_pos, // for checking reverse match
    futag::FutagPath &curr_analyzed_path,          // for checking reverse match
    std::vector<FutagInitVarDeclCallExpr> &init_calls,
    const json &analysis_jdb);

// Class for matching Init CallExpression
class FutagMatchInitCallExprCB : public MatchFinder::MatchCallback {
  public:
    FutagMatchInitCallExprCB(
        AnalysisManager &Mgr, const FunctionDecl *consumer_func,
        std::map<const VarDecl *, const CallExpr *> &matched_init_callexpr,
        const json &analysis_jdb)
        : Mgr{Mgr},                       // Analysis manager
          consumer_func{consumer_func}, // Function
          matched_init_callexpr{
              matched_init_callexpr},   // result - matched call expressions
          analysis_jdb{analysis_jdb} {} // Analysis database

    AnalysisManager &Mgr;               // For passing the AnalysisManager
    const FunctionDecl *consumer_func; // Current analyzed function
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

    std::map<const VarDecl *, const CallExpr *> &matched_init_callexpr;
    const json &analysis_jdb;
};

// Class for matching definition CallExpression
class FutagMatchDefCallExprCB : public MatchFinder::MatchCallback {
  public:
    FutagMatchDefCallExprCB(AnalysisManager &Mgr, //
                            clang::CFGStmtMap *cfg_stmt_map,
                            FutagPath &curr_context_path,
                            futag::FutagPath::iterator &curr_analyzed_pos,
                            futag::FutagPath &curr_analyzed_path,
                            std::vector<FutagInitVarDeclCallExpr> &init_calls,
                            const json &analysis_jdb)
        : Mgr{Mgr},                               //
          cfg_stmt_map{cfg_stmt_map},             //
          curr_context_path{curr_context_path},   //
          curr_analyzed_pos{curr_analyzed_pos},   //
          curr_analyzed_path{curr_analyzed_path}, //
          init_calls{init_calls},                 //
          analysis_jdb{analysis_jdb} {}

    virtual void run(const MatchFinder::MatchResult &Result);

  private:
    AnalysisManager &Mgr;
    clang::CFGStmtMap *cfg_stmt_map; // map for matching found callexpr
    FutagPath &curr_context_path;    // current path for adding node to path
    futag::FutagPath::iterator &curr_analyzed_pos; // for checking reverse match
    futag::FutagPath &curr_analyzed_path;          // for checking reverse match
    std::vector<FutagInitVarDeclCallExpr> &init_calls;
    const json &analysis_jdb;
};
// Class for matching modifying CallExpression
class FutagMatchModCallExprCB : public MatchFinder::MatchCallback {
  public:
    FutagMatchModCallExprCB(AnalysisManager &Mgr,            //
                            clang::CFGStmtMap *cfg_stmt_map, //
                            FutagPath &curr_context_path,
                            futag::FutagPath::iterator &curr_analyzed_pos,
                            futag::FutagPath &curr_analyzed_path,
                            std::vector<FutagInitVarDeclCallExpr> &init_calls,
                            std::vector<FutagCallExprInfo> &modifying_calls,
                            const json &analysis_jdb, //
                            Stmt *curr_search_node)
        : Mgr{Mgr},                               //
          cfg_stmt_map{cfg_stmt_map},             //
          curr_context_path{curr_context_path},   //
          curr_analyzed_pos{curr_analyzed_pos},   //
          curr_analyzed_path{curr_analyzed_path}, //
          init_calls{init_calls},                 //
          modifying_calls{modifying_calls},       //
          analysis_jdb{analysis_jdb},             //
          curr_search_node{curr_search_node} {}   //

    virtual void run(const MatchFinder::MatchResult &Result);

  private:
    AnalysisManager &Mgr;            // map for matching found callexpr
    clang::CFGStmtMap *cfg_stmt_map; // map for matching found callexpr
    FutagPath &curr_context_path;    // current path for adding node to path
    futag::FutagPath::iterator &curr_analyzed_pos; // for checking reverse match
    futag::FutagPath &curr_analyzed_path;          // for checking reverse match
    std::vector<FutagInitVarDeclCallExpr> &init_calls;
    std::vector<FutagCallExprInfo> &modifying_calls;
    const json &analysis_jdb;
    Stmt *curr_search_node;
};
} // namespace futag

#endif