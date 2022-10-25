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

// first define matchers
// assign
const auto decls =
    declStmt(
        forEachDescendant(
            varDecl(anyOf(hasInitializer(stmt(forEachDescendant(
                              declRefExpr(to(varDecl().bind("declInit")))))),
                          hasInitializer(anything()),
                          unless(hasInitializer(anything()))))
                .bind("decl")))
        .bind("declStmt");

const auto bop =
    binaryOperator(
        isAssignmentOp(),
        hasLHS(ignoringImpCasts(declRefExpr(to(varDecl().bind("lval"))))),
        anyOf(hasRHS(forEachDescendant(
                  expr(declRefExpr(to(varDecl().bind("rval")))))),
              hasRHS(anything())))
        .bind("binop");

// fixme do something with unary ops which are embedded in statements like:
// TODO: int x = a++;
const auto uop =
    unaryOperator(isIncrementDecrementOp(),
                  hasDescendant(declRefExpr(to(varDecl().bind("uval")))))
        .bind("unop");

const auto ret =
    returnStmt(forEachDescendant(declRefExpr(to(varDecl().bind("retVar")))))
        .bind("ret");
// branch
const auto ifs =
    ifStmt(hasCondition(anyOf(
               forEachDescendant(declRefExpr(to(varDecl().bind("ifCondVar")))),
               anything())))
        .bind("if");
// loop. TODO: detect and handle continue/break statements
const auto whiles =
    whileStmt(hasCondition(anyOf(forEachDescendant(declRefExpr(
                                     to(varDecl().bind("whileCondVar")))),
                                 anything())))
        .bind("while");
// compound
const auto compounds = compoundStmt().bind("comp");

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

class Statement {
public:
  enum class Type { Base, Assign, Branch, Loop, Compound };

  enum class Edge {
    None,
    False,
    True,
  };

  static std::string EdgeToStr(Edge e);

  struct StatementLocCmp {
    bool operator()(const std::pair<Statement *, Edge> &lhs,
                    const std::pair<Statement *, Edge> &rhs) const {
      return lhs.first->loc.isBeforeInTranslationUnitThan(rhs.first->loc);
    }
  };

  explicit Statement(const clang::Stmt *_astRef, clang::FullSourceLoc _loc)
      : loc(_loc), astRef(_astRef) {
    setId();
  }

  explicit Statement(const clang::Stmt *_astRef, clang::FullSourceLoc _loc,
                     std::set<const clang::ValueDecl *> _define)
      : define(std::move(std::move(_define))), loc(_loc), astRef(_astRef) {
    setId();
  }

  virtual ~Statement() = default;

  // graph
  void addControlChild(std::pair<Statement *, Edge> child);
  void addDataEdge(Statement *s);

  // define/use
  void addUse(const clang::ValueDecl *_use) { use.insert(_use); }

  void addDefine(const clang::ValueDecl *_define) { define.insert(_define); }

  // location
  void setLocation(clang::FullSourceLoc _loc) { loc = _loc; }

  clang::FullSourceLoc getLocation() const { return loc; }

  // getters
  std::set<std::pair<Statement *, Edge>, StatementLocCmp>
  getControlChildren() const {
    return controlChildren;
  }

  std::set<std::pair<Statement *, Edge>, StatementLocCmp>
  getControlParents() const {
    return controlParents;
  }

  std::set<Statement *> getDataEdges() const { return dataEdges; }

  std::set<Statement *> getDataParents() const { return dataParents; }

  std::set<const clang::ValueDecl *> getDefine() const { return define; }

  std::set<const clang::ValueDecl *> getUses() const { return use; }

  const clang::Stmt *getAstRef() const { return astRef; }

  // returns if source has path to dest in graph.

  // name
  virtual Type name() { return Type::Base; }

  virtual std::string nameAsString() { return "Statement"; }
  virtual std::string sourceString(clang::SourceManager &sm);
  // factory method
  static Statement *create(const clang::Stmt *astref, clang::FullSourceLoc loc);

  // this draws in the data dependence edges to the graph
  // caller and initializer
  void setDataEdges();

  // s.l.i.c.e
  static void slice(Statement *slicingStmt, bool backwards);
  void resetSlice();
  void markSliced() { inSlice = true; }
  void unmarkSliced() { inSlice = false; }
  bool isInSlice() const { return inSlice; }
  int getId() const { return id; }

  // print structure
  std::string dump();
  // graphviz output
  std::string dumpDot(clang::SourceManager &sm, bool markSliced);

protected:
  std::string dumpLevel(int level);
  std::string dumpDotRec(clang::SourceManager &sm, bool markSliced,
                         std::map<int, std::vector<int>> &rank_map, int depth);
  // [(var,[(stmt,edge)]]
  typedef std::map<const clang::ValueDecl *,
                   std::set<std::pair<Statement *, Edge>>>
      defsMap;
  defsMap setDataEdgesRec(const defsMap &parent_def_map,
                          std::vector<Statement *> loopRefs, int inABranch);
  void setId() {
    static auto _id = 0;
    id = _id++;
  }
  static std::string stmt2str(const clang::Stmt *s, clang::SourceManager &sm);
  static std::string firstOnly(const clang::Stmt *s, const clang::Stmt *s2,
                               clang::SourceManager &sm);
  // graph
  std::set<std::pair<Statement *, Edge>, StatementLocCmp> controlChildren;
  std::set<Statement *> dataEdges;
  std::set<std::pair<Statement *, Edge>, StatementLocCmp> controlParents;
  std::set<Statement *> dataParents;
  // These store the variables that are defined / used in this statement
  std::set<const clang::ValueDecl *> define;
  std::set<const clang::ValueDecl *> use;
  clang::FullSourceLoc loc;
  int id;
  bool inSlice = false;
  // Store a reference to the AST
  const clang::Stmt *astRef = nullptr;
};

// Specializations
class AssignStatement : public Statement {
public:
  using Statement::Statement;
  Type name() override { return Type::Assign; }
  std::string nameAsString() override { return "Assign"; }
};

class BranchStatement : public Statement {
public:
  using Statement::Statement;
  Type name() override { return Type::Branch; }
  std::string nameAsString() override { return "Branch"; }
  std::string sourceString(clang::SourceManager &sm) override;
};

// Loop and Branch almost the same, but they differ in the data dependence edge
// creations.
class LoopStatement : public Statement {
public:
  using Statement::Statement;
  Type name() override { return Type::Loop; }
  std::string nameAsString() override { return "Loop"; }
  std::string sourceString(clang::SourceManager &sm) override;
};

class CompoundStatement : public Statement {
public:
  using Statement::Statement;
  Type name() override { return Type::Compound; }
  std::string nameAsString() override { return "Compound"; }
  std::string sourceString(clang::SourceManager &sm) override;
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
  bool HandleLiterals(const clang::Expr *implicitArg,
                      json &currArgumentContext);
  void HandleDeclRefExpr(const DeclRefExpr *arg, json &currArgumentContext);
  void HandleCharacterLiteral(const CharacterLiteral *arg,
                              json &currArgumentContext);
  void HandleFixedPointLiteral(const FixedPointLiteral *arg,
                               json &currArgumentContext);
  void HandleFloatingLiteral(const FloatingLiteral *arg,
                             json &currArgumentContext);
  void HandleImaginaryLiteral(const ImaginaryLiteral *arg,
                              json &currArgumentContext);
  void HandleIntegerLiteral(const IntegerLiteral *arg,
                            json &currArgumentContext);
  void HandleStringLiteral(const clang::StringLiteral *arg,
                           json &currArgumentContext);

  void HandleCallExpr(const CallExpr *arg, json &currArgumentContext);

  json &currentContext;
};

// Processes all call expressions inside specific function to
// determine callee arguments types
class FutagArgumentUsageDeterminer : public MatchFinder::MatchCallback {
public:
  FutagArgumentUsageDeterminer(json &currentParamContext, AnalysisManager &Mgr,
                               Stmt *CurrentNode, const FunctionDecl *CurrFunc)
      : Mgr{Mgr}, CurrentNode{CurrentNode}, CurrFunc{CurrFunc},
        currentParamContext{currentParamContext} {}
  AnalysisManager &Mgr;
  Stmt *CurrentNode;            // For passing the current node for searching
  const FunctionDecl *CurrFunc; // Currently analyzed function
  virtual void run(const MatchFinder::MatchResult &Result);

private:
  json &currentParamContext;
};

class FutagContextConsumerCallBack : public MatchFinder::MatchCallback {
private:
  bool hasStmt(const Stmt *value) {
    return stmt_map.find(value) != stmt_map.end();
  }
  static FullSourceLoc
  getLoc(const ast_matchers::MatchFinder::MatchResult &result,
         const Stmt *astRef);

  void setSlicingStmt(const ast_matchers::MatchFinder::MatchResult &result,
                      const Stmt *astRef);

public:
  FutagContextConsumerCallBack(AnalysisManager &Mgr, const FunctionDecl *func,
                               unsigned int lineNo, unsigned int colNo)
      : Mgr{Mgr}, func{func}, lineNo{lineNo}, colNo{colNo} {
    if (!hasStmt(func->getBody())) {
      stmt_map[func->getBody()] = new CompoundStatement(
          func->getBody(), Mgr.getASTContext().getFullLoc(func->getBeginLoc()));
    }
    for (auto &var : func->parameters()) {
      stmt_map[func->getBody()]->addDefine(var);
    }
  }
  void printMap();
  struct slicingStmtPos {
    slicingStmtPos() = default;

    slicingStmtPos(int _sline, int _scol, int _eline, int _ecol)
        : sline(_sline), scol(_scol), eline(_eline), ecol(_ecol) {}

    unsigned int sline{0};
    unsigned int scol{0};
    unsigned int eline{INT_MAX};
    unsigned int ecol{INT_MAX};
    bool refined(unsigned int sl, unsigned int sc, unsigned int el,
                 unsigned int ec);
  };
  AnalysisManager &Mgr;
  const FunctionDecl *func; // For passing the current node for searching
  virtual void run(const MatchFinder::MatchResult &Result);
  std::map<const Stmt *, Statement *> stmt_map;
  void dumpDots();
  // tool params
  const std::string funcName;
  unsigned int lineNo = 0;
  unsigned int colNo = 0;
  bool dumpDot = false;
  const Stmt *slicingStmt = nullptr;
  slicingStmtPos slicePos;
  SourceManager *sm = nullptr;
};

} // namespace futag

#endif