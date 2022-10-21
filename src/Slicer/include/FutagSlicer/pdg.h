#ifndef PDG_H
#define PDG_H

#include "clang/AST/AST.h"
#include <set>
#include <utility>

/*!
 * Program Dependence Graph
 * Node information stored in Statements
 * specifics are in the specializations
 */

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
#endif // PDG_H