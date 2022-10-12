#include "FutagSlicer/pdgBuilder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include <fstream>

using namespace clang::ast_matchers;

namespace clang {
namespace slicer {
namespace {
AST_MATCHER(BinaryOperator, isAssignmentOp) { return Node.isAssignmentOp(); }

AST_MATCHER(UnaryOperator, isIncrementDecrementOp) {
  return Node.isIncrementDecrementOp();
}

std::string getFile(const Stmt *stmt, SourceManager *sm) {
  assert(!(stmt == nullptr || sm == nullptr));
  const auto fileID = sm->getFileID(stmt->getBeginLoc());
  const auto fileEntry = sm->getFileEntryForID(fileID);
  if (fileEntry == nullptr) {
    return "";
  }
  return fileEntry->getName().str();
}
} // namespace
void PDGBuilder::dumpDots() {
  auto srcFileName = getFile(root, sm);
  auto out = srcFileName + "_" + funcName + ".dot";
  std::ofstream file(out);
  file << stmt_map[root]->dumpDot(*sm, false);
  file.close();

  out = srcFileName + "_" + funcName + "_backward_slice.dot";
  std::ofstream file2(out);
  stmt_map[root]->slice(stmt_map[slicingStmt], true);
  file2 << stmt_map[root]->dumpDot(*sm, true);
  file2.close();
  stmt_map[root]->resetSlice();

  out = srcFileName + "_" + funcName + "_forward_slice.dot";
  std::ofstream file3(out);
  stmt_map[root]->slice(stmt_map[slicingStmt], false);
  file3 << stmt_map[root]->dumpDot(*sm, true);
  file3.close();
}

bool PDGBuilder::slicingStmtPos::refined(unsigned int sl, unsigned int sc,
                                         unsigned int el, unsigned int ec) {
  auto ret = false;
  if (sl > sline) {
    sline = sl;
    ret = true;
  }
  if (sc > scol) {
    scol = sc;
    ret = true;
  }
  if (el < eline) {
    eline = el;
    ret = true;
  }
  if (ec < ecol) {
    ecol = ec;
    ret = true;
  }
  return ret;
}

void PDGBuilder::setSlicingStmt(const MatchFinder::MatchResult &result,
                                const Stmt *astRef) {
  const auto start = result.Context->getFullLoc(astRef->getBeginLoc());
  const auto end = result.Context->getFullLoc(astRef->getEndLoc());

  if (start.getSpellingLineNumber() <= lineNo &&
      start.getSpellingColumnNumber() <= colNo &&
      lineNo <= end.getSpellingLineNumber() &&
      colNo <= end.getSpellingColumnNumber() &&
      slicePos.refined(
          start.getSpellingLineNumber(), start.getSpellingColumnNumber(),
          end.getSpellingLineNumber(), end.getSpellingColumnNumber())) {
    slicingStmt = astRef;
  }
}

void PDGBuilder::registerMatchers(MatchFinder *MatchFinder) {
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
  // int x = a++;
  const auto uop =
      unaryOperator(isIncrementDecrementOp(),
                    hasDescendant(declRefExpr(to(varDecl().bind("uval")))))
          .bind("unop");

  const auto ret =
      returnStmt(forEachDescendant(declRefExpr(to(varDecl().bind("retVar")))))
          .bind("ret");
  // branch
  const auto ifs = ifStmt(hasCondition(anyOf(forEachDescendant(declRefExpr(to(
                                                 varDecl().bind("ifCondVar")))),
                                             anything())))
                       .bind("if");
  // loop
  // todo detect and handle continue/break statements + the big question: should
  // we?
  const auto whiles =
      whileStmt(hasCondition(anyOf(forEachDescendant(declRefExpr(
                                       to(varDecl().bind("whileCondVar")))),
                                   anything())))
          .bind("while");
  // compound
  const auto compounds = compoundStmt().bind("comp");

  // then add them to MatchFinder
  MatchFinder->addMatcher(
      functionDecl(hasName(funcName),
                   eachOf(forEachDescendant(ifs), forEachDescendant(whiles),
                          forEachDescendant(compounds),
                          forEachDescendant(decls), forEachDescendant(bop),
                          forEachDescendant(uop), forEachDescendant(ret)))
          .bind("f"),
      this);
}

void PDGBuilder::run(const MatchFinder::MatchResult &result) {
  // process the match results
  // ensure every entry added once
  // branch
  if (const auto is = result.Nodes.getNodeAs<IfStmt>("if")) {
    if (!hasStmt(is)) {
      stmt_map[is] = new BranchStatement(is, getLoc(result, is));
    }
    if (!hasStmt(is->getThen())) {
      stmt_map[is->getThen()] =
          Statement::create(is->getThen(), getLoc(result, is->getThen()));
    }
    stmt_map[is]->addControlChild(
        {stmt_map[is->getThen()], Statement::Edge::True});
    if (is->getElse() != nullptr) {
      if (!hasStmt(is->getElse())) {
        stmt_map[is->getElse()] =
            Statement::create(is->getElse(), getLoc(result, is->getElse()));
      }
      stmt_map[is]->addControlChild(
          {stmt_map[is->getElse()], Statement::Edge::False});
    }
    const auto cvar = result.Nodes.getNodeAs<VarDecl>("ifCondVar");
    if (cvar != nullptr) {
      stmt_map[is]->addUse(cvar);
    }
  }
  // loop
  if (const auto ws = result.Nodes.getNodeAs<WhileStmt>("while")) {
    if (!hasStmt(ws)) {
      stmt_map[ws] = new LoopStatement(ws, getLoc(result, ws));
    }
    if (stmt_map[ws]->getControlChildren().empty()) {
      if (!hasStmt(ws->getBody())) {
        stmt_map[ws->getBody()] =
            Statement::create(ws->getBody(), getLoc(result, ws->getBody()));
      }
      stmt_map[ws]->addControlChild(
          {stmt_map[ws->getBody()], Statement::Edge::True});
    }
    const auto cvar = result.Nodes.getNodeAs<VarDecl>("whileCondVar");
    if (cvar != nullptr) {
      stmt_map[ws]->addUse(cvar);
    }
  }
  // compound
  if (const auto cs = result.Nodes.getNodeAs<CompoundStmt>("comp")) {
    if (!hasStmt(cs)) {
      stmt_map[cs] = new CompoundStatement(cs, getLoc(result, cs));
    }
    if (stmt_map[cs]->getControlChildren().empty()) {
      for (auto c : cs->children()) {
        if (stmt_map.find(c) == stmt_map.end()) {
          stmt_map[c] = Statement::create(c, getLoc(result, c));
        }
        stmt_map[cs]->addControlChild({stmt_map[c], Statement::Edge::True});
      }
    }
  }
  // the function
  if (const auto f = result.Nodes.getNodeAs<FunctionDecl>("f")) {
    root = f->getBody();
    if (!hasStmt(root)) {
      stmt_map[root] = new CompoundStatement(root, getLoc(result, root));
    }
    for (auto &var : f->parameters()) {
      stmt_map[root]->addDefine(var);
    }
  }
  // assign
  if (const auto ds = result.Nodes.getNodeAs<DeclStmt>("declStmt")) {
    const auto d = result.Nodes.getNodeAs<VarDecl>("decl");
    if (!hasStmt(ds)) {
      stmt_map[ds] = new AssignStatement(ds, getLoc(result, ds), {d});
    } else {
      stmt_map[ds]->addDefine(d);
    }
    const auto init = result.Nodes.getNodeAs<VarDecl>("declInit");
    if (init != nullptr) {
      stmt_map[ds]->addUse(init);
    }
    setSlicingStmt(result, ds);
  }
  if (const auto bo = result.Nodes.getNodeAs<BinaryOperator>("binop")) {
    const auto lhs = result.Nodes.getNodeAs<VarDecl>("lval");
    if (!hasStmt(bo)) {
      stmt_map[bo] = new AssignStatement(bo, getLoc(result, bo), {lhs});
    } else {
      stmt_map[bo]->addDefine(lhs);
    }
    const auto rval = result.Nodes.getNodeAs<VarDecl>("rval");
    if (rval != nullptr) {
      stmt_map[bo]->addUse(rval);
    }
    setSlicingStmt(result, bo);
  }
  if (const auto uo = result.Nodes.getNodeAs<UnaryOperator>("unop")) {
    const auto var = result.Nodes.getNodeAs<VarDecl>("uval");
    if (!hasStmt(uo)) {
      stmt_map[uo] = new AssignStatement(uo, getLoc(result, uo), {var});
    } else {
      stmt_map[uo]->addDefine(var);
    }
    stmt_map[uo]->addUse(var);
    setSlicingStmt(result, uo);
  }
  if (const auto ret = result.Nodes.getNodeAs<ReturnStmt>("ret")) {
    const auto var = result.Nodes.getNodeAs<VarDecl>("retVar");
    if (!hasStmt(ret)) {
      stmt_map[ret] = new AssignStatement(ret, getLoc(result, ret));
    }
    stmt_map[ret]->addUse(var);
    setSlicingStmt(result, ret);
  }
  // save sourcemanager, we'll need it later for dot creation.
  if (sm == nullptr) {
    sm = result.SourceManager;
  }
}

void PDGBuilder::onEndOfTranslationUnit() {
  // dump useful info
  if (slicingStmt != nullptr) {
    llvm::errs() << "slicing statement is:\n";
    slicingStmt->dumpColor();
  } else {
    llvm::errs() << "You've given invalid location for slicing var, since I've "
                    "found no variable there.\n";
    return;
  }
  llvm::errs() << "With control edges, but no data dependence edges:\n";
  llvm::errs() << stmt_map[root]->dump();
  stmt_map[root]->setDataEdges();
  llvm::errs() << "With data dependence edges too:\n";
  llvm::errs() << stmt_map[root]->dump();
  if (dumpDot) {
    dumpDots();
  }
}
} // namespace slicer
} // namespace clang