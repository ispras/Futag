#include "Futag/MatchFinder.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include <fstream>
#include <iostream>
#include <queue>

#include "Futag/ArgumentsUsage.h"
#include "Futag/Basic.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace llvm;

using namespace clang::ast_matchers;
namespace futag {

void FutagMatchBinaryOperatorCallBack::run(
    const MatchFinder::MatchResult &Result) {
  const auto *MatchedBinaryOperator =
      Result.Nodes.getNodeAs<BinaryOperator>("FutagMatchBinaryOperator");
  if (!MatchedBinaryOperator) {
    return;
  }

  // The RHS of operator is one of:
  // 1. Function caller:
  //   dyn_cast<DeclRefExpr>(dyn_cast<ImplicitCastExpr>(MatchedBinaryOperator->getRHS())->getSubExpr())->getNameInfo().getAsString()
  // 2. another variable with DeclRefExpr ?
  // 3. value such as: FloatingLiteral, IntegerLiteral, StringLiteral ...
  // depends on data type
  // 4. Change value by reference, pointer ??
  auto *rightCallExpr = dyn_cast<CallExpr>(MatchedBinaryOperator->getRHS());
  if (rightCallExpr) {
    // llvm::outs() << "and right hand side is function call: "
    //              <<
    //              rightCallExpr->getDirectCallee()->getQualifiedNameAsString()
    //              << " \n";
  }

  return;
}

bool FutagMatchCallExprCallBack::HandleLiterals(const clang::Expr *arg,
                                                json &currArgumentContext) {
  if (const auto *charecterLiteralArg = dyn_cast<CharacterLiteral>(arg)) {
    HandleCharacterLiteral(charecterLiteralArg, currArgumentContext);
    return true;
  }

  if (const auto *fixedPointLiteralArg = dyn_cast<FixedPointLiteral>(arg)) {
    HandleFixedPointLiteral(fixedPointLiteralArg, currArgumentContext);
    return true;
  }

  if (const auto *floatingPointLiteralArg = dyn_cast<FloatingLiteral>(arg)) {
    HandleFloatingLiteral(floatingPointLiteralArg, currArgumentContext);
    return true;
  }

  if (const auto *imaginaryLiteralArg = dyn_cast<ImaginaryLiteral>(arg)) {
    HandleImaginaryLiteral(imaginaryLiteralArg, currArgumentContext);
    return true;
  }

  if (const auto *integerLiteralArg = dyn_cast<IntegerLiteral>(arg)) {
    HandleIntegerLiteral(integerLiteralArg, currArgumentContext);
    return true;
  }

  if (const auto *stringLiteralArg = dyn_cast<clang::StringLiteral>(arg)) {
    HandleStringLiteral(stringLiteralArg, currArgumentContext);
    return true;
  }

  return false;
}

void FutagMatchCallExprCallBack::HandleDeclRefExpr(const DeclRefExpr *arg,
                                                   json &currArgumentContext) {
  currArgumentContext["arg_type_futag"] = FutagType::DeclRefStr();
  currArgumentContext["literal_value"] = arg->getNameInfo().getAsString();
}

void FutagMatchCallExprCallBack::HandleCharacterLiteral(
    const CharacterLiteral *arg, json &currArgumentContext) {
  currArgumentContext["arg_type_futag"] = FutagType::ConstValStr();
  currArgumentContext["literal_value"] = arg->getValue();
}

void FutagMatchCallExprCallBack::HandleFixedPointLiteral(
    const FixedPointLiteral *arg, json &currArgumentContext) {
  currArgumentContext["arg_type_futag"] = FutagType::ConstValStr();
  // @TODO: radix value selected arbitrary!
  currArgumentContext["literal_value"] = arg->getValueAsString(10);
}

void FutagMatchCallExprCallBack::HandleFloatingLiteral(
    const FloatingLiteral *arg, json &currArgumentContext) {
  arg->getValueAsApproximateDouble();
  currArgumentContext["arg_type_futag"] = FutagType::ConstValStr();
  currArgumentContext["literal_value"] = arg->getValueAsApproximateDouble();
}

void FutagMatchCallExprCallBack::HandleImaginaryLiteral(
    const ImaginaryLiteral *arg, json &currArgumentContext) {
  currArgumentContext["arg_type_futag"] = FutagType::ConstValStr();
  // currArgumentContext["literal_value"] = arg->get;
}

void FutagMatchCallExprCallBack::HandleIntegerLiteral(
    const IntegerLiteral *arg, json &currArgumentContext) {
  // Process signed and unsigned integers separately
  currArgumentContext["arg_type_futag"] = FutagType::ConstValStr();
  currArgumentContext["literal_value"] = (arg->getValue().isSignBitSet())
                                             ? arg->getValue().getSExtValue()
                                             : arg->getValue().getZExtValue();
}

void FutagMatchCallExprCallBack::HandleStringLiteral(
    const clang::StringLiteral *arg, json &currArgumentContext) {
  currArgumentContext["arg_type_futag"] = FutagType::ConstValStr();
  currArgumentContext["literal_value"] = arg->getBytes();
}

void FutagMatchCallExprCallBack::HandleCallExpr(const CallExpr *arg,
                                                json &currArgumentContext) {
  currArgumentContext["arg_type_futag"] = FutagType::FuncCallResStr();
  const FunctionDecl *func = arg->getDirectCallee();
  if (!func) {
    FullSourceLoc callExprLoc =
        Mgr.getASTContext().getFullLoc(arg->getBeginLoc());

    std::string callExprStr;
    llvm::raw_string_ostream rso(callExprStr);
    arg->printPretty(rso, nullptr, Mgr.getASTContext().getPrintingPolicy());

    llvm::errs() << __func__
                 << " - Cannot get direct callee: " + rso.str() + " " +
                        callExprLoc.printToString(Mgr.getSourceManager()) +
                        "\n";
    return;
  }

  currArgumentContext["call_expr_function"] = func->getQualifiedNameAsString();
}

void FutagMatchCallExprCallBack::run(const MatchFinder::MatchResult &Result) {
  const auto *callExpr = Result.Nodes.getNodeAs<CallExpr>("FutagCalledFunc");

  if (!callExpr) {
    return;
  }

  // 1. Extract function declaration
  const FunctionDecl *func = callExpr->getDirectCallee();
  if (!func) {
    // ? After fatal error report, what is the behaviour of Checker?
    // llvm::report_fatal_error("Cannot find Callee!");
    return;
  }

  // 2. Calculate ODRHash
  std::string funcHash =
      std::to_string(futag::utils::ODRHashCalculator::CalculateHash(CurrFunc));

  // 3. Get instance of SourceManager to extract information about call
  // location
  SourceManager &srcMgr = Result.Context->getSourceManager();
  SourceLocation loc = srcMgr.getExpansionLoc(callExpr->getExprLoc());

  // If we don't have basic information for currently processed call,
  // Create new object with the key = funcHash
  if (!currentContext.contains(funcHash))
    currentContext[funcHash] = json{};

  // Check if we have call_contexts field
  if (!currentContext[funcHash].contains("call_contexts")) {
    currentContext[funcHash]["call_contexts"] = json::array();
  }

  // Check if we have func_name field
  if (!currentContext[funcHash].contains("func_name")) {
    currentContext[funcHash]["func_name"] =
        CurrFunc->getQualifiedNameAsString();
  }

  // Preprocess current filename by deleting all ./ and ../
  std::string currFileName =
      futag::utils::PathProcessor::RemoveUnnecessaryPathComponents(
          srcMgr.getFilename(loc).str());

  // Build full call location
  std::string calledFromFullLoc =
      currFileName + ":" + std::to_string(srcMgr.getExpansionLineNumber(loc));

  json currentCallContext =
      json{{"called_from", calledFromFullLoc},
           {"called_from_func_name", func->getQualifiedNameAsString()},
           {"args_desc", json::array()}};

  for (uint32_t i = 0; i < callExpr->getNumArgs(); i++) {
    // ? In the list Function's arguments, there are constants, variables,
    // caller or ? expression
    QualType argType = callExpr->getArg(i)->getType();

    json currArgumentContext{{"arg_num", i},
                             {"arg_type", argType.getAsString()},
                             {"arg_type_futag", FutagType::UnknownStr()}};

    if (const auto *callExprArg = dyn_cast<CallExpr>(callExpr->getArg(i))) {
      HandleCallExpr(callExprArg, currArgumentContext);
    } else if (const auto *declRefExpr =
                   dyn_cast<DeclRefExpr>(callExpr->getArg(i))) {
      HandleDeclRefExpr(declRefExpr, currArgumentContext);
    } else if (HandleLiterals(callExpr->getArg(i), currArgumentContext)) {
    } else if (const auto *implicitArg =
                   dyn_cast<ImplicitCastExpr>(callExpr->getArg(i))) {
      if (const auto *arg =
              dyn_cast<DeclRefExpr>(implicitArg->IgnoreParenImpCasts())) {
        HandleDeclRefExpr(arg, currArgumentContext);
      }
    }

    currentCallContext["args_desc"].push_back(currArgumentContext);
  }

  // Write new call location to the array
  currentContext[funcHash]["call_contexts"].push_back(currentCallContext);
  return;
}

void FutagArgumentUsageDeterminer::run(const MatchFinder::MatchResult &Result) {
  const auto *callExpr = Result.Nodes.getNodeAs<CallExpr>("FutagCalledFunc");
  const auto *param =
      Result.Nodes.getNodeAs<DeclRefExpr>("FutagCalledFuncArgument");
  if (!callExpr && !param) {
    return;
  }

  const FunctionDecl *func = callExpr->getDirectCallee();
  if (!func) {
    FullSourceLoc callExprLoc =
        Mgr.getASTContext().getFullLoc(callExpr->getBeginLoc());

    std::string callExprStr;
    llvm::raw_string_ostream rso(callExprStr);
    callExpr->printPretty(rso, nullptr,
                          Mgr.getASTContext().getPrintingPolicy());

    llvm::errs() << __func__
                 << " - Cannot get direct callee: " + rso.str() + " " +
                        callExprLoc.printToString(Mgr.getSourceManager()) +
                        "\n";
    return;
  }

  ArgumentsUsage argUsage;
  for (uint32_t i = 0; i < callExpr->getNumArgs(); i++) {
    // Ignore parenthesis implicit casts
    const auto *param =
        dyn_cast<DeclRefExpr>(callExpr->getArg(i)->IgnoreParenImpCasts());

    // Try to ignore all possible type casts
    if (!param)
      param = dyn_cast<DeclRefExpr>(callExpr->getArg(i)->IgnoreCasts());

    /*
     * Check if parameter to the function call is DeclRefExpr (variable). If it
     * is true, check that the name of the argument is the same as the caller's
     * argument name. If this is true, it means, that the parameter is passed
     * directly into some known function (e.g. open), and we can easily mark
     * parameter type for the caller.
     * Consider this example:
     * int func(char* path)
     * {
     *   return open(path, O_RDONLY);
     * }
     * func's path will be marked as FILE_PATH_INPUT
     */
    if (param &&
        param->getDecl()->getNameAsString() ==
            currentParamContext["param_name"] &&
        currentParamContext["param_usage"] ==
            ArgumentsUsage::ArgumentTypeToStr(ArgumentsUsage::AT::UNKNOWN)) {
      currentParamContext["param_usage"] = argUsage.DetermineArgumentTypeStr(
          func->getNameAsString(), i, callExpr);
    }
  }

  return;
}

void FutagMatchVarDeclCallBack::run(const MatchFinder::MatchResult &Result) {
  const auto *MatchedVarDecl =
      Result.Nodes.getNodeAs<VarDecl>("FutagMatchVarDecl");
  if (MatchedVarDecl) {
    std::ofstream tmpfile;
    tmpfile.open("foundMatchDeclaration.txt", std::ios_base::app);
    tmpfile << "Found VarDecl name: " << MatchedVarDecl->getName().str()
            << "\n";
    tmpfile.close();
  }
  return;
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
void FutagContextConsumerCallBack::dumpDots() {
  auto srcFileName = futag::getFile(func->getBody(), sm);
  auto out = srcFileName + "_" + funcName + ".dot";
  std::ofstream file(out);
  file << stmt_map[func->getBody()]->dumpDot(*sm, false);
  file.close();

  out = srcFileName + "_" + funcName + "_backward_slice.dot";
  std::ofstream file2(out);
  stmt_map[func->getBody()]->slice(stmt_map[slicingStmt], true);
  file2 << stmt_map[func->getBody()]->dumpDot(*sm, true);
  file2.close();
  stmt_map[func->getBody()]->resetSlice();

  out = srcFileName + "_" + funcName + "_forward_slice.dot";
  std::ofstream file3(out);
  stmt_map[func->getBody()]->slice(stmt_map[slicingStmt], false);
  file3 << stmt_map[func->getBody()]->dumpDot(*sm, true);
  file3.close();
}
bool FutagContextConsumerCallBack::slicingStmtPos::refined(unsigned int sl,
                                                           unsigned int sc,
                                                           unsigned int el,
                                                           unsigned int ec) {
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

FullSourceLoc FutagContextConsumerCallBack::getLoc(
    const ast_matchers::MatchFinder::MatchResult &result, const Stmt *astRef) {
  return result.Context->getFullLoc(astRef->getBeginLoc());
}

void FutagContextConsumerCallBack::setSlicingStmt(
    const MatchFinder::MatchResult &result, const Stmt *astRef) {
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
void FutagContextConsumerCallBack::printMap() {
  std::map<const Stmt *, Statement *>::iterator it;
  llvm::outs() << "- Map print: \n";
  for (it = this->stmt_map.begin(); it != this->stmt_map.end(); it++) {
    clang::LangOptions lo;
    std::string out_str;
    llvm::raw_string_ostream outstream(out_str);
    it->first->printPretty(outstream, NULL, PrintingPolicy(lo));
    llvm::outs() << "-- map item: " << out_str << ':'
                 << it->second->nameAsString() << "\n";
  }
}
void FutagContextConsumerCallBack::run(const MatchFinder::MatchResult &result) {
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
    llvm::outs() << "!!! Match if\n";
    // printMap();
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
    llvm::outs() << "!!! Match while\n";
    // printMap();
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
    llvm::outs() << "!!! Match compound\n";
    // printMap();
  }
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
    llvm::outs() << "!!! Match declStmt\n";
    // printMap();
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
    llvm::outs() << "!!! Match Binary\n";
    // printMap();
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
    llvm::outs() << "!!! Match unary\n";
    // printMap();
  }
  if (const auto ret = result.Nodes.getNodeAs<ReturnStmt>("ret")) {
    const auto var = result.Nodes.getNodeAs<VarDecl>("retVar");
    if (!hasStmt(ret)) {
      stmt_map[ret] = new AssignStatement(ret, getLoc(result, ret));
    }
    stmt_map[ret]->addUse(var);
    setSlicingStmt(result, ret);
    llvm::outs() << "!!! Match return\n";
    // printMap();
  }
  // save sourcemanager, we'll need it later for dot creation.
  if (sm == nullptr) {
    sm = result.SourceManager;
  }
}

void Statement::addControlChild(std::pair<Statement *, Edge> child) {
  controlChildren.insert(child);
  child.first->controlParents.insert({this, child.second});
}

void Statement::addDataEdge(Statement *s) {
  dataEdges.insert(s);
  s->dataParents.insert(this);
}

Statement *Statement::create(const clang::Stmt *astref,
                             clang::FullSourceLoc loc) {
  // Assignment
  if (const auto bs = llvm::dyn_cast<clang::BinaryOperator>(astref)) {
    if (bs->isAssignmentOp()) {
      return new AssignStatement(astref, loc);
    }
  } else if (llvm::isa<clang::DeclStmt>(astref)) {
    return new AssignStatement(astref, loc);
  } else if (llvm::isa<clang::ReturnStmt>(astref)) {
    return new AssignStatement(astref, loc);
  }
  // Branch
  else if (auto is = llvm::dyn_cast<clang::IfStmt>(astref)) {
    return new BranchStatement(astref, loc);
  }
  // Compound
  else if (llvm::isa<clang::CompoundStmt>(astref)) {
    return new CompoundStatement(astref, loc);
  }
  // Loop
  else if (llvm::isa<clang::WhileStmt>(astref)) {
    return new LoopStatement(astref, loc);
  }
  return new Statement(astref, loc);
}

// making the PDG
// todo refactor it to iterative
// use DFS with a (searchable) stack, and handle Loop, Branch specific
// operations differently maybe use the class design handle the nested whiles,
// ifs others for stack, use a: vector<Statement*,def_map> for registering level
// defs or just hack another variable into it
void Statement::setDataEdges() {
  // initialize initial def_map from this node's defines
  defsMap def_map;
  for (auto &def : define) {
    def_map.insert({def, {{this, Edge::None}}});
  }
  // we're using DFS for visiting every statement in execution order.
  setDataEdgesRec(def_map, {}, 0);
}

// we should use the phi-node technique for collecting all different definitions
// from branches by transforming def_map to: [(var,[(stmt,edge)]], to store
// multiple values (two for if-else, n for amount of case in switch-case) in it,
// and if meet with a new value AFTER if, overwrite the set with that one value.
Statement::defsMap Statement::setDataEdgesRec(const defsMap &parent_def_map,
                                              std::vector<Statement *> loopRefs,
                                              int inABranch) {
  defsMap def_map;
  // make every parent definition edge true.

  for (auto &ds : parent_def_map) {
    for (auto &d : ds.second)
      def_map[ds.first].insert({d.first, Edge::None});
  }
  if (name() == Type::Loop) {
    loopRefs.push_back(this);
  }
  if (name() == Type::Branch) {
    inABranch++;
  }
  // create loop-carried dependences by
  // visiting every child twice
  for (auto loopIteration = 0; loopIteration < 2; ++loopIteration) {
    for (auto &stmt : controlChildren) {
      // def-def edges
      for (auto &def : stmt.first->getDefine()) {
        auto added = false;
        if (def_map.find(def) != def_map.end()) {
          for (auto defStmt = def_map[def].begin();
               defStmt != def_map[def].end();) {
            // if they're on the same branch
            if ((inABranch == 0 || defStmt->second == Edge::None ||
                 inABranch > 0 && defStmt->second == stmt.second) &&
                // and they're not the same
                defStmt->first->id != stmt.first->id) {
              defStmt->first->addDataEdge(stmt.first);
            }
            // add stmt as an other branch definition
            // if we are in the same branch && we have a def-def relation,
            // overwrite the previous def.
            if (inABranch > 0) {
              if (defStmt->second == stmt.second &&
                  defStmt->second != Edge::None) {
                defStmt = def_map[def].erase(defStmt);
              } else {
                ++defStmt;
              }
              def_map[def].insert(stmt);
              added = true;
            } else {
              ++defStmt;
            }
          }
        }
        // make this stmt the latest definition
        if (inABranch == 0 || !added) {
          def_map[def] = {stmt};
        }
        // while backedge to predicate
        for (auto lr : loopRefs) {
          auto uses = lr->getUses();
          if (uses.find(def) != uses.end()) {
            for (auto &defStmt : def_map[def]) {
              defStmt.first->addDataEdge(lr);
            }
          }
        }
      }
      // def-use edges
      for (auto &uses : stmt.first->getUses()) {
        assert(def_map.find(uses) != def_map.end());
        // don't add loops
        for (auto &defStmt : def_map[uses]) {
          if (defStmt.first != stmt.first) {
            defStmt.first->addDataEdge(stmt.first);
          }
        }
      }

      // go down
      if (!stmt.first->controlChildren.empty()) {
        defsMap child_def_map;
        // erase defs from the other branch
        for (auto &defs : def_map) {
          for (auto def : defs.second) {
            if (def.second == Edge::None || def.second == stmt.second ||
                loopIteration > 0) {
              child_def_map[defs.first].insert(def);
            }
          }
        }
        auto child_new_defs(
            stmt.first->setDataEdgesRec(child_def_map, loopRefs, inABranch));
        // merge new definitions from child to our def_map
        // if branch, merge with the label to the child
        if (inABranch > 0) {
          for (auto &kv : child_new_defs) {
            for (auto &v : kv.second) {
              if (v.second != Edge::None)
                def_map[kv.first].insert({v.first, stmt.second});
            }
          }
        } else {
          for (auto &kv : child_new_defs) {
            if (kv.second.size() > 1) {
              // empty previous definition only if there is definition
              // overwritten in every branch.
              //  this is temporarily fixed as 2, but for implementing
              //  switch-cases, we need a smarter solution.
              if (kv.second.size() > 2) {
                def_map[kv.first].clear();
              }
              for (auto &v : kv.second) {
                if (v.second != Edge::None) {
                  def_map[kv.first].insert(v);
                }
              }
            } else {
              def_map[kv.first] = kv.second;
            }
          }
        }
      }
    }
    // create loop-carried dependences by
    // visiting every child once again after
    // deleting local definitions (declStmts)
    // we also need to erase local defs when returning our defs to caller parent
    for (auto it = def_map.begin(); it != def_map.end();) {
      for (auto it2 = it->second.begin(); it2 != it->second.end();) {
        if (llvm::isa<clang::DeclStmt>(it2->first->getAstRef()) &&
            it2->second != Edge::None) {
          it2 = it->second.erase(it2);
        } else {
          ++it2;
        }
      }
      if (it->second.empty()) {
        it = def_map.erase(it);
      } else {
        ++it;
      }
    }
    // if we're not in a loop, don't visit twice
    if (name() != Type::Loop) {
      break;
    }
  }
  if (name() == Type::Loop) {
    loopRefs.erase(std::remove(loopRefs.begin(), loopRefs.end(), this),
                   loopRefs.end());
  }
  if (name() == Type::Branch) {
    inABranch--;
  }
  return def_map;
}

// print out graph structure
std::string Statement::dump() { return dumpLevel(1); }

// todo make it nicer
std::string Statement::dumpLevel(int level) {
  std::string tab(level, ' ');
  auto nodeId = ": id: " + std::to_string(id);
  std::string defs = ", def: ";
  for (auto &var : define) {
    defs += ", " + var->getNameAsString();
  }
  std::string uses = ", use: ";
  for (auto &var : use) {
    uses += ", " + var->getNameAsString();
  }
  std::string dataDeps = ", data deps: ";
  for (auto &stmt : dataEdges) {
    dataDeps += ", " + std::to_string(stmt->getId());
  }
  std::string cparents = ", control parents: ";
  for (auto &p : controlParents) {
    cparents += ", " + std::to_string(p.first->getId());
  }
  std::string dparents = ", data parents: ";
  for (auto &p : dataParents) {
    dparents += ", " + std::to_string(p->getId());
  }
  auto locs = ", loc: (" + std::to_string(loc.getSpellingLineNumber()) + "," +
              std::to_string(loc.getSpellingColumnNumber()) + ")";
  auto ret = nameAsString() + nodeId + defs + uses + locs + dataDeps +
             cparents + dparents + "\n";
  for (auto &child : controlChildren) {
    ret += tab + child.first->dumpLevel(level + 1);
  }
  return ret;
}

std::string Statement::EdgeToStr(Edge e) {
  switch (e) {
  case Edge::None:
    return "";
  case Edge::False:
    return "F";
  case Edge::True:
    return "T";
  default:
    return "";
  }
}

std::string Statement::stmt2str(const clang::Stmt *s,
                                clang::SourceManager &sm) {
  // (T, U) => "T,,"
  auto text = clang::Lexer::getSourceText(
                  clang::CharSourceRange::getTokenRange(s->getSourceRange()),
                  sm, clang::LangOptions(), nullptr)
                  .str();
  if (text.at(text.size() - 1) == ',') {
    return clang::Lexer::getSourceText(
               clang::CharSourceRange::getCharRange(s->getSourceRange()), sm,
               clang::LangOptions(), nullptr)
        .str();
  }
  return text;
}

std::string Statement::firstOnly(const clang::Stmt *s, const clang::Stmt *s2,
                                 clang::SourceManager &sm) {
  auto first = stmt2str(s, sm);
  const auto second = stmt2str(s2, sm);
  assert(first.size() > second.size());
  assert(first.find(second) != std::string::npos);
  first = first.substr(0, first.find(second));
  return first;
}

std::string Statement::sourceString(clang::SourceManager &sm) {
  return stmt2str(astRef, sm);
}

std::string BranchStatement::sourceString(clang::SourceManager &sm) {
  return firstOnly(astRef, (*controlChildren.begin()).first->getAstRef(), sm);
}

std::string LoopStatement::sourceString(clang::SourceManager &sm) {
  return firstOnly(astRef, (*controlChildren.begin()).first->getAstRef(), sm);
}

std::string CompoundStatement::sourceString(clang::SourceManager & /*sm*/) {
  return "{}";
}

std::string Statement::dumpDot(clang::SourceManager &sm, bool markSliced) {
  std::string ret = "digraph {\nrankdir=TD;\n";
  std::map<int, std::vector<int>> rank_map;
  ret += dumpDotRec(sm, markSliced, rank_map, 0);
  // insert ranks
  for (auto &kv : rank_map) {
    ret += "{ rank=same ";
    for (auto &i : kv.second) {
      ret += std::to_string(i) + " ";
    }
    ret += "}";
  }
  ret += "\n}";
  return ret;
}

// todo make it nicer + make left-to-right ordering of nodes correct. in
// ranking, constraint=false might help.
std::string Statement::dumpDotRec(clang::SourceManager &sm, bool markSliced,
                                  std::map<int, std::vector<int>> &rank_map,
                                  int depth) {
  auto ret = std::to_string(id) + "[label=\"" + sourceString(sm) + "\"";
  if (markSliced && isInSlice()) {
    ret += ",color=red]; \n";
  } else {
    ret += "]; \n";
  }

  for (auto &c : controlChildren) {
    ret += std::to_string(id) + " -> " + std::to_string(c.first->getId()) +
           "[label=\"" + EdgeToStr(c.second) + "\",style=bold";
    if (markSliced && isInSlice() && c.first->isInSlice()) {
      ret += ",color=red];\n";
    } else {
      ret += "];\n";
    }

    if (!c.first->getControlChildren().empty()) {
      ret += c.first->dumpDotRec(sm, markSliced, rank_map, depth + 1);
    } else {
      // edge case of recursion
      ret += std::to_string(c.first->getId()) + "[label=\"" +
             c.first->sourceString(sm) + "\"";
      if (markSliced && c.first->isInSlice()) {
        ret += ",color=red];\n";
      } else {
        ret += "];\n";
      }

      for (auto &e : c.first->getDataEdges()) {
        ret += std::to_string(c.first->getId()) + " -> " +
               std::to_string(e->getId());
        if (markSliced && c.first->isInSlice() && e->isInSlice()) {
          ret += "[color=red];\n";
        } else {
          ret += ";\n";
        }
      }
    }
    rank_map[depth].push_back(c.first->getId());
  }
  for (auto &e : dataEdges) {
    ret += std::to_string(id) + " -> " + std::to_string(e->getId());
    if (markSliced && isInSlice() && e->isInSlice()) {
      ret += "[color=red];\n";
    } else {
      ret += ";\n";
    }
  }
  return ret;
}

// s.l.i.c.e
// slicing sets a flag on the affected nodes so they can be visualized.
void Statement::slice(Statement *slicingStmt, bool backwards) {
  std::map<Statement *, Statement *> child;
  std::queue<Statement *> Q;
  std::set<Statement *> S;
  Q.emplace(slicingStmt);
  child[slicingStmt] = nullptr;
  auto current = slicingStmt;
  while (!Q.empty()) {
    current = Q.front();
    Q.pop();
    std::set<Statement *> toVisit;
    if (backwards) {
      for (auto &e : current->getControlParents()) {
        toVisit.insert(e.first);
      }
      for (auto &e : current->getDataParents()) {
        toVisit.insert(e);
      }
    } else {
      for (auto &e : current->getControlChildren()) {
        toVisit.insert(e.first);
      }
      for (auto &e : current->getDataEdges()) {
        toVisit.insert(e);
      }
    }
    for (auto &node : toVisit) {
      if (S.find(node) == S.end()) {
        S.insert(node);
        child[node] = current;
        Q.emplace(node);
      }
    }
  }
  // mark edges
  for (auto &kv : child) {
    kv.first->markSliced();
    if (kv.second != nullptr) {
      kv.second->markSliced();
    }
  }
  // debug
  // for (auto& kv : child) {
  //  if(kv.second != nullptr) std::cout << kv.first->getId() << " -> " <<
  //  kv.second->getId() << "\n"; else std::cout << kv.first->getId() << "\n";
  //}
}

void Statement::resetSlice() {
  unmarkSliced();
  for (auto &c : controlChildren) {
    c.first->resetSlice();
  }
}
} // namespace futag