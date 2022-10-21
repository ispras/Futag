#include "FutagSlicer/pdg.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Casting.h"
#include <iostream>
#include <queue>

// make graph bidirectional
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