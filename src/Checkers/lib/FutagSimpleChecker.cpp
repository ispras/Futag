/**
 * @file FutagSimpleChecker.cpp
 * @author Tran Chi Thien (thientcgithub@gmail.com)
 * @brief
 * @version 2.0.5
 * @date 2023-04-17
 *
 * @copyright Copyright (c) 2023
 *
 */

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Futag/MatchFinder.h"
#include "nlohmann/json.hpp"
#include "clang/AST/Decl.h"
#include "clang/AST/ODRHash.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

#include "llvm/Support/raw_ostream.h"

#include "Futag/Basic.h"
#include "Futag/Utils.h"

using namespace llvm;
using namespace clang;
using namespace ento;
using namespace nlohmann;
using namespace futag;

//===----------------------------------------------------------------------===//
// Checker to analyze function declarations
//===----------------------------------------------------------------------===//
namespace {

class FutagMatchFuncDeclCallBack : public MatchFinder::MatchCallback {
  public:
    FutagMatchFuncDeclCallBack( AnalysisManager &Mgr)
        : Mgr{Mgr} {}
    AnalysisManager &Mgr; // For passing the AnalysisManager
    virtual void run(const MatchFinder::MatchResult &Result);
};

class FutagSimpleChecker : public Checker<check::ASTDecl<TranslationUnitDecl>> {

  public:
    // Entry point. Collects all needed information using recursive ast visitor
    void checkASTDecl(const TranslationUnitDecl *TUD, AnalysisManager &Mgr,
                      BugReporter &BR) const;

    /* Collects information about function */
    void VisitFunction(const FunctionDecl *func, AnalysisManager &Mgr) const;
    /* Collects information about struct declarations*/
    void VisitRecord(const RecordDecl *func, AnalysisManager &Mgr) const;
    /* Collects information about typedefs */
    void VisitTypedef(const TypedefDecl *func, AnalysisManager &Mgr) const;
    /* Collects information about enums */
    void VisitEnum(const EnumDecl *func, AnalysisManager &Mgr) const;
};

} // namespace

void FutagMatchFuncDeclCallBack::run(const MatchFinder::MatchResult &Result) {
    const auto *func_decl = Result.Nodes.getNodeAs<FunctionDecl>("functionDe");

    if (!func_decl) {
        return;
    }
    llvm::outs()<< "\n-- Found function declaration: \"" << func_decl->getDeclName().getAsString() << " ";
    // If the available function is defined in system header file, then skip.

    FullSourceLoc func_begin_loc =
        Mgr.getASTContext().getFullLoc(func_decl->getBeginLoc());
    int32_t curr_func_begin_loc = func_begin_loc.getSpellingLineNumber();
    auto fe = func_begin_loc.getFileEntry();
    std::string file_name;
    std::string parent_hash = "";

    if (fe->tryGetRealPathName().empty()) {
        if (fe->getName().empty()) {
            std::cerr << " -- Debug info: Cannot find filename and filepath!\n";
        } else {
            file_name = fe->getName().str();
        }
    } else {
        file_name = fe->tryGetRealPathName().str();
    }
    llvm::outs()<< "  in file \""<< file_name << "\" \n\n";
    return;
}
void FutagSimpleChecker::checkASTDecl(const TranslationUnitDecl *TUD,
                                 AnalysisManager &Mgr, BugReporter &BR) const {

    struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
        const FutagSimpleChecker *futag_checker;
        AnalysisManager &analysisMgr;

        explicit LocalVisitor(const FutagSimpleChecker *Checker,
                              AnalysisManager &AnalysisMgr)
            : futag_checker(Checker), analysisMgr(AnalysisMgr) {}

        /* callback when a function declaration is encountered */
        bool VisitFunctionDecl(FunctionDecl *FD) {
            futag_checker->VisitFunction(FD, analysisMgr);
            return true;
        }

        /* callback when a struct declaration is encountered */
        bool VisitRecordDecl(RecordDecl *RD) {
            futag_checker->VisitRecord(RD, analysisMgr);
            return true;
        }

        /* callback when a typedef declaration is encountered */
        bool VisitTypedefDecl(TypedefDecl *TD) {
            futag_checker->VisitTypedef(TD, analysisMgr);
            return true;
        }

        /* callback when a enum declaration is encountered */
        bool VisitEnumDecl(EnumDecl *ED) {
            futag_checker->VisitEnum(ED, analysisMgr);
            return true;
        }
    };

    LocalVisitor visitor(this, Mgr);
    visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TUD));
}

// Called for every function declaration
void FutagSimpleChecker::VisitFunction(const FunctionDecl *func,
                                  AnalysisManager &Mgr) const {
    llvm::outs()<< "-- Analyzing function: \"" << func->getDeclName().getAsString() << "\"\n";
    // If the available function is defined in system header file, then skip.
    if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc())) {
        llvm::outs()<< "  } \""<< func->getDeclName().getAsString() << "\" is in system headers!\n";
        return;
    }
    

    FullSourceLoc func_begin_loc =
        Mgr.getASTContext().getFullLoc(func->getBeginLoc());
    FullSourceLoc func_end_loc =
        Mgr.getASTContext().getFullLoc(func->getEndLoc());
    if (!func_begin_loc.getFileEntry()) {
        return;
    }
    int32_t curr_func_begin_loc = func_begin_loc.getSpellingLineNumber();
    auto fe = func_begin_loc.getFileEntry();
    std::string file_name;
    std::string parent_hash = "";

    if (fe->tryGetRealPathName().empty()) {
        if (fe->getName().empty()) {
            std::cerr << " -- Debug info: Cannot find filename and filepath!\n";
        } else {
            file_name = fe->getName().str();
        }
    } else {
        file_name = fe->tryGetRealPathName().str();
    }
    llvm::outs()<< "  in file \""<< file_name << "\" \n";

    MatchFinder Finder;
    // Match all CallExpression of target function
    auto match_callexpr =
        functionDecl(hasName(func->getDeclName().getAsString()))
            .bind("functionDe");

    FutagMatchFuncDeclCallBack target_func_call_callback{ Mgr};;
    Finder.addMatcher(match_callexpr, &target_func_call_callback);
    Finder.matchAST(Mgr.getASTContext());

    return;
}

void FutagSimpleChecker::VisitRecord(const RecordDecl *RD,
                                AnalysisManager &Mgr) const {

    return;
}
void FutagSimpleChecker::VisitTypedef(const TypedefDecl *TD,
                                 AnalysisManager &Mgr) const {
    return;
}

void FutagSimpleChecker::VisitEnum(const EnumDecl *ED, AnalysisManager &Mgr) const {
    return;
}

void ento::registerFutagSimpleChecker(CheckerManager &Mgr) {
    Mgr.registerChecker<FutagSimpleChecker>();
}

bool ento::shouldRegisterFutagSimpleChecker(const CheckerManager &mgr) {
    return true;
}