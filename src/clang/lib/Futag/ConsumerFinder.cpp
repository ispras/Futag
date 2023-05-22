/**
 * @file ConsumerFinder.cpp
 * @author Tran Chi Thien
 * @brief This file contains functions for analyzing consumer program
 * @version 2.0.4
 * @date 2023-04-17
 * 
 * @copyright Copyright (c) 2023
 * 
 */
#include "Futag/ConsumerFinder.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Analysis/Analyses/CFGReachabilityAnalysis.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/CFGStmtMap.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <queue>
#include <utility>
#include <vector>
using namespace clang;
using namespace llvm;

// using namespace clang::ast_matchers;
namespace futag {
/**
 * @brief Get the Call Expr Simple Info object
 * 
 * @param call_expr 
 * @param cfg_stmt_map 
 * @param Mgr 
 * @return futag::FutagCallExprInfo 
 */
futag::FutagCallExprInfo GetCallExprSimpleInfo( //
    const CallExpr *call_expr,                  //
    clang::CFGStmtMap *cfg_stmt_map,            //
    AnalysisManager &Mgr)                       //
{

    FullSourceLoc full_loc =
        Mgr.getASTContext().getFullLoc(call_expr->getBeginLoc());
    futag::FutagCodeLoc code_loc;
    code_loc.line = full_loc.getSpellingLineNumber();
    code_loc.col = full_loc.getSpellingColumnNumber();
    code_loc.file = (full_loc.getFileEntry() == nullptr
                         ? ""
                         : full_loc.getFileEntry()->getName().str());
    unsigned int cfg_block_ID = cfg_stmt_map->getBlock(call_expr)->getBlockID();
    std::vector<futag::FutagInitArg> init_args;
    for (uint32_t i = 0; i < call_expr->getNumArgs(); i++) {
        auto curr_arg = call_expr->getArg(i);
        DeclRefExpr *declRefExpr;
        bool is_decl_ref_expr = false;
        FutagInitArg curr_init_arg;
        curr_init_arg.init_type = ArgUnknown;

        if (const auto *callExprArg = dyn_cast<CallExpr>(curr_arg)) {
            if (!callExprArg->getDirectCallee()) {
                continue;
            }
        } else if (declRefExpr = const_cast<DeclRefExpr *>(
                       dyn_cast<DeclRefExpr>(curr_arg))) {
            is_decl_ref_expr = true;

        } else if (const auto *implicitArg =
                       dyn_cast<ImplicitCastExpr>(curr_arg)) {
            if (declRefExpr = const_cast<DeclRefExpr *>(dyn_cast<DeclRefExpr>(
                    implicitArg->IgnoreParenImpCasts()))) {
                is_decl_ref_expr = true;
            }
        } else {
            if (const auto *charecterLiteralArg =
                    dyn_cast<CharacterLiteral>(curr_arg)) {
                curr_init_arg.init_type = ArgConstValue;
                curr_init_arg.value = "chr(" + std::to_string(charecterLiteralArg->getValue()) + ")";
            }

            if (const auto *fixedPointLiteralArg =
                    dyn_cast<FixedPointLiteral>(curr_arg)) {
                curr_init_arg.init_type = ArgConstValue;
                curr_init_arg.value =
                    fixedPointLiteralArg->getValueAsString(10);
            }

            if (const auto *floatingPointLiteralArg =
                    dyn_cast<FloatingLiteral>(curr_arg)) {
                curr_init_arg.init_type = ArgConstValue;
                curr_init_arg.value =
                    floatingPointLiteralArg->getValueAsApproximateDouble();
            }

            if (const auto *imaginaryLiteralArg =
                    dyn_cast<ImaginaryLiteral>(curr_arg)) {
                curr_init_arg.init_type = ArgConstValue;
                curr_init_arg.value = "";
            }

            if (const auto *integerLiteralArg =
                    dyn_cast<IntegerLiteral>(curr_arg)) {
                curr_init_arg.init_type = ArgConstValue;
                curr_init_arg.value =
                    (integerLiteralArg->getValue().isSignBitSet())
                        ? integerLiteralArg->getValue().getSExtValue()
                        : integerLiteralArg->getValue().getZExtValue();
            }

            if (const auto *stringLiteralArg =
                    dyn_cast<clang::StringLiteral>(curr_arg)) {
                curr_init_arg.init_type = ArgConstValue;
                curr_init_arg.value = "\"" + stringLiteralArg->getBytes().str()+"\"";
            }
        }
        if (is_decl_ref_expr) {
            curr_init_arg.init_type = ArgVarRef;
            if (declRefExpr->getDecl()) {
                curr_init_arg.value = declRefExpr->getDecl()->getNameAsString();
                curr_init_arg.var_decl =
                    const_cast<ValueDecl *>(declRefExpr->getDecl());
            }
        }
        init_args.insert(init_args.end(), curr_init_arg);
    }
    clang::LangOptions lo;
    std::string stmt_str;
    llvm::raw_string_ostream rso_stmt(stmt_str);
    call_expr->printPretty(rso_stmt, NULL,
                           Mgr.getASTContext().getPrintingPolicy());
    FutagCallExprInfo result{
        call_expr,
        call_expr->getDirectCallee()->getQualifiedNameAsString(),
        call_expr->getDirectCallee()->getNameAsString(),
        stmt_str,
        init_args,
        cfg_block_ID,
        code_loc};
    return result;
}

/**
 * @brief Get the Call Expr Info object
 * 
 * @param call_expr 
 * @param cfg_stmt_map 
 * @param Mgr 
 * @param analysis_jdb 
 * @param init_calls 
 * @return futag::FutagCallExprInfo 
 */
futag::FutagCallExprInfo GetCallExprInfo(              //
    const CallExpr *call_expr,                         //
    clang::CFGStmtMap *cfg_stmt_map,                   //
    AnalysisManager &Mgr,                              //
    const json &analysis_jdb,                          //
    std::vector<FutagInitVarDeclCallExpr> &init_calls) //
{

    FullSourceLoc full_loc =
        Mgr.getASTContext().getFullLoc(call_expr->getBeginLoc());
    futag::FutagCodeLoc code_loc;
    code_loc.line = full_loc.getSpellingLineNumber();
    code_loc.col = full_loc.getSpellingColumnNumber();
    code_loc.file = (full_loc.getFileEntry() == nullptr
                         ? ""
                         : full_loc.getFileEntry()->getName().str());
    unsigned int cfg_block_ID = cfg_stmt_map->getBlock(call_expr)->getBlockID();
    // unsigned int cfg_block_ID = 0;
    std::vector<futag::FutagInitArg> init_args;
    for (uint32_t i = 0; i < call_expr->getNumArgs(); i++) {
        auto curr_arg = call_expr->getArg(i);
        DeclRefExpr *declRefExpr;
        bool is_decl_ref_expr = false;
        FutagInitArg curr_init_arg;
        curr_init_arg.init_type = ArgUnknown;

        if (const auto *callExprArg = dyn_cast<CallExpr>(curr_arg)) {
            curr_init_arg.init_type = ArgUnknown;
            if (!callExprArg->getDirectCallee()) {
                continue;
            }
            for (auto it : analysis_jdb["functions"]) {
                if (callExprArg->getDirectCallee()->getNameAsString() ==
                    it["name"]) {
                    utils::Random rand{};
                    std::string rand_name =
                        "FutagRefVar" +
                        rand.GenerateRandomString(consts::cAlphabet, 3);
                    init_calls.insert(
                        init_calls.begin(),
                        {rand_name, GetCallExprSimpleInfo(callExprArg,
                                                          cfg_stmt_map, Mgr)});
                    curr_init_arg.init_type = ArgVarRef;
                    curr_init_arg.value = rand_name;
                    break;
                }
            }

        } else if (declRefExpr = const_cast<DeclRefExpr *>(
                       dyn_cast<DeclRefExpr>(curr_arg))) {
            is_decl_ref_expr = true;

        } else if (HandleLiterals(curr_arg, curr_init_arg)) {
        } else if (const auto *implicitArg =
                       dyn_cast<ImplicitCastExpr>(curr_arg)) {
            if (declRefExpr = const_cast<DeclRefExpr *>(dyn_cast<DeclRefExpr>(
                    implicitArg->IgnoreParenImpCasts()))) {
                is_decl_ref_expr = true;
            } else if (HandleLiterals(curr_arg->IgnoreParenCasts(),
                                      curr_init_arg)) {
            }
        }
        if (is_decl_ref_expr) {
            curr_init_arg.init_type = ArgVarRef;
            if (declRefExpr->getDecl()) {
                curr_init_arg.value = declRefExpr->getDecl()->getNameAsString();
                curr_init_arg.var_decl =
                    const_cast<ValueDecl *>(declRefExpr->getDecl());
            }
        }
        init_args.insert(init_args.end(), curr_init_arg);
    }
    clang::LangOptions lo;
    std::string stmt_str;
    llvm::raw_string_ostream rso_stmt(stmt_str);
    call_expr->printPretty(rso_stmt, NULL,
                           Mgr.getASTContext().getPrintingPolicy());
    FutagCallExprInfo result{
        call_expr,
        call_expr->getDirectCallee()->getQualifiedNameAsString(),
        call_expr->getDirectCallee()->getNameAsString(),
        stmt_str,
        init_args,
        cfg_block_ID,
        code_loc};
    return result;
}

/**
 * @brief 
 * 
 * @param Mgr 
 * @param var_name 
 * @param curr_search_node 
 * @param cfg_stmt_map 
 * @param curr_context_path 
 * @param curr_analyzed_pos 
 * @param curr_analyzed_path 
 * @param init_calls 
 * @param modifying_calls 
 * @param analysis_jdb 
 */
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
    const json &analysis_jdb) {
    MatchFinder Finder;
    const auto matched_modifying_call =
        callExpr(hasDescendant(declRefExpr(to(varDecl(hasName(var_name))))))
            .bind("ModCallExpr");

    futag::FutagMatchModCallExprCB target_func_call_callback{
        Mgr,                //
        cfg_stmt_map,       // map for matching found callexpr
        curr_context_path,  // current path for adding node to path
        curr_analyzed_pos,  // for checking reverse match
        curr_analyzed_path, // for checking reverse match
        init_calls,         //
        modifying_calls,    //
        analysis_jdb,       //
        curr_search_node,   //
    };

    Finder.addMatcher(matched_modifying_call, &target_func_call_callback);
    Finder.futagMatchAST(Mgr.getASTContext(), curr_search_node);
}


/**
 * @brief 
 * 
 * @param Mgr 
 * @param iter_arg 
 * @param curr_search_node 
 * @param cfg_stmt_map 
 * @param curr_context_path 
 * @param curr_analyzed_pos 
 * @param curr_analyzed_path 
 * @param init_calls 
 * @param analysis_jdb 
 */
void SearchVarDeclInBlock(
    AnalysisManager &Mgr,
    FutagInitArg iter_arg,           // current argument for search
    Stmt *curr_search_node,          // current node for search
    clang::CFGStmtMap *cfg_stmt_map, // map for matching found callexpr
    FutagPath &curr_context_path,    // current path for adding node to path
    futag::FutagPath::iterator &curr_analyzed_pos, // for checking reverse match
    futag::FutagPath &curr_analyzed_path,          // for checking reverse match
    std::vector<FutagInitVarDeclCallExpr> &init_calls,
    const json &analysis_jdb) {
    
    MatchFinder Finder;

    const auto matched_binaryoperator =
        binaryOperator(
            isAssignmentOperator(),
            hasLHS(declRefExpr(
                to(varDecl(hasName(iter_arg.value)).bind("DefVarName")))),
            hasRHS(hasDescendant(
                declRefExpr(to(functionDecl().bind("DefTargetFunctionCall")))
                    .bind("DefDeclRefExpr"))))
            .bind("DefFutagBinOpArg");

    const auto matched_vardecl =
        varDecl(hasName(iter_arg.value),
                hasDescendant(declRefExpr(to(functionDecl().bind(
                                              "DefTargetFunctionCall")))
                                  .bind("DefDeclRefExpr")))
            .bind("DefFutagVarDecl");
    futag::FutagMatchDefCallExprCB target_func_call_callback{
        Mgr,                //
        cfg_stmt_map,       // map for matching found callexpr
        curr_context_path,  // current path for adding node to path
        curr_analyzed_pos,  // for checking reverse match
        curr_analyzed_path, // for checking reverse match
        init_calls,         //
        analysis_jdb,       //
    };

    Finder.addMatcher(matched_binaryoperator, &target_func_call_callback);
    Finder.addMatcher(matched_vardecl, &target_func_call_callback);
    Finder.futagMatchAST(Mgr.getASTContext(), curr_search_node);
    return;
}

/**
 * @brief 
 * 
 * @param arg 
 * @param curr_init_arg 
 * @return true 
 * @return false 
 */
bool HandleLiterals(const Expr *arg, FutagInitArg &curr_init_arg) {
    if (const auto *charecterLiteralArg = dyn_cast<CharacterLiteral>(arg)) {
        curr_init_arg.init_type = ArgConstValue;
        curr_init_arg.value = "chr(" + std::to_string(charecterLiteralArg->getValue()) + ")";
        return true;
    }

    if (const auto *fixedPointLiteralArg = dyn_cast<FixedPointLiteral>(arg)) {
        curr_init_arg.init_type = ArgConstValue;
        curr_init_arg.value = fixedPointLiteralArg->getValueAsString(10);
        return true;
    }

    if (const auto *floatingPointLiteralArg = dyn_cast<FloatingLiteral>(arg)) {
        curr_init_arg.init_type = ArgConstValue;
        curr_init_arg.value =
            floatingPointLiteralArg->getValueAsApproximateDouble();
        return true;
    }

    if (const auto *imaginaryLiteralArg = dyn_cast<ImaginaryLiteral>(arg)) {
        curr_init_arg.init_type = ArgConstValue;
        curr_init_arg.value = "";
        return true;
    }

    if (const auto *integerLiteralArg = dyn_cast<IntegerLiteral>(arg)) {
        curr_init_arg.init_type = ArgConstValue;
        curr_init_arg.value =
            (integerLiteralArg->getValue().isSignBitSet())
                ? integerLiteralArg->getValue().getSExtValue()
                : integerLiteralArg->getValue().getZExtValue();
        return true;
    }

    if (const auto *stringLiteralArg = dyn_cast<clang::StringLiteral>(arg)) {
        curr_init_arg.init_type = ArgConstValue;
        curr_init_arg.value = "\"" + stringLiteralArg->getBytes().str()+"\"";
    }
    return false;
}

/**
 * @brief This callback run function searches for all call expressions in the
 * current analyzed function
 *
 * @param Result
 */
void FutagMatchInitCallExprCB::run(const MatchFinder::MatchResult &Result) {
    /*
        const auto matched_binaryoperator =
        binaryOperator(
            isAssignmentOperator(),
            hasLHS(declRefExpr(to(varDecl().bind("VarName")))),
            hasRHS(hasDescendant(
                declRefExpr(to(functionDecl().bind("TargetFunctionCall")))
                    .bind("DeclRefExpr"))))
            .bind("FutagBinOpArg");

        const auto matched_vardecl =
            varDecl(hasDescendant(
                        declRefExpr(to(functionDecl().bind("TargetFunctionCall")))
                            .bind("DeclRefExpr")))
                .bind("FutagVarDecl");
    */
    const auto *MatchedBinaryOperator =
        Result.Nodes.getNodeAs<BinaryOperator>("FutagBinOpArg");
    const auto *MatchedFunctionDecl =
        Result.Nodes.getNodeAs<FunctionDecl>("TargetFunctionCall");
    const auto *MatchedVarDecl = Result.Nodes.getNodeAs<VarDecl>("VarName");
    const auto *MatchedDeclRefExpr =
        Result.Nodes.getNodeAs<DeclRefExpr>("DeclRefExpr");

    if (MatchedBinaryOperator && MatchedFunctionDecl && MatchedVarDecl &&
        MatchedDeclRefExpr) {
        std::string target_func_name = MatchedFunctionDecl->getNameAsString();
        for (auto it : analysis_jdb["functions"]) {
            // if (target_func_name == it["name"] && it["is_simple"]) {
            if (target_func_name == it["name"]) { //} && it["is_simple"]) {
                // llvm::outs()
                //     << "Found variable \"" <<
                //     MatchedVarDecl->getNameAsString()
                //     << "\"\t initialized with BinOp \"" << target_func_name
                //     << "\"\n";
                const auto *call_expr =
                    dyn_cast<CallExpr>(MatchedBinaryOperator->getRHS());
                if (call_expr &&
                    call_expr->getDirectCallee()->getNameAsString() ==
                        target_func_name) {
                    // llvm::outs()
                    //     << "-- Matched CallExpr "
                    //     << call_expr->getDirectCallee()->getNameAsString()
                    //     << "\n";
                    matched_init_callexpr[MatchedVarDecl] = call_expr;
                    return;
                } else {
                    llvm::outs() << "-- Not match CallExpr \n";
                }
                break;
            }
        }
    }

    MatchedVarDecl = Result.Nodes.getNodeAs<VarDecl>("FutagVarDecl");
    MatchedFunctionDecl =
        Result.Nodes.getNodeAs<FunctionDecl>("TargetFunctionCall");
    MatchedDeclRefExpr = Result.Nodes.getNodeAs<DeclRefExpr>("DeclRefExpr");

    if (MatchedVarDecl && MatchedFunctionDecl && MatchedDeclRefExpr) {
        for (auto it : analysis_jdb["functions"]) {
            // if (MatchedFunctionDecl->getNameAsString() == it["name"] &&
            //     it["is_simple"]) {
            if (MatchedFunctionDecl->getNameAsString() == it["name"]) { //} &&
                // it["is_simple"]) {
                //  llvm::outs()
                //      << "Found variable \"" <<
                //      MatchedVarDecl->getNameAsString()
                //      << "\" \t initialized with VarDecl \""
                //      << MatchedFunctionDecl->getNameAsString() << "\"\n";
                const auto *expr = MatchedVarDecl->getAnyInitializer();

                const auto *call_expr = dyn_cast<CallExpr>(expr);

                if (call_expr) {
                    // llvm::outs()
                    //     << "-- Matched CallExpr "
                    //     << call_expr->getDirectCallee()->getNameAsString()
                    //     << "\n";
                    matched_init_callexpr[MatchedVarDecl] = call_expr;
                    return;
                } else {
                    llvm::outs() << "-- Not match CallExpr \n";
                }
                break;
            }
        }
    }

    return;
}

/**
 * @brief This callback run function searches for all call expressions in the
 * current analyzed function
 *
 * @param Result
 */
void FutagMatchDefCallExprCB::run(const MatchFinder::MatchResult &Result) {
    const auto *MatchedBinaryOperator =
        Result.Nodes.getNodeAs<BinaryOperator>("DefFutagBinOpArg");
    const auto *MatchedFunctionDecl =
        Result.Nodes.getNodeAs<FunctionDecl>("DefTargetFunctionCall");
    const auto *MatchedVarDecl = Result.Nodes.getNodeAs<VarDecl>("DefVarName");
    const auto *MatchedDeclRefExpr =
        Result.Nodes.getNodeAs<DeclRefExpr>("DefDeclRefExpr");

    if (MatchedBinaryOperator && MatchedFunctionDecl && MatchedVarDecl &&
        MatchedDeclRefExpr) {
        std::string target_func_name = MatchedFunctionDecl->getNameAsString();
        for (auto it : analysis_jdb["functions"]) {
            if (target_func_name == it["name"]) {
                llvm::outs()
                    << "Found variable \"" << MatchedVarDecl->getNameAsString()
                    << "\" \t initialized with VarDecl \""
                    << MatchedFunctionDecl->getNameAsString() << "\"\n";
                const auto *call_expr =
                    dyn_cast<CallExpr>(MatchedBinaryOperator->getRHS());
                if (call_expr &&
                    call_expr->getDirectCallee()->getNameAsString() ==
                        target_func_name) {
                    llvm::outs()
                        << "MatchedVarDecl->getAnyInitializer(): "
                        << call_expr->getDirectCallee()->getNameAsString()
                        << "\n";
                    cfg_stmt_map->getBlock(call_expr)->getBlockID();
                    init_calls.insert(init_calls.begin(),
                                      {
                                          MatchedVarDecl->getNameAsString(),
                                          GetCallExprInfo(  //
                                              call_expr,    //
                                              cfg_stmt_map, //
                                              Mgr,          //
                                              analysis_jdb, //
                                              init_calls)   //
                                      });
                    return;
                }
            }
        }
    }

    MatchedVarDecl = Result.Nodes.getNodeAs<VarDecl>("DefFutagVarDecl");
    MatchedFunctionDecl =
        Result.Nodes.getNodeAs<FunctionDecl>("DefTargetFunctionCall");
    MatchedDeclRefExpr = Result.Nodes.getNodeAs<DeclRefExpr>("DefDeclRefExpr");

    if (MatchedVarDecl && MatchedFunctionDecl && MatchedDeclRefExpr) {
        for (auto it : analysis_jdb["functions"]) {
            if (MatchedFunctionDecl->getNameAsString() == it["name"]) {
                llvm::outs()
                    << "Found variable \"" << MatchedVarDecl->getNameAsString()
                    << "\" \t initialized with VarDecl \""
                    << MatchedFunctionDecl->getNameAsString() << "\"\n";
                const auto *expr = MatchedVarDecl->getAnyInitializer();
                const auto *call_expr = dyn_cast<CallExpr>(expr);

                if (call_expr &&
                    call_expr->getDirectCallee()->getNameAsString() ==
                        it["name"]) {
                    llvm::outs()
                        << "MatchedVarDecl->getAnyInitializer(): "
                        << call_expr->getDirectCallee()->getNameAsString()
                        << "\n";
                    init_calls.insert(init_calls.begin(),
                                      {
                                          MatchedVarDecl->getNameAsString(),
                                          GetCallExprInfo(  //
                                              call_expr,    //
                                              cfg_stmt_map, //
                                              Mgr,          //
                                              analysis_jdb, //
                                              init_calls)   //
                                      });
                    return;
                }
            }
        }
    }

    return;
}

/**
 * @brief This callback run function searches for all call expressions in the
 * current analyzed function
 *
 * @param Result
 */
void FutagMatchModCallExprCB::run(const MatchFinder::MatchResult &Result) {
    const auto *ModCallExpr = Result.Nodes.getNodeAs<CallExpr>("ModCallExpr");
    if (!ModCallExpr || !ModCallExpr->getDirectCallee())
        return;
    for (auto it : analysis_jdb["functions"]) {
        if (ModCallExpr->getDirectCallee()->getNameAsString() == it["name"]) {

            futag::FutagCallExprInfo call_expr_info = futag::GetCallExprInfo( //
                ModCallExpr,                                                  //
                cfg_stmt_map,                                                 //
                Mgr,                                                          //
                analysis_jdb,                                                 //
                init_calls                                                    //
            );
            modifying_calls.insert(modifying_calls.end(), call_expr_info);
            break;
        }
    }
    return;
}

} // namespace futag
