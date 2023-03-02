#include "Futag/ConsummerFinder.h"
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

futag::FutagCallExprInfo GetCallExprInfo(const CallExpr *call_expr,
                                         clang::CFGStmtMap *cfg_stmt_map,
                                         AnalysisManager &Mgr) {
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
            curr_init_arg.init_type = ArgFuncCall;
            curr_init_arg.func_call = const_cast<CallExpr *>(callExprArg);
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
                curr_init_arg.value = charecterLiteralArg->getValue();
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
                curr_init_arg.value = stringLiteralArg->getBytes().str();
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
    FutagCallExprInfo result{call_expr, stmt_str, init_args, cfg_block_ID,
                             code_loc};
    return result;
}

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

void FutagMatchInitCallExprCB::HandleDeclRefExpr(const DeclRefExpr *arg,
                                                 json &curr_arg_context) {}

bool FutagMatchInitCallExprCB::HandleLiterals(const Expr *arg, json &attr) {
    if (const auto *charecterLiteralArg = dyn_cast<CharacterLiteral>(arg)) {
        HandleCharacterLiteral(charecterLiteralArg, attr);
        return true;
    }

    if (const auto *fixedPointLiteralArg = dyn_cast<FixedPointLiteral>(arg)) {
        HandleFixedPointLiteral(fixedPointLiteralArg, attr);
        return true;
    }

    if (const auto *floatingPointLiteralArg = dyn_cast<FloatingLiteral>(arg)) {
        HandleFloatingLiteral(floatingPointLiteralArg, attr);
        return true;
    }

    if (const auto *imaginaryLiteralArg = dyn_cast<ImaginaryLiteral>(arg)) {
        HandleImaginaryLiteral(imaginaryLiteralArg, attr);
        return true;
    }

    if (const auto *integerLiteralArg = dyn_cast<IntegerLiteral>(arg)) {
        HandleIntegerLiteral(integerLiteralArg, attr);
        return true;
    }

    if (const auto *stringLiteralArg = dyn_cast<clang::StringLiteral>(arg)) {
        HandleStringLiteral(stringLiteralArg, attr);
        return true;
    }

    return false;
}

void FutagMatchInitCallExprCB::HandleCharacterLiteral(
    const CharacterLiteral *arg, json &attr) {
    llvm::outs() << "HandleCharacterLiteral\n";
    attr["literal_type"] = "CharacterLiteral";
    attr["value"] = arg->getValue();
}

void FutagMatchInitCallExprCB::HandleFixedPointLiteral(
    const FixedPointLiteral *arg, json &attr) {
    llvm::outs() << "HandleFixedPointLiteral\n";
    attr["literal_type"] = "FixedPointLiteral";
    // @TODO: radix value selected arbitrary!
    attr["value"] = arg->getValueAsString(10);
}

void FutagMatchInitCallExprCB::HandleFloatingLiteral(const FloatingLiteral *arg,
                                                     json &attr) {
    llvm::outs() << "HandleFloatingLiteral\n";
    // arg->getValueAsApproximateDouble();
    attr["literal_type"] = "FloatingLiteral";
    attr["value"] = arg->getValueAsApproximateDouble();
}

void FutagMatchInitCallExprCB::HandleImaginaryLiteral(
    const ImaginaryLiteral *arg, json &attr) {
    llvm::outs() << "HandleImaginaryLiteral\n";
    attr["literal_type"] = "ImaginaryLiteral";
    attr["value"] = "";
}

void FutagMatchInitCallExprCB::HandleIntegerLiteral(const IntegerLiteral *arg,
                                                    json &attr) {
    // Process signed and unsigned integers separately
    llvm::outs() << "HandleIntegerLiteral\n";
    attr["literal_type"] = "IntegerLiteral";
    attr["value"] = (arg->getValue().isSignBitSet())
                        ? arg->getValue().getSExtValue()
                        : arg->getValue().getZExtValue();
}

void FutagMatchInitCallExprCB::HandleStringLiteral(
    const clang::StringLiteral *arg, json &attr) {
    // llvm::outs() << "HandleStringLiteral\n";
    attr["literal_type"] = "StringLiteral";

    attr["value"] = arg->getBytes();
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
            if (target_func_name == it["name"] && it["is_simple"]) {
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
            if (MatchedFunctionDecl->getNameAsString() == it["name"] &&
                it["is_simple"]) {
                // llvm::outs()
                //     << "Found variable \"" <<
                //     MatchedVarDecl->getNameAsString()
                //     << "\" \t initialized with VarDecl \""
                //     << MatchedFunctionDecl->getNameAsString() << "\"\n";
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
                    unsigned int found_block_ID =
                        cfg_stmt_map->getBlock(call_expr)->getBlockID();
                    if (std::find(curr_analyzed_path.begin(),
                                  curr_analyzed_path.end(),
                                  found_block_ID) <= curr_analyzed_pos) {
                        if (std::find(curr_analyzed_path.begin(),
                                      curr_analyzed_path.end(),
                                      found_block_ID) < curr_analyzed_pos) {
                            curr_context_path.insert(curr_context_path.begin(),
                                                     found_block_ID);
                        }
                        init_calls.insert(
                            init_calls.begin(),
                            {MatchedVarDecl->getNameAsString(),
                             GetCallExprInfo(call_expr, cfg_stmt_map, Mgr)});
                        return;
                    }
                }
                break;
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
                    unsigned int found_block_ID =
                        cfg_stmt_map->getBlock(call_expr)->getBlockID();
                    if (std::find(curr_analyzed_path.begin(),
                                  curr_analyzed_path.end(),
                                  found_block_ID) <= curr_analyzed_pos) {
                        if (std::find(curr_analyzed_path.begin(),
                                      curr_analyzed_path.end(),
                                      found_block_ID) < curr_analyzed_pos) {
                            curr_context_path.insert(curr_context_path.begin(),
                                                     found_block_ID);
                        }
                        init_calls.insert(
                            init_calls.begin(),
                            {MatchedVarDecl->getNameAsString(),
                             GetCallExprInfo(call_expr, cfg_stmt_map, Mgr)});
                        return;
                    }
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
void FutagMatchModCallExprCB::run(const MatchFinder::MatchResult &Result) {
    const auto *ModCallExpr = Result.Nodes.getNodeAs<CallExpr>("ModCallExpr");
    if (!ModCallExpr || !ModCallExpr->getDirectCallee())
        return;
    for (auto it : analysis_jdb["functions"]) {
        if (ModCallExpr->getDirectCallee()->getNameAsString() == it["name"]) {

            futag::FutagCallExprInfo call_expr_info =
                futag::GetCallExprInfo(ModCallExpr, cfg_stmt_map, Mgr);
            modifying_calls.insert(modifying_calls.end(), call_expr_info);

            for (auto iter_arg : call_expr_info.args) {
                if (iter_arg.init_type == futag::ArgVarRef) {
                    bool found_init_arg = false;
                    for (auto iter_init_call : init_calls) {
                        if (iter_arg.value == iter_init_call.var_name) {
                            found_init_arg = true;
                        }
                    }
                    if (!found_init_arg) {
                        SearchVarDeclInBlock(
                            Mgr,
                            iter_arg,           // current argument for search
                            curr_search_node,   // current node for search
                            cfg_stmt_map,       // for matching found callexpr
                            curr_context_path,  // for adding node to curr path
                            curr_analyzed_pos,  // for checking match
                            curr_analyzed_path, // for checking match
                            init_calls,         //
                            analysis_jdb);
                    }
                }
            }
            break;
        }
    }
    return;
}

} // namespace futag
