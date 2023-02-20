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

void FutagMatchConsummerCallExprCallBack::FindPathInCFG(
    const CFGBlock *stmt_block, std::vector<unsigned> &path,
    std::vector<std::vector<unsigned>> &all_path) {
    if (std::find(path.begin(), path.end(), stmt_block->getBlockID()) !=
        path.end()) {
        all_path.insert(all_path.begin(), path);
        return;
    }
    path.insert(path.begin(), stmt_block->getBlockID());
    if (stmt_block->pred_size() == 0) {
        all_path.insert(all_path.begin(), path);
        return;
    }

    for (auto pred_block : stmt_block->preds()) {
        FindPathInCFG(pred_block, path, all_path);
        path.erase(path.begin());
    }
}

void FutagMatchConsummerCallExprCallBack::HandleDeclRefExpr(
    const DeclRefExpr *arg, json &curr_arg_context) {}

bool FutagMatchConsummerCallExprCallBack::HandleLiterals(const Expr *arg,
                                                         json &attr) {
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

void FutagMatchConsummerCallExprCallBack::HandleCharacterLiteral(
    const CharacterLiteral *arg, json &attr) {
    llvm::outs() << "HandleCharacterLiteral\n";
    attr["literal_type"] = "CharacterLiteral";
    attr["value"] = arg->getValue();
}

void FutagMatchConsummerCallExprCallBack::HandleFixedPointLiteral(
    const FixedPointLiteral *arg, json &attr) {
    llvm::outs() << "HandleFixedPointLiteral\n";
    attr["literal_type"] = "FixedPointLiteral";
    // @TODO: radix value selected arbitrary!
    attr["value"] = arg->getValueAsString(10);
}

void FutagMatchConsummerCallExprCallBack::HandleFloatingLiteral(
    const FloatingLiteral *arg, json &attr) {
    llvm::outs() << "HandleFloatingLiteral\n";
    // arg->getValueAsApproximateDouble();
    attr["literal_type"] = "FloatingLiteral";
    attr["value"] = arg->getValueAsApproximateDouble();
}

void FutagMatchConsummerCallExprCallBack::HandleImaginaryLiteral(
    const ImaginaryLiteral *arg, json &attr) {
    llvm::outs() << "HandleImaginaryLiteral\n";
    attr["literal_type"] = "ImaginaryLiteral";
    attr["value"] = "";
}

void FutagMatchConsummerCallExprCallBack::HandleIntegerLiteral(
    const IntegerLiteral *arg, json &attr) {
    // Process signed and unsigned integers separately
    llvm::outs() << "HandleIntegerLiteral\n";
    attr["literal_type"] = "IntegerLiteral";
    attr["value"] = (arg->getValue().isSignBitSet())
                        ? arg->getValue().getSExtValue()
                        : arg->getValue().getZExtValue();
}

void FutagMatchConsummerCallExprCallBack::HandleStringLiteral(
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
void FutagMatchConsummerCallExprCallBack::run(
    const MatchFinder::MatchResult &Result) {
    const auto *call_expr = Result.Nodes.getNodeAs<CallExpr>("FunctionCallee");
    if (!call_expr)
        return;

    std::string func_name;
    const FunctionDecl *called_func = call_expr->getDirectCallee();
    if (!called_func)
        return;

    for (auto it : analysis_jdb["functions"]) {

        // if (called_func->getNameAsString() == it["name"] &&
        // it["is_simple"])
        // {
        if (called_func->getNameAsString() == it["name"]) {
            matched_call_expr.insert(matched_call_expr.end(), call_expr);
        }
    }

    return;
}

} // namespace futag
