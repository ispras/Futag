/**
 * @file MatchFinder.cpp
 * @author Tran Chi Thien
 * @brief 
 * @version 0.1
 * @date 2023-03-20
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "Futag/MatchFinder.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include <algorithm>
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

void FutagMatchBinOperatorArgCallBack::run(
    const MatchFinder::MatchResult &Result) {
    const auto *MatchedBinaryOperator =
        Result.Nodes.getNodeAs<BinaryOperator>("FutagBinOpArg");
    if (!MatchedBinaryOperator) {
        return;
    }
    // llvm::outs() << "Match binary operator!!!!";
    // The RHS of operator is one of:
    // 1. Function caller:
    //   dyn_cast<DeclRefExpr>(dyn_cast<ImplicitCastExpr>(MatchedBinaryOperator->getRHS())->getSubExpr())->getNameInfo().getAsString()
    // 2. another variable with DeclRefExpr ?
    // 3. value such as: FloatingLiteral, IntegerLiteral, StringLiteral ...
    // depends on data type
    // 4. Change value by reference, pointer ??

    auto *lhs = dyn_cast<DeclRefExpr>(MatchedBinaryOperator->getLHS());
    auto *rhs = dyn_cast<CallExpr>(MatchedBinaryOperator->getRHS());
    // if (lhs && rhs) {
    if (lhs && rhs) {
        // llvm::outs() << "Argument "
        //              << lhs->getNameInfo().getName().getAsString() << "\t";
        if (rhs->getDirectCallee()) {
            FullSourceLoc callExprLoc =
                Mgr.getASTContext().getFullLoc(rhs->getBeginLoc());
            curr_arg_context["call_init"].push_back(
                {{"called_func", rhs->getDirectCallee()->getNameAsString()},
                 {"line", callExprLoc.getSpellingLineNumber()},
                 {"col", callExprLoc.getSpellingColumnNumber()}});
            // llvm::outs() << "is called from BinaryOp: "
            //              << rhs->getDirectCallee()->getNameAsString() <<
            //              "\n";
            // }else{
            //     llvm::outs() << "is called from Unknown!!!\n";
        }
    }

    return;
}
void FutagMatchVarDeclArgCallBack::run(const MatchFinder::MatchResult &Result) {
    const auto *MatchedVarDecl =
        Result.Nodes.getNodeAs<VarDecl>("FutagVarDeclArgName");
    const auto *MatchedDeclRefExpr =
        Result.Nodes.getNodeAs<DeclRefExpr>("FutagVarDeclArgCall");
    if (!MatchedVarDecl && !MatchedDeclRefExpr) {
        return;
    }

    if (MatchedDeclRefExpr) {
        // llvm::outs()
        //     << "is called from VarDecl: "
        //     << MatchedDeclRefExpr->getNameInfo().getName().getAsString()
        //     << "\n";
        // call_init["callexpr_function"] =
        // MatchedDeclRefExpr->getNameAsString();
        FullSourceLoc callExprLoc =
            Mgr.getASTContext().getFullLoc(MatchedDeclRefExpr->getBeginLoc());
        curr_arg_context["call_init"].push_back(
            {{"called_func", MatchedDeclRefExpr->getDecl()->getNameAsString()},
             {"line", callExprLoc.getSpellingLineNumber()},
             {"col", callExprLoc.getSpellingColumnNumber()}});
    }

    return;
}

bool FutagMatchCallExprCallBack::HandleLiterals(const clang::Expr *arg,
                                                json &curr_arg_context) {
    if (const auto *charecterLiteralArg = dyn_cast<CharacterLiteral>(arg)) {
        HandleCharacterLiteral(charecterLiteralArg, curr_arg_context);
        return true;
    }

    if (const auto *fixedPointLiteralArg = dyn_cast<FixedPointLiteral>(arg)) {
        HandleFixedPointLiteral(fixedPointLiteralArg, curr_arg_context);
        return true;
    }

    if (const auto *floatingPointLiteralArg = dyn_cast<FloatingLiteral>(arg)) {
        HandleFloatingLiteral(floatingPointLiteralArg, curr_arg_context);
        return true;
    }

    if (const auto *imaginaryLiteralArg = dyn_cast<ImaginaryLiteral>(arg)) {
        HandleImaginaryLiteral(imaginaryLiteralArg, curr_arg_context);
        return true;
    }

    if (const auto *integerLiteralArg = dyn_cast<IntegerLiteral>(arg)) {
        HandleIntegerLiteral(integerLiteralArg, curr_arg_context);
        return true;
    }

    if (const auto *stringLiteralArg = dyn_cast<clang::StringLiteral>(arg)) {
        HandleStringLiteral(stringLiteralArg, curr_arg_context);
        return true;
    }

    return false;
}

void FutagMatchCallExprCallBack::HandleDeclRefExpr(const DeclRefExpr *arg,
                                                   json &curr_arg_context) {
    curr_arg_context["futag_type"] = FutagType::DeclRefStr();
    curr_arg_context["literal_value"] = arg->getNameInfo().getAsString();
    // Test Matcher
    // clang-query-13
    //  /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/tests/test_null.c

    // clang-query-13
    // /home/futag/Futag-tests/curl/curl-7.85.0/tests/libtest/lib503.c --
    // -- match varDecl(hasName(arg->getDecl()->getNameAsString()),
    // hasDescendant(declRefExpr()))

    // const auto binary_op = binaryOperator(
    //     isAssignmentOperator(), hasRHS(hasDescendant(declRefExpr(
    //                                 to(varDecl(hasName(param->getName())))))));
    // return;
    curr_arg_context["call_init"] = json::array();

    MatchFinder Finder;
    const auto matched_vardecl =
        varDecl(
            hasName(arg->getDecl()->getNameAsString()),
            hasDescendant(
                declRefExpr(to(functionDecl())).bind("FutagVarDeclArgCall")))
            .bind("FutagVarDeclArgName");

    const auto matched_binaryoperator =
        binaryOperator(isAssignmentOperator(),
                       hasLHS(declRefExpr(to(varDecl(
                           hasName(arg->getDecl()->getNameAsString()))))),
                       hasRHS(hasDescendant(declRefExpr())))
            .bind("FutagBinOpArg");

    futag::FutagMatchBinOperatorArgCallBack search_binop_arg_init{
        Mgr, curr_node, arg, curr_arg_context};
    futag::FutagMatchVarDeclArgCallBack search_vardecl_arg_init{
        Mgr, curr_node, arg, curr_arg_context};
    Finder.addMatcher(matched_binaryoperator, &search_binop_arg_init);
    Finder.addMatcher(matched_vardecl, &search_vardecl_arg_init);
    Finder.futagMatchAST(Mgr.getASTContext(), curr_node);
    if (!curr_arg_context["call_init"].empty()) {
        // llvm::outs()<< "ok\n";
        curr_arg_context["futag_type"] = FutagType::FuncCallResStr();
    }
}

void FutagMatchCallExprCallBack::HandleCharacterLiteral(
    const CharacterLiteral *arg, json &curr_arg_context) {
    curr_arg_context["futag_type"] = FutagType::ConstValStr();
    curr_arg_context["literal_value"] = arg->getValue();
}

void FutagMatchCallExprCallBack::HandleFixedPointLiteral(
    const FixedPointLiteral *arg, json &curr_arg_context) {
    curr_arg_context["futag_type"] = FutagType::ConstValStr();
    // @TODO: radix value selected arbitrary!
    curr_arg_context["literal_value"] = arg->getValueAsString(10);
}

void FutagMatchCallExprCallBack::HandleFloatingLiteral(
    const FloatingLiteral *arg, json &curr_arg_context) {
    arg->getValueAsApproximateDouble();
    curr_arg_context["futag_type"] = FutagType::ConstValStr();
    curr_arg_context["literal_value"] = arg->getValueAsApproximateDouble();
}

void FutagMatchCallExprCallBack::HandleImaginaryLiteral(
    const ImaginaryLiteral *arg, json &curr_arg_context) {
    curr_arg_context["futag_type"] = FutagType::ConstValStr();
    curr_arg_context["literal_value"] = "";
}

void FutagMatchCallExprCallBack::HandleIntegerLiteral(const IntegerLiteral *arg,
                                                      json &curr_arg_context) {
    // Process signed and unsigned integers separately
    curr_arg_context["futag_type"] = FutagType::ConstValStr();
    curr_arg_context["literal_value"] = (arg->getValue().isSignBitSet())
                                            ? arg->getValue().getSExtValue()
                                            : arg->getValue().getZExtValue();
}

void FutagMatchCallExprCallBack::HandleStringLiteral(
    const clang::StringLiteral *arg, json &curr_arg_context) {
    curr_arg_context["futag_type"] = FutagType::ConstValStr();
    curr_arg_context["literal_value"] = arg->getBytes();
}

void FutagMatchCallExprCallBack::HandleCallExpr(const CallExpr *arg,
                                                json &curr_arg_context) {
    curr_arg_context["futag_type"] = FutagType::FuncCallResStr();
    const FunctionDecl *func = arg->getDirectCallee();
    if (!func) {
        FullSourceLoc callExprLoc =
            Mgr.getASTContext().getFullLoc(arg->getBeginLoc());

        std::string callExprStr;
        llvm::raw_string_ostream rso(callExprStr);
        arg->printPretty(rso, nullptr, Mgr.getASTContext().getPrintingPolicy());

        llvm::errs() << __func__
                     << " - Cannot get direct callee: " + rso.str() + ", location: " +
                            callExprLoc.printToString(Mgr.getSourceManager()) +
                            "\n";
        return;
    }

    curr_arg_context["callexpr_function"] = func->getQualifiedNameAsString();
}

/**
 * @brief This callback run function searches for all call expressions in the
 * current analyzed function
 *
 * @param Result
 */
void FutagMatchCallExprCallBack::run(const MatchFinder::MatchResult &Result) {
    const auto *callExpr = Result.Nodes.getNodeAs<CallExpr>("FutagCalledFunc");

    if (!callExpr) {
        return;
    }

    // 1. Extract function declaration
    const FunctionDecl *called_func = callExpr->getDirectCallee();
    if (!called_func) {
        // Search for MACRO definition
        return;
    }

    // 2. Calculate ODRHash
    std::string called_func_hash = std::to_string(
        futag::utils::ODRHashCalculator::CalculateHash(called_func));

    std::string consumer_func_hash = std::to_string(
        futag::utils::ODRHashCalculator::CalculateHash(consumer_func));

    // 3. Get instance of SourceManager to extract information about call
    // location
    SourceManager &srcMgr = Result.Context->getSourceManager();
    SourceLocation loc = srcMgr.getExpansionLoc(callExpr->getExprLoc());

    // If we don't have basic information for currently processed call,
    // Create new object with the key = funcHash
    if (!curr_context.contains(consumer_func_hash))
        curr_context[consumer_func_hash] = json{};

    // Check if we have call_contexts field
    if (!curr_context[consumer_func_hash].contains("call_contexts")) {
        curr_context[consumer_func_hash]["call_contexts"] = json::array();
    }

    // Check if we have func_name field
    if (!curr_context[consumer_func_hash].contains("func_name")) {
        curr_context[consumer_func_hash]["func_name"] =
            consumer_func->getQualifiedNameAsString();
    }

    // Preprocess current filename by deleting all ./ and ../
    std::string curr_file_name =
        futag::utils::PathProcessor::RemoveUnnecessaryPathComponents(
            srcMgr.getFilename(loc).str());

    // Build full call location
    std::string called_from_full_loc =
        curr_file_name + ":" +
        std::to_string(srcMgr.getExpansionLineNumber(loc));

    json currentCallContext =
        json{{"target_func_loc", called_from_full_loc},
             {"target_func_name", called_func->getQualifiedNameAsString()},
             {"target_func_hash", called_func_hash},
             {"args_desc", json::array()}};

    for (uint32_t i = 0; i < callExpr->getNumArgs(); i++) {
        // In the  Function's arguments list, there are constants,
        // variables,callexpr
        QualType arg_type = callExpr->getArg(i)->getType();
        // std::string arg_name = "";
        json curr_arg_context{{"idx", i},
                              //   {"name", arg_name},
                              {"data_type", arg_type.getAsString()},
                              {"futag_type", FutagType::UnknownStr()},
                              {"literal_value", ""},
                              {"callexpr_function", ""}};

        // if (auto cast = dyn_cast<ImplicitCastExpr>(callExpr->getArg(i))) {
        //     if (auto arg = dyn_cast<DeclRefExpr>(cast->getSubExpr())) {
        //         arg_name = arg->getNameInfo().getName().getAsString();
        //     }
        // }

        if (const auto *callExprArg = dyn_cast<CallExpr>(callExpr->getArg(i))) {
            // Handle CallExpr inside argument list of target function call
            HandleCallExpr(callExprArg, curr_arg_context);
        } else if (const auto *declRefExpr =
                       dyn_cast<DeclRefExpr>(callExpr->getArg(i))) {
            HandleDeclRefExpr(declRefExpr, curr_arg_context);
        } else if (HandleLiterals(callExpr->getArg(i), curr_arg_context)) {
        } else if (const auto *implicitArg =
                       dyn_cast<ImplicitCastExpr>(callExpr->getArg(i))) {
            if (const auto *arg =
                    dyn_cast<DeclRefExpr>(implicitArg->IgnoreParenImpCasts())) {
                HandleDeclRefExpr(arg, curr_arg_context);
            }else if (HandleLiterals(callExpr->getArg(i)->IgnoreParenCasts(), curr_arg_context)){
            }
        }

        currentCallContext["args_desc"].push_back(curr_arg_context);
    }

    // Write new call location to the array
    curr_context[consumer_func_hash]["call_contexts"].push_back(
        currentCallContext);
    return;
}

void FutagArgUsageDeterminer::run(const MatchFinder::MatchResult &Result) {
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
         * Check if parameter to the function call is DeclRefExpr
         * (variable). If it is true, check that the name of the argument is
         * the same as the caller's argument name. If this is true, it
         * means, that the parameter is passed directly into some known
         * function (e.g. open), and we can easily mark parameter type for
         * the caller. Consider this example: int func(char* path)
         * {
         *   return open(path, O_RDONLY);
         * }
         * func's path will be marked as FILE_PATH_INPUT
         */
        if (param &&
            param->getDecl()->getNameAsString() ==
                curr_param_context["param_name"] &&
            curr_param_context["param_usage"] ==
                ArgumentsUsage::ArgumentTypeToStr(
                    ArgumentsUsage::AT::UNKNOWN)) {
            curr_param_context["param_usage"] =
                argUsage.DetermineArgumentTypeStr(func->getNameAsString(), i,
                                                  callExpr);
        }
    }

    return;
}

void FutagMatchVarDeclCallBack::run(const MatchFinder::MatchResult &Result) {
    const auto *matched_vardecl =
        Result.Nodes.getNodeAs<VarDecl>("FutagMatchVarDecl");
    if (matched_vardecl) {
        std::ofstream tmpfile;
        tmpfile.open("foundMatchDeclaration.txt", std::ios_base::app);
        tmpfile << "Found VarDecl name: " << matched_vardecl->getName().str()
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

void FutagCatchInfoCallBack::run(const MatchFinder::MatchResult &result) {
    const auto *declRefExpr =
        result.Nodes.getNodeAs<DeclRefExpr>("declRefExpr");

    if (!declRefExpr) {
        return;
    }

    auto stmt_begin_loc =
        result.Context->getFullLoc(declRefExpr->getBeginLoc());
    auto stmt_end_loc = result.Context->getFullLoc(declRefExpr->getEndLoc());

    if (stmt_begin_loc.getSpellingLineNumber() >= BeginLine &&
        stmt_begin_loc.getSpellingLineNumber() <= EndLine &&
        stmt_end_loc.getSpellingLineNumber() >= BeginLine &&
        stmt_end_loc.getSpellingLineNumber() <= EndLine) {
        ODRHash Hash;
        Hash.AddDecl(declRefExpr->getDecl());
        auto hash = Hash.CalculateHash();
        bool found = false;
        for (auto element : decl_hash_list) {
            if (hash == element) {
                found = true;
                break;
            }
        }
        if (!found) {
            decl_hash_list.push_back(hash);
            decl_ref_list.push_back(declRefExpr);
        }
    }

    return;
}

FutagCatchInfoCallBack::~FutagCatchInfoCallBack() {
    for (auto &element : decl_ref_list) {
        llvm::outs() << " -- variable name: "
                     << element->getNameInfo().getAsString();
        llvm::outs() << " variable type: " << element->getType().getAsString()
                     << "\n";
    }
}

} // namespace futag
