#include "Futag/MatchFinder.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include <fstream>
#include <iostream>

#include "Futag/ArgumentsUsage.h"
#include "Futag/Basic.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
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
                 << " - Cannot get direct callee: " +
                        rso.str() + " " +
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
      futag::utils::PathProcessor::RemoveUnnecessaryPathComponents(srcMgr.getFilename(loc).str());

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
    callExpr->printPretty(rso, nullptr, Mgr.getASTContext().getPrintingPolicy());

    llvm::errs() << __func__
                 << " - Cannot get direct callee: " +
                        rso.str() + " " +
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
      currentParamContext["param_usage"] =
          argUsage.DetermineArgumentTypeStr(func->getNameAsString(), i, callExpr);
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
} // namespace futag