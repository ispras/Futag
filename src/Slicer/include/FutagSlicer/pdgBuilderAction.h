#ifndef PDGBUILDERACTION_H
#define PDGBUILDERACTION_H

#include "pdgBuilder.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include <memory>
#include <utility>

namespace clang {
namespace slicer {
class PDGBuilderAction : public ASTFrontendAction {
public:
  explicit PDGBuilderAction(std::string _funcName, int _lineNo, int _colNo,
                            bool _dumpDot);
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &Compiler,
                                                 StringRef InFile) override;

private:
  ast_matchers::MatchFinder MatchFinder;
  PDGBuilder Matcher;
};

class PDGBuilderActionFactory : public tooling::FrontendActionFactory {
public:
  PDGBuilderActionFactory(std::string _funcName, int _lineNo, int _colNo,
                          bool _dumpDot)
      : funcName(std::move(std::move(_funcName))), lineNo(_lineNo),
        colNo(_colNo), dumpDot(_dumpDot) {}

  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<PDGBuilderAction>(funcName, lineNo, colNo, dumpDot);
  }

private:
  std::string funcName;
  int lineNo;
  int colNo;
  bool dumpDot;
};
} // namespace slicer
} // namespace clang

#endif // PDGBUILDERACTION_H