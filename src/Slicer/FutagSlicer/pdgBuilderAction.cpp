#include "FutagSlicer/pdgBuilderAction.h"
#include <utility>

namespace clang {
namespace slicer {
PDGBuilderAction::PDGBuilderAction(std::string funcName, int lineNo, int colNo,
                                   bool dumpDot)
    : Matcher(std::move(funcName), lineNo, colNo, dumpDot) {
  Matcher.registerMatchers(&MatchFinder);
}

std::unique_ptr<ASTConsumer>
PDGBuilderAction::CreateASTConsumer(CompilerInstance & /*Compiler*/,
                                    StringRef /*InFile*/) {
  return MatchFinder.newASTConsumer();
}
} // namespace slicer
} // namespace clang