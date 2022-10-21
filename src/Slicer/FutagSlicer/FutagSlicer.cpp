#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
// Declares llvm::cl::extrahelp.
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/Support/CommandLine.h"

#include "FutagSlicer/pdgBuilderAction.h"
using namespace clang::tooling;
using namespace clang::ast_matchers;
using namespace llvm;
// Apply a custom category to all command-line options so that they are the
// only ones displayed.
static cl::OptionCategory FutagSlicerCat("slicer options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
static cl::extrahelp MoreHelp("\nMore help text...");

static cl::opt<std::string>
    FuncName("function-name", cl::desc(R"(The name of the function to slice.)"),
             cl::init("main"), cl::cat(FutagSlicerCat));
static cl::opt<int>
    LineNo("line", cl::desc(R"(The line number of the statement to slice.)"),
           cl::init(0), cl::cat(FutagSlicerCat));

static cl::opt<int>
    ColNo("column", cl::desc(R"(The column number of the statement to slice.)"),
          cl::init(0), cl::cat(FutagSlicerCat));

static cl::opt<bool>
    DumpDot("dump-dot", cl::desc(R"(Specifies whether tool should dump dot.)"),
            cl::init(false), cl::cat(FutagSlicerCat));

int main(int argc, const char **argv) {
  auto cp = CommonOptionsParser::create(argc, argv, FutagSlicerCat);
  CommonOptionsParser &op = cp.get();
  ClangTool Tool(op.getCompilations(), op.getSourcePathList());

  const auto Factory = std::make_unique<clang::slicer::PDGBuilderActionFactory>(
      FuncName, LineNo, ColNo, DumpDot);
  return Tool.run(Factory.get());
}