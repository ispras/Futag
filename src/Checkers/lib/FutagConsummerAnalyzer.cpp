/***
 *
 */
//== FutagConsummerAnalyzer.cpp ==//
//===----------------------------------------------------------------------===//
//
// This checker finds usage context of tested library in consummer
// libraries/programs
//
//===----------------------------------------------------------------------===//

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Futag/ConsummerFinder.h"
#include "nlohmann/json.hpp"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ODRHash.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Analysis/Analyses/CFGReachabilityAnalysis.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Analysis/CFGStmtMap.h"
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
#include "llvm/Support/Process.h"
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
/**
 * @brief This is class for checker
 *
 */
class FutagConsummerAnalyzer
    : public Checker<check::ASTDecl<TranslationUnitDecl>> {
  private:
    bool m_log_debug_message{false};

    mutable json callexpr_context_json{};
    // mutable json m_func_decl_info{};
    // mutable json m_types_info{};
    mutable json mIncludesInfo{};

    // Opens json file specified in currentReportPath and writes new
    // data provided in "state" variable to the "functions" key of the
    // resulting json file.
    void WriteInfoToTheFile(const StringRef currentReportPath,
                            json &state) const;

    void GenCFGInfo(AnalysisManager &Mgr, CFG *cfg, const FunctionDecl *func,
                    const StringRef report_path) const;

    void FindAllCFGPaths(const CFG *cfg, CFGBlock cfg_block, FutagGraph &fgraph,
                         FutagPath &curr_paths,
                         std::vector<FutagPath> &all_cfg_paths) const;

  public:
    std::string report_dir = "";
    // Path to json db file
    std::string db_file = "";
    // json db
    json analysis_jdb;

    // Save all path of CFG
    mutable std::vector<FutagPath> all_cfg_paths;

    // Full path to the current context report file
    mutable SmallString<0> context_report_path{};

    // Full path to the graphviz file
    mutable SmallString<0> report_path;

    // Full path to save the function declaration (in header files)
    mutable SmallString<0> func_decl_report_path{};

    // Full path to report that has information about structs, typedefs and
    // enums
    mutable SmallString<0> types_info_report_path{};

    // Full path to the report with includes info
    mutable SmallString<0> includesInfoReportPath{};

    // Used to generate random filename
    utils::Random rand{};

    FutagConsummerAnalyzer();
    ~FutagConsummerAnalyzer();

    // Entry point. Collects all needed information using recursive ast visitor
    void checkASTDecl(const TranslationUnitDecl *TUD, AnalysisManager &Mgr,
                      BugReporter &BR) const;

    /* Collects information about function */
    void AnalyzeVisitedFunctionDecl(const FunctionDecl *func,
                                    AnalysisManager &Mgr) const;
};

} // namespace
void FutagConsummerAnalyzer::WriteInfoToTheFile(
    const StringRef t_curr_report_path, json &tState) const {

    if (m_log_debug_message) {
        std::cerr << __func__ << " -> Report path: " << t_curr_report_path.str()
                  << "\n";
    }

    if (sys::fs::exists(t_curr_report_path)) {
        std::cerr << std::string(__func__) +
                         " -> Report file already exists: " +
                         t_curr_report_path.str() + "!";
    }

    // Create top-level directories
    sys::fs::create_directories(sys::path::parent_path(t_curr_report_path));

    // Create report file
    std::fstream curr_report_file(t_curr_report_path.str(),
                                  std::ios::in | std::ios::out | std::ios::app);

    if (curr_report_file.is_open()) {
        // Write updated json report to the file
        curr_report_file << std::setw(4) << tState << std::endl;
    } else {
        // Just crash with report_fatal_error
        std::cerr << std::string(__func__) +
                         " -> Cannot write updated json to the file: " +
                         t_curr_report_path.str() + "!";
    }
}
/**
 * @brief This function searches for all paths in the CFG of analyzed function
 * recursively
 *
 * @param cfg           The Control Flow graph of analyzed function
 * @param cfg_block     Represents for current node in CFG
 * @param fgraph        The generated graph of CFG (set of edges and nodes)
 * @param curr_paths    saves the current discovered path
 * @param all_cfg_paths saves all discovered paths
 */
void FutagConsummerAnalyzer::FindAllCFGPaths(
    const CFG *cfg, CFGBlock cfg_block, FutagGraph &fgraph,
    FutagPath &curr_paths, std::vector<FutagPath> &all_cfg_paths) const {

    if (cfg_block.getBlockID() == cfg->getExit().getBlockID()) {
        curr_paths.insert(curr_paths.end(), cfg_block.getBlockID());
        all_cfg_paths.insert(all_cfg_paths.end(), curr_paths);
    } else {
        curr_paths.insert(curr_paths.end(), cfg_block.getBlockID());
        // llvm::outs()<< "Current path:\n";
        // for(auto i : curr_paths){
        //     llvm::outs()<< i << " ";
        // }
        // llvm::outs()<< "\n";
        for (CFGBlock *succ : cfg_block.succs()) {
            if (!succ)
                continue;
            FutagEdge tmp = {cfg_block.getBlockID(), succ->getBlockID()};
            if (std::find(fgraph.begin(), fgraph.end(), &tmp) == fgraph.end()) {
                fgraph.insert(fgraph.end(), tmp);
                FindAllCFGPaths(cfg, *succ, fgraph, curr_paths, all_cfg_paths);
                fgraph.erase(fgraph.end() - 1);
            }
        }
    }
}

/**
 * @brief This function generates information of Control Flow graph: the graph
 * with edges and nodes, all the paths in this graph
 *
 * @param Mgr           The Analysis manager
 * @param cfg           The Control Flow graph of analyzed function
 * @param func          The analyzed function
 * @param report_path   The system path for saving files: .dot for the graphviz
 * format, and .raw for raw data of CFG
 */
void FutagConsummerAnalyzer::GenCFGInfo(AnalysisManager &Mgr, CFG *cfg,
                                        const FunctionDecl *func,
                                        const StringRef report_path) const {
    std::string curr_func_hash =
        std::to_string(futag::utils::ODRHashCalculator::CalculateHash(func));

    std::string cfg_raw_filename = report_path.str() + func->getNameAsString() +
                                   "-" + curr_func_hash + "-cfg.raw";
    std::string graphviz_filename = report_path.str() +
                                    func->getNameAsString() + "-" +
                                    curr_func_hash + "-graphviz.dot";
    llvm::outs() << "Graph file: " << graphviz_filename << "\n";
    if (sys::fs::exists(cfg_raw_filename) &&
        sys::fs::exists(graphviz_filename)) {
        return;
    }
    std::fstream cfg_report_file(cfg_raw_filename, std::ios::out);
    if (!cfg_report_file.is_open()) {
        std::cerr << " -> Cannot write to the file: " + cfg_raw_filename +
                         "!\n";
        return;
    }

    clang::LangOptions lo;
    std::string cfg_str;
    llvm::raw_string_ostream rso_cfg(cfg_str);
    cfg->print(rso_cfg, lo, true);
    cfg_report_file << rso_cfg.str() << "\n";
    cfg_report_file.close();
    CFGBlock entry_block = cfg->getEntry();
    CFGBlock exit_block = cfg->getExit();
    vector<CFGBlock *> blocks;
    blocks.insert(blocks.begin(), &entry_block);
    futag::FutagGraph fgraph;

    int count = 0;
    while (blocks.size() > 0) {
        count += 1;
        auto curr_block = blocks[0];
        blocks.erase(blocks.begin());
        // if (!curr_block || curr_block->succs().empty())
        //     continue;
        int curr_id = curr_block->getBlockID();
        for (CFGBlock *iter_block : curr_block->succs()) {
            if (!iter_block)
                continue;
            futag::FutagEdge tmp = {curr_block->getBlockID(),
                                    iter_block->getBlockID()};

            if (std::find(blocks.begin(), blocks.end(), iter_block) ==
                    blocks.end() &&
                std::find(fgraph.begin(), fgraph.end(), tmp) == fgraph.end()) {
                blocks.insert(blocks.end(), iter_block);
            }
            if (std::find(fgraph.begin(), fgraph.end(), tmp) == fgraph.end()) {
                fgraph.insert(fgraph.end(), tmp);
            }
        }
    }

    std::fstream graphviz_file(graphviz_filename, std::ios::out);
    if (!graphviz_file.is_open()) {
        std::cerr << " -> Cannot write to the file: " + graphviz_filename +
                         "!\n";
        return;
    }

    graphviz_file << "digraph G { /* " << func->getNameAsString() << " */\n";
    graphviz_file << "    splines = \"TRUE\";\n";
    for (auto e : fgraph) {
        graphviz_file << e.node_f << " -> " << e.node_t << "\n";
    }
    graphviz_file << "}";
    graphviz_file.close();
    fgraph.clear();
    FutagPath curr_path;
    FindAllCFGPaths(cfg, cfg->getEntry(), fgraph, curr_path, all_cfg_paths);
    std::string paths_filename = report_path.str() + func->getNameAsString() +
                                 "-" + curr_func_hash + "-path.raw";
    std::fstream paths_report(paths_filename, std::ios::out);
    if (!paths_report.is_open()) {
        std::cerr << " -> Cannot write to the file: " + paths_filename + "!\n";
        return;
    }

    for (auto path : all_cfg_paths) {
        for (auto i : path) {
            paths_report << i << " ";
        }
        paths_report << "\n";
    }
    paths_report.close();
}

FutagConsummerAnalyzer::FutagConsummerAnalyzer()
    : m_log_debug_message{std::getenv("FUTAG_FUNCTION_ANALYZER_DEBUG_LOG") !=
                          nullptr},
      callexpr_context_json{},
      //   m_func_decl_info{},
      //   m_types_info{},
      report_dir{},
      //   context_report_path{},
      //   func_decl_report_path{},
      //   types_info_report_path{},
      //   includesInfoReportPath{},
      rand{} {}

FutagConsummerAnalyzer::~FutagConsummerAnalyzer() {
    // Write new data to the json state file
    if (!callexpr_context_json.empty()) {
        WriteInfoToTheFile(context_report_path, callexpr_context_json);
    }
}

void FutagConsummerAnalyzer::checkASTDecl(const TranslationUnitDecl *TUD,
                                          AnalysisManager &Mgr,
                                          BugReporter &BR) const {

    // Save all relevant includes
    const SourceManager &sm = Mgr.getASTContext().getSourceManager();
    if (!sm.getMainFileID().isValid()) {
        return;
    }
    for (auto it = sm.fileinfo_begin(); it != sm.fileinfo_end(); it++) {

        SourceLocation includeLoc =
            sm.getIncludeLoc(sm.translateFile(it->first));
        string include_path =
            utils::PathProcessor::RemoveUnnecessaryPathComponents(
                it->first->getName().str());
        // include_path[0] != '/' - is probably an awfully bad check to avoid
        // system headers, but I couldn't find any way around
        if (includeLoc.isValid() && sm.isInMainFile(includeLoc)) {
            mIncludesInfo["includes"].push_back(include_path);
        }
    }
    std::string compiler_opts = Mgr.getAnalyzerOptions().FullCompilerInvocation;
    auto fe = sm.getFileEntryForID(sm.getMainFileID());
    if (fe->tryGetRealPathName().empty()) {
        if (fe->getName().empty()) {
            return;
        }
        mIncludesInfo["file"] = fe->getName();
    } else {
        mIncludesInfo["file"] = fe->tryGetRealPathName();
    }
    mIncludesInfo["compiler_opts"] = compiler_opts;

    struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
        const FutagConsummerAnalyzer *futag_checker;
        AnalysisManager &analysisMgr;

        explicit LocalVisitor(const FutagConsummerAnalyzer *Checker,
                              AnalysisManager &AnalysisMgr)
            : futag_checker(Checker), analysisMgr(AnalysisMgr) {}

        /* callback when a function declaration is encountered */
        bool VisitFunctionDecl(FunctionDecl *FD) {
            futag_checker->AnalyzeVisitedFunctionDecl(FD, analysisMgr);
            return true;
        }
    };

    LocalVisitor visitor(this, Mgr);
    visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TUD));
}

// Called for every function declaration
void FutagConsummerAnalyzer::AnalyzeVisitedFunctionDecl(
    const FunctionDecl *func, AnalysisManager &Mgr) const {

    // If the provided function doesn't have a body or the function
    // is a declaration (not a definition) -> skip this entry.
    if (!func->hasBody() || !func->isThisDeclarationADefinition()) {
        return;
    }
    FullSourceLoc func_begin_loc =
        Mgr.getASTContext().getFullLoc(func->getBeginLoc());
    auto fe = func_begin_loc.getFileEntry();
    if (!fe)
        return;

    std::string file_name;
    if (fe->tryGetRealPathName().empty()) {
        return;
    } else {
        file_name = fe->tryGetRealPathName().str();
    }
    MatchFinder Finder;
    // Match all CallExpression of target function
    auto matcher_callexpr =
        callExpr(callee(functionDecl())).bind("FunctionCallee");
    // callExpr(anyOf(callExpr(callee(functionDecl())).bind("FunctionCallee"),
    //                callExpr(hasDescendant(declRefExpr(to(functionDecl()))))
    //                    .bind("DeclRefExpr")));
    // Callback to match call-expresions in Function Body
    Stmt *curr_node = func->getBody();
    std::vector<const CallExpr *> matched_call_expr;

    futag::FutagMatchConsummerCallExprCallBack target_func_call_callback{
        Mgr,               // Analysis manager
        func,              // Function
        matched_call_expr, // result - matched call expressions
        analysis_jdb       // Analysis database
    };
    Finder.addMatcher(matcher_callexpr, &target_func_call_callback);
    Finder.futagMatchAST(Mgr.getASTContext(), curr_node);

    if (matched_call_expr.size()) {
        // Build the CFG of current function
        CFG *cfg = Mgr.getCFG(func);
        if (!cfg)
            return;
        GenCFGInfo(Mgr, cfg, func, report_path);
        llvm::outs() << "`Total matched call expressions: "
                     << matched_call_expr.size() << "\n";
        for (const CallExpr *iter : matched_call_expr) {
            clang::LangOptions lo;
            std::string stmt_str;
            llvm::raw_string_ostream rso_stmt(stmt_str);
            iter->printPretty(rso_stmt, NULL,
                              Mgr.getASTContext().getPrintingPolicy());

            ParentMap parent_map = ParentMap(func->getBody());

            //  Match the CFGStmtMap
            auto *cfg_stmt_map = CFGStmtMap::Build(cfg, &parent_map);
            const CFGBlock *stmt_block = cfg_stmt_map->getBlock(iter);
            llvm::outs() << " |-- CallExpr: " << stmt_str
                         << "; of block: " << stmt_block->getBlockID() << "\n";

            // for (uint32_t i = 0; i < iter->getNumArgs(); i++) {
            //     if (const auto *callExprArg =
            //             dyn_cast<CallExpr>(iter->getArg(i))) {
            //         // Handle CallExpr inside argument list of target function
            //         // call
            //         HandleCallExpr(callExprArg, curr_arg_context);
            //     } else if (const auto *declRefExpr =
            //                    dyn_cast<DeclRefExpr>(iter->getArg(i))) {
            //         HandleDeclRefExpr(declRefExpr, curr_arg_context);
            //     } else if (HandleLiterals(iter->getArg(i),
            //                               curr_arg_context)) {
            //     } else if (const auto *implicitArg = dyn_cast<ImplicitCastExpr>(
            //                    iter->getArg(i))) {
            //         if (const auto *arg = dyn_cast<DeclRefExpr>(
            //                 implicitArg->IgnoreParenImpCasts())) {
            //             HandleDeclRefExpr(arg, curr_arg_context);
            //         } else if (HandleLiterals(
            //                        iter->getArg(i)->IgnoreParenCasts(),
            //                        curr_arg_context)) {
            //         }
            //     }
            // }

            // llvm::outs() << " `- Paths found:\n";
            // for (auto path : all_cfg_paths) {
            //     if (std::find(path.begin(), path.end(),
            //                   stmt_block->getBlockID()) != path.end()) {
            //         llvm::outs() << "    [ ";
            //         for (auto node : path) {
            //             llvm::outs() << node << " ";
            //         }
            //         llvm::outs() << "]\n";
            //     }
            // }
        }
    }
    return;
}

void ento::registerFutagConsummerAnalyzer(CheckerManager &Mgr) {
    auto *Chk = Mgr.registerChecker<FutagConsummerAnalyzer>();
    Chk->report_dir =
        std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
            Mgr.getCurrentCheckerName(), "report_dir"));

    if (!sys::fs::exists(Chk->report_dir)) {
        sys::fs::create_directory(Chk->report_dir);
    }
    Chk->db_file = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
        Mgr.getCurrentCheckerName(), "db_file"));

    llvm::errs() << Chk->report_dir << "\n";
    if (!sys::fs::exists(Chk->db_file)) {
        llvm::errs() << "db file not found!";
        return;
    }
    std::ifstream ifs(Chk->db_file);
    Chk->analysis_jdb = json::parse(ifs);

    if (!sys::fs::exists(Chk->report_dir)) {
        sys::fs::create_directory(Chk->report_dir);
    }
    Chk->report_path = "";
    sys::path::append(Chk->report_path, Chk->report_dir, "_");

    Chk->context_report_path = "";
    sys::path::append(
        Chk->context_report_path, Chk->report_dir,
        "context-" + Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
            ".futag-analyzer.json");
}

bool ento::shouldRegisterFutagConsummerAnalyzer(const CheckerManager &mgr) {
    return true;
}