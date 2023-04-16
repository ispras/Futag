/**
 * @file FutagConsumerAnalyzer.cpp
 * @author Tran Chi Thien
 * @brief 
 * @version 2.0.2
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

#include "Futag/ConsumerFinder.h"
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
class FutagConsumerAnalyzer
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
                         FutagPath &curr_path,
                         std::vector<FutagPath> &all_cfg_paths) const;
    // void SearchContextInCFGPath(std::string var_name, CFGBlock cfg_block,
    //                             FutagPath &curr_path,
    //                             FutagContext &curr_context) const;

  public:
    mutable SmallString<0> consumer_report_path;
    // Path to json db file
    std::string db_filepath = "";
    // json db
    json analysis_jdb;

    // Save all path of CFG
    mutable std::vector<FutagPath> all_cfg_paths;

    // Full path to the current context report file
    // mutable SmallString<0> context_report_path{};


    // Full path to save the function declaration (in header files)
    mutable SmallString<0> func_decl_report_path{};

    // Full path to report that has information about structs, typedefs and
    // enums
    mutable SmallString<0> types_info_report_path{};

    // Full path to the report with includes info
    mutable SmallString<0> includesInfoReportPath{};

    // Used to generate random filename
    utils::Random rand{};

    FutagConsumerAnalyzer();
    ~FutagConsumerAnalyzer();

    // Entry point. Collects all needed information using recursive ast visitor
    void checkASTDecl(const TranslationUnitDecl *TUD, AnalysisManager &Mgr,
                      BugReporter &BR) const;

    /* Collects information about function */
    void AnalyzeVisitedFunctionDecl(const FunctionDecl *func,
                                    AnalysisManager &Mgr) const;
};

} // namespace

void WriteContextToFile(                               //
    std::fstream &output_context_file,                 //
    std::vector<FutagInitVarDeclCallExpr> &init_calls, //
    std::vector<FutagCallExprInfo> &modifying_calls,   //
    std::vector<unsigned int> sorted_block_Idx         //
) {
    json init_calls_json;
    for (auto call : init_calls) {
        json args = json::array();
        for (auto arg : call.call_expr_info.args) {
            json arg_info = {
                {"init_type", arg.init_type}, //
                {"value", arg.value}          //
            };
            args.push_back(arg_info);
        }
        json call_expr_json = {
            {"name", call.call_expr_info.name},
            {"qname", call.call_expr_info.name},
            {"cfg_block_ID", call.call_expr_info.cfg_block_ID},
            {"str_stmt", call.call_expr_info.str_stmt},
            {"file", call.call_expr_info.location.file},
            {"line", call.call_expr_info.location.line},
            {"col", call.call_expr_info.location.col},
            {"args", args} //
        };
        init_calls_json[call.var_name] = call_expr_json;
    }
    json cfg_blocks = json::array();
    for (auto idx : sorted_block_Idx) {
        cfg_blocks.push_back(idx);
    }
    json modifying_calls_json = json::array();
    for (auto call : modifying_calls) {
        if (std::find(sorted_block_Idx.begin(), sorted_block_Idx.end(),
                      call.cfg_block_ID) == sorted_block_Idx.end()) {
            continue;
        }

        json args = json::array();
        for (auto arg : call.args) {
            json arg_info = {
                {"init_type", arg.init_type}, //
                {"value", arg.value}          //
            };
            args.push_back(arg_info);
        }

        modifying_calls_json.push_back({
            {"name", call.name},
            {"qname", call.name},
            {"cfg_block_ID", call.cfg_block_ID},
            {"str_stmt", call.str_stmt},
            {"file", call.location.file},
            {"line", call.location.line},
            {"col", call.location.col},
            {"args", args} //
        });
    }
    json result;
    result["cfg_blocks"] = cfg_blocks;
    result["init_calls"] = init_calls_json;
    result["modifying_calls"] = modifying_calls_json;
    output_context_file << std::setw(4) << result << std::endl;
};

void FutagConsumerAnalyzer::WriteInfoToTheFile(
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

// /**
//  * @brief
//  *
//  * @param var_name
//  * @param cfg_block
//  * @param curr_path
//  */
// void SearchContextInCFGPath(std::string var_name, CFGBlock cfg_block,
//                             FutagPath &curr_path,
//                             FutagContext &curr_context) const {

//                             }

/**
 * @brief This function searches for all paths in the CFG of analyzed
 * function recursively
 *
 * @param cfg           The Control Flow graph of analyzed function
 * @param cfg_block     Represents for current node in CFG
 * @param fgraph        The generated graph of CFG (set of edges and nodes)
 * @param curr_path    saves the current discovered path
 * @param all_cfg_paths saves all discovered paths
 */
void FutagConsumerAnalyzer::FindAllCFGPaths(
    const CFG *cfg, CFGBlock cfg_block, FutagGraph &fgraph,
    FutagPath &curr_path, std::vector<FutagPath> &all_cfg_paths) const {

    if (cfg_block.getBlockID() == cfg->getExit().getBlockID()) {
        // curr_path.insert(curr_path.end(), cfg_block.getBlockID());
        all_cfg_paths.insert(all_cfg_paths.end(), curr_path);
    } else {

        // llvm::outs()<< "Current path:\n";
        // for(auto i : curr_path){
        //     llvm::outs()<< i << " ";
        // }
        // llvm::outs()<< "\n";
        for (CFGBlock *succ : cfg_block.succs()) {
            if (!succ)
                continue;
            FutagEdge tmp = {cfg_block.getBlockID(), succ->getBlockID()};
            if (std::find(fgraph.begin(), fgraph.end(), tmp) == fgraph.end()) {
                fgraph.insert(fgraph.end(), tmp);
                curr_path.insert(curr_path.end(), succ->getBlockID());
                FindAllCFGPaths(cfg, *succ, fgraph, curr_path, all_cfg_paths);
                curr_path.erase(curr_path.end() - 1);
                fgraph.erase(fgraph.end() - 1);
            }
        }
    }
}

/**
 * @brief This function generates information of Control Flow graph: the
 * graph with edges and nodes, all the paths in this graph
 *
 * @param Mgr           The Analysis manager
 * @param cfg           The Control Flow graph of analyzed function
 * @param func          The analyzed function
 * @param report_path   The system path for saving files: .dot for the
 * graphviz format, and .raw for raw data of CFG
 */
void FutagConsumerAnalyzer::GenCFGInfo(AnalysisManager &Mgr, CFG *cfg,
                                        const FunctionDecl *func,
                                        const StringRef report_path) const {
    std::string curr_func_hash =
        std::to_string(futag::utils::ODRHashCalculator::CalculateHash(func));

    std::string cfg_raw_filename = report_path.str() + func->getNameAsString() +
                                   "-" + curr_func_hash + "-cfg.raw";
    std::string graphviz_filename = report_path.str() +
                                    func->getNameAsString() + "-" +
                                    curr_func_hash + "-graphviz.dot";
    // llvm::outs() << "Graph file: " << graphviz_filename << "\n";
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
}

FutagConsumerAnalyzer::FutagConsumerAnalyzer()
    : m_log_debug_message{std::getenv("FUTAG_FUNCTION_ANALYZER_DEBUG_LOG") !=
                          nullptr},
      callexpr_context_json{},
      //   m_func_decl_info{},
      //   m_types_info{},
      consumer_report_path{},
      //   context_report_path{},
      //   func_decl_report_path{},
      //   types_info_report_path{},
      //   includesInfoReportPath{},
      rand{} {}

FutagConsumerAnalyzer::~FutagConsumerAnalyzer() {
    // Write new data to the json state file
    // if (!callexpr_context_json.empty()) {
    //     WriteInfoToTheFile(context_report_path, callexpr_context_json);
    // }
}

void FutagConsumerAnalyzer::checkASTDecl(const TranslationUnitDecl *TUD,
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
        // include_path[0] != '/' - is probably an awfully bad check to
        // avoid system headers, but I couldn't find any way around
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
        const FutagConsumerAnalyzer *futag_checker;
        AnalysisManager &analysisMgr;

        explicit LocalVisitor(const FutagConsumerAnalyzer *Checker,
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
void FutagConsumerAnalyzer::AnalyzeVisitedFunctionDecl(
    const FunctionDecl *func, AnalysisManager &Mgr) const {

    // If the provided function doesn't have a body or the function
    // is a declaration (not a definition) -> skip this entry.
    if (!func->hasBody()) {
        return;
    }
    if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc())) {
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

    // Match all CallExpression of target function
    const auto matcher_callexpr =
        callExpr(callee(functionDecl())).bind("FunctionCallee");

    // callExpr(anyOf(callExpr(callee(functionDecl())).bind("FunctionCallee"),
    //                callExpr(hasDescendant(declRefExpr(to(functionDecl()))))
    //                    .bind("DeclRefExpr")));
    // Callback to match call-expresions in Function Body

    Stmt *curr_search_node = func->getBody();

    std::map<const VarDecl *, const CallExpr *> matched_init_contexts;

    // Save init context of argument
    std::map<std::string, FutagCallContext> call_contexts;

    // init_contexts;

    futag::FutagMatchInitCallExprCB target_func_call_callback{
        Mgr,                   // Analysis manager
        func,                  // Function
        matched_init_contexts, // result - matched call expressions
        analysis_jdb           // Analysis database
    };
    Finder.addMatcher(matched_binaryoperator, &target_func_call_callback);
    Finder.addMatcher(matched_vardecl, &target_func_call_callback);
    Finder.futagMatchAST(Mgr.getASTContext(), curr_search_node);
    llvm::outs() << "[Futag]: Analyzing function \"" << func->getNameAsString()
                 << "\"\n";
    if (matched_init_contexts.size()) {
        llvm::outs() << "[Futag]: Print contexts\n";
        // Build the CFG of current function
        CFG *cfg = Mgr.getCFG(func);
        if (!cfg) {
            llvm::outs() << "-- Empty CFG for function: "
                         << func->getNameAsString() << "\n";
            return;
        }

        std::string curr_func_hash = std::to_string(
            futag::utils::ODRHashCalculator::CalculateHash(func));

        GenCFGInfo(Mgr, cfg, func, consumer_report_path);

        FutagPath result_path;
        result_path.insert(result_path.end(), cfg->getEntry().getBlockID());
        FutagGraph fgraph;
        FindAllCFGPaths(cfg, cfg->getEntry(), fgraph, result_path,
                        all_cfg_paths);

        std::string paths_filename = consumer_report_path.c_str() +
                                     func->getNameAsString() + "-" +
                                     curr_func_hash + "-path.raw";

        std::fstream paths_report(paths_filename, std::ios::out);
        if (!paths_report.is_open()) {
            std::cerr << " -> Cannot write to the file: " + paths_filename +
                             "!\n";
            return;
        }

        for (auto path : all_cfg_paths) {
            for (auto i : path) {
                paths_report << i << " ";
            }
            paths_report << "\n";
        }
        paths_report.close();

        std::vector<std::string> result_context_files;

        for (const auto &[var, callexpr] : matched_init_contexts) {

            clang::LangOptions lo;
            std::string stmt_str;
            llvm::raw_string_ostream rso_stmt(stmt_str);
            callexpr->printPretty(rso_stmt, NULL,
                                  Mgr.getASTContext().getPrintingPolicy());
            // llvm::outs() << " -- variable: \"" << var->getNameAsString()
            //              << "\",";
            // llvm::outs() << " callexpr: \"" << stmt_str << "\"\n";

            //  Match the CFGStmtMap
            ParentMap parent_map = ParentMap(func->getBody());
            clang::CFGStmtMap *cfg_stmt_map;
            cfg_stmt_map = CFGStmtMap::Build(cfg, &parent_map);
            const CFGBlock *stmt_block = cfg_stmt_map->getBlock(callexpr);
            // llvm::outs() << " |-- CallExpr: " << stmt_str
            //              << "; of block: " << stmt_block->getBlockID() <<
            //              "\n";

            for (auto curr_analyzed_path : all_cfg_paths) {
                if (std::find(curr_analyzed_path.begin(),
                              curr_analyzed_path.end(),
                              stmt_block->getBlockID()) ==
                    curr_analyzed_path.end()) { // If the block of FIRST context
                                                // init not found -
                                                // break and continue new path
                    continue;
                }
                std::vector<FutagInitVarDeclCallExpr> init_calls;
                std::vector<FutagCallExprInfo> modifying_calls;

                FutagCallExprInfo init_call_expr = GetCallExprInfo(
                    callexpr, cfg_stmt_map, Mgr, analysis_jdb, init_calls);

                FutagInitVarDeclCallExpr curr_init{var->getNameAsString(),
                                                   init_call_expr};

                init_calls.insert(init_calls.begin(), curr_init);

                // Find all paths, which contains BlockID
                auto curr_analyzed_pos = std::find(curr_analyzed_path.begin(),
                                                   curr_analyzed_path.end(),
                                                   stmt_block->getBlockID());

                if (curr_analyzed_pos == curr_analyzed_path.end())
                    continue;

                FutagPath curr_context_path = {stmt_block->getBlockID()};
                // For each argument, if argument is VarRef -> search for
                // InitVarDeclCallExpr in current block and precedent blocks

                for (auto iter_arg : init_call_expr.args) {
                    // Search in each predecent block!!!!
                    if (iter_arg.init_type == futag::ArgVarRef) {
                        bool found_definition = false;
                        for (auto def : init_calls) {
                            if (def.var_name == iter_arg.value) {
                                found_definition = true;
                                break;
                            }
                        }
                        if (found_definition)
                            break;
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

                if (var->getType()->isPointerType()) {
                    SearchModifyingCallExprInBlock(
                        Mgr,
                        var->getNameAsString(), // current argument for search
                        curr_search_node,       // current node for search
                        cfg_stmt_map,           // for matching found callexpr
                        curr_context_path,      // for adding node to curr path
                        curr_analyzed_pos,      // for checking match
                        curr_analyzed_path,     // for checking match
                        init_calls,             //
                        modifying_calls,        //
                        analysis_jdb);
                }
                /*

            */
                llvm::outs() << "\nContext:\n";
                clang::LangOptions lo;
                std::string stmt_str;
                llvm::raw_string_ostream rso_stmt(stmt_str);

                std::vector<unsigned int>
                    found_blocks; // Saving all CFG Block of found call
                                  // expressions
                for (auto iter_call : init_calls) {
                    stmt_str = "";
                    iter_call.call_expr_info.call_expr->printPretty(
                        rso_stmt, NULL,
                        Mgr.getASTContext().getPrintingPolicy());
                    llvm::outs()
                        << "Init var: " << iter_call.var_name
                        << ", init call: " << stmt_str << ", blockID: "
                        << iter_call.call_expr_info.cfg_block_ID << "; \n";
                    // If cfg_block_ID is not in found_block -> add
                    if (std::find(found_blocks.begin(), found_blocks.end(),
                                  iter_call.call_expr_info.cfg_block_ID) ==
                        found_blocks.end()) {
                        found_blocks.insert(
                            found_blocks.end(),
                            iter_call.call_expr_info.cfg_block_ID);
                    }
                }
                for (auto iter_call : modifying_calls) {
                    stmt_str = "";
                    iter_call.call_expr->printPretty(
                        rso_stmt, NULL,
                        Mgr.getASTContext().getPrintingPolicy());
                    llvm::outs() << "`-->> modifying_calls: " << stmt_str
                                 << ", blockID: " << iter_call.cfg_block_ID
                                 << ", location: " << iter_call.location.file
                                 << ":" << iter_call.location.line << ":"
                                 << iter_call.location.col << ";\n";

                    // If cfg_block_ID is not in found_block -> add
                    if (std::find(found_blocks.begin(), found_blocks.end(),
                                  iter_call.cfg_block_ID) ==
                        found_blocks.end()) {
                        found_blocks.insert(found_blocks.end(),
                                            iter_call.cfg_block_ID);
                    }
                }

                std::map<unsigned int, unsigned int>
                    block_Idx; //<position, BlockID>
                // Search found blocks in current path, if not found -> quit!
                int *help_array = new int(found_blocks.size());
                unsigned int idx = 0;
                llvm::outs() << "Current analyzed path: ";
                for (auto item : curr_analyzed_path) {
                    llvm::outs() << item << " ";
                }
                llvm::outs() << "\n";
                for (int i = 0; i < found_blocks.size(); i++) {
                    auto pos =
                        std::find(curr_analyzed_path.begin(),
                                  curr_analyzed_path.end(), found_blocks[i]);
                    if (pos == curr_analyzed_path.end()) {

                        help_array[idx] = -1;
                    } else {
                        help_array[idx] = pos - curr_analyzed_path.begin();

                        block_Idx.insert(block_Idx.end(),
                                         {pos - curr_analyzed_path.begin(),
                                          found_blocks[i]});
                    }
                    idx++;
                }

                // llvm::outs() << ".... found_blocks: ";
                // for (auto item : found_blocks) {
                //     llvm::outs() << item << " ";
                // }
                // llvm::outs() << "\n";
                // llvm::outs() << ".... help_array: ";
                // for (int i = 0; i < found_blocks.size(); i++) {
                //     llvm::outs() << help_array[i] << " ";
                // }
                // llvm::outs() << "\n";
                std::vector<unsigned int> sorted_block_Idx;

                for (int i = 0; i < found_blocks.size(); i++) {
                    if (help_array[i] == -1)
                        continue;
                    for (int j = i + 1; j < found_blocks.size(); j++) {
                        if (help_array[j] == -1)
                            continue;
                        if (help_array[j] < help_array[i]) {
                            unsigned int tmp = help_array[j];
                            help_array[j] = help_array[i];
                            help_array[i] = tmp;
                        }
                    }
                }

                // llvm::outs() << ".... help_array after sorted: ";
                // for (int i = 0; i < found_blocks.size(); i++) {
                //     llvm::outs() << help_array[i] << " ";
                // }
                // llvm::outs() << "\n";
                // llvm::outs() << ".... sorted blocks: ";
                for (int i = 0; i < found_blocks.size(); i++) {
                    if (help_array[i] >= 0) {
                        sorted_block_Idx.insert(sorted_block_Idx.end(),
                                                block_Idx[help_array[i]]);
                        // llvm::outs() << block_Idx[help_array[i]] << " ";
                    }
                }
                // llvm::outs() << "\n";
                std::string tmp = "_";
                for (unsigned int sb : sorted_block_Idx) {
                    tmp += std::to_string(sb);
                }

                std::string output_context_filename =
                    func->getNameAsString() + "_" + var->getNameAsString() +
                    tmp;
                // llvm::outs()
                //     << "output_context_filename: " << output_context_filename
                //     << "\n";
                if (std::find(result_context_files.begin(),
                              result_context_files.end(),
                              output_context_filename) ==
                        result_context_files.end() &&
                    sorted_block_Idx.size()) {
                    // llvm::outs() << "=== Context found!!!!!";
                    result_context_files.insert(result_context_files.end(),
                                                output_context_filename);
                    utils::Random rand{};
                    // llvm::outs()<< "output file path: "<< consumer_report_path.c_str() + output_context_filename + ".json" << "\n";
                    std::fstream output_context_file(
                        consumer_report_path.c_str() + output_context_filename + ".json",
                        std::ios::out);
                    if (!output_context_file.is_open()) {
                        std::cerr << " -> Cannot write to the file: " +
                                         output_context_filename + "!\n";
                        return;
                    }
                    WriteContextToFile(output_context_file, init_calls,
                                       modifying_calls, sorted_block_Idx);
                    output_context_file.close();
                }
            }
        }
    }
    return;
}

void ento::registerFutagConsumerAnalyzer(CheckerManager &Mgr) {
    auto *Chk = Mgr.registerChecker<FutagConsumerAnalyzer>();
    std::string consumer_report_path =
        std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
            Mgr.getCurrentCheckerName(), "consumer_report_path"));

    if (!sys::fs::exists(consumer_report_path)) {
        sys::fs::create_directory(consumer_report_path);
    }
    Chk->db_filepath = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
        Mgr.getCurrentCheckerName(), "db_filepath"));

    if (!sys::fs::exists(Chk->db_filepath)) {
        llvm::errs() << "db file not found!";
        return;
    }
    std::ifstream ifs(Chk->db_filepath);
    Chk->analysis_jdb = json::parse(ifs);

    if (!sys::fs::exists(Chk->consumer_report_path)) {
        sys::fs::create_directory(Chk->consumer_report_path);
    }
    Chk->consumer_report_path = "";
    sys::path::append(Chk->consumer_report_path, consumer_report_path, "_");
}

bool ento::shouldRegisterFutagConsumerAnalyzer(const CheckerManager &mgr) {
    return true;
}