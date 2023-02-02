//== FutagAnalyzer.cpp ----------------------------------- -*- C++ -*--=//
//
//===----------------------------------------------------------------------===//
//
// This module tries to collect some useful information to use with futag
// while generating libfuzzer targets.
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

#include "Futag/MatchFinder.h"
#include "nlohmann/json.hpp"
#include "clang/AST/Decl.h"
#include "clang/AST/ODRHash.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/CFG.h"
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

class FutagAnalyzer : public Checker<check::ASTDecl<TranslationUnitDecl>> {
  private:
    bool m_log_debug_message{false};

    mutable json m_call_context_info{};
    mutable json m_func_decl_info{};
    mutable json m_types_info{};
    mutable json mIncludesInfo{};

    // Opens json file specified in currentReportPath and writes new
    // data provided in "state" variable to the "functions" key of the
    // resulting json file.
    void WriteInfoToTheFile(const StringRef currentReportPath,
                            json &state) const;

    // Collects basic information about currently processed function:
    //   - Hash of the function (calculated using getODRHash)
    //   - Function name
    //   - File name, where function is defined
    //   - Line number, where function is defined
    //   - Return value type
    //   - Parameter names/types
    void CollectBasicFunctionInfo(json &curr_json_context,
                                  const FunctionDecl *func,
                                  AnalysisManager &Mgr,
                                  int32_t curr_func_begin_loc,
                                  const std::string &file_name,
                                  const futag::FunctionType function_type,
                                  const std::string &parent_hash) const;

    // Collects "advanced", context-related function information.
    // This information consists from a lot of different things. For example:
    //   - File/Line, where the call is found
    void CollectAdvancedFunctionInfo(json &call_context_json,
                                     const FunctionDecl *func,
                                     AnalysisManager &Mgr,
                                     const std::string &file_name) const;

    // Tries to identify how current function uses its arguments.
    // This method only performs elementary analysis, which consists
    // of AST traversal and extracting all default interesting (open, strcpy,
    // ...) functions. After that we check if parameter to the original function
    // is passed into one of the known functions and if so, we can determine the
    // parameter type
    void DetermineArgUsageInAST(json &param_info, const FunctionDecl *func,
                                AnalysisManager &Mgr,
                                const clang::ParmVarDecl *param) const;

  public:
    std::string report_dir = "";

    // Full path to the current context report file
    mutable SmallString<0> context_report_path{};

    // Full path to save the function declaration (in header files)
    mutable SmallString<0> func_decl_report_path{};

    // Full path to report that has information about structs, typedefs and
    // enums
    mutable SmallString<0> types_info_report_path{};

    // Full path to the report with includes info
    mutable SmallString<0> includesInfoReportPath{};

    // Used to generate random filename
    utils::Random rand{};

    FutagAnalyzer();
    ~FutagAnalyzer();

    // Entry point. Collects all needed information using recursive ast visitor
    void checkASTDecl(const TranslationUnitDecl *TUD, AnalysisManager &Mgr,
                      BugReporter &BR) const;

    /* Collects information about function */
    void VisitFunction(const FunctionDecl *func, AnalysisManager &Mgr) const;
    /* Collects information about struct declarations*/
    void VisitRecord(const RecordDecl *func, AnalysisManager &Mgr) const;
    /* Collects information about typedefs */
    void VisitTypedef(const TypedefDecl *func, AnalysisManager &Mgr) const;
    /* Collects information about enums */
    void VisitEnum(const EnumDecl *func, AnalysisManager &Mgr) const;
};

} // namespace

void FutagAnalyzer::WriteInfoToTheFile(const StringRef t_curr_report_path,
                                       json &tState) const {

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

void FutagAnalyzer::CollectBasicFunctionInfo(
    json &curr_json_context, const FunctionDecl *func, AnalysisManager &Mgr,
    int32_t curr_func_begin_loc, const std::string &file_name,
    const futag::FunctionType function_type,
    const std::string &parent_hash) const {
    // Use ODRHash as a key for a json object. This is required later due to the
    // fact that we need to update state for already existing functions, thus we
    // somehow should be able to find these functions in the json file.
    std::string curr_func_hash =
        std::to_string(futag::utils::ODRHashCalculator::CalculateHash(func));

    // Write general info: function qualified name, name, filename where the
    // function is defined, line on which function is defined, return type of
    // the function and if we should fuzz it or no
    std::string curr_func_qname(func->getQualifiedNameAsString());
    std::string curr_func_name(func->getDeclName().getAsString());

    vector<futag::GenTypeInfo> gen_list_for_return_type =
        futag::getGenType(func->getReturnType());
    json gen_list_return_type_json = json::array();
    for (auto &g : gen_list_for_return_type) {
        gen_list_return_type_json.push_back(
            {{"type_name", g.type_name},
             {"base_type_name", g.base_type_name},
             {"length", g.length},
             {"local_qualifier", g.local_qualifier},
             {"gen_type", g.gen_type},
             {"gen_type_name", GetFutagGenTypeFromIdx(g.gen_type)}});
    }

    json basic_function_info = {
        {"name", curr_func_name},
        {"qname", curr_func_qname},
        {"hash", curr_func_hash},
        {"is_simple", futag::isSimpleFunction(func)},
        {"func_type", function_type},
        {"access_type", func->getAccess()},
        {"storage_class", func->getStorageClass()},
        {"parent_hash", parent_hash},
        {"location", file_name + ":" + std::to_string(curr_func_begin_loc)},
        {"return_type", func->getReturnType().getAsString()},
        {"gen_return_type", gen_list_return_type_json},
        // {"return_type_pointer", func->getReturnType()->isPointerType()},
        // If current function doesn't have parameters, don't use it for
        // fuzzing, but still collect all relevant information
        {"fuzz_it", func->parameters().size() >= 1 && curr_func_name != "main"},
        {"call_contexts", json::array()}};

    // If we already have call_contexts field, use data from it
    if (curr_json_context.contains(curr_func_hash) &&
        curr_json_context[curr_func_hash].contains("call_contexts"))
        basic_function_info["call_contexts"] =
            curr_json_context[curr_func_hash]["call_contexts"];

    // Write params info
    basic_function_info["params"] = json::array();
    for (uint32_t param_idx = 0; param_idx < func->getNumParams();
         ++param_idx) {
        auto &curr_param = func->parameters()[param_idx];
        QualType param_qual_type = curr_param->getType();

        // futag::DataTypeDetail datatypeDetail =
        //     futag::getDataTypeDetail(param_qual_type);
        // Write parameter name, its type and if it is template parameter or not

        vector<futag::GenTypeInfo> gen_list_for_param =
            futag::getGenType(param_qual_type);
        json gen_list_json = json::array();
        for (auto &g : gen_list_for_param) {
            gen_list_json.push_back(
                {{"type_name", g.type_name},
                 {"base_type_name", g.base_type_name},
                 {"length", g.length},
                 {"local_qualifier", g.local_qualifier},
                 {"gen_type", g.gen_type},
                 {"gen_type_name", GetFutagGenTypeFromIdx(g.gen_type)}});
        }

        basic_function_info["params"].push_back(
            {{"param_name", curr_param->getQualifiedNameAsString()},
             {"param_type", param_qual_type.getAsString()},
             //  {"generator_type", datatypeDetail.generator_type},
             //  {"array_size", datatypeDetail.array_size},
             //  {"parent_type", datatypeDetail.parent_type},
             //  {"parent_gen", datatypeDetail.parent_gen},
             {"gen_list", gen_list_json},
             {"param_usage", "UNKNOWN"}});

        // Try to determine argument usage
        DetermineArgUsageInAST(basic_function_info["params"].back(), func, Mgr,
                               curr_param);
    }

    if (m_log_debug_message) {
        std::cerr << "Current function name: " << curr_func_name << "\n"
                  << "Old function name: "
                  << ((curr_json_context[curr_func_hash].contains("name"))
                          ? curr_json_context[curr_func_hash]["name"]
                          : "null")
                  << "\n"
                  << "Current function hash: " << curr_func_hash << "\n"
                  << "Constructed json dump: " << basic_function_info.dump(4)
                  << "\n"
                  << "Json dump from file: "
                  << curr_json_context[curr_func_hash].dump(4) << "\n";
    }
    // We may have already collected information about xrefs, but other fields
    // should not exist
    assert(!curr_json_context[curr_func_hash].contains("fuzz_it"));

    // Write info about function
    curr_json_context[curr_func_hash].update(basic_function_info);
}
/**
 * @brief This function search for all Call Expressions of target function in
 * AST.
 *
 * @param call_context_json
 * @param func
 * @param Mgr
 * @param file_name
 */
void FutagAnalyzer::CollectAdvancedFunctionInfo(
    json &call_context_json, const FunctionDecl *func, AnalysisManager &Mgr,
    const std::string &file_name) const {
    MatchFinder Finder;
    // Match all CallExpression of target function
    auto match_callexpr =
        callExpr(callee(functionDecl(unless(isExpansionInSystemHeader()))))
            .bind("FutagCalledFunc");

    // Callback to Match function calls
    // Get Current Node for matching
    Stmt *curr_node = func->getBody();
    futag::FutagMatchCallExprCallBack target_func_call_callback{
        call_context_json, Mgr, curr_node, func};
    Finder.addMatcher(match_callexpr, &target_func_call_callback);
    Finder.futagMatchAST(Mgr.getASTContext(), curr_node);
}

void FutagAnalyzer::DetermineArgUsageInAST(
    json &param_info, const FunctionDecl *func, AnalysisManager &Mgr,
    const clang::ParmVarDecl *param) const {
    Stmt *func_body = func->getBody();
    futag::FutagArgUsageDeterminer func_call_callback{param_info, Mgr,
                                                      func_body, func};

    // Match all callExprs, where one of the arguments have the same name
    auto MatchFuncCall =
        callExpr(hasAnyArgument(hasDescendant(
                     declRefExpr(to(varDecl(hasName(param->getName()))))
                         .bind("FutagCalledFuncArgument"))))
            .bind("FutagCalledFunc");

    MatchFinder Finder;
    Finder.addMatcher(MatchFuncCall, &func_call_callback);
    Finder.futagMatchAST(Mgr.getASTContext(), func_body);
}

FutagAnalyzer::FutagAnalyzer()
    : m_log_debug_message{std::getenv("FUTAG_FUNCTION_ANALYZER_DEBUG_LOG") !=
                          nullptr},
      m_call_context_info{}, m_func_decl_info{}, m_types_info{}, report_dir{},
      context_report_path{}, func_decl_report_path{}, types_info_report_path{},
      includesInfoReportPath{}, rand{} {
    m_types_info = {{"enums", json::array()},
                    {"typedefs", json::array()},
                    {"records", json::array()}};

    mIncludesInfo =
        json{{"file", ""}, {"includes", json::array()}, {"compiler_opts", ""}};
}

FutagAnalyzer::~FutagAnalyzer() {
    // Write new data to the json state file
    if (!m_call_context_info.empty()) {
        WriteInfoToTheFile(context_report_path, m_call_context_info);
    }
    WriteInfoToTheFile(func_decl_report_path, m_func_decl_info);
    WriteInfoToTheFile(types_info_report_path, m_types_info);
    WriteInfoToTheFile(includesInfoReportPath, mIncludesInfo);
}

void FutagAnalyzer::checkASTDecl(const TranslationUnitDecl *TUD,
                                 AnalysisManager &Mgr, BugReporter &BR) const {

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
        const FutagAnalyzer *futag_checker;
        AnalysisManager &analysisMgr;

        explicit LocalVisitor(const FutagAnalyzer *Checker,
                              AnalysisManager &AnalysisMgr)
            : futag_checker(Checker), analysisMgr(AnalysisMgr) {}

        /* callback when a function declaration is encountered */
        bool VisitFunctionDecl(FunctionDecl *FD) {
            futag_checker->VisitFunction(FD, analysisMgr);
            return true;
        }

        /* callback when a struct declaration is encountered */
        bool VisitRecordDecl(RecordDecl *RD) {
            futag_checker->VisitRecord(RD, analysisMgr);
            return true;
        }

        /* callback when a typedef declaration is encountered */
        bool VisitTypedefDecl(TypedefDecl *TD) {
            futag_checker->VisitTypedef(TD, analysisMgr);
            return true;
        }

        /* callback when a enum declaration is encountered */
        bool VisitEnumDecl(EnumDecl *ED) {
            futag_checker->VisitEnum(ED, analysisMgr);
            return true;
        }
    };

    LocalVisitor visitor(this, Mgr);
    visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TUD));
}

// Called for every function declaration
void FutagAnalyzer::VisitFunction(const FunctionDecl *func,
                                  AnalysisManager &Mgr) const {

    // If the available function is defined in system header file, then skip.
    if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc())) {
        return;
    }
    // If the provided function doesn't have a body or the function
    // is a declaration (not a definition) -> skip this entry.
    if (!func->hasBody() || !func->isThisDeclarationADefinition()) {
        return;
    }

    FullSourceLoc func_begin_loc =
        Mgr.getASTContext().getFullLoc(func->getBeginLoc());
    FullSourceLoc func_end_loc =
        Mgr.getASTContext().getFullLoc(func->getEndLoc());
    if (!func_begin_loc.getFileEntry()) {
        return;
    }
    int32_t curr_func_begin_loc = func_begin_loc.getSpellingLineNumber();
    auto fe = func_begin_loc.getFileEntry();
    std::string file_name;
    std::string parent_hash = "";

    if (fe->tryGetRealPathName().empty()) {
        if (fe->getName().empty()) {
            std::cerr << " -- Debug info: Cannot find filename and filepath!\n";
        } else {
            file_name = fe->getName().str();
        }
    } else {
        file_name = fe->tryGetRealPathName().str();
    }
    futag::FunctionType function_type = futag::_FUNC_UNKNOW_RECORD;
    if (isa<CXXMethodDecl>(func)) {
        auto method_decl = dyn_cast<CXXMethodDecl>(func);
        function_type = futag::_FUNC_CXXMETHOD;
        ODRHash Hash;
        Hash.AddCXXRecordDecl(method_decl->getParent());
        parent_hash = std::to_string(Hash.CalculateHash());
        if (method_decl->isStatic()) {
            function_type = futag::_FUNC_STATIC;
            // If isStatic () ---> ok, we'll call without initializing class
        }
        // How to get Parent class:
        //   const CXXRecordDecl *class_decl =
        //   dyn_cast<CXXMethodDecl>(func)->getParent();

        if (isa<CXXConstructorDecl>(func)) {
            auto constructor = dyn_cast<CXXConstructorDecl>(func);
            function_type = futag::_FUNC_CONSTRUCTOR;
            if (constructor->isDefaultConstructor()) {
                function_type = futag::_FUNC_DEFAULT_CONSTRUCTOR;
            }
        }
        if (isa<CXXDestructorDecl>(func)) {
            function_type = futag::_FUNC_DESTRUCTOR;
        }
    } else {
        if (func->isGlobal()) {
            function_type = futag::_FUNC_GLOBAL;
        }
    }
    // Collect basic information about current function
    CollectBasicFunctionInfo(m_func_decl_info, func, Mgr, curr_func_begin_loc,
                             file_name, function_type, parent_hash);
    CollectAdvancedFunctionInfo(m_call_context_info, func, Mgr, file_name);
    return;
}

void FutagAnalyzer::VisitRecord(const RecordDecl *RD,
                                AnalysisManager &Mgr) const {

    // RecordDecl->getDefinition() Returns the RecordDecl that actually defines
    // this struct/union/class. When determining whether or not a
    // struct/union/class is completely defined, one should use this method as
    // opposed to 'isCompleteDefinition'. 'isCompleteDefinition' indicates
    // whether or not a specific RecordDecl is a completed definition, not
    // whether or not the record type is defined. This method returns NULL if
    // there is no RecordDecl that defines the struct/union/tag.
    bool defined_in_sys_header =
        Mgr.getSourceManager().isInSystemHeader(RD->getLocation());

    if (m_log_debug_message) {
        llvm::outs() << "Encountered RecordDecl (is_system:"
                     << defined_in_sys_header << "): " << RD->getNameAsString()
                     << "\n";
        for (auto it = RD->field_begin(); it != RD->field_end(); it++)
            llvm::outs() << "  " << it->getType().getAsString() << " ("
                         << it->getType().getCanonicalType().getAsString()
                         << ") " << it->getNameAsString() << "\n";
    }

    if (defined_in_sys_header)
        return;
    if (!RD->getDefinition())
        return;
    ODRHash Hash;
    RD = RD->getDefinition();

    futag::FutagRecordType record_type = _UNKNOW_RECORD;
    if (RD->isClass()) {
        record_type = _CLASS_RECORD;
    }
    if (RD->isUnion()) {
        record_type = _UNION_RECORD;
    }
    if (RD->isStruct()) {
        record_type = _STRUCT_RECORD;
    }
    // llvm::outs() << "Record visit: " << RD->getNameAsString() << "\n";
    // Calculate hash of record for
    std::string hash_str = "";
    if (isa<CXXRecordDecl>(RD)) {
        auto cxx_record_decl = dyn_cast_or_null<CXXRecordDecl>(RD);
        // llvm::outs() << "Record cast: " << cxx_record_decl->getNameAsString()
        // <<
        // "\n";
        if (cxx_record_decl && cxx_record_decl->hasDefinition()) {
            // llvm::outs() << "Record has definition: "
            //              << cxx_record_decl->getNameAsString() << "\n";

            Hash.AddCXXRecordDecl(cxx_record_decl->getDefinition());
            hash_str = std::to_string(Hash.CalculateHash());
        }
        // } else {
        //   llvm::outs() << "Record uncast!!!!\n";
    } else {
        // TagDecl *tag_decl = type_source->getAsTagDecl();
        if (auto decl = dyn_cast_or_null<Decl>(RD)) {
            Hash.AddDecl(decl);
            hash_str = std::to_string(Hash.CalculateHash());
        }
    }
    m_types_info["records"].push_back(
        {{"name", RD->getNameAsString()},
         {"qname", RD->getQualifiedNameAsString()},
         {"access_type", RD->getAccess()},
         {"type", record_type},
         {"is_simple", futag::isSimpleRecord(RD)},
         {"hash", hash_str},
         {"fields", json::array()}});

    json &currentStruct = m_types_info["records"].back();
    for (auto it = RD->getDefinition()->field_begin();
         it != RD->getDefinition()->field_end(); it++) {
        json gen_list_json = json::array();
        if (futag::isSimpleType(it->getType())) {
            vector<futag::GenTypeInfo> gen_list_for_field =
                futag::getGenField(it->getType());

            for (auto &g : gen_list_for_field) {
                gen_list_json.push_back(
                    {{"type_name", g.type_name},
                     {"base_type_name", g.base_type_name},
                     {"length", g.length},
                     {"local_qualifier", g.local_qualifier},
                     {"gen_type", g.gen_type},
                     {"gen_type_name", GetFutagGenTypeFromIdx(g.gen_type)}});
            }
        }

        currentStruct["fields"].push_back({
            {"field_name", it->getNameAsString()},
            {"field_type", it->getType().getAsString()},
            {"gen_list", gen_list_json},
            {"is_simple", futag::isSimpleType(it->getType())},
        });
    }
    return;
}
void FutagAnalyzer::VisitTypedef(const TypedefDecl *TD,
                                 AnalysisManager &Mgr) const {
    ODRHash Hash;
    std::string hash_str = "";
    bool defined_in_sys_header =
        Mgr.getSourceManager().isInSystemHeader(TD->getLocation());

    if (m_log_debug_message) {
        llvm::outs() << "Encountered TypedefDecl (is_system:"
                     << defined_in_sys_header << "):\n";
        llvm::outs() << "  - typedef " << TD->getUnderlyingType().getAsString()
                     << " " << TD->getNameAsString() << "\n";
    }

    if (defined_in_sys_header)
        return;
    QualType type_source = TD->getTypeSourceInfo()->getType();

    while (const ElaboratedType *elabTy =
               dyn_cast<ElaboratedType>(type_source.getTypePtr())) {
        type_source = elabTy->desugar();
    }

    TagDecl *tag_decl = type_source->getAsTagDecl();
    if (tag_decl) {
        // llvm::outs() << TD->getNameAsString()
        //              << " - getKindName: " << tag_decl->getKindName();
        if (tag_decl->isClass() || tag_decl->isStruct() ||
            tag_decl->isUnion()) {
            auto RD = type_source->getAsRecordDecl();
            if (RD) {
                if (isa<CXXRecordDecl>(RD)) {
                    auto cxx_record_decl = dyn_cast_or_null<CXXRecordDecl>(RD);
                    if (cxx_record_decl && cxx_record_decl->hasDefinition()) {
                        // llvm::outs() << "Record has definition: "
                        //              << cxx_record_decl->getNameAsString() <<
                        //              "\n";
                        Hash.AddCXXRecordDecl(cxx_record_decl->getDefinition());
                        hash_str = std::to_string(Hash.CalculateHash());
                    }
                }
            }
        }
        if (tag_decl->isEnum()) {
            // llvm::outs() << " - isEnum tag ";
            const EnumType *enum_type = dyn_cast<EnumType>(type_source);
            auto enum_type_decl = enum_type->getDecl();
            // for (auto it = enum_type_decl->enumerator_begin();
            //      it != enum_type_decl->enumerator_end(); it++) {
            //   llvm::outs() << "-- field_value" <<
            //   it->getInitVal().getExtValue()
            //                << "; field_name: " << it->getNameAsString() <<
            //                "\n";
            // }
            Hash.AddEnumDecl(enum_type_decl);
            hash_str = std::to_string(Hash.CalculateHash());
        }
        if (hash_str == "") {
            if (auto decl = dyn_cast_or_null<Decl>(tag_decl)) {
                Hash.AddDecl(decl);
                hash_str = std::to_string(Hash.CalculateHash());
            }
        }
    }
    m_types_info["typedefs"].push_back(
        {{"name", TD->getNameAsString()},
         {"qname", TD->getQualifiedNameAsString()},
         {"access_type", TD->getAccess()},
         {"underlying_type", TD->getUnderlyingType().getAsString()},
         {"type_source", type_source.getAsString()},
         {"type_source_hash", hash_str},
         {"is_builtin",
          TD->getUnderlyingType().getCanonicalType()->isBuiltinType()},
         {"canonical_type",
          TD->getUnderlyingType().getCanonicalType().getAsString()}});

    return;
}

void FutagAnalyzer::VisitEnum(const EnumDecl *ED, AnalysisManager &Mgr) const {
    bool defined_in_sys_header =
        Mgr.getSourceManager().isInSystemHeader(ED->getLocation());

    if (m_log_debug_message) {
        llvm::outs() << "Encountered EnumDecl (is_system:"
                     << defined_in_sys_header << "): " << ED->getNameAsString()
                     << "\n";
        for (auto it = ED->enumerator_begin(); it != ED->enumerator_end();
             it++) {
            llvm::outs() << "  - " << it->getNameAsString() << " = "
                         << it->getInitVal().getExtValue() << "\n";
        }
        llvm::outs() << "\n";
    }

    if (defined_in_sys_header)
        return;

    ODRHash Hash;
    Hash.AddEnumDecl(ED);

    m_types_info["enums"].push_back(
        {{"name", ED->getNameAsString()},
         {"qname", ED->getQualifiedNameAsString()},
         {"access_type", ED->getAccess()},
         {"hash", std::to_string(Hash.CalculateHash())},
         {"enum_values", json::array()}});
    json &currentEnum = m_types_info["enums"].back();

    for (auto it = ED->enumerator_begin(); it != ED->enumerator_end(); it++) {
        currentEnum["enum_values"].push_back(
            {{"field_value", it->getInitVal().getExtValue()},
             {"field_name", it->getNameAsString()}});
    }

    return;
}

void ento::registerFutagAnalyzer(CheckerManager &Mgr) {
    auto *Chk = Mgr.registerChecker<FutagAnalyzer>();
    Chk->report_dir =
        std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
            Mgr.getCurrentCheckerName(), "report_dir"));

    if (!sys::fs::exists(Chk->report_dir)) {
        sys::fs::create_directory(Chk->report_dir);
    }

    Chk->context_report_path = "";
    sys::path::append(
        Chk->context_report_path, Chk->report_dir,
        "context-" + Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
            ".futag-analyzer.json");

    Chk->func_decl_report_path = "";
    sys::path::append(
        Chk->func_decl_report_path, Chk->report_dir,
        "declaration-" + Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
            ".futag-analyzer.json");

    Chk->types_info_report_path = "";
    sys::path::append(
        Chk->types_info_report_path, Chk->report_dir,
        "types-info-" + Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
            ".futag-analyzer.json");

    Chk->includesInfoReportPath = "";
    sys::path::append(
        Chk->includesInfoReportPath, Chk->report_dir,
        "file-info-" + Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
            ".futag-analyzer.json");
}

bool ento::shouldRegisterFutagAnalyzer(const CheckerManager &mgr) {
    return true;
}