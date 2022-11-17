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
  bool mLogDebugMessages{false};

  mutable json mCallContextInfo{};
  mutable json mFunctionDeclInfo{};
  mutable json mTypesInfo{};
  mutable json mIncludesInfo{};

  // Opens json file specified in currentReportPath and writes new
  // data provided in "state" variable to the "functions" key of the
  // resulting json file.
  void WriteInfoToTheFile(const StringRef currentReportPath, json &state) const;

  // Collects basic information about currently processed function:
  //   - Hash of the function (calculated using getODRHash)
  //   - Function name
  //   - File name, where function is defined
  //   - Line number, where function is defined
  //   - Return value type
  //   - Parameter names/types
  void CollectBasicFunctionInfo(json &currJsonCtx, const FunctionDecl *func,
                                AnalysisManager &Mgr, int32_t currFuncBeginLoc,
                                const std::string &fileName,
                                const futag::FunctionType function_type,
                                const std::string &parentHash) const;

  // Collects "advanced", context-related function information.
  // This information consists from a lot of different things. For example:
  //   - File/Line, where the call is found
  void CollectAdvancedFunctionsInfo(json &callContextJson,
                                    const FunctionDecl *func,
                                    AnalysisManager &Mgr,
                                    const std::string &fileName) const;

  // Tries to identify how current function uses its arguments.
  // This method only performs elementary analysis, which consists
  // of AST traversal and extracting all default interesting (open, strcpy, ...)
  // functions. After that we check if parameter to the original function is
  // passed into one of the known functions and if so, we can determine the
  // parameter type
  void DetermineArgumentUsageAST(json &paramInfo, const FunctionDecl *func,
                                 AnalysisManager &Mgr,
                                 const clang::ParmVarDecl *param) const;

public:
  std::string reportDir = "";

  // Full path to the current context report file
  mutable SmallString<0> contextReportPath{};

  // Full path to the current function declaration report file
  mutable SmallString<0> funcDeclReportPath{};

  // Full path to report that has information about structs, typedefs and enums
  mutable SmallString<0> typesInfoReportPath{};

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

void FutagAnalyzer::WriteInfoToTheFile(const StringRef tCurrentReportPath,
                                       json &tState) const {

  if (mLogDebugMessages) {
    std::cerr << __func__ << " -> Report path: " << tCurrentReportPath.str()
              << "\n";
  }

  if (sys::fs::exists(tCurrentReportPath)) {
    std::cerr << std::string(__func__) + " -> Report file already exists: " +
                     tCurrentReportPath.str() + "!";
  }

  // Create top-level directories
  sys::fs::create_directories(sys::path::parent_path(tCurrentReportPath));

  // Create report file
  std::fstream currReportFile(tCurrentReportPath.str(),
                              std::ios::in | std::ios::out | std::ios::app);

  if (currReportFile.is_open()) {
    // Write updated json report to the file
    currReportFile << std::setw(4) << tState << std::endl;
  } else {
    // Just crash with report_fatal_error
    std::cerr << std::string(__func__) +
                     " -> Cannot write updated json to the file: " +
                     tCurrentReportPath.str() + "!";
  }
}

void FutagAnalyzer::CollectBasicFunctionInfo(
    json &currJsonCtx, const FunctionDecl *func, AnalysisManager &Mgr,
    int32_t currFuncBeginLoc, const std::string &fileName,
    const futag::FunctionType function_type,
    const std::string &parentHash) const {
  // Use ODRHash as a key for a json object. This is required later due to the
  // fact that we need to update state for already existing functions, thus we
  // somehow should be able to find these functions in the json file.
  std::string keyFuncHash =
      std::to_string(futag::utils::ODRHashCalculator::CalculateHash(func));

  // Write general info: function name, filename where the function is defined,
  // line on which function is defined, return type of the function and
  // if we should fuzz it or no
  std::string currFuncQName(func->getQualifiedNameAsString());
  std::string currFuncName(func->getDeclName().getAsString());

  json basicFunctionInfo = {
      {"name", currFuncName},
      {"qname", currFuncQName},
      {"is_simple", futag::isSimpleFunction(func)},
      {"func_type", function_type},
      {"access_type", func->getAccess()},
      {"storage_class", func->getStorageClass()},
      {"parent_hash", parentHash},
      {"location", fileName + ":" + std::to_string(currFuncBeginLoc)},
      {"return_type", func->getReturnType().getAsString()},
      {"return_type_pointer", func->getReturnType()->isPointerType()},
      // If current function doesn't have parameters, don't use it for fuzzing,
      // but still collect all relevant information
      {"fuzz_it", func->parameters().size() >= 1 && currFuncName != "main"},
      {"call_contexts", json::array()}};

  // If we already have call_contexts field, use data from it
  if (currJsonCtx.contains(keyFuncHash) &&
      currJsonCtx[keyFuncHash].contains("call_contexts"))
    basicFunctionInfo["call_contexts"] =
        currJsonCtx[keyFuncHash]["call_contexts"];

  // Write params info
  basicFunctionInfo["params"] = json::array();
  for (uint32_t paramIdx = 0; paramIdx < func->getNumParams(); ++paramIdx) {
    auto &currParam = func->parameters()[paramIdx];
    QualType paramQualType = currParam->getType();

    futag::DataTypeDetail datatypeDetail =
        futag::getDataTypeDetail(paramQualType);
    // Write parameter name, its type and if it is template parameter or not
    basicFunctionInfo["params"].push_back(
        {{"param_name", currParam->getQualifiedNameAsString()},
         {"param_type", paramQualType.getAsString()},
         {"generator_type", datatypeDetail.generator_type},
         {"array_size", datatypeDetail.array_size},
         {"parent_type", datatypeDetail.parent_type},
         {"parent_gen", datatypeDetail.parent_gen},
         {"canonical_type", paramQualType.getCanonicalType().getAsString()},
         {"param_usage", "UNKNOWN"}});

    // Try to determine argument usage
    DetermineArgumentUsageAST(basicFunctionInfo["params"].back(), func, Mgr,
                              currParam);
  }

  if (mLogDebugMessages) {
    std::cerr << "Current function name: " << currFuncName << "\n"
              << "Old function name: "
              << ((currJsonCtx[keyFuncHash].contains("name"))
                      ? currJsonCtx[keyFuncHash]["name"]
                      : "null")
              << "\n"
              << "Current function hash: " << keyFuncHash << "\n"
              << "Constructed json dump: " << basicFunctionInfo.dump(4) << "\n"
              << "Json dump from file: " << currJsonCtx[keyFuncHash].dump(4)
              << "\n";
  }
  // We may have already collected information about xrefs, but other fields
  // should not exist
  assert(!currJsonCtx[keyFuncHash].contains("fuzz_it"));

  // Write info about function
  currJsonCtx[keyFuncHash].update(basicFunctionInfo);
}

void FutagAnalyzer::CollectAdvancedFunctionsInfo(
    json &callContextJson, const FunctionDecl *func, AnalysisManager &Mgr,
    const std::string &fileName) const {
  MatchFinder Finder;

  auto MatchFuncCall =
      callExpr(callee(functionDecl(unless(isExpansionInSystemHeader()))))
          .bind("FutagCalledFunc");

  // Callback to Match function calls
  // Get Current Node for matching
  Stmt *CurrentNode = func->getBody();
  futag::FutagMatchCallExprCallBack functionCallCallBack{callContextJson, Mgr,
                                                         CurrentNode, func};
  Finder.addMatcher(MatchFuncCall, &functionCallCallBack);
  Finder.futagMatchAST(Mgr.getASTContext(), CurrentNode);
}

void FutagAnalyzer::DetermineArgumentUsageAST(
    json &paramInfo, const FunctionDecl *func, AnalysisManager &Mgr,
    const clang::ParmVarDecl *param) const {
  Stmt *funcBody = func->getBody();
  futag::FutagArgumentUsageDeterminer functionCallCallback{paramInfo, Mgr,
                                                           funcBody, func};

  // Match all callExprs, where one of the arguments have the same name
  auto MatchFuncCall =
      callExpr(hasAnyArgument(hasDescendant(
                   declRefExpr(to(varDecl(hasName(param->getName()))))
                       .bind("FutagCalledFuncArgument"))))
          .bind("FutagCalledFunc");

  MatchFinder Finder;
  Finder.addMatcher(MatchFuncCall, &functionCallCallback);
  Finder.futagMatchAST(Mgr.getASTContext(), funcBody);
}

FutagAnalyzer::FutagAnalyzer()
    : mLogDebugMessages{std::getenv("FUTAG_FUNCTION_ANALYZER_DEBUG_LOG") !=
                        nullptr},
      mCallContextInfo{}, mFunctionDeclInfo{}, mTypesInfo{}, reportDir{},
      contextReportPath{}, funcDeclReportPath{}, typesInfoReportPath{},
      includesInfoReportPath{}, rand{} {
  mTypesInfo = {{"enums", json::array()},
                {"typedefs", json::array()},
                {"records", json::array()}};

  mIncludesInfo =
      json{{"file", ""}, {"includes", json::array()}, {"compiler_opts", ""}};
}

FutagAnalyzer::~FutagAnalyzer() {
  // Write new data to the json state file
  if (!mCallContextInfo.empty()) {
    WriteInfoToTheFile(contextReportPath, mCallContextInfo);
  }
  WriteInfoToTheFile(funcDeclReportPath, mFunctionDeclInfo);
  WriteInfoToTheFile(typesInfoReportPath, mTypesInfo);
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

    SourceLocation includeLoc = sm.getIncludeLoc(sm.translateFile(it->first));
    string includePath = utils::PathProcessor::RemoveUnnecessaryPathComponents(
        it->first->getName().str());
    // includePath[0] != '/' - is probably an awfully bad check to avoid system
    // headers, but I couldn't find any way around
    if (includeLoc.isValid() && sm.isInMainFile(includeLoc)) {
      mIncludesInfo["includes"].push_back(includePath);
    }
  }
  std::string compilerOpts = Mgr.getAnalyzerOptions().FullCompilerInvocation;
  auto fe = sm.getFileEntryForID(sm.getMainFileID());
  if (fe->tryGetRealPathName().empty()) {
    if (fe->getName().empty()) {
      return;
    }
    mIncludesInfo["file"] = fe->getName();
  } else {
    mIncludesInfo["file"] = fe->tryGetRealPathName();
  }
  mIncludesInfo["compiler_opts"] = compilerOpts;

  struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const FutagAnalyzer *futagChecker;
    AnalysisManager &analysisMgr;

    explicit LocalVisitor(const FutagAnalyzer *Checker,
                          AnalysisManager &AnalysisMgr)
        : futagChecker(Checker), analysisMgr(AnalysisMgr) {}

    /* callback when a function declaration is encountered */
    bool VisitFunctionDecl(FunctionDecl *FD) {
      futagChecker->VisitFunction(FD, analysisMgr);
      return true;
    }

    /* callback when a struct declaration is encountered */
    bool VisitRecordDecl(RecordDecl *RD) {
      futagChecker->VisitRecord(RD, analysisMgr);
      return true;
    }

    /* callback when a typedef declaration is encountered */
    bool VisitTypedefDecl(TypedefDecl *TD) {
      futagChecker->VisitTypedef(TD, analysisMgr);
      return true;
    }

    /* callback when a enum declaration is encountered */
    bool VisitEnumDecl(EnumDecl *ED) {
      futagChecker->VisitEnum(ED, analysisMgr);
      return true;
    }
  };

  LocalVisitor visitor(this, Mgr);
  visitor.TraverseDecl(const_cast<TranslationUnitDecl *>(TUD));
}

// Called for every function declaration
void FutagAnalyzer::VisitFunction(const FunctionDecl *func,
                                  AnalysisManager &Mgr) const {

  // FunctionTemplateDecl
  if (Mgr.getSourceManager().isInSystemHeader(func->getBeginLoc())) {
    return;
  }

  // If the provided function doesn't have a body or the function
  // is a declaration (not a definition) -> skip this entry.
  if (!func->hasBody() || !func->isThisDeclarationADefinition()) {
    return;
  }

  FullSourceLoc fBeginLoc = Mgr.getASTContext().getFullLoc(func->getBeginLoc());
  FullSourceLoc fEndLoc = Mgr.getASTContext().getFullLoc(func->getEndLoc());
  if (!fBeginLoc.getFileEntry()) {
    return;
  }
  int32_t currFuncBeginLoc = fBeginLoc.getSpellingLineNumber();
  auto fe = fBeginLoc.getFileEntry();
  std::string fileName;
  std::string parentHash = "";

  if (fe->tryGetRealPathName().empty()) {
    if (fe->getName().empty()) {
      std::cerr << " -- Debug info: Cannot find filename and filepath!\n";
    } else {
      fileName = fe->getName().str();
    }
  } else {
    fileName = fe->tryGetRealPathName().str();
  }
  futag::FunctionType function_type = futag::_FUNC_UNKNOW_RECORD;
  if (isa<CXXMethodDecl>(func)) {
    auto methodDecl = dyn_cast<CXXMethodDecl>(func);
    function_type = futag::_FUNC_STATIC;
    ODRHash Hash;
    Hash.AddCXXRecordDecl(methodDecl->getParent());
    parentHash = std::to_string(Hash.CalculateHash());
    if (methodDecl->isStatic()) {
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
  }
  if (func->isGlobal()) {
    function_type = futag::_FUNC_GLOBAL;
  }

  // Collect basic information about current function
  CollectBasicFunctionInfo(mFunctionDeclInfo, func, Mgr, currFuncBeginLoc,
                           fileName, function_type, parentHash);

  // Collect advanced information about function calls inside current function
  CollectAdvancedFunctionsInfo(mCallContextInfo, func, Mgr, fileName);
  return;
}

void FutagAnalyzer::VisitRecord(const RecordDecl *RD,
                                AnalysisManager &Mgr) const {

  // RecordDecl->getDefinition() Returns the RecordDecl that actually defines
  // this struct/union/class. When determining whether or not a
  // struct/union/class is completely defined, one should use this method as
  // opposed to 'isCompleteDefinition'. 'isCompleteDefinition' indicates whether
  // or not a specific RecordDecl is a completed definition, not whether or not
  // the record type is defined. This method returns NULL if there is no
  // RecordDecl that defines the struct/union/tag.
  bool definedInSystemHeader =
      Mgr.getSourceManager().isInSystemHeader(RD->getLocation());

  if (mLogDebugMessages) {
    llvm::outs() << "Encountered RecordDecl (is_system:"
                 << definedInSystemHeader << "): " << RD->getNameAsString()
                 << "\n";
    for (auto it = RD->field_begin(); it != RD->field_end(); it++)
      llvm::outs() << "  " << it->getType().getAsString() << " ("
                   << it->getType().getCanonicalType().getAsString() << ") "
                   << it->getNameAsString() << "\n";
  }

  if (definedInSystemHeader)
    return;
  if (!RD->getDefinition())
    return;

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
  std::string hash = "";
  if (isa<CXXRecordDecl>(RD)) {
    auto cxxRecordDecl = dyn_cast_or_null<CXXRecordDecl>(RD);
    // llvm::outs() << "Record cast: " << cxxRecordDecl->getNameAsString() <<
    // "\n";
    if (cxxRecordDecl && cxxRecordDecl->hasDefinition()) {
      // llvm::outs() << "Record has definition: "
      //              << cxxRecordDecl->getNameAsString() << "\n";
      ODRHash Hash;
      Hash.AddCXXRecordDecl(cxxRecordDecl->getDefinition());
      hash = std::to_string(Hash.CalculateHash());
    }
    // } else {
    //   llvm::outs() << "Record uncast!!!!\n";
  }
  mTypesInfo["records"].push_back({{"name", RD->getNameAsString()},
                                   {"qname", RD->getQualifiedNameAsString()},
                                   {"access_type", RD->getAccess()},
                                   {"type", record_type},
                                   {"is_simple", futag::isSimpleRecord(RD)},
                                   {"hash", hash},
                                   {"fields", json::array()}});
  json &currentStruct = mTypesInfo["records"].back();
  for (auto it = RD->getDefinition()->field_begin();
       it != RD->getDefinition()->field_end(); it++) {
    json gen_list_json = json::array();
    if (futag::isSimpleType(it->getType())) {
      vector<futag::GenFieldInfo> gen_list_for_field =
          futag::getGenField(it->getType());

      for (auto g : gen_list_for_field) {
        gen_list_json.push_back({{"curr_type_name", g.curr_type_name},
                                 {"base_type_name", g.base_type_name},
                                 {"length", g.length},
                                 {"local_qualifier", g.local_qualifier},
                                 {"gen_type", g.gen_type}});
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
  std::string hash = "";
  bool definedInSystemHeader =
      Mgr.getSourceManager().isInSystemHeader(TD->getLocation());

  if (mLogDebugMessages) {
    llvm::outs() << "Encountered TypedefDecl (is_system:"
                 << definedInSystemHeader << "):\n";
    llvm::outs() << "  - typedef " << TD->getUnderlyingType().getAsString()
                 << " " << TD->getNameAsString() << "\n";
  }

  if (definedInSystemHeader)
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
    if (tag_decl->isClass() || tag_decl->isStruct() || tag_decl->isUnion()) {
      auto RD = type_source->getAsRecordDecl();
      if (RD) {
        if (isa<CXXRecordDecl>(RD)) {
          auto cxxRecordDecl = dyn_cast_or_null<CXXRecordDecl>(RD);
          if (cxxRecordDecl && cxxRecordDecl->hasDefinition()) {
            // llvm::outs() << "Record has definition: "
            //              << cxxRecordDecl->getNameAsString() << "\n";
            Hash.AddCXXRecordDecl(cxxRecordDecl->getDefinition());
            hash = std::to_string(Hash.CalculateHash());
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
      //   llvm::outs() << "-- field_value" << it->getInitVal().getExtValue()
      //                << "; field_name: " << it->getNameAsString() << "\n";
      // }
      Hash.AddEnumDecl(enum_type_decl);
      hash = std::to_string(Hash.CalculateHash());
    }
  }
  mTypesInfo["typedefs"].push_back(
      {{"name", TD->getNameAsString()},
       {"qname", TD->getQualifiedNameAsString()},
       {"access_type", TD->getAccess()},
       {"underlying_type", TD->getUnderlyingType().getAsString()},
       {"type_source", type_source.getAsString()},
       {"type_source_hash", hash},
       {"is_builtin",
        TD->getUnderlyingType().getCanonicalType()->isBuiltinType()},
       {"canonical_type",
        TD->getUnderlyingType().getCanonicalType().getAsString()}});

  return;
}

void FutagAnalyzer::VisitEnum(const EnumDecl *ED, AnalysisManager &Mgr) const {
  bool definedInSystemHeader =
      Mgr.getSourceManager().isInSystemHeader(ED->getLocation());

  if (mLogDebugMessages) {
    llvm::outs() << "Encountered EnumDecl (is_system:" << definedInSystemHeader
                 << "): " << ED->getNameAsString() << "\n";
    for (auto it = ED->enumerator_begin(); it != ED->enumerator_end(); it++) {
      llvm::outs() << "  - " << it->getNameAsString() << " = "
                   << it->getInitVal().getExtValue() << "\n";
    }
    llvm::outs() << "\n";
  }

  if (definedInSystemHeader)
    return;

  ODRHash Hash;
  Hash.AddEnumDecl(ED);

  mTypesInfo["enums"].push_back({{"name", ED->getNameAsString()},
                                 {"qname", ED->getQualifiedNameAsString()},
                                 {"access_type", ED->getAccess()},
                                 {"hash", std::to_string(Hash.CalculateHash())},
                                 {"enum_values", json::array()}});
  json &currentEnum = mTypesInfo["enums"].back();

  for (auto it = ED->enumerator_begin(); it != ED->enumerator_end(); it++) {
    currentEnum["enum_values"].push_back(
        {{"field_value", it->getInitVal().getExtValue()},
         {"field_name", it->getNameAsString()}});
  }

  return;
}

void ento::registerFutagAnalyzer(CheckerManager &Mgr) {
  auto *Chk = Mgr.registerChecker<FutagAnalyzer>();
  Chk->reportDir = std::string(Mgr.getAnalyzerOptions().getCheckerStringOption(
      Mgr.getCurrentCheckerName(), "report_dir"));

  if (!sys::fs::exists(Chk->reportDir)) {
    sys::fs::create_directory(Chk->reportDir);
  }

  Chk->contextReportPath = "";
  sys::path::append(Chk->contextReportPath, Chk->reportDir,
                    "context-" +
                        Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
                        ".futag-analyzer.json");

  Chk->funcDeclReportPath = "";
  sys::path::append(Chk->funcDeclReportPath, Chk->reportDir,
                    "declaration-" +
                        Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
                        ".futag-analyzer.json");

  Chk->typesInfoReportPath = "";
  sys::path::append(Chk->typesInfoReportPath, Chk->reportDir,
                    "types-info-" +
                        Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
                        ".futag-analyzer.json");

  Chk->includesInfoReportPath = "";
  sys::path::append(Chk->includesInfoReportPath, Chk->reportDir,
                    "file-info-" +
                        Chk->rand.GenerateRandomString(consts::cAlphabet, 16) +
                        ".futag-analyzer.json");
}

bool ento::shouldRegisterFutagAnalyzer(const CheckerManager &mgr) {
  return true;
}