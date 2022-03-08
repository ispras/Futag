//===-- GenTargets.cpp -------*- C++ -*-===//
//
// This file is distributed under the GPL v3 license (https://www.gnu.org/licenses/gpl-3.0.en.html).
//

/***********************************************/
/*      ______  __  __  ______  ___     ______ */
/*     / ____/ / / / / /_  __/ /   |   / ____/ */
/*    / /_    / / / /   / /   / /| |  / / __   */
/*   / __/   / /_/ /   / /   / ___ | / /_/ /   */
/*  /_/      \____/   /_/   /_/  |_| \____/    */
/*                                             */
/*     Fuzzing target Automated Generator      */
/*             a tool of ISP RAS               */
/*                                             */
/***********************************************/

#include <sys/stat.h>

#include <algorithm>
#include <string>

#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "futag/4libFuzzer.h"
#include "futag/Basic.h"

using namespace std;
using namespace llvm;
using namespace clang;
using namespace tooling;
using namespace clang::driver;
using namespace clang::tooling;
// using namespace clang::ast_matchers;

Rewriter rewriter;
string output_folder;
string compiled_filename;
vector<string> include_headers;

void gen_builtin_type(string, int, vector<string> *, string *, string *);

void gen_qualified_type(QualType *, vector<string> *, string *, string *);

void gen_4type(QualType *, vector<string> *, vector<string> *, string *,
               string *, ASTContext *);
void gen_4funcdecl(const FunctionDecl *, vector<string> *, vector<string> *,
                   string *, string *, ASTContext *);

vector<futag::FunctionDetail> funcdecl_list;
vector<futag::EnumDetail> enumdecl_list;
vector<futag::TypedefDetail> typedefdecl_list;
vector<futag::StructDetail> struct_decl_list;

vector<RecordDecl *> classdecl_list;
vector<RecordDecl *> structdecl_list;
vector<RecordDecl *> uniondecl_list;
vector<QualType> qualtype_list;

class Futag4libFuzzerVisitor
    : public RecursiveASTVisitor<Futag4libFuzzerVisitor> {
 private:
  ASTContext *astContext;  // used for getting additional AST info

 public:
  // ostream create_fuzz_target(string file_path);
  explicit Futag4libFuzzerVisitor(CompilerInstance *CI)
      : astContext(&(CI->getASTContext()))  // initialize private members
  {
    rewriter.setSourceMgr(astContext->getSourceManager(),
                          astContext->getLangOpts());
  }

  virtual bool VisitFunctionDecl(FunctionDecl *func) {
    const SourceManager &sm = astContext->getSourceManager();
    if (sm.isInSystemHeader(func->getBeginLoc())) {
      return true;
    }
    if (func->parameters().size() < 1) {
      return true;
    }
    // llvm::outs() << "Visit function declaration " << func->getNameAsString()
    // << "\n"; Return if function is a method of class
    if (isa<CXXMethodDecl>(func)) {
      return true;
    }
    futag::FunctionDetail func_detail;
    func_detail.genok = false;
    func_detail.name = func->getNameAsString();
    QualType return_qual_type = func->getReturnType();
    func_detail.return_qualtype = return_qual_type;
    func_detail.return_type =
        futag::getTypeSequenceFromQualType(return_qual_type);
    ;

    futag::getTypeSequenceFromQualType(return_qual_type);
    ;
    vector<futag::TypeSequence> params_type_sequence;
    vector<futag::FuncParam> param_list;
    for (ParmVarDecl *x : func->parameters()) {
      QualType qual_type = x->getType();
      futag::TypeSequence type_sequence =
          futag::getTypeSequenceFromQualType(qual_type);
      params_type_sequence.insert(params_type_sequence.end(), type_sequence);

      futag::FuncParam param;
      param.name = x->getNameAsString();
      param.type = futag::getTypeSequenceFromQualType(qual_type);
      param_list.insert(param_list.end(), param);
    }
    func_detail.params = params_type_sequence;
    funcdecl_list.insert(funcdecl_list.end(), func_detail);

    Stmt *func_call_body = func->getBody();

    if (func_call_body) {
      for (Stmt::child_iterator i = func_call_body->child_begin(),
                                e = func_call_body->child_end();
           i != e; ++i) {
        if (CallExpr *sub_call_expr = dyn_cast<CallExpr>(*i)) {
          if (sub_call_expr->getDirectCallee()) {
            llvm::outs() << "function call inside function body: "
                         << sub_call_expr->getDirectCallee()
                                ->getNameInfo()
                                .getName()
                                .getAsString()
                         << "\n";
          }
        }
      }
    }
    return true;
  }

  // Meet the struct, union or class declaration
  virtual bool VisitRecordDecl(RecordDecl *record) {
    if (record->isClass()) {
      classdecl_list.insert(classdecl_list.end(), record);
    }
    if (record->isUnion()) {
      uniondecl_list.insert(uniondecl_list.end(), record);
    }

    if (record->isStruct()) {
      bool found = false;
      for (auto _struct : struct_decl_list) {
        if (_struct.name == record->getNameAsString()) {
          found = true;
          break;
        }
      }
      if (!found) {
        futag::StructDetail struct_detail;
        if (record->getNameAsString() == "") {
          return true;
        }
        struct_detail.name = record->getNameAsString();
        struct_detail.incomplete = false;
        vector<futag::StructFieldDetail> fields;
        for (auto *field : record->fields()) {
          futag::StructFieldDetail field_detail;
          field_detail.name = field->getNameAsString();
          futag::TypeSequence field_detail_sequence =
              futag::getTypeSequenceFromQualType(field->getType());
          if (field_detail_sequence
                      .sequence[field_detail_sequence.sequence.size() - 1]
                      .generator_type == futag::GEN_INCOMPLETE ||
              field_detail_sequence
                      .sequence[field_detail_sequence.sequence.size() - 1]
                      .generator_type == futag::GEN_UNKNOWN ||
              field_detail_sequence
                      .sequence[field_detail_sequence.sequence.size() - 1]
                      .generator_type == futag::GEN_VOID) {
            struct_detail.incomplete = true;
            break;
          }
          if (field_detail_sequence
                  .sequence[field_detail_sequence.sequence.size() - 1]
                  .generator_type == futag::GEN_STRUCT) {
            vector<string> type_split = futag::explode(
                field_detail_sequence
                    .sequence[field_detail_sequence.sequence.size() - 1]
                    .type_name,
                ' ');
            bool found_struct_decl = false;
            for (vector<futag::StructDetail>::iterator s_iter =
                     struct_decl_list.begin();
                 s_iter != struct_decl_list.end(); ++s_iter) {
              if (type_split[1] != s_iter->name) continue;
              found_struct_decl = true;
              if (s_iter->incomplete) {
                struct_detail.incomplete = true;
                break;
              }
            }
            if (!found_struct_decl) {
              struct_detail.incomplete = true;
              break;
            }
          }
          field_detail.type_sequence = field_detail_sequence;
          fields.insert(fields.end(), field_detail);
        }
        if (fields.size() == 0) {
          struct_detail.incomplete = true;
        } else {
          struct_detail.fields = fields;
        }

        struct_decl_list.insert(struct_decl_list.end(), struct_detail);
      }
    }

    return true;
  }
  // Meet the typedef declaration
  virtual bool VisitTypedefDecl(TypedefDecl *typedecl) {
    const SourceManager &sm = astContext->getSourceManager();

    if (sm.isInSystemHeader(typedecl->getLocation())) {
      return true;
    }
    futag::TypedefDetail td;
    td.name = typedecl->getNameAsString();
    td.decl_name = typedecl->getTypeSourceInfo()->getType().getAsString();
    typedefdecl_list.insert(typedefdecl_list.end(), td);

    /* check if declaration is a "typedef struct" */
    QualType qualTy = typedecl->getTypeSourceInfo()->getType();
    /* "dig" into elaborated types (can be >1) in AST until reach a terminal*/
    while (const ElaboratedType *elabTy =
               dyn_cast<ElaboratedType>(qualTy.getTypePtr())) {
      qualTy = elabTy->desugar();
    }
    /* terminal reached. Check if it's a struct declaration */
    if (strcmp(qualTy->getTypeClassName(), "Record") == 0) {
      const RecordType *recTy = dyn_cast<RecordType>(qualTy);
      RecordDecl *recDecl = recTy->getDecl();
      bool found = false;
      for (auto _struct : struct_decl_list) {
        if (_struct.name == td.name) {
          found = true;
          break;
        }
      }
      if (!found) {
        futag::StructDetail struct_detail;
        struct_detail.name = td.name;
        struct_detail.incomplete = false;
        vector<futag::StructFieldDetail> fields;
        for (auto *field : recDecl->fields()) {
          futag::StructFieldDetail field_detail;
          field_detail.name = field->getNameAsString();
          futag::TypeSequence field_detail_sequence =
              futag::getTypeSequenceFromQualType(field->getType());
          if (field_detail_sequence
                      .sequence[field_detail_sequence.sequence.size() - 1]
                      .generator_type == futag::GEN_INCOMPLETE ||
              field_detail_sequence
                      .sequence[field_detail_sequence.sequence.size() - 1]
                      .generator_type == futag::GEN_UNKNOWN) {
            struct_detail.incomplete = true;
          }
          if (!struct_detail.incomplete &&
              field_detail_sequence
                      .sequence[field_detail_sequence.sequence.size() - 1]
                      .generator_type == futag::GEN_STRUCT) {
            vector<string> type_split = futag::explode(
                field_detail_sequence
                    .sequence[field_detail_sequence.sequence.size() - 1]
                    .type_name,
                ' ');
            bool found_struct_decl = false;
            for (vector<futag::StructDetail>::iterator s_iter =
                     struct_decl_list.begin();
                 s_iter != struct_decl_list.end(); ++s_iter) {
              if (type_split[1] != s_iter->name) continue;
              found_struct_decl = true;
              if (s_iter->incomplete) {
                struct_detail.incomplete = true;
                break;
              }
            }
            if (!found_struct_decl) {
              struct_detail.incomplete = true;
              break;
            }
          }
          field_detail.type_sequence = field_detail_sequence;
          fields.insert(fields.end(), field_detail);
        }
        if (fields.size() == 0) {
          struct_detail.incomplete = true;
        } else {
          struct_detail.fields = fields;
        }
        struct_decl_list.insert(struct_decl_list.end(), struct_detail);
      }
    }
    return true;
  }

  virtual bool VisitEnumDecl(EnumDecl *enumdec) {
    const SourceManager &sm = astContext->getSourceManager();

    if (sm.isInSystemHeader(enumdec->getLocation())) {
      return true;
    }
    futag::EnumDetail enum_detail;

    enum_detail.name = enumdec->getNameAsString();
    vector<string> items;
    unsigned char size = 0;
    for (auto *field : enumdec->enumerators()) {
      size++;
      items.insert(items.end(), field->getNameAsString());
    }
    enum_detail.size = size;
    enumdecl_list.insert(enumdecl_list.end(), enum_detail);
    return true;
  }
};

class Futag4libFuzzerASTConsumer : public ASTConsumer {
 private:
  Futag4libFuzzerVisitor *visitor;  // doesn't have to be private

 public:
  explicit Futag4libFuzzerASTConsumer(CompilerInstance *CI)
      : visitor(new Futag4libFuzzerVisitor(CI)) {}
  virtual void HandleTranslationUnit(ASTContext &Context) {
    visitor->TraverseDecl(Context.getTranslationUnitDecl());
  }
};

class Futag4libFuzzerFrontendAction : public ASTFrontendAction {
 public:
  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
      clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
    return std::unique_ptr<clang::ASTConsumer>(
        new Futag4libFuzzerASTConsumer(&Compiler));
  }
};

static cl::OptionCategory FutagCategory("futag-gen4libfuzzer options");

static cl::opt<string> OutFolder(
    "folder",
    cl::desc(
        R"(Option for specifying folder for generated targets, default value is '.futag-targets'.)"),
    cl::init(".futag-targets"), cl::cat(FutagCategory));

static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(
    "\n Futag-gen4libfuzzer is used to generate libFuzzer targets for all APIs "
    "functions of library.\n");

int main(int argc, const char **argv) {
  CommonOptionsParser op(argc, argv, FutagCategory);
  const auto File = op.getSourcePathList();

  ClangTool Tool(op.getCompilations(), op.getSourcePathList());

  output_folder = OutFolder.getValue();

  compiled_filename = op.getSourcePathList()[0];
  ifstream compiled_file(compiled_filename);
  string tmp_line;
  if (compiled_file.is_open()) {
    while (getline(compiled_file, tmp_line)) {
      include_headers.insert(include_headers.end(), tmp_line);
    }
  }
  llvm::outs() << "Collecting information about your source code...\n";
  Tool.run(newFrontendActionFactory<Futag4libFuzzerFrontendAction>().get());

  llvm::outs() << "Found " << typedefdecl_list.size()
               << " typedef declaration(s) \n";
  llvm::outs() << "Found " << struct_decl_list.size()
               << " struct declaration(s) \n";
  llvm::outs() << "Found " << enumdecl_list.size() << " enum declaration(s) \n";
  llvm::outs() << "Found " << classdecl_list.size()
               << " class declaration(s) \n";
  llvm::outs() << "Found " << funcdecl_list.size()
               << " function declaration(s)\n";
  llvm::outs() << "========================\n";
  llvm::outs() << "Generating targets:\n";

  int count_targets = 0;
  for (vector<futag::FunctionDetail>::iterator f_iter = funcdecl_list.begin();
       f_iter != funcdecl_list.end(); ++f_iter) {
    bool gen_this_function = true;

    for (vector<futag::TypeSequence>::iterator p_iter = f_iter->params.begin();
         p_iter != f_iter->params.end(); ++p_iter) {
      bool gen_this_param = false;

      for (vector<futag::QualTypeDetail>::iterator qt_iter =
               p_iter->sequence.begin();
           qt_iter != p_iter->sequence.end(); ++qt_iter) {
        gen_this_param = false;
        if (qt_iter->generator_type == futag::GEN_STRING ||
            qt_iter->generator_type == futag::GEN_ENUM ||
            qt_iter->generator_type == futag::GEN_BUILTIN ||
            qt_iter->generator_type == futag::GEN_ARRAY ||
            qt_iter->generator_type == futag::GEN_VOID) {
          gen_this_param = true;
          continue;
        }

        if (qt_iter->generator_type == futag::GEN_UNKNOWN &&
            qt_iter->partition == futag::OBJECT_TYPE) {
          for (auto td : typedefdecl_list) {
            if (td.name == qt_iter->type_name && !gen_this_param) {
              vector<string> type_split = futag::explode(td.decl_name, ' ');
              if (std::find(type_split.begin(), type_split.end(), "struct") !=
                  type_split.end()) {
                string struct_name = type_split[1];
                for (vector<futag::StructDetail>::iterator s_iter =
                         struct_decl_list.begin();
                     s_iter != struct_decl_list.end(); ++s_iter) {
                  if (struct_name != s_iter->name) continue;
                  if (!s_iter->incomplete) {
                    gen_this_param = true;
                    qt_iter->generator_type = futag::GEN_STRUCT;
                    qt_iter->gen_var_struct = struct_name;
                    while (qt_iter + 1 != p_iter->sequence.end()) {
                      p_iter->sequence.erase(p_iter->sequence.end() - 1);
                    }
                    break;
                  }
                }
              }
            }
          }
        }

        if (qt_iter->generator_type == futag::GEN_STRUCT && !gen_this_param) {
          // 1. find in struct declaration if defined
          vector<string> type_split = futag::explode(qt_iter->type_name, ' ');
          if (std::find(type_split.begin(), type_split.end(), "struct") !=
              type_split.end()) {
            string struct_name = type_split[1];
            for (vector<futag::StructDetail>::iterator s_iter =
                     struct_decl_list.begin();
                 s_iter != struct_decl_list.end(); ++s_iter) {
              if (struct_name != s_iter->name) continue;
              if (!s_iter->incomplete) {
                gen_this_param = true;
                qt_iter->gen_var_struct = struct_name;
                while (qt_iter + 1 != p_iter->sequence.end()) {
                  p_iter->sequence.erase(p_iter->sequence.end() - 1);
                }
                continue;
              }
            }
          }
        }
        // 2. find in function return type
        if ((qt_iter->generator_type == futag::GEN_STRUCT ||
             qt_iter->generator_type == futag::GEN_INCOMPLETE ||
             qt_iter->generator_type == futag::GEN_FUNCTION) &&
            !gen_this_param) {
          futag::FunctionDetail *found_function =
              futag::searchParamTypeInReturnType(&*qt_iter, &funcdecl_list,
                                                 &struct_decl_list);

          if (found_function) {
            gen_this_param = true;
            qt_iter->generator_type = futag::GEN_FUNCTION;
            qt_iter->gen_var_function = found_function->name;
            while (qt_iter + 1 != p_iter->sequence.end()) {
              p_iter->sequence.erase(p_iter->sequence.end() - 1);
            }
            continue;
          }
        }

        if ((qt_iter->generator_type == futag::GEN_POINTER ||
             qt_iter->generator_type == futag::GEN_QUALIFIER) &&
            !gen_this_param) {
          futag::FunctionDetail *found_function =
              futag::searchParamTypeInReturnType(&*qt_iter, &funcdecl_list,
                                                 &struct_decl_list);

          if (found_function) {
            qt_iter->generator_type = futag::GEN_FUNCTION;
            qt_iter->gen_var_function = found_function->name;
            while (qt_iter + 1 != p_iter->sequence.end()) {
              p_iter->sequence.erase(p_iter->sequence.end() - 1);
            }
            continue;
          }
          gen_this_param = true;
        }

        if (!gen_this_param) {
          gen_this_function = false;
          break;
        }
      }
      if (!gen_this_function) {
        break;
      }
    }  // end params list
    if (gen_this_function) {
      count_targets++;
      f_iter->genok = true;
    }
  }  // End function_decl_list
  llvm::outs() << "Total generated function: " << count_targets << "\n";

  // Begin generating for function
  for (vector<futag::FunctionDetail>::reverse_iterator f_iter =
           funcdecl_list.rbegin();
       f_iter != funcdecl_list.rend(); ++f_iter) {
    int index = 0;
    if (!f_iter->genok) {
      continue;
    }
    futag::genstruct *generator = new futag::genstruct;
    generator->cstring_count = 0;
    generator->function_name = f_iter->name;
    generator->return_qualtype = f_iter->return_qualtype;
    string var_name = "var";
    string last_var_name = "";
    for (vector<futag::TypeSequence>::iterator p_iter = f_iter->params.begin();
         p_iter != f_iter->params.end(); ++p_iter) {
      string cur_var_name = var_name + "_" + to_string(index);
      last_var_name = cur_var_name;
      // futag::printQualTypeSequence(*p_iter);
      for (vector<futag::QualTypeDetail>::reverse_iterator qt_iter =
               p_iter->sequence.rbegin();
           qt_iter != p_iter->sequence.rend(); ++qt_iter) {
        if (qt_iter->generator_type == futag::GEN_BUILTIN) {
          gen_builtin(cur_var_name, *qt_iter, generator);
          last_var_name = cur_var_name;
        }

        if (qt_iter->generator_type == futag::GEN_VOID) {
          last_var_name = "NULL";
        }

        if (qt_iter->generator_type == futag::GEN_STRING) {
          gen_string(cur_var_name, *qt_iter, generator);
          last_var_name = cur_var_name;
        }

        if (qt_iter->generator_type == futag::GEN_ENUM) {
          gen_enum(cur_var_name, *qt_iter, &enumdecl_list, generator);
          last_var_name = cur_var_name;
        }

        if (qt_iter->generator_type == futag::GEN_QUALIFIER) {
          gen_qualifier("q_" + last_var_name, last_var_name, *qt_iter,
                        generator);
          last_var_name = "q_" + last_var_name;
        }

        if (qt_iter->generator_type == futag::GEN_POINTER) {
          gen_pointer("p_" + last_var_name, last_var_name, *qt_iter, generator);
          last_var_name = "p_" + last_var_name;
        }

        if (qt_iter->generator_type == futag::GEN_ARRAY) {
          gen_array(cur_var_name, *qt_iter, generator);
          last_var_name = cur_var_name;
        }

        if (qt_iter->generator_type == futag::GEN_STRUCT) {
          if (qt_iter->gen_var_struct != "") {
            futag::gen_struct_by_name(
                "s" + cur_var_name, qt_iter->gen_var_struct, &struct_decl_list,
                &enumdecl_list, generator);
            last_var_name = "s" + cur_var_name;
          }
        }
        if (qt_iter->generator_type == futag::GEN_FUNCTION) {
          if (qt_iter->gen_var_function != "") {
            futag::gen_var_function_by_name(
                "f" + cur_var_name, qt_iter->gen_var_function, &funcdecl_list,
                &enumdecl_list, generator);
            last_var_name = "f" + cur_var_name;
          }
        }
      }
      generator->args_list.insert(generator->args_list.end(), last_var_name);
      index++;
    }

    // Create directory for fuzz targets
    futag::create_target_dir(output_folder);
    const char *function_filename = f_iter->name.c_str();
    // Create target file
    const char *target_file =
        futag::get_target_file(output_folder, function_filename);
    if (!target_file) {
      llvm::outs() << "Can not create target file: " << target_file
                   << " - passed!\n\n";
      return 0;
    }
    ofstream *fuzz_file = new ofstream;
    fuzz_file->open(target_file);
    // Generating fuzz target
    futag::gen_wrapper_4libFuzzer(fuzz_file, include_headers, generator);
    fuzz_file->close();
    delete generator;
    delete fuzz_file;
  }
  return 0;
}