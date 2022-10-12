#ifndef PDGBUILDER_H
#define PDGBUILDER_H

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include <string>

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <utility>

#include "pdg.h"

/*! main class for processing the AST
  */
namespace clang
{
  namespace slicer
  {
    class PDGBuilder : public ast_matchers::MatchFinder::MatchCallback
    {
    public:
      struct slicingStmtPos
      {
        slicingStmtPos() = default;

        slicingStmtPos(int _sline, int _scol, int _eline, int _ecol) : sline(_sline), scol(_scol),
                                                                       eline(_eline), ecol(_ecol)
        {
        }

        unsigned int sline{0};
        unsigned int scol{0};
        unsigned int eline{INT_MAX};
        unsigned int ecol{INT_MAX};
        bool refined(unsigned int sl, unsigned int sc, unsigned int el, unsigned int ec);
      };

      explicit PDGBuilder() = default;

      explicit PDGBuilder(std::string _funcName,
                          int _lineNo,
                          int _colNo,
                          bool _dumpDot) : funcName(std::move(std::move(_funcName)))
                                           , lineNo(_lineNo)
                                           , colNo(_colNo)
                                           , dumpDot(_dumpDot)
      {
      }

      void registerMatchers(ast_matchers::MatchFinder* MatchFinder);

      void run(const ast_matchers::MatchFinder::MatchResult& result) override;

      void onEndOfTranslationUnit() override;

    private:
      bool hasStmt(const Stmt* value)
      {
        return stmt_map.find(value) != stmt_map.end();
      }

      static FullSourceLoc getLoc(const ast_matchers::MatchFinder::MatchResult& result, const Stmt* astRef)
      {
        return result.Context->getFullLoc(astRef->getBeginLoc());
      }

      void setSlicingStmt(const ast_matchers::MatchFinder::MatchResult& result, const Stmt* astRef);
      void dumpDots();
      // tool params
      const std::string funcName;
      unsigned int lineNo = 0;
      unsigned int colNo = 0;
      bool dumpDot = false;
      const Stmt* slicingStmt = nullptr;
      slicingStmtPos slicePos;
      SourceManager* sm = nullptr;
      // the function
      Stmt* root = nullptr;
      // We store the Statements in a map.
      std::map<const Stmt*, Statement*> stmt_map;
    };
  } // namespace slicer
} // namespace clang
#endif // PDGBUILDER_H