set(LLVM_LINK_COMPONENTS
  support
  )

add_clang_executable(futag-slicer
  FutagSlicer.cpp
  pdg.cpp
  pdgBuilder.cpp
  pdgBuilderAction.cpp
  )

clang_target_link_libraries(futag-slicer
  PRIVATE
  clangAST
  clangASTMatchers
  clangBasic
  clangFrontend
  clangTooling
  )

install (TARGETS futag-slicer RUNTIME DESTINATION bin)
