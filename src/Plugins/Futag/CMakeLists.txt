add_llvm_library(BuildAnalysis MODULE BuildAnalysis.cpp PLUGIN_TOOL clang)
if(LLVM_ENABLE_PLUGINS AND (WIN32 OR CYGWIN))
  set(LLVM_LINK_COMPONENTS
    Support
  )
  clang_target_link_libraries(BuildAnalysis PRIVATE
    clangAST
    clangBasic
    clangFrontend
    )
endif()
