set(LLVM_LINK_COMPONENTS
  support
)
set(LLVM_OPTIONAL_SOURCES
  Gen4Crusher.cpp
  Gen4libFuzzer.cpp
)

add_clang_executable(futag-gen4libfuzzer
  Gen4libFuzzer.cpp
)
add_clang_executable(futag-gen4crusher
  Gen4Crusher.cpp
)

clang_target_link_libraries(futag-gen4libfuzzer
 PRIVATE
 clangAST
 clangASTMatchers
 clangBasic
 clangFrontend
 clangTooling
 FutagLib
)
clang_target_link_libraries(futag-gen4crusher
 PRIVATE
 clangAST
 clangASTMatchers
 clangBasic
 clangFrontend
 clangTooling
 FutagLib
)

install (TARGETS futag-gen4libfuzzer RUNTIME DESTINATION bin)
install (TARGETS futag-gen4crusher RUNTIME DESTINATION bin)