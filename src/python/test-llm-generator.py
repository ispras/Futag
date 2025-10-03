#!/usr/bin/env python3
"""
Simple test script to verify LLM generator module functionality.
This script tests the LLM generator without requiring full installation.
"""

import sys
import os
import json
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "futag-package" / "src"))

def test_llm_generator_import():
    """Test that LLMGenerator can be imported."""
    print("=" * 80)
    print("Test 1: Import LLMGenerator")
    print("=" * 80)
    
    try:
        from futag.llm_generator import LLMGenerator, check_llm_dependencies
        print("✓ LLMGenerator imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Failed to import LLMGenerator: {e}")
        return False

def test_dependency_check():
    """Test the dependency checker."""
    print("\n" + "=" * 80)
    print("Test 2: Check LLM Dependencies")
    print("=" * 80)
    
    try:
        from futag.llm_generator import check_llm_dependencies
        
        # Check OpenAI
        has_openai = check_llm_dependencies("openai")
        print(f"OpenAI dependencies: {'✓ Available' if has_openai else '✗ Not available'}")
        
        # Check Anthropic
        has_anthropic = check_llm_dependencies("anthropic")
        print(f"Anthropic dependencies: {'✓ Available' if has_anthropic else '✗ Not available'}")
        
        return True
    except Exception as e:
        print(f"✗ Dependency check failed: {e}")
        return False

def test_prompt_building():
    """Test prompt building functionality."""
    print("\n" + "=" * 80)
    print("Test 3: Prompt Building")
    print("=" * 80)
    
    try:
        from futag.llm_generator import LLMGenerator
        
        # Create a mock analysis file
        mock_analysis = {
            "functions": [
                {
                    "name": "test_function",
                    "signature": "int test_function(const char* input, size_t len)",
                    "params": [
                        {"type": "const char*", "name": "input"},
                        {"type": "size_t", "name": "len"}
                    ],
                    "return_type": "int",
                    "location": "test.c:10",
                    "access_type": 0,
                    "is_cpp": False
                }
            ],
            "compiled_files": []
        }
        
        # Create temporary directory structure
        test_dir = Path("/tmp/futag_llm_test")
        test_dir.mkdir(exist_ok=True)
        
        lib_root = test_dir / "library"
        lib_root.mkdir(exist_ok=True)
        
        analysis_dir = lib_root / ".futag-analysis"
        analysis_dir.mkdir(exist_ok=True)
        
        analysis_file = analysis_dir / "futag-analysis-result.json"
        with open(analysis_file, 'w') as f:
            json.dump(mock_analysis, f)
        
        # Test prompt building (without actual LLM call)
        llm_gen = LLMGenerator(
            futag_llvm_package=str(test_dir),
            library_root=str(lib_root),
            llm_provider="openai",
            llm_model="gpt-4"
        )
        
        prompt = llm_gen._build_prompt(mock_analysis["functions"][0])
        
        print("✓ Prompt building successful")
        print("\nGenerated prompt preview:")
        print("-" * 80)
        print(prompt[:500] + "..." if len(prompt) > 500 else prompt)
        print("-" * 80)
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        
        return True
    except Exception as e:
        print(f"✗ Prompt building failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_code_extraction():
    """Test code extraction from LLM response."""
    print("\n" + "=" * 80)
    print("Test 4: Code Extraction")
    print("=" * 80)
    
    try:
        from futag.llm_generator import LLMGenerator
        
        # Create a minimal instance for testing
        test_dir = Path("/tmp/futag_llm_test2")
        test_dir.mkdir(exist_ok=True)
        
        lib_root = test_dir / "library"
        lib_root.mkdir(exist_ok=True)
        
        analysis_dir = lib_root / ".futag-analysis"
        analysis_dir.mkdir(exist_ok=True)
        
        analysis_file = analysis_dir / "futag-analysis-result.json"
        with open(analysis_file, 'w') as f:
            json.dump({"functions": [], "compiled_files": []}, f)
        
        llm_gen = LLMGenerator(
            futag_llvm_package=str(test_dir),
            library_root=str(lib_root)
        )
        
        # Test with markdown code block
        response_with_block = """Here is the fuzzing harness:

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) return 0;
    return 0;
}
```

This harness checks the size first."""
        
        code = llm_gen._extract_code(response_with_block)
        print("✓ Code extraction from markdown successful")
        print("\nExtracted code:")
        print("-" * 80)
        print(code)
        print("-" * 80)
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        
        return True
    except Exception as e:
        print(f"✗ Code extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("Futag LLM Generator Test Suite")
    print("=" * 80)
    
    results = []
    
    # Run tests
    results.append(("Import Test", test_llm_generator_import()))
    results.append(("Dependency Check", test_dependency_check()))
    results.append(("Prompt Building", test_prompt_building()))
    results.append(("Code Extraction", test_code_extraction()))
    
    # Print summary
    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name}: {status}")
    
    print("-" * 80)
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
