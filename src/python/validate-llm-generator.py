#!/usr/bin/env python3
"""
Validation script for LLM Generator functionality.
Tests the core functionality without requiring LLM API access.
"""

import sys
import os
from pathlib import Path

# Add the src directory to Python path
script_dir = Path(__file__).parent
src_path = script_dir / "futag-package" / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))
else:
    # Try alternative path
    alt_path = script_dir.parent / "src" / "python" / "futag-package" / "src"
    if alt_path.exists():
        sys.path.insert(0, str(alt_path))

def main():
    print("=" * 80)
    print("Validating LLM Generator Implementation")
    print("=" * 80)
    
    # Test 1: Import modules
    print("\n1. Testing imports...")
    try:
        from futag.llm_generator import LLMGenerator, check_llm_dependencies
        print("   ✓ LLMGenerator imported successfully")
    except ImportError as e:
        print(f"   ✗ Import failed: {e}")
        return 1
    
    # Test 2: Check module structure
    print("\n2. Checking module structure...")
    required_methods = ['_init_llm_client', '_build_prompt', '_call_llm', 
                       '_extract_code', 'gen_target_with_llm', 'gen_targets_with_llm']
    for method in required_methods:
        if hasattr(LLMGenerator, method):
            print(f"   ✓ Method '{method}' exists")
        else:
            print(f"   ✗ Method '{method}' missing")
            return 1
    
    # Test 3: Check dependency detection
    print("\n3. Testing dependency detection...")
    has_openai = check_llm_dependencies("openai")
    has_anthropic = check_llm_dependencies("anthropic")
    print(f"   OpenAI available: {has_openai}")
    print(f"   Anthropic available: {has_anthropic}")
    if not has_openai:
        print("   Note: Install with 'pip install openai' to enable OpenAI support")
    if not has_anthropic:
        print("   Note: Install with 'pip install anthropic' to enable Anthropic support")
    
    # Test 4: Test prompt building
    print("\n4. Testing prompt building...")
    try:
        import json
        import tempfile
        
        # Create temporary test structure
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            lib_root = tmppath / "library"
            lib_root.mkdir()
            
            analysis_dir = lib_root / ".futag-analysis"
            analysis_dir.mkdir()
            
            # Create mock analysis file
            mock_analysis = {
                "functions": [
                    {
                        "name": "test_func",
                        "signature": "int test_func(const char* data, size_t size)",
                        "params": [
                            {"type": "const char*", "name": "data"},
                            {"type": "size_t", "name": "size"}
                        ],
                        "return_type": "int",
                        "location": "test.c:1",
                        "access_type": 0
                    }
                ],
                "compiled_files": []
            }
            
            analysis_file = analysis_dir / "futag-analysis-result.json"
            with open(analysis_file, 'w') as f:
                json.dump(mock_analysis, f)
            
            # Test LLMGenerator initialization
            try:
                llm_gen = LLMGenerator(
                    futag_llvm_package=str(tmppath),
                    library_root=str(lib_root),
                    llm_provider="openai",
                    llm_model="gpt-4"
                )
                print("   ✓ LLMGenerator initialized successfully")
                
                # Test prompt building
                prompt = llm_gen._build_prompt(mock_analysis["functions"][0])
                if "test_func" in prompt and "LLVMFuzzerTestOneInput" in prompt:
                    print("   ✓ Prompt building works correctly")
                else:
                    print("   ✗ Prompt content incorrect")
                    return 1
                    
            except Exception as e:
                print(f"   ✗ Initialization or prompt building failed: {e}")
                return 1
    except Exception as e:
        print(f"   ✗ Test setup failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Test 5: Code extraction
    print("\n5. Testing code extraction...")
    try:
        test_response = """
Here is a fuzzing harness:

```c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
```

This is a simple harness.
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            lib_root = tmppath / "library"
            lib_root.mkdir()
            
            analysis_dir = lib_root / ".futag-analysis"
            analysis_dir.mkdir()
            
            analysis_file = analysis_dir / "futag-analysis-result.json"
            with open(analysis_file, 'w') as f:
                json.dump({"functions": [], "compiled_files": []}, f)
            
            llm_gen = LLMGenerator(
                futag_llvm_package=str(tmppath),
                library_root=str(lib_root)
            )
            
            code = llm_gen._extract_code(test_response)
            if "LLVMFuzzerTestOneInput" in code and "return 0;" in code:
                print("   ✓ Code extraction works correctly")
            else:
                print("   ✗ Code extraction failed")
                return 1
    except Exception as e:
        print(f"   ✗ Code extraction test failed: {e}")
        return 1
    
    # Test 6: Integration with Generator class
    print("\n6. Testing Generator class integration...")
    try:
        from futag.generator import Generator
        if hasattr(Generator, 'gen_targets_with_llm'):
            print("   ✓ gen_targets_with_llm method exists in Generator class")
            
            # Check method signature
            import inspect
            sig = inspect.signature(Generator.gen_targets_with_llm)
            params = list(sig.parameters.keys())
            required_params = ['llm_provider', 'llm_model', 'max_functions']
            if all(p in params for p in required_params):
                print("   ✓ Method has correct parameters")
            else:
                print("   ✗ Method parameters incomplete")
                return 1
        else:
            print("   ✗ gen_targets_with_llm method not found in Generator class")
            return 1
    except ImportError as e:
        print(f"   ✗ Could not import Generator: {e}")
        return 1
    except Exception as e:
        print(f"   ✗ Integration test failed: {e}")
        return 1
    
    # Summary
    print("\n" + "=" * 80)
    print("✓ All validation tests passed!")
    print("=" * 80)
    print("\nLLM Generator is ready to use.")
    print("\nNext steps:")
    print("1. Install LLM dependencies: pip install openai anthropic")
    print("2. Set API key: export OPENAI_API_KEY='your-key'")
    print("3. Use gen_targets_with_llm() in your scripts")
    print("\nSee docs/LLM-GENERATION.md for detailed usage instructions.")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
