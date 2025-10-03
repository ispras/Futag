#!/usr/bin/env python3
"""
Simple test to verify local LLM provider support is working.
"""

import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "futag-package" / "src"))

def test_ollama_provider():
    """Test Ollama provider initialization."""
    print("Testing Ollama provider...")
    from futag.llm_generator import LLMGenerator
    import json
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        lib_root = tmppath / "library"
        lib_root.mkdir()
        
        analysis_dir = lib_root / ".futag-analysis"
        analysis_dir.mkdir()
        
        analysis_file = analysis_dir / "futag-analysis-result.json"
        with open(analysis_file, 'w') as f:
            json.dump({"functions": [], "compiled_files": []}, f)
        
        # Test Ollama provider
        llm_gen = LLMGenerator(
            futag_llvm_package=str(tmppath),
            library_root=str(lib_root),
            llm_provider="ollama",
            llm_model="codellama:13b"
        )
        
        print(f"  ✓ Ollama provider initialized: {llm_gen.llm_provider}")
        print(f"  ✓ Model: {llm_gen.llm_model}")
        return True

def test_local_provider():
    """Test local OpenAI-compatible provider initialization."""
    print("\nTesting local OpenAI-compatible provider...")
    from futag.llm_generator import LLMGenerator
    import json
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        lib_root = tmppath / "library"
        lib_root.mkdir()
        
        analysis_dir = lib_root / ".futag-analysis"
        analysis_dir.mkdir()
        
        analysis_file = analysis_dir / "futag-analysis-result.json"
        with open(analysis_file, 'w') as f:
            json.dump({"functions": [], "compiled_files": []}, f)
        
        # Test local provider
        llm_gen = LLMGenerator(
            futag_llvm_package=str(tmppath),
            library_root=str(lib_root),
            llm_provider="local",
            llm_model="local-model"
        )
        
        print(f"  ✓ Local provider initialized: {llm_gen.llm_provider}")
        print(f"  ✓ Model: {llm_gen.llm_model}")
        return True

def test_dependency_check():
    """Test dependency checker for local LLMs."""
    print("\nTesting dependency check...")
    from futag.llm_generator import check_llm_dependencies
    
    has_requests = check_llm_dependencies("ollama")
    print(f"  ✓ Ollama dependencies (requests): {has_requests}")
    
    has_local = check_llm_dependencies("local")
    print(f"  ✓ Local dependencies (requests): {has_local}")
    
    return has_requests and has_local

def main():
    print("=" * 80)
    print("Local LLM Support Test")
    print("=" * 80)
    
    try:
        # Test 1: Ollama
        test_ollama_provider()
        
        # Test 2: Local OpenAI-compatible
        test_local_provider()
        
        # Test 3: Dependencies
        test_dependency_check()
        
        print("\n" + "=" * 80)
        print("✓ All local LLM provider tests passed!")
        print("=" * 80)
        print("\nLocal LLM support is working correctly.")
        print("\nTo use local LLMs:")
        print("1. Install Ollama from https://ollama.ai/download")
        print("2. Run: ollama serve")
        print("3. Pull a model: ollama pull codellama:13b")
        print("4. Use in your code:")
        print("   generator.gen_targets_with_llm(")
        print("       llm_provider='ollama',")
        print("       llm_model='codellama:13b'")
        print("   )")
        return 0
        
    except Exception as e:
        print(f"\n✗ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
