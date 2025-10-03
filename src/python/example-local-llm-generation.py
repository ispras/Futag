#!/usr/bin/env python3
"""
Example script for using Futag with LOCAL LLM-based fuzzing wrapper generation.

This example demonstrates how to use local LLMs (Ollama, LM Studio, etc.) 
for generating fuzzing harnesses without requiring cloud API keys.
"""

from futag.preprocessor import *
from futag.generator import * 

# Configuration
FUTAG_PATH = "../futag-llvm"  # Path to futag-llvm directory
LIBRARY_PATH = "../json-c"    # Path to library source code

# =============================================================================
# Traditional Workflow: Build and Analyze
# =============================================================================

print("=" * 80)
print("Step 1: Build and Analyze Library")
print("=" * 80)

builder = Builder(
    FUTAG_PATH,
    LIBRARY_PATH,
    clean=True,  # Clean previous builds
    flags="-g -O0"
)

builder.auto_build()
builder.analyze()

# =============================================================================
# Local LLM Generation with Ollama
# =============================================================================

print("\n" + "=" * 80)
print("Option 1: Using Ollama (Recommended for Local LLMs)")
print("=" * 80)

# Prerequisites for Ollama:
# 1. Install Ollama: https://ollama.ai/download
# 2. Start Ollama: ollama serve
# 3. Pull a model: ollama pull codellama:13b
#    or: ollama pull llama2:13b
#    or: ollama pull mistral

print("""
Prerequisites:
1. Install Ollama from https://ollama.ai/download
2. Start Ollama server: ollama serve
3. Pull a model: 
   - ollama pull codellama:13b (recommended for code generation)
   - ollama pull llama2:13b
   - ollama pull mistral
   - ollama pull deepseek-coder
""")

generator = Generator(
    FUTAG_PATH,
    LIBRARY_PATH,
    target_type=LIBFUZZER
)

# Example 1: Using CodeLlama (best for code generation)
print("\nExample 1: Using CodeLlama 13B (recommended)")
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="codellama:13b",  # or "codellama:7b", "codellama:34b"
    max_functions=5,  # Start small for testing
    temperature=0.2,  # Lower temperature for more focused code generation
    max_tokens=2048
)

print(f"\nOllama Generation Results:")
print(f"  Total functions: {stats['total']}")
print(f"  Successful: {stats['successful']}")
print(f"  Failed: {stats['failed']}")

# Example 2: Using Llama2 (general purpose)
print("\n\nExample 2: Using Llama2 13B")
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="llama2:13b",  # or "llama2:7b", "llama2:70b"
    max_functions=3,
    temperature=0.3
)

# Example 3: Using Mistral (balanced performance)
print("\n\nExample 3: Using Mistral")
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="mistral",  # or "mistral:7b-instruct"
    max_functions=3,
    temperature=0.3
)

# Example 4: Using DeepSeek Coder (specialized for code)
print("\n\nExample 4: Using DeepSeek Coder")
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="deepseek-coder:6.7b",
    max_functions=3,
    temperature=0.2
)

# =============================================================================
# Local LLM Generation with LM Studio / LocalAI / Other OpenAI-Compatible
# =============================================================================

print("\n" + "=" * 80)
print("Option 2: Using LM Studio or OpenAI-Compatible Local Server")
print("=" * 80)

# Prerequisites for LM Studio:
# 1. Download and install LM Studio: https://lmstudio.ai/
# 2. Load a model (e.g., CodeLlama, Mistral)
# 3. Start the local server (default: http://localhost:1234)

print("""
Prerequisites:
1. Download LM Studio from https://lmstudio.ai/
2. Load a model (recommended: CodeLlama, Mistral, or DeepSeek Coder)
3. Start the local server (default port: 1234)
4. Or use any OpenAI-compatible server (LocalAI, text-generation-webui, etc.)

Environment variable:
  export LOCAL_LLM_HOST="http://localhost:1234"  # Change if using different port
""")

# Using default LM Studio configuration
stats = generator.gen_targets_with_llm(
    llm_provider="local",
    llm_model="local-model",  # Model name depends on your local server
    max_functions=5,
    temperature=0.2,
    max_tokens=2048
)

print(f"\nLocal LLM Generation Results:")
print(f"  Total functions: {stats['total']}")
print(f"  Successful: {stats['successful']}")
print(f"  Failed: {stats['failed']}")

# =============================================================================
# Custom Ollama Host Configuration
# =============================================================================

print("\n" + "=" * 80)
print("Advanced: Custom Ollama Host Configuration")
print("=" * 80)

# If Ollama is running on a different host/port
print("""
To use Ollama on a different host or port:
  export OLLAMA_HOST="http://192.168.1.100:11434"  # Remote Ollama server
  export OLLAMA_HOST="http://localhost:11435"      # Different port
""")

# The generator will automatically use the OLLAMA_HOST environment variable

# =============================================================================
# Comparing Local vs Cloud LLMs
# =============================================================================

print("\n" + "=" * 80)
print("Comparison: Local vs Cloud LLMs")
print("=" * 80)
print("""
Local LLMs (Ollama, LM Studio):
  Pros:
    ✓ Free to use (no API costs)
    ✓ Complete privacy (data stays local)
    ✓ No internet required
    ✓ Unlimited generations
    ✓ Full control over models
  
  Cons:
    ✗ Requires local hardware (GPU recommended)
    ✗ Slower than cloud APIs
    ✗ Slightly lower quality for smaller models
    ✗ Initial setup required

Cloud LLMs (OpenAI, Anthropic):
  Pros:
    ✓ Higher quality results
    ✓ Faster generation
    ✓ No local setup needed
  
  Cons:
    ✗ API costs ($0.01-$0.15 per function)
    ✗ Privacy concerns (data sent to cloud)
    ✗ Requires internet connection
    ✗ Rate limits apply

Recommendation for Local LLMs:
  - Use CodeLlama 13B or DeepSeek Coder for best results
  - Start with temperature 0.2-0.3 for code generation
  - Use GPU if available for faster generation
  - Consider using smaller models (7B) for testing, larger (13B+) for production
""")

# =============================================================================
# Compile Generated Targets
# =============================================================================

print("\n" + "=" * 80)
print("Step 2: Compile Generated Targets")
print("=" * 80)

# Compile all generated targets (both traditional and LLM-generated)
generator.compile_targets(workers=4, keep_failed=True)

print("\n" + "=" * 80)
print("Example Complete!")
print("=" * 80)
print("""
Next Steps:
1. Review generated harnesses in: futag-fuzz-drivers/
2. Check statistics: futag-fuzz-drivers/llm_generation_stats.json
3. Run fuzzing on compiled targets
4. Iterate and improve based on results

For more information:
  - Ollama documentation: https://ollama.ai/
  - LM Studio: https://lmstudio.ai/
  - Futag docs: docs/LLM-GENERATION.md
""")
