#!/usr/bin/env python3
"""
Example script for using Futag with LLM-based fuzzing wrapper generation.

This example demonstrates how to use the new LLM-based generation feature,
which is similar to oss-fuzz-gen approach. The LLM can generate fuzzing
harnesses using large language models (OpenAI, Anthropic, or local models).
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
# Option 1: Traditional Static Analysis-Based Generation
# =============================================================================

print("\n" + "=" * 80)
print("Option 1: Traditional Generation (Static Analysis)")
print("=" * 80)

generator = Generator(
    FUTAG_PATH,
    LIBRARY_PATH,
    target_type=LIBFUZZER  # or AFLPLUSPLUS
)

# Generate targets using traditional static analysis
generator.gen_targets(anonymous=False, max_wrappers=10)
generator.compile_targets(workers=4, keep_failed=True)

# =============================================================================
# Option 2: LLM-Based Generation (NEW - Similar to oss-fuzz-gen)
# =============================================================================

print("\n" + "=" * 80)
print("Option 2: LLM-Based Generation (Similar to oss-fuzz-gen)")
print("=" * 80)

# Example 1: Using OpenAI GPT-4
# Make sure to set OPENAI_API_KEY environment variable or pass it directly
print("\nExample 1: Using OpenAI GPT-4")
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    # llm_api_key="your-api-key-here",  # or set OPENAI_API_KEY env var
    max_functions=5,  # Limit to 5 functions for testing
    temperature=0.7,
    max_tokens=2048
)

print(f"\nLLM Generation Results:")
print(f"  Total functions: {stats['total']}")
print(f"  Successful: {stats['successful']}")
print(f"  Failed: {stats['failed']}")

# Example 2: Using OpenAI GPT-3.5-turbo (faster and cheaper)
print("\n\nExample 2: Using OpenAI GPT-3.5-turbo")
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-3.5-turbo",
    max_functions=10,
    temperature=0.5
)

# Example 3: Using Anthropic Claude
# Make sure to set ANTHROPIC_API_KEY environment variable
print("\n\nExample 3: Using Anthropic Claude")
stats = generator.gen_targets_with_llm(
    llm_provider="anthropic",
    llm_model="claude-3-opus-20240229",
    max_functions=5
)

# =============================================================================
# Hybrid Approach: Combine Both Methods
# =============================================================================

print("\n" + "=" * 80)
print("Hybrid Approach: Use Both Traditional and LLM-Based Generation")
print("=" * 80)

# First, generate with traditional method
print("\nGenerating with traditional method...")
generator.gen_targets(anonymous=False, max_wrappers=5)

# Then, supplement with LLM-based generation for additional coverage
print("\nSupplementing with LLM-based generation...")
llm_stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    max_functions=5
)

# Compile all generated targets
print("\nCompiling all generated targets...")
generator.compile_targets(workers=4, keep_failed=True)

# =============================================================================
# Notes and Best Practices
# =============================================================================

print("\n" + "=" * 80)
print("Notes on LLM-Based Generation:")
print("=" * 80)
print("""
1. API Key Setup:
   - OpenAI: Set OPENAI_API_KEY environment variable
   - Anthropic: Set ANTHROPIC_API_KEY environment variable
   - Or pass api_key directly to gen_targets_with_llm()

2. Cost Considerations:
   - GPT-4: Higher quality but more expensive
   - GPT-3.5-turbo: Faster and cheaper, good for most cases
   - Consider using max_functions to limit API calls

3. Temperature Settings:
   - Lower (0.0-0.3): More deterministic, conservative
   - Medium (0.4-0.7): Balanced creativity and consistency
   - Higher (0.8-1.0): More creative but potentially less reliable

4. Hybrid Approach:
   - Use traditional generation for well-understood patterns
   - Use LLM for complex or unusual cases
   - Combine both for maximum coverage

5. Dependencies:
   - Install: pip install openai anthropic
   - Optional: Use requirements.txt from futag-package

6. Output:
   - LLM-generated harnesses are saved in futag-fuzz-drivers/
   - Check llm_generation_stats.json for detailed results
""")

print("\n" + "=" * 80)
print("Example Complete!")
print("=" * 80)
