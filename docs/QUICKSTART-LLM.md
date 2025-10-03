# Quick Start: LLM-Based Fuzzing Wrapper Generation

This is a 5-minute quick start guide to get you up and running with LLM-based fuzzing wrapper generation in Futag.

## Prerequisites

- Futag installed and configured
- Python 3.6+
- An OpenAI or Anthropic API key

## Step 1: Install Dependencies (1 minute)

```bash
pip install openai anthropic
```

## Step 2: Set Your API Key (30 seconds)

```bash
export OPENAI_API_KEY="your-api-key-here"
```

Get your API key from:
- OpenAI: https://platform.openai.com/api-keys
- Anthropic: https://console.anthropic.com/

## Step 3: Prepare Your Library (1 minute)

```python
from futag.preprocessor import Builder

# Build and analyze your library
builder = Builder("futag-llvm/", "path/to/your/library/")
builder.auto_build()
builder.analyze()
```

## Step 4: Generate Fuzzing Wrappers with LLM (2 minutes)

```python
from futag.generator import Generator

# Initialize generator
gen = Generator("futag-llvm/", "path/to/your/library/")

# Generate with GPT-4 (recommended for quality)
stats = gen.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    max_functions=5  # Start small
)

# Or use GPT-3.5-turbo (faster and cheaper)
stats = gen.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-3.5-turbo",
    max_functions=10
)

print(f"✓ Generated {stats['successful']} fuzzing harnesses")
print(f"✗ Failed: {stats['failed']}")
```

## Step 5: Compile and Test (30 seconds)

```python
# Compile the generated harnesses
gen.compile_targets(workers=4, keep_failed=True)
```

## Complete Example Script

Save this as `quick-llm-test.py`:

```python
#!/usr/bin/env python3
from futag.preprocessor import Builder
from futag.generator import Generator

# Configuration
FUTAG_PATH = "futag-llvm/"
LIBRARY_PATH = "path/to/your/library/"

# Step 1: Build and analyze
print("Building and analyzing library...")
builder = Builder(FUTAG_PATH, LIBRARY_PATH)
builder.auto_build()
builder.analyze()

# Step 2: Generate with LLM
print("\nGenerating fuzzing wrappers with LLM...")
gen = Generator(FUTAG_PATH, LIBRARY_PATH)
stats = gen.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-3.5-turbo",  # Start with cheaper model
    max_functions=5
)

print(f"\n✓ Successfully generated: {stats['successful']}")
print(f"✗ Failed: {stats['failed']}")

# Step 3: Compile
print("\nCompiling generated harnesses...")
gen.compile_targets(workers=4, keep_failed=True)

print("\n🎉 Done! Check futag-fuzz-drivers/ for results.")
```

Run it:
```bash
python3 quick-llm-test.py
```

## What's Next?

1. **Try Different Models**: Test GPT-4 for better quality
2. **Increase Coverage**: Generate for more functions
3. **Hybrid Approach**: Combine with traditional generation
4. **Review Results**: Check generated harnesses in `futag-fuzz-drivers/`

## Tips for Success

- **Start Small**: Begin with 5-10 functions to test
- **Use GPT-3.5**: It's 10x cheaper and works well for most cases
- **Review Generated Code**: LLM output should be verified
- **Monitor Costs**: Check your API usage dashboard

## Troubleshooting

**Problem**: ImportError for openai
**Solution**: `pip install openai`

**Problem**: API key not found
**Solution**: Make sure `OPENAI_API_KEY` is exported in your shell

**Problem**: Rate limit errors
**Solution**: Reduce `max_functions` or wait a few minutes

## Cost Estimate

For 10 functions with GPT-3.5-turbo:
- Approximate cost: $0.10 - $0.30
- Time: 1-2 minutes

For comparison with GPT-4:
- Approximate cost: $0.50 - $1.50
- Time: 2-5 minutes

## More Information

- Full documentation: [docs/LLM-GENERATION.md](LLM-GENERATION.md)
- Russian documentation: [docs/LLM-GENERATION.ru.md](LLM-GENERATION.ru.md)
- Example script: [src/python/example-llm-generation.py](../src/python/example-llm-generation.py)

Happy fuzzing! 🚀
