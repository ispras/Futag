# LLM-Based Fuzzing Wrapper Generation

## Overview

Futag now supports LLM-based fuzzing wrapper generation, similar to the approach used in [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen). This feature uses Large Language Models (LLMs) to automatically generate fuzzing harnesses for library functions.

## Key Features

- **Multiple LLM Providers**: Support for OpenAI (GPT-4, GPT-3.5-turbo), Anthropic (Claude), and local models
- **Intelligent Code Generation**: Uses advanced prompts to generate high-quality fuzzing harnesses
- **Flexible Integration**: Can be used standalone or combined with traditional static analysis
- **Configurable**: Adjustable temperature, max tokens, and model selection

## Installation

Install the required dependencies:

```bash
pip install openai anthropic
```

Or use the requirements file:

```bash
cd src/python/futag-package
pip install -r requirements.txt
```

## Quick Start

### 1. Setup API Keys

Set your API key as an environment variable:

```bash
# For OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# For Anthropic
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

### 2. Basic Usage

```python
from futag.preprocessor import Builder
from futag.generator import Generator

# Build and analyze library
builder = Builder("futag-llvm/", "library-path/")
builder.auto_build()
builder.analyze()

# Generate fuzzing harnesses with LLM
generator = Generator("futag-llvm/", "library-path/")
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    max_functions=10
)

print(f"Generated {stats['successful']} fuzzing harnesses")
```

## Advanced Usage

### Using Different LLM Providers

#### OpenAI GPT-4

```python
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    llm_api_key="your-key",  # Optional if env var is set
    max_functions=10,
    temperature=0.7,
    max_tokens=2048
)
```

#### OpenAI GPT-3.5-turbo (Faster/Cheaper)

```python
stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-3.5-turbo",
    max_functions=20,
    temperature=0.5
)
```

#### Anthropic Claude

```python
stats = generator.gen_targets_with_llm(
    llm_provider="anthropic",
    llm_model="claude-3-opus-20240229",
    max_functions=10
)
```

### Hybrid Approach: Traditional + LLM

Combine traditional static analysis with LLM-based generation:

```python
from futag.generator import Generator

generator = Generator("futag-llvm/", "library-path/")

# First: Traditional generation
generator.gen_targets(anonymous=False, max_wrappers=10)

# Then: Supplement with LLM-based generation
llm_stats = generator.gen_targets_with_llm(
    llm_provider="openai",
    llm_model="gpt-4",
    max_functions=5
)

# Compile all targets
generator.compile_targets(workers=4, keep_failed=True)
```

## Configuration Parameters

### `gen_targets_with_llm()` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `llm_provider` | str | "openai" | LLM provider: 'openai', 'anthropic', or 'local' |
| `llm_model` | str | "gpt-4" | Model name (e.g., 'gpt-4', 'gpt-3.5-turbo', 'claude-3-opus-20240229') |
| `llm_api_key` | str | None | API key (or use environment variable) |
| `max_functions` | int | None | Maximum number of functions to generate (None = all) |
| `temperature` | float | 0.7 | LLM temperature (0.0-1.0, lower = more deterministic) |
| `max_tokens` | int | 2048 | Maximum tokens in LLM response |

### Temperature Guidelines

- **0.0-0.3**: Highly deterministic, conservative generation
- **0.4-0.7**: Balanced creativity and consistency (recommended)
- **0.8-1.0**: More creative but potentially less reliable

## Output

Generated harnesses are saved to:
- `futag-fuzz-drivers/<function_name>/<function_name>_llm_fuzz.c`
- Statistics: `futag-fuzz-drivers/llm_generation_stats.json`

Example statistics file:
```json
{
  "total": 10,
  "successful": 8,
  "failed": 2,
  "successful_functions": ["func1", "func2", ...],
  "failed_functions": ["func3", "func4"]
}
```

## Comparison: Traditional vs LLM-Based

### Traditional Static Analysis

**Pros:**
- No API costs
- Fast and deterministic
- Works offline
- Well-tested and reliable

**Cons:**
- May struggle with complex types
- Limited to predefined patterns
- Less flexible

### LLM-Based Generation

**Pros:**
- Handles complex scenarios better
- More flexible and adaptive
- Can learn from context
- Similar to human-written harnesses

**Cons:**
- Requires API access and costs money
- Non-deterministic (varies between runs)
- Needs internet connection
- Generated code should be reviewed

### Recommendation

Use a **hybrid approach**:
1. Start with traditional generation for standard cases
2. Use LLM for complex or problematic functions
3. Review and test all generated harnesses

## Cost Estimation

Approximate costs (as of 2024):

| Model | Cost per 1M tokens | Estimated per function |
|-------|-------------------|------------------------|
| GPT-4 | $30 (input) / $60 (output) | $0.05-$0.15 |
| GPT-3.5-turbo | $0.50 (input) / $1.50 (output) | $0.01-$0.03 |
| Claude-3-Opus | $15 (input) / $75 (output) | $0.03-$0.10 |

**Tip**: Start with GPT-3.5-turbo for testing, then use GPT-4 for production.

## Examples

See complete examples in:
- `src/python/example-llm-generation.py` - Comprehensive example with all features
- `examples/` - Sample generated harnesses

## Troubleshooting

### API Key Issues

```python
# Check if dependencies are installed
from futag.llm_generator import check_llm_dependencies
if check_llm_dependencies("openai"):
    print("OpenAI dependencies available")
```

### Common Errors

1. **ImportError: No module named 'openai'**
   - Solution: `pip install openai`

2. **API key not found**
   - Solution: Set environment variable or pass `llm_api_key` parameter

3. **Rate limit errors**
   - Solution: Use `max_functions` to limit requests, add delays between calls

## Future Enhancements

Planned features:
- [ ] Local LLM support (Ollama, LM Studio)
- [ ] Fine-tuned models for fuzzing
- [ ] Iterative refinement based on compilation results
- [ ] Integration with fuzzing results for feedback loop
- [ ] Cost optimization and caching

## References

- [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen) - Google's LLM-based fuzzing tool
- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic API Documentation](https://docs.anthropic.com/)
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)

## Contributing

To contribute to LLM-based generation:
1. Test with different LLM models
2. Improve prompts in `llm_generator.py`
3. Add support for new LLM providers
4. Share your results and feedback
