# LLM-Based Fuzzing Wrapper Generation

## Overview

Futag now supports LLM-based fuzzing wrapper generation, similar to the approach used in [oss-fuzz-gen](https://github.com/google/oss-fuzz-gen). This feature uses Large Language Models (LLMs) to automatically generate fuzzing harnesses for library functions.

## Key Features

- **Multiple LLM Providers**: Support for OpenAI (GPT-4, GPT-3.5-turbo), Anthropic (Claude), Ollama, and OpenAI-compatible local servers
- **Local LLM Support**: Run completely offline with Ollama, LM Studio, or other local models
- **Intelligent Code Generation**: Uses advanced prompts to generate high-quality fuzzing harnesses
- **Flexible Integration**: Can be used standalone or combined with traditional static analysis
- **Configurable**: Adjustable temperature, max tokens, and model selection
- **Privacy-Friendly**: Keep your code private with local LLMs

## Installation

### Cloud LLM Dependencies

Install the required dependencies for cloud-based LLMs:

```bash
pip install openai anthropic
```

Or use the requirements file:

```bash
cd src/python/futag-package
pip install -r requirements.txt
```

### Local LLM Setup

For local LLMs, you need the `requests` library (included in requirements.txt):

```bash
pip install requests
```

#### Option 1: Ollama (Recommended)

1. **Install Ollama**: Download from https://ollama.ai/download
2. **Start Ollama server**:
   ```bash
   ollama serve
   ```
3. **Pull a model** (recommended models for code generation):
   ```bash
   # Best for code generation
   ollama pull codellama:13b
   
   # Alternatives
   ollama pull deepseek-coder:6.7b
   ollama pull mistral
   ollama pull llama2:13b
   ```

#### Option 2: LM Studio

1. **Download LM Studio**: https://lmstudio.ai/
2. **Load a model**: Download and load CodeLlama, Mistral, or DeepSeek Coder
3. **Start the local server**: Click "Start Server" (default: http://localhost:1234)

#### Option 3: Other OpenAI-Compatible Servers

You can use any OpenAI-compatible local server:
- LocalAI: https://localai.io/
- text-generation-webui: https://github.com/oobabooga/text-generation-webui
- vLLM: https://github.com/vllm-project/vllm

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

#### Local LLMs with Ollama (No API Key Required!)

```python
# Using CodeLlama (best for code generation)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="codellama:13b",  # or codellama:7b, codellama:34b
    max_functions=10,
    temperature=0.2,  # Lower for more deterministic code
    max_tokens=2048
)

# Using DeepSeek Coder (specialized for coding)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="deepseek-coder:6.7b",
    max_functions=10,
    temperature=0.2
)

# Using Mistral (balanced performance)
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="mistral",
    max_functions=10,
    temperature=0.3
)
```

#### Local LLMs with LM Studio or OpenAI-Compatible Server

```python
# Set environment variable for custom host (optional)
# export LOCAL_LLM_HOST="http://localhost:1234"

stats = generator.gen_targets_with_llm(
    llm_provider="local",
    llm_model="local-model",  # Model name from your server
    max_functions=10,
    temperature=0.2,
    max_tokens=2048
)
```

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
| `llm_provider` | str | "openai" | LLM provider: 'openai', 'anthropic', 'ollama', or 'local' |
| `llm_model` | str | "gpt-4" | Model name (e.g., 'gpt-4', 'codellama:13b', 'mistral') |
| `llm_api_key` | str | None | API key for cloud providers (not needed for local) |
| `max_functions` | int | None | Maximum number of functions to generate (None = all) |
| `temperature` | float | 0.7 | LLM temperature (0.0-1.0, lower = more deterministic) |
| `max_tokens` | int | 2048 | Maximum tokens in LLM response |

### Recommended Models by Provider

| Provider | Recommended Models | Use Case |
|----------|-------------------|----------|
| **Ollama** | codellama:13b | Best for code generation |
| | deepseek-coder:6.7b | Coding specialist, good balance |
| | mistral | General purpose, fast |
| | llama2:13b | General purpose |
| **OpenAI** | gpt-4 | Highest quality |
| | gpt-3.5-turbo | Fast and cost-effective |
| **Anthropic** | claude-3-opus-20240229 | High quality |
| | claude-3-sonnet-20240229 | Balanced |
| **Local** | Any OpenAI-compatible | Depends on your setup |

### Temperature Guidelines

- **0.0-0.3**: Highly deterministic, conservative generation (recommended for local code models)
- **0.4-0.7**: Balanced creativity and consistency (good for cloud models)
- **0.8-1.0**: More creative but potentially less reliable

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `OLLAMA_HOST` | Ollama server URL | http://localhost:11434 |
| `LOCAL_LLM_HOST` | Local LLM server URL | http://localhost:1234 |

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

### Cloud LLM-Based Generation

**Pros:**
- Handles complex scenarios better
- More flexible and adaptive
- Can learn from context
- Similar to human-written harnesses
- Highest quality output

**Cons:**
- Requires API access and costs money ($0.01-$0.15 per function)
- Non-deterministic (varies between runs)
- Needs internet connection
- Generated code should be reviewed
- Privacy concerns (data sent to cloud)

### Local LLM-Based Generation (NEW!)

**Pros:**
- **Free to use** (no API costs)
- **Complete privacy** (data stays local)
- **No internet required**
- **Unlimited generations**
- Full control over models
- Good quality with proper models (CodeLlama, DeepSeek)

**Cons:**
- Requires local hardware (GPU recommended but not required)
- Slower than cloud APIs
- Slightly lower quality for smaller models
- Initial setup and model download required
- Needs disk space for models (4-26GB per model)

### Recommendation

Use a **hybrid approach**:
1. Start with traditional generation for standard cases
2. Use local LLMs (Ollama + CodeLlama) for complex functions - FREE!
3. Use cloud LLMs (GPT-4) only for the most challenging cases
4. Review and test all generated harnesses

**Cost-Effective Strategy:**
- Phase 1: Traditional generation (free, fast)
- Phase 2: Local LLM generation (free, private, unlimited)
- Phase 3: Cloud LLM for remaining difficult cases (paid, high quality)

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
- `src/python/example-llm-generation.py` - Cloud LLM examples (OpenAI, Anthropic)
- `src/python/example-local-llm-generation.py` - **Local LLM examples (Ollama, LM Studio)**
- `examples/` - Sample generated harnesses

## Troubleshooting

### Local LLM Issues

#### Ollama Connection Failed
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if not running
ollama serve

# Check available models
ollama list
```

#### Model Not Found
```bash
# Pull the required model
ollama pull codellama:13b

# Or list available models online
ollama search codellama
```

#### Slow Generation with Ollama
- Use a GPU for faster inference
- Use smaller models (7B instead of 13B)
- Reduce max_tokens parameter
- Consider using quantized models

#### LM Studio Connection Issues
- Ensure the server is started in LM Studio
- Check the port (default: 1234)
- Set LOCAL_LLM_HOST if using a different port:
  ```bash
  export LOCAL_LLM_HOST="http://localhost:8080"
  ```

### Cloud API Key Issues

```python
# Check if dependencies are installed
from futag.llm_generator import check_llm_dependencies
if check_llm_dependencies("openai"):
    print("OpenAI dependencies available")
```

### Common Errors

1. **ImportError: No module named 'openai'**
   - Solution: `pip install openai`

2. **ImportError: No module named 'requests'**
   - Solution: `pip install requests` (needed for local LLMs)

3. **API key not found**
   - Solution: Set environment variable or pass `llm_api_key` parameter

4. **Rate limit errors** (cloud APIs)
   - Solution: Use `max_functions` to limit requests, add delays between calls

5. **Connection refused (Ollama)**
   - Solution: Start Ollama with `ollama serve`
   - Check firewall settings

6. **Model not found (Ollama)**
   - Solution: Pull model with `ollama pull codellama:13b`

7. **Out of memory (local LLMs)**
   - Solution: Use smaller model (e.g., codellama:7b instead of 13b)
   - Close other applications
   - Consider cloud APIs for resource-limited systems

## Future Enhancements

Planned features:
- [x] Local LLM support (Ollama, LM Studio) ✅ **COMPLETED**
- [ ] Fine-tuned models for fuzzing
- [ ] Iterative refinement based on compilation results
- [ ] Integration with fuzzing results for feedback loop
- [ ] Cost optimization and caching
- [ ] Support for more local LLM providers (vLLM, llama.cpp)
- [ ] Model quantization support for faster inference

## References

- [Ollama](https://ollama.ai/) - Run large language models locally
- [LM Studio](https://lmstudio.ai/) - User-friendly local LLM interface
- [CodeLlama](https://ai.meta.com/blog/code-llama-large-language-model-coding/) - Meta's code-specialized LLM
- [DeepSeek Coder](https://github.com/deepseek-ai/DeepSeek-Coder) - Code-focused LLM
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
