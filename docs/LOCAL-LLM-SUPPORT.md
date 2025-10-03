# Local LLM Support for Futag

## Summary

This update adds support for **local Large Language Models (LLMs)** to Futag's fuzzing harness generation system, allowing you to generate fuzzing targets without requiring cloud API keys or internet connection.

## What's New

### Supported Local LLM Providers

1. **Ollama** (Recommended)
   - Easy to install and use
   - Supports CodeLlama, Mistral, DeepSeek Coder, and more
   - Free and runs completely offline
   - Simple API for local model inference

2. **OpenAI-Compatible Local Servers**
   - LM Studio
   - LocalAI
   - text-generation-webui
   - vLLM
   - Any OpenAI API-compatible server

## Key Features

- ✅ **100% Free** - No API costs, unlimited generations
- ✅ **Complete Privacy** - Your code never leaves your machine
- ✅ **Offline Operation** - No internet required after model download
- ✅ **Easy Setup** - Simple installation and configuration
- ✅ **Good Quality** - Especially with CodeLlama and DeepSeek Coder models

## Quick Start

### Using Ollama

```bash
# 1. Install Ollama
# Download from https://ollama.ai/download

# 2. Start Ollama
ollama serve

# 3. Pull a code generation model
ollama pull codellama:13b

# 4. Use in your Python code
```

```python
from futag.generator import Generator

generator = Generator("futag-llvm/", "library-path/")
stats = generator.gen_targets_with_llm(
    llm_provider="ollama",
    llm_model="codellama:13b",
    max_functions=10
)
```

### Using LM Studio

```bash
# 1. Download LM Studio from https://lmstudio.ai/
# 2. Load a model (e.g., CodeLlama)
# 3. Start the server (default port: 1234)
```

```python
from futag.generator import Generator

generator = Generator("futag-llvm/", "library-path/")
stats = generator.gen_targets_with_llm(
    llm_provider="local",
    llm_model="local-model",
    max_functions=10
)
```

## Files Changed

### Core Implementation
- `src/python/futag-package/src/futag/llm_generator.py` - Added Ollama and local server support
- `src/python/futag-package/src/futag/generator.py` - Updated documentation

### Dependencies
- `src/python/futag-package/requirements.txt` - Added `requests` library

### Examples
- `src/python/example-local-llm-generation.py` - Comprehensive examples for local LLMs

### Documentation
- `docs/LLM-GENERATION.md` - Updated with local LLM instructions (English)
- `docs/LLM-GENERATION.ru.md` - Updated with local LLM instructions (Russian)

### Tests
- `src/python/test-local-llm.py` - Tests for local LLM provider initialization

## Recommended Models

| Model | Size | Use Case | Speed |
|-------|------|----------|-------|
| codellama:7b | ~4 GB | Fast generation, good quality | ⚡⚡⚡ |
| codellama:13b | ~7 GB | Best balance of speed/quality | ⚡⚡ |
| deepseek-coder:6.7b | ~4 GB | Code specialist | ⚡⚡⚡ |
| mistral | ~4 GB | General purpose | ⚡⚡⚡ |
| llama2:13b | ~7 GB | General purpose | ⚡⚡ |

## Configuration

### Environment Variables

```bash
# Ollama server URL (optional)
export OLLAMA_HOST="http://localhost:11434"

# Local LLM server URL (optional)
export LOCAL_LLM_HOST="http://localhost:1234"
```

## Cost Comparison

| Provider | Cost per Function | Privacy | Internet Required |
|----------|------------------|---------|-------------------|
| **Local (Ollama)** | FREE | ✅ Complete | ❌ No |
| **Local (LM Studio)** | FREE | ✅ Complete | ❌ No |
| OpenAI GPT-4 | $0.05-$0.15 | ❌ Cloud | ✅ Yes |
| OpenAI GPT-3.5 | $0.01-$0.03 | ❌ Cloud | ✅ Yes |
| Anthropic Claude | $0.03-$0.10 | ❌ Cloud | ✅ Yes |

## Hardware Requirements

### Minimum (7B models)
- RAM: 8 GB
- Storage: 5 GB per model
- GPU: Optional (but recommended)

### Recommended (13B models)
- RAM: 16 GB
- Storage: 10 GB per model
- GPU: NVIDIA with 8+ GB VRAM (for faster inference)

### Optimal (34B models)
- RAM: 32 GB
- Storage: 20 GB per model
- GPU: NVIDIA with 16+ GB VRAM

## Performance Tips

1. **Use GPU** - Significantly faster inference (10-100x)
2. **Start Small** - Test with 7B models first
3. **Lower Temperature** - Use 0.2-0.3 for code generation
4. **Reduce max_tokens** - Limit to 1024-2048 for better performance
5. **Use Quantized Models** - Smaller, faster, with minimal quality loss

## Troubleshooting

### Ollama not connecting
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve
```

### Model not found
```bash
# List available models
ollama list

# Pull the model
ollama pull codellama:13b
```

### Slow generation
- Use a smaller model (7B instead of 13B)
- Use GPU if available
- Reduce max_tokens parameter

## Learn More

- **Documentation**: See `docs/LLM-GENERATION.md` for complete documentation
- **Examples**: See `src/python/example-local-llm-generation.py` for usage examples
- **Ollama**: https://ollama.ai/
- **LM Studio**: https://lmstudio.ai/

## Contributing

To improve local LLM support:
1. Test with different models and share results
2. Optimize prompts for better code generation
3. Add support for additional local LLM providers
4. Report issues and suggest improvements
