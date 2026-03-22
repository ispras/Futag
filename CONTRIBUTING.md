# Contributing to Futag

## Development Setup

### Prerequisites
- CMake >= 3.13.4
- GCC >= 7.1.0
- Python >= 3.8
- pip >= 22.1.1

### Building the LLVM toolchain

```bash
cd build-llvm && ./prepare.sh
cd ../build && ./build.sh
```

### Installing the Python package (development mode)

```bash
cd futag-package
pip install -e ".[test]"
```

### Running tests

```bash
cd futag-package
python -m pytest tests/ -v
```

## Code Style

### Python
- Follow PEP 8
- Use Google-style docstrings
- All new methods must have type hints and docstrings
- Use `logging` module instead of `print()`
- Use `with` statements for file I/O
- Raise exceptions from `futag.exceptions` instead of `sys.exit()`

### C++
- Follow LLVM coding style (configured in .clang-format)
- Column limit: 80 characters
- Indent: 4 spaces

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commit messages
3. Ensure all Python tests pass
4. Update documentation if APIs change
5. Submit PR with description of changes

## Adding a New Generator Backend

See docs/generators.md for the BaseGenerator pattern. Implement 10 abstract `_gen_*` methods.

## LLVM Version Support

When adding support for a new LLVM version:
1. Create version-specific source files (e.g., FutagAnalyzer19.cpp)
2. Create version-specific CMakeLists (e.g., CMakeLists19.txt)
3. Update Checkers.td with version-specific copy
4. Update build/build.sh version detection
5. The base file should always match the latest supported LLVM version
