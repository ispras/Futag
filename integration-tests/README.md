# Futag Product Tests

Dockerized test suites for validating Futag across multiple platforms.

## Test Categories

### build-test/
Validates building the LLVM toolchain with Futag checkers from source.

| Platform | Dockerfile | LLVM Version |
|----------|-----------|--------------|
| Ubuntu 20.04 | `ubuntu20/ubuntu20.Dockerfile` | LLVM 14 |
| Ubuntu 22.04 | `ubuntu22/ubuntu22.Dockerfile` | LLVM 18 |
| Ubuntu 24.04 | `ubuntu24/ubuntu24.Dockerfile` | LLVM 19 |
| Alt Linux 11 | `alt11/alt11.Dockerfile` | LLVM 18 |
| Alt Linux 12 | `alt12/alt12.Dockerfile` | LLVM 19 |

### libraries-test/
End-to-end tests against real open-source libraries (json-c, php, FreeImage, etc.).

### package-test/
Tests the pre-built Python package installation and basic functionality.

## Running Tests

Each test directory contains:
- `Dockerfile` — Container build definition
- `build.sh` — Build the Docker image
- `run.sh` — Run the test container

Example:
```bash
cd build-test/ubuntu24
./build.sh
./run.sh
```

## CI Integration

See [.github/workflows/](../../.github/workflows/) for automated CI workflows.
