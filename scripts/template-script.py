#!/usr/bin/env python3
"""Futag template script demonstrating three usage patterns.

Pattern 1 (lines 14-28): Basic library analysis and fuzz target generation.
Pattern 2 (lines 31-43): Consumer program analysis for context extraction.
Pattern 3 (lines 45-53): Context-based fuzz target generation from consumer usage.
"""
from futag.preprocessor import *
from futag.generator import *

# =============================================================================
# Pattern 1: Build, analyze, and generate fuzz targets for a library
# =============================================================================

test_build = Builder(
    "../futag-llvm",               # Path to the futag-llvm working directory
    "../json-c",                   # Path to the library source directory
    flags="-g -O0",                # Compiler flags for building
    clean=True,                    # Clean futag-build/install/analysis dirs before running (default: False)
    build_path="../json-c/futag-build",      # Path to build directory (optional)
    install_path="../json-c/futag-install",  # Path to install directory (optional)
    analysis_path="../json-c/futag-analysis", # Path to analysis directory (optional)
    processes=4,                   # Number of CPU cores for building (optional)
    build_ex_params="--disable-zip" # Extra build parameters (optional)
)

test_build.auto_build()
test_build.analyze()

generator = Generator(
    "../futag-llvm/",
    "json-c",
)
generator.gen_targets()
generator.compile_targets(
    workers=4,
    keep_failed=True
)

# =============================================================================
# Pattern 2: Analyze a consumer program to extract library usage contexts
# =============================================================================

FUTAG_PATH = "/home/futag/Futag/futag-llvm"
library_root = "json-c-json-c-0.16-20220414"

consumer_root = "libstorj-1.0.3"
consumer_builder = ConsumerBuilder(
    FUTAG_PATH,       # Path to the futag-llvm directory
    library_root,     # Path to the library source directory
    consumer_root,    # Path to the consumer program source directory
    # clean=True,
    # processes=16,
)
consumer_builder.auto_build()
consumer_builder.analyze()

# =============================================================================
# Pattern 3: Generate fuzz targets from consumer usage contexts
# =============================================================================

context_generator = ContextGenerator(
    FUTAG_PATH,
    library_root,
)

context_generator.gen_context()            # Generate fuzz wrappers for contexts
context_generator.compile_targets(         # Compile the generated fuzz wrappers
    keep_failed=True,
)
