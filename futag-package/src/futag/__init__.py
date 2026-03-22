# Copyright (c) 2023-2024 ISP RAS (https://www.ispras.ru)
# Licensed under the GNU General Public License v3.0
# See LICENSE file in the project root for full license text.

"""Futag - Fuzz target Automated Generator.

A tool from ISP RAS for automated generation of fuzzing wrappers
(fuzz targets) for software libraries. Analyzes library source code
via custom Clang/LLVM static analysis checkers and generates fuzz
targets in LibFuzzer or AFLplusplus format.

Typical usage::

    from futag.preprocessor import Builder
    from futag.generator import Generator
    from futag.toolchain import ToolchainConfig

    builder = Builder(futag_llvm_path, library_root, clean=True)
    builder.auto_build()
    builder.analyze()

    tc = ToolchainConfig.from_futag_llvm(futag_llvm_path)
    generator = Generator(library_root, toolchain=tc)
    generator.gen_targets()
    generator.compile_targets(workers=4)

Classes:
    Builder: Builds and analyzes target libraries.
    ConsumerBuilder: Analyzes consumer programs using the library.
    Generator: Generates fuzz targets using raw memcpy buffer consumption.
    FuzzDataProviderGenerator: Generates fuzz targets using FuzzedDataProvider API.
    BlobStamperGenerator: Generates fuzz targets using LibBlobStamper.
    ContextGenerator: Generates context-aware fuzz targets from consumer usage.
    NatchGenerator: Generates fuzz targets from Natch crash traces.
    Fuzzer: Executes generated fuzz targets and collects crashes.
    NatchFuzzer: Executes Natch-generated fuzz targets with corpus support.
"""

__version__ = "3.0.1"

import logging
logging.getLogger('futag').addHandler(logging.NullHandler())


def setup_console_logging(enable=True):
    """Configure console logging for the futag package.

    When enabled, attaches a StreamHandler to the 'futag' logger at INFO level.
    Idempotent: calling multiple times will not add duplicate handlers.

    Args:
        enable: If True, add a console handler. If False, do nothing.
    """
    if not enable:
        return
    futag_logger = logging.getLogger('futag')
    # Avoid adding duplicate console handlers
    for h in futag_logger.handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, (logging.NullHandler, logging.FileHandler)):
            return
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
    futag_logger.addHandler(handler)
    futag_logger.setLevel(logging.INFO)
