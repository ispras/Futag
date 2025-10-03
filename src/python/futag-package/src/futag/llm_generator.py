"""
**************************************************
**      ______  __  __  ______  ___     ______  **
**     / ____/ / / / / /_  __/ /   |   / ____/  **
**    / /_    / / / /   / /   / /| |  / / __    **
**   / __/   / /_/ /   / /   / ___ | / /_/ /    **
**  /_/      \____/   /_/   /_/  |_| \____/     **
**                                              **
**     Fuzzing target Automated Generator       **
**             a tool of ISP RAS                **
**************************************************
** LLM-based fuzzing wrapper generator module   **
** Similar to oss-fuzz-gen approach             **
**************************************************
"""

import json
import pathlib
import os
import re
from typing import Dict, List, Optional, Any
from futag.sysmsg import *


class LLMGenerator:
    """LLM-based Generator for fuzzing wrappers
    
    This class provides LLM-based generation of fuzzing wrappers,
    similar to oss-fuzz-gen approach. It can use various LLM providers
    (OpenAI, Anthropic, local models) to generate fuzzing harnesses.
    """
    
    def __init__(
        self,
        futag_llvm_package: str,
        library_root: str,
        target_type: int = LIBFUZZER,
        json_file: str = ANALYSIS_FILE_PATH,
        output_path: str = FUZZ_DRIVER_PATH,
        llm_provider: str = "openai",
        llm_model: str = "gpt-4",
        llm_api_key: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048
    ):
        """Initialize LLMGenerator.
        
        Args:
            futag_llvm_package (str): Path to the futag-llvm package
            library_root (str): Path to the library root
            target_type (int): Format of fuzz-drivers (LIBFUZZER or AFLPLUSPLUS)
            json_file (str): Path to the futag-analysis-result.json file
            output_path (str): Where to save fuzz-drivers
            llm_provider (str): LLM provider ('openai', 'anthropic', 'local')
            llm_model (str): Model name to use
            llm_api_key (str): API key for the LLM provider (or None for env var)
            temperature (float): Temperature for LLM generation
            max_tokens (int): Maximum tokens for LLM response
        """
        self.futag_llvm_package = pathlib.Path(futag_llvm_package).absolute()
        self.library_root = pathlib.Path(library_root).absolute()
        self.target_type = target_type
        self.json_file = pathlib.Path(json_file) if pathlib.Path(json_file).exists() else self.library_root / json_file
        self.output_path = self.library_root / output_path
        
        # LLM configuration
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.llm_api_key = llm_api_key or os.getenv(f"{llm_provider.upper()}_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        # Load analysis data
        if not self.json_file.exists():
            raise ValueError(INVALID_ANALYSIS_FILE)
        
        with open(self.json_file, 'r') as f:
            self.target_library = json.load(f)
        
        # Create output directories
        self.output_path.mkdir(parents=True, exist_ok=True)
        (self.output_path / "succeeded").mkdir(parents=True, exist_ok=True)
        (self.output_path / "failed").mkdir(parents=True, exist_ok=True)
        
        # Initialize LLM client
        self._init_llm_client()
    
    def _init_llm_client(self):
        """Initialize the LLM client based on provider."""
        if self.llm_provider == "openai":
            try:
                import openai
                self.llm_client = openai
                if self.llm_api_key:
                    self.llm_client.api_key = self.llm_api_key
            except ImportError:
                print("-- [Futag-LLM] Warning: openai package not installed. Install with: pip install openai")
                self.llm_client = None
        elif self.llm_provider == "anthropic":
            try:
                import anthropic
                self.llm_client = anthropic.Anthropic(api_key=self.llm_api_key)
            except ImportError:
                print("-- [Futag-LLM] Warning: anthropic package not installed. Install with: pip install anthropic")
                self.llm_client = None
        elif self.llm_provider == "local":
            # For local models (e.g., via Ollama or LM Studio)
            self.llm_client = None
            print("-- [Futag-LLM] Using local LLM provider")
        else:
            print(f"-- [Futag-LLM] Warning: Unknown LLM provider: {self.llm_provider}")
            self.llm_client = None
    
    def _build_prompt(self, function_info: Dict[str, Any]) -> str:
        """Build a prompt for LLM to generate fuzzing wrapper.
        
        Args:
            function_info: Dictionary containing function information from analysis
            
        Returns:
            Prompt string for the LLM
        """
        function_name = function_info.get("name", "")
        function_signature = function_info.get("signature", "")
        params = function_info.get("params", [])
        return_type = function_info.get("return_type", "void")
        location = function_info.get("location", "")
        
        # Build parameter information
        param_descriptions = []
        for i, param in enumerate(params):
            param_type = param.get("type", "")
            param_name = param.get("name", f"param{i}")
            param_descriptions.append(f"  - Parameter {i+1}: {param_type} {param_name}")
        
        params_text = "\n".join(param_descriptions) if param_descriptions else "  - No parameters"
        
        # Determine target format
        target_format = "LibFuzzer" if self.target_type == LIBFUZZER else "AFL++"
        
        prompt = f"""You are an expert in fuzzing and security testing. Generate a fuzzing harness for the following C/C++ function.

Function Information:
- Name: {function_name}
- Signature: {function_signature}
- Return Type: {return_type}
- Location: {location}

Parameters:
{params_text}

Requirements:
1. Generate a {target_format} fuzzing harness
2. The harness should follow standard fuzzing best practices
3. Include proper input validation and error handling
4. Use the fuzzer-provided data buffer efficiently
5. Free any allocated memory to avoid memory leaks
6. Include necessary header files
7. The entry point should be: int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)

Generate a complete, compilable C/C++ fuzzing harness. Include all necessary headers and implementations.
Only output the code, no additional explanations.
"""
        return prompt
    
    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call the LLM with the given prompt.
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            Generated code or None if failed
        """
        if not self.llm_client:
            print("-- [Futag-LLM] Error: LLM client not initialized")
            return None
        
        try:
            if self.llm_provider == "openai":
                response = self.llm_client.ChatCompletion.create(
                    model=self.llm_model,
                    messages=[
                        {"role": "system", "content": "You are an expert fuzzing harness generator."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens
                )
                return response.choices[0].message.content
            
            elif self.llm_provider == "anthropic":
                response = self.llm_client.messages.create(
                    model=self.llm_model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            
            elif self.llm_provider == "local":
                # Placeholder for local LLM integration
                print("-- [Futag-LLM] Local LLM not yet implemented")
                return None
                
        except Exception as e:
            print(f"-- [Futag-LLM] Error calling LLM: {str(e)}")
            return None
    
    def _extract_code(self, llm_response: str) -> str:
        """Extract C/C++ code from LLM response.
        
        Args:
            llm_response: Raw response from LLM
            
        Returns:
            Extracted code
        """
        if not llm_response:
            return ""
        
        # Try to extract code from markdown code blocks
        code_block_pattern = r"```(?:c|cpp|c\+\+)?\n(.*?)\n```"
        matches = re.findall(code_block_pattern, llm_response, re.DOTALL)
        
        if matches:
            return matches[0]
        
        # If no code block found, return the whole response
        return llm_response
    
    def gen_target_with_llm(self, function_info: Dict[str, Any]) -> bool:
        """Generate a fuzzing target for a function using LLM.
        
        Args:
            function_info: Dictionary containing function information
            
        Returns:
            True if successful, False otherwise
        """
        function_name = function_info.get("name", "unknown")
        print(f"-- [Futag-LLM] Generating fuzzing harness for: {function_name}")
        
        # Build prompt
        prompt = self._build_prompt(function_info)
        
        # Call LLM
        llm_response = self._call_llm(prompt)
        if not llm_response:
            print(f"-- [Futag-LLM] Failed to generate harness for {function_name}")
            return False
        
        # Extract code
        code = self._extract_code(llm_response)
        if not code:
            print(f"-- [Futag-LLM] Failed to extract code for {function_name}")
            return False
        
        # Save to file
        output_dir = self.output_path / function_name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine file extension
        file_ext = ".cpp" if function_info.get("is_cpp", False) else ".c"
        output_file = output_dir / f"{function_name}_llm_fuzz{file_ext}"
        
        try:
            with open(output_file, 'w') as f:
                f.write(code)
            print(f"-- [Futag-LLM] Generated harness saved to: {output_file}")
            return True
        except Exception as e:
            print(f"-- [Futag-LLM] Error saving harness: {str(e)}")
            return False
    
    def gen_targets_with_llm(
        self,
        max_functions: Optional[int] = None,
        filter_public_only: bool = True
    ) -> Dict[str, Any]:
        """Generate fuzzing targets for multiple functions using LLM.
        
        Args:
            max_functions: Maximum number of functions to generate (None for all)
            filter_public_only: Only generate for public functions
            
        Returns:
            Dictionary with generation statistics
        """
        functions = self.target_library.get("functions", [])
        
        # Filter functions
        if filter_public_only:
            functions = [f for f in functions if f.get("access_type") == AS_NONE or f.get("access_type") == AS_PUBLIC]
        
        # Limit number of functions
        if max_functions:
            functions = functions[:max_functions]
        
        print(f"-- [Futag-LLM] Generating harnesses for {len(functions)} functions")
        
        successful = []
        failed = []
        
        for func in functions:
            if self.gen_target_with_llm(func):
                successful.append(func["name"])
            else:
                failed.append(func["name"])
        
        stats = {
            "total": len(functions),
            "successful": len(successful),
            "failed": len(failed),
            "successful_functions": successful,
            "failed_functions": failed
        }
        
        # Save statistics
        stats_file = self.output_path / "llm_generation_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"\n-- [Futag-LLM] Generation complete:")
        print(f"   Total: {stats['total']}")
        print(f"   Successful: {stats['successful']}")
        print(f"   Failed: {stats['failed']}")
        
        return stats


# Helper function to check if LLM dependencies are available
def check_llm_dependencies(provider: str = "openai") -> bool:
    """Check if required LLM packages are installed.
    
    Args:
        provider: LLM provider name
        
    Returns:
        True if dependencies are available
    """
    try:
        if provider == "openai":
            import openai
            return True
        elif provider == "anthropic":
            import anthropic
            return True
        return True
    except ImportError:
        return False
