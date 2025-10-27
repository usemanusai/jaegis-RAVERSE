import os
import logging

logger = logging.getLogger(__name__)


class DisassemblyAnalysisAgent:
    """Agent responsible for obtaining AI-assisted disassembly/analysis context."""

    def __init__(self, openrouter_agent):
        """
        Initialize the Disassembly & Analysis Agent with the Orchestrating Agent.

        :param openrouter_agent: Instance of the Orchestrating Agent.
        """
        self.openrouter_agent = openrouter_agent

    def disassemble(self, binary_path):
        """
        Disassemble the binary file using OpenRouter.

        :param binary_path: Path to the binary file.
        :return: Disassembled output as a string.
        """
        try:
            if not os.path.exists(binary_path):
                logger.error(f"File not found: {binary_path}")
                return None
            if not os.access(binary_path, os.R_OK):
                logger.error(f"File not readable: {binary_path}")
                return None
            # MCP-guided prompt: Based on binary patching best practices research
            # (see docs/BINARY_PATCHING_BEST_PRACTICES.md)
            # Emphasizes PE/ELF format awareness, instruction boundaries, and specific patterns
            prompt = f"""Analyze the binary file at path: {binary_path}

CONTEXT: This is a password-protected executable (PE/ELF format). You need to locate the password verification logic for patching.

INSTRUCTIONS:
1. Identify string comparison operations:
   - x86: CMP, TEST instructions
   - Function calls: strcmp, memcmp, strncmp
   - Look for patterns like: CMP [register], [value] followed by conditional jump

2. Locate conditional jump instructions:
   - Common opcodes: JE (0x74), JNE (0x75), JZ, JNZ
   - Must be at instruction boundary (not mid-instruction)
   - Typically 2-byte short jump or 5-6 byte near jump

3. Extract memory addresses:
   - Virtual addresses (VA) in hexadecimal with '0x' prefix
   - Ensure addresses fall within executable sections
   - Note: VA-to-file-offset conversion will be handled separately

FORMAT: Respond ONLY with valid JSON (no explanatory text):
{{
  "compare_addr": "0x401234",
  "jump_addr": "0x401240",
  "opcode": "74",
  "analysis": "CMP instruction at 0x401234, JE at 0x401240"
}}

VALIDATION:
- All addresses must be valid hex: 0x[0-9a-fA-F]+
- Opcode must be 2-digit hex: [0-9a-fA-F]{{2}}
- Addresses should be realistic for typical executables (0x400000-0x500000 range for PE)"""
            response = self.openrouter_agent.call_openrouter(prompt)
            return response['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"Error during disassembly: {e}")
            return None

