import re
import json
import logging

logger = logging.getLogger(__name__)


class LogicIdentificationMappingAgent:
    """Agent that extracts comparison and jump addresses and opcode from analysis output."""

    def __init__(self, openrouter_agent):
        """
        Initialize the Logic Identification & Mapping Agent with the Orchestrating Agent.

        :param openrouter_agent: Instance of the Orchestrating Agent.
        """
        # Ensure there's a usable call_openrouter for tests and usage
        if openrouter_agent is None:
            class _Stub:
                def call_openrouter(self, prompt):
                    return {"choices": [{"message": {"content": ""}}]}
            openrouter_agent = _Stub()
        elif not hasattr(openrouter_agent, "call_openrouter"):
            setattr(openrouter_agent, "call_openrouter", lambda prompt: {"choices": [{"message": {"content": ""}}]})
        self.openrouter_agent = openrouter_agent

    def identify_logic(self, disassembly_output):
        """
        Identify the logic and map the conditional jump instruction using OpenRouter.

        :param disassembly_output: Disassembled output of the binary.
        :return: Dictionary containing compare_addr, jump_addr, and opcode.
        """
        try:
            sample_json = (
                '{\n'
                '  "compare_addr": "0x401234",\n'
                '  "jump_addr": "0x401240",\n'
                '  "opcode": "74"\n'
                '}'
            )
            # MCP-guided prompt: Enhanced with x86 opcode reference and instruction boundary awareness
            # (see docs/BINARY_PATCHING_BEST_PRACTICES.md Section 2: Conditional Jump Opcodes)
            prompt = (
                "Analyze this disassembly output to locate password verification logic:\n\n"
                f"{disassembly_output}\n\n"
                "TASK: Identify the comparison and conditional jump for password bypass patching.\n\n"
                "OPCODE REFERENCE (x86 Conditional Jumps):\n"
                "- JE/JZ (Jump if Equal/Zero): 0x74 (short), 0x0F 0x84 (near)\n"
                "- JNE/JNZ (Jump if Not Equal/Not Zero): 0x75 (short), 0x0F 0x85 (near)\n"
                "- JA (Jump if Above): 0x77 (short), 0x0F 0x87 (near)\n"
                "- JB (Jump if Below): 0x72 (short), 0x0F 0x82 (near)\n\n"
                "IDENTIFY:\n"
                "1. compare_addr: Address of string comparison (CMP, TEST, or strcmp/memcmp call)\n"
                "2. jump_addr: Address of conditional jump IMMEDIATELY following comparison\n"
                "3. opcode: Single-byte opcode for SHORT jump (e.g., '74' for JE, '75' for JNE)\n"
                "   - Use SHORT jump opcode only (2-byte instruction)\n"
                "   - For password bypass: typically invert JE→JNE (0x74→0x75) or vice versa\n\n"
                "CRITICAL: Ensure jump_addr is at an instruction boundary (not mid-instruction).\n\n"
                "Respond ONLY with valid JSON in this exact format:\n"
                f"{sample_json}\n\n"
                "Do not include any explanatory text outside the JSON object."
            )
            response = self.openrouter_agent.call_openrouter(prompt)
            content = response['choices'][0]['message']['content']

            # Try JSON parsing first
            try:
                json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(0))
                    return {
                        'compare_addr': data.get('compare_addr', '0x0000'),
                        'jump_addr': data.get('jump_addr', '0x0000'),
                        'opcode': data.get('opcode', '00')
                    }
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON response, falling back to regex")

            # Fallback to existing regex parsing
            compare_addr, jump_addr, opcode = self.parse_response(content)
            return {'compare_addr': compare_addr, 'jump_addr': jump_addr, 'opcode': opcode}
        except Exception as e:
            logger.error(f"Error during logic identification: {e}")
            return None

    def _validate_hex_addr(self, s: str) -> bool:
        return bool(re.fullmatch(r"0x[0-9a-fA-F]+", s or ""))

    def _validate_opcode_byte(self, s: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{2}", s or ""))

    def parse_response(self, content):
        """
        Parse the response from OpenRouter to extract critical information.

        :param content: Response content from OpenRouter.
        :return: Tuple containing compare_addr, jump_addr, and opcode.
        """
        # Example parsing logic (this should be adapted to the actual response format)
        compare_addr_match = re.search(r'compare_addr: (0x[0-9a-fA-F]+)', content or "")
        jump_addr_match = re.search(r'jump_addr: (0x[0-9a-fA-F]+)', content or "")
        opcode_match = re.search(r'opcode: ([0-9a-fA-F]+)', content or "")

        compare_addr = compare_addr_match.group(1) if compare_addr_match else "0x0000"
        jump_addr = jump_addr_match.group(1) if jump_addr_match else "0x0000"
        opcode = opcode_match.group(1) if opcode_match else "00"

        # Validate formats; fall back to safe defaults
        if not self._validate_hex_addr(compare_addr):
            logger.warning("Invalid compare_addr format; using default 0x0000")
            compare_addr = "0x0000"
        if not self._validate_hex_addr(jump_addr):
            logger.warning("Invalid jump_addr format; using default 0x0000")
            jump_addr = "0x0000"
        if not self._validate_opcode_byte(opcode):
            logger.warning("Invalid opcode format; using default 00")
            opcode = "00"

        return compare_addr, jump_addr, opcode

