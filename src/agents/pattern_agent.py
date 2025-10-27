"""
Pattern Recognition Agent for RAVERSE
Date: October 25, 2025

This module provides pattern recognition for identifying password checks
and other security-relevant code patterns.
"""

from typing import List, Dict, Optional, Tuple
import re
from utils.semantic_search import SemanticSearchEngine
from agents.llm_agent import LLMAgent
from agents.disassembly_agent import DisassemblyAgent
from utils.metrics import metrics_collector


class PatternAgent:
    """
    Specialized agent for recognizing code patterns, especially password checks.
    """
    
    # Common password check patterns
    PASSWORD_CHECK_PATTERNS = [
        # String comparison patterns
        {
            "name": "strcmp_pattern",
            "instructions": ["call.*strcmp", "test.*eax", "j[ne].*"],
            "confidence": 0.9,
            "description": "Standard strcmp password check"
        },
        {
            "name": "memcmp_pattern",
            "instructions": ["call.*memcmp", "test.*eax", "j[ne].*"],
            "confidence": 0.9,
            "description": "Memory comparison password check"
        },
        # Manual comparison patterns
        {
            "name": "byte_compare_loop",
            "instructions": ["mov.*byte", "cmp.*", "jne.*", "inc.*", "loop.*"],
            "confidence": 0.8,
            "description": "Byte-by-byte comparison loop"
        },
        # Hash comparison patterns
        {
            "name": "hash_compare",
            "instructions": ["call.*(md5|sha|hash)", "cmp.*", "je.*"],
            "confidence": 0.85,
            "description": "Hash-based password verification"
        },
        # XOR/encryption patterns
        {
            "name": "xor_decrypt",
            "instructions": ["xor.*", "cmp.*", "je.*"],
            "confidence": 0.7,
            "description": "XOR-based password check"
        }
    ]
    
    def __init__(
        self,
        disassembly_agent: DisassemblyAgent,
        semantic_search: Optional[SemanticSearchEngine] = None,
        llm_agent: Optional[LLMAgent] = None
    ):
        """
        Initialize pattern agent.
        
        Args:
            disassembly_agent: Disassembly agent instance
            semantic_search: Optional semantic search engine
            llm_agent: Optional LLM agent for advanced analysis
        """
        self.disasm = disassembly_agent
        self.semantic_search = semantic_search
        self.llm = llm_agent
    
    def _match_pattern(
        self,
        instructions: List[Dict],
        pattern: Dict
    ) -> Optional[Dict]:
        """
        Check if instructions match a pattern.
        
        Args:
            instructions: List of instruction dicts
            pattern: Pattern to match
            
        Returns:
            Match result if found, None otherwise
        """
        pattern_instrs = pattern["instructions"]
        instr_text = [i["full"].lower() for i in instructions]
        
        # Simple sequential pattern matching
        matches = []
        for i in range(len(instr_text)):
            matched = True
            for j, pat in enumerate(pattern_instrs):
                if i + j >= len(instr_text):
                    matched = False
                    break
                if not re.search(pat, instr_text[i + j]):
                    matched = False
                    break
            
            if matched:
                matches.append({
                    "start_index": i,
                    "end_index": i + len(pattern_instrs),
                    "matched_instructions": instructions[i:i + len(pattern_instrs)]
                })
        
        if matches:
            return {
                "pattern_name": pattern["name"],
                "description": pattern["description"],
                "confidence": pattern["confidence"],
                "matches": matches
            }
        
        return None
    
    def identify_password_checks(
        self,
        start_address: int,
        num_instructions: int = 50
    ) -> List[Dict]:
        """
        Identify password check patterns in code.
        
        Args:
            start_address: Starting address to analyze
            num_instructions: Number of instructions to analyze
            
        Returns:
            List of identified password check patterns
        """
        # Disassemble code
        instructions = self.disasm.disassemble_at_address(
            start_address,
            num_instructions
        )
        
        # Check against known patterns
        identified = []
        for pattern in self.PASSWORD_CHECK_PATTERNS:
            match = self._match_pattern(instructions, pattern)
            if match:
                identified.append(match)
        
        # Use LLM for additional analysis if available
        if self.llm and identified:
            disasm_text = self.disasm.get_disassembly_text(instructions)
            llm_analysis = self.llm.identify_password_check(disasm_text)
            
            # Merge LLM analysis with pattern matching
            for item in identified:
                item["llm_analysis"] = llm_analysis
        
        return identified
    
    def find_similar_patterns(
        self,
        code_snippet: str,
        limit: int = 10
    ) -> List[Dict]:
        """
        Find similar code patterns using semantic search.
        
        Args:
            code_snippet: Code snippet to find similar patterns for
            limit: Maximum number of results
            
        Returns:
            List of similar patterns
        """
        if not self.semantic_search:
            return []
        
        return self.semantic_search.find_similar_code(
            code_snippet,
            limit=limit,
            similarity_threshold=0.7
        )
    
    def analyze_function_for_patterns(
        self,
        function_address: int
    ) -> Dict:
        """
        Analyze entire function for security patterns.
        
        Args:
            function_address: Function start address
            
        Returns:
            Comprehensive pattern analysis
        """
        # Disassemble function
        function_data = self.disasm.disassemble_function(function_address)
        instructions = function_data["instructions"]
        
        # Identify patterns
        password_checks = []
        for i in range(0, len(instructions), 10):
            chunk = instructions[i:i + 20]
            for pattern in self.PASSWORD_CHECK_PATTERNS:
                match = self._match_pattern(chunk, pattern)
                if match:
                    password_checks.append(match)
        
        # Analyze control flow
        control_flow = self.disasm.analyze_control_flow(function_address)
        
        # Count instruction types
        instruction_stats = {}
        for instr in instructions:
            mnemonic = instr["mnemonic"]
            instruction_stats[mnemonic] = instruction_stats.get(mnemonic, 0) + 1
        
        # Identify suspicious patterns
        suspicious = []
        
        # Check for anti-debugging
        if "rdtsc" in instruction_stats or "cpuid" in instruction_stats:
            suspicious.append({
                "type": "anti_debug",
                "description": "Timing-based anti-debugging detected"
            })
        
        # Check for obfuscation
        if instruction_stats.get("xor", 0) > 5:
            suspicious.append({
                "type": "obfuscation",
                "description": "Heavy XOR usage suggests obfuscation"
            })
        
        # Check for string operations
        string_ops = sum([
            instruction_stats.get("movs", 0),
            instruction_stats.get("cmps", 0),
            instruction_stats.get("scas", 0)
        ])
        
        if string_ops > 3:
            suspicious.append({
                "type": "string_operations",
                "description": "String operations detected (possible password check)"
            })
        
        return {
            "function_address": f"0x{function_address:x}",
            "num_instructions": len(instructions),
            "password_checks": password_checks,
            "control_flow": control_flow,
            "instruction_stats": instruction_stats,
            "suspicious_patterns": suspicious
        }
    
    def extract_comparison_values(
        self,
        instructions: List[Dict]
    ) -> List[Dict]:
        """
        Extract comparison values from instructions.
        
        Args:
            instructions: List of instruction dicts
            
        Returns:
            List of comparison values found
        """
        comparisons = []
        
        for instr in instructions:
            mnemonic = instr["mnemonic"]
            op_str = instr["op_str"]
            
            if mnemonic == "cmp":
                # Extract operands
                operands = op_str.split(",")
                if len(operands) == 2:
                    comparisons.append({
                        "address": instr["address"],
                        "operand1": operands[0].strip(),
                        "operand2": operands[1].strip(),
                        "type": "cmp"
                    })
            
            elif mnemonic == "test":
                operands = op_str.split(",")
                if len(operands) == 2:
                    comparisons.append({
                        "address": instr["address"],
                        "operand1": operands[0].strip(),
                        "operand2": operands[1].strip(),
                        "type": "test"
                    })
        
        return comparisons
    
    def identify_target_addresses(
        self,
        analysis: Dict
    ) -> List[int]:
        """
        Identify target addresses for patching based on analysis.
        
        Args:
            analysis: Pattern analysis results
            
        Returns:
            List of target addresses
        """
        targets = []
        
        # Extract from password checks
        if "password_checks" in analysis:
            for check in analysis["password_checks"]:
                if "matches" in check:
                    for match in check["matches"]:
                        if "matched_instructions" in match:
                            # Target the comparison instruction
                            for instr in match["matched_instructions"]:
                                if instr["mnemonic"] in ["cmp", "test", "je", "jne"]:
                                    addr = int(instr["address"], 16)
                                    targets.append(addr)
        
        # Extract from control flow
        if "control_flow" in analysis and "branches" in analysis["control_flow"]:
            for branch in analysis["control_flow"]["branches"]:
                addr = int(branch["from"], 16)
                targets.append(addr)
        
        # Remove duplicates and sort
        targets = sorted(list(set(targets)))
        
        return targets
    
    def score_pattern_confidence(
        self,
        pattern_results: List[Dict]
    ) -> float:
        """
        Calculate overall confidence score for pattern matches.
        
        Args:
            pattern_results: List of pattern match results
            
        Returns:
            Overall confidence score (0-1)
        """
        if not pattern_results:
            return 0.0
        
        # Weight by confidence and number of matches
        total_score = 0.0
        total_weight = 0.0
        
        for result in pattern_results:
            confidence = result.get("confidence", 0.5)
            num_matches = len(result.get("matches", []))
            
            weight = num_matches
            total_score += confidence * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return total_score / total_weight
    
    def generate_pattern_report(
        self,
        analysis: Dict
    ) -> str:
        """
        Generate human-readable pattern analysis report.
        
        Args:
            analysis: Pattern analysis results
            
        Returns:
            Formatted report text
        """
        lines = []
        lines.append("=" * 60)
        lines.append("PATTERN ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append("")
        
        lines.append(f"Function: {analysis.get('function_address', 'Unknown')}")
        lines.append(f"Instructions: {analysis.get('num_instructions', 0)}")
        lines.append("")
        
        # Password checks
        password_checks = analysis.get("password_checks", [])
        lines.append(f"Password Checks Found: {len(password_checks)}")
        for i, check in enumerate(password_checks, 1):
            lines.append(f"\n  Check #{i}:")
            lines.append(f"    Pattern: {check.get('pattern_name', 'Unknown')}")
            lines.append(f"    Description: {check.get('description', 'N/A')}")
            lines.append(f"    Confidence: {check.get('confidence', 0):.2%}")
        
        lines.append("")
        
        # Suspicious patterns
        suspicious = analysis.get("suspicious_patterns", [])
        if suspicious:
            lines.append(f"Suspicious Patterns: {len(suspicious)}")
            for pattern in suspicious:
                lines.append(f"  - {pattern.get('type', 'Unknown')}: {pattern.get('description', 'N/A')}")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)

