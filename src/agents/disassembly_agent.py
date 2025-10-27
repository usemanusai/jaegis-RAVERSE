"""
Disassembly Agent for RAVERSE
Date: October 25, 2025

This module provides specialized disassembly capabilities using capstone.
"""

from typing import List, Dict, Optional, Tuple
import capstone
from utils.binary_utils import BinaryAnalyzer
from utils.database import DatabaseManager
from utils.metrics import metrics_collector
import time


class DisassemblyAgent:
    """
    Specialized agent for binary disassembly and code extraction.
    """
    
    def __init__(
        self,
        binary_analyzer: BinaryAnalyzer,
        db_manager: Optional[DatabaseManager] = None
    ):
        """
        Initialize disassembly agent.
        
        Args:
            binary_analyzer: Binary analyzer instance
            db_manager: Optional database manager
        """
        self.analyzer = binary_analyzer
        self.db = db_manager
        
        # Initialize capstone disassembler
        if self.analyzer.arch == "x86":
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:  # x64
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        self.cs.detail = True
    
    def disassemble_at_address(
        self,
        address: int,
        num_instructions: int = 20
    ) -> List[Dict]:
        """
        Disassemble instructions starting at address.
        
        Args:
            address: Starting address
            num_instructions: Number of instructions to disassemble
            
        Returns:
            List of disassembled instructions
        """
        # Read bytes from address
        offset = self.analyzer.va_to_offset(address)
        code = self.analyzer.binary_data[offset:offset + num_instructions * 15]  # Max 15 bytes per instruction
        
        instructions = []
        count = 0
        
        for instr in self.cs.disasm(code, address):
            if count >= num_instructions:
                break
            
            instructions.append({
                "address": f"0x{instr.address:x}",
                "mnemonic": instr.mnemonic,
                "op_str": instr.op_str,
                "bytes": instr.bytes.hex(),
                "size": instr.size,
                "full": f"{instr.mnemonic} {instr.op_str}"
            })
            count += 1
        
        return instructions
    
    def disassemble_function(
        self,
        start_address: int,
        max_instructions: int = 100
    ) -> Dict:
        """
        Disassemble an entire function.
        
        Args:
            start_address: Function start address
            max_instructions: Maximum instructions to disassemble
            
        Returns:
            Function disassembly with metadata
        """
        instructions = []
        current_address = start_address
        offset = self.analyzer.va_to_offset(start_address)
        
        # Read larger chunk for function
        code = self.analyzer.binary_data[offset:offset + max_instructions * 15]
        
        for instr in self.cs.disasm(code, start_address):
            instructions.append({
                "address": f"0x{instr.address:x}",
                "mnemonic": instr.mnemonic,
                "op_str": instr.op_str,
                "bytes": instr.bytes.hex(),
                "size": instr.size,
                "full": f"{instr.mnemonic} {instr.op_str}"
            })
            
            # Stop at RET instruction
            if instr.mnemonic == "ret":
                break
            
            if len(instructions) >= max_instructions:
                break
        
        return {
            "start_address": f"0x{start_address:x}",
            "num_instructions": len(instructions),
            "instructions": instructions,
            "size_bytes": sum(i["size"] for i in instructions)
        }
    
    def identify_code_sections(self) -> List[Dict]:
        """
        Identify executable code sections in binary.

        Returns normalized section information for both PE and ELF formats.

        Returns:
            List of dictionaries containing:
                - name: Section name
                - start_address: Virtual address where section is loaded
                - size: Size of section in bytes
                - file_offset: Offset in file where section data starts
                - characteristics/flags: Section attributes (format-specific)

        Raises:
            ValueError: If binary data is not loaded

        Example:
            >>> agent = DisassemblyAgent(analyzer)
            >>> sections = agent.identify_code_sections()
            >>> print(sections[0]['name'])
            '.text'
        """
        import logging
        logger = logging.getLogger(__name__)

        if not self.analyzer.binary_data:
            raise ValueError("Binary data not loaded")

        sections = []

        if hasattr(self.analyzer, 'pe') and self.analyzer.pe:
            # PE file
            logger.debug("identifying_pe_code_sections")
            for section in self.analyzer.pe.sections:
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    sections.append({
                        "name": section.Name.decode().rstrip('\x00'),
                        "start_address": self.analyzer.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
                        "size": section.Misc_VirtualSize,
                        "file_offset": section.PointerToRawData,
                        "characteristics": f"0x{section.Characteristics:x}",
                        # Legacy fields for backward compatibility
                        "virtual_address": f"0x{section.VirtualAddress:x}",
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_address": f"0x{section.PointerToRawData:x}",
                        "raw_size": section.SizeOfRawData
                    })

        elif hasattr(self.analyzer, 'elf') and self.analyzer.elf:
            # ELF file
            logger.debug("identifying_elf_code_sections")
            for section in self.analyzer.elf.iter_sections():
                if section['sh_flags'] & 0x4:  # SHF_EXECINSTR
                    sections.append({
                        "name": section.name,
                        "start_address": section['sh_addr'],
                        "size": section['sh_size'],
                        "file_offset": section['sh_offset'],
                        "flags": f"0x{section['sh_flags']:x}",
                        # Legacy fields for backward compatibility
                        "virtual_address": f"0x{section['sh_addr']:x}",
                        "offset": f"0x{section['sh_offset']:x}"
                    })
        else:
            logger.warning("unknown_binary_format",
                          has_pe=hasattr(self.analyzer, 'pe'),
                          has_elf=hasattr(self.analyzer, 'elf'))

        logger.info("identified_code_sections", count=len(sections))
        return sections
    
    def extract_functions(self) -> List[Dict]:
        """
        Extract function boundaries (basic heuristic).
        
        Returns:
            List of detected functions
        """
        functions = []
        sections = self.identify_code_sections()
        
        for section in sections:
            # Parse addresses
            if "virtual_address" in section:
                start_va = int(section["virtual_address"], 16)
                size = section.get("virtual_size") or section.get("size", 0)
                
                # Simple heuristic: look for function prologues
                offset = self.analyzer.va_to_offset(start_va)
                code = self.analyzer.binary_data[offset:offset + size]
                
                # Common x86/x64 function prologues
                prologues = [
                    b'\x55\x89\xe5',  # push ebp; mov ebp, esp
                    b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp (x64)
                    b'\x48\x83\xec',  # sub rsp, imm8 (x64)
                ]
                
                for i in range(0, len(code) - 10, 4):
                    for prologue in prologues:
                        if code[i:i+len(prologue)] == prologue:
                            func_va = start_va + i
                            functions.append({
                                "address": f"0x{func_va:x}",
                                "section": section["name"],
                                "prologue": prologue.hex()
                            })
                            break
        
        return functions[:100]  # Limit to first 100 functions
    
    def find_string_references(self, target_string: str) -> List[Dict]:
        """
        Find references to a string in code by scanning executable sections.

        Locates all occurrences of the target string in the binary, then scans
        all executable code sections to find instructions that reference these
        string addresses. Supports both direct references (e.g., lea, mov) and
        indirect references through data sections.

        Args:
            target_string: String to search for in the binary

        Returns:
            List of dictionaries containing:
                - string_address: Virtual address of the string
                - string_offset: File offset of the string
                - string: The actual string content
                - xrefs: List of code addresses that reference this string
                - xref_instructions: List of disassembled instructions referencing the string

        Raises:
            ValueError: If binary data is not loaded

        Example:
            >>> agent = DisassemblyAgent(analyzer)
            >>> refs = agent.find_string_references("password")
            >>> print(refs[0]['xrefs'])
            ['0x401000', '0x401234']
        """
        import logging
        logger = logging.getLogger(__name__)

        if not self.analyzer.binary_data:
            raise ValueError("Binary data not loaded")

        logger.info("finding_string_references", target=target_string)
        start_time = time.time()

        references = []
        target_bytes = target_string.encode()
        data = self.analyzer.binary_data

        # Step 1: Find all occurrences of the string in the binary
        string_locations = []
        offset = 0
        while True:
            offset = data.find(target_bytes, offset)
            if offset == -1:
                break

            try:
                string_va = self.analyzer.offset_to_va(offset)
                string_locations.append({
                    "va": string_va,
                    "offset": offset,
                    "string": target_string
                })
            except Exception as e:
                logger.warning(f"Failed to convert offset to VA: {e}", offset=offset)

            offset += len(target_bytes)

        if not string_locations:
            logger.info("no_string_occurrences_found", target=target_string)
            return references

        logger.info("found_string_occurrences", count=len(string_locations))

        # Step 2: Get all executable code sections
        try:
            code_sections = self.identify_code_sections()
        except Exception as e:
            logger.error("failed_to_identify_code_sections", error=str(e))
            # Fallback: return string locations without xrefs
            for loc in string_locations:
                references.append({
                    "string_address": f"0x{loc['va']:x}",
                    "string_offset": f"0x{loc['offset']:x}",
                    "string": loc['string'],
                    "xrefs": [],
                    "xref_instructions": []
                })
            return references

        # Step 3: Scan each code section for references to string addresses
        for loc in string_locations:
            xrefs = []
            xref_instructions = []

            for section in code_sections:
                try:
                    # Disassemble the entire code section
                    section_start = section['start_address']
                    section_size = section['size']
                    section_offset = section['file_offset']

                    # Read code bytes
                    code_bytes = data[section_offset:section_offset + section_size]

                    # Disassemble and look for references
                    for insn in self.cs.disasm(code_bytes, section_start):
                        # Check if instruction references the string address
                        if self._instruction_references_address(insn, loc['va']):
                            xrefs.append(f"0x{insn.address:x}")
                            xref_instructions.append({
                                "address": f"0x{insn.address:x}",
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                                "bytes": insn.bytes.hex()
                            })

                except Exception as e:
                    logger.warning(f"Error scanning section {section.get('name', 'unknown')}: {e}")
                    continue

            references.append({
                "string_address": f"0x{loc['va']:x}",
                "string_offset": f"0x{loc['offset']:x}",
                "string": loc['string'],
                "xrefs": xrefs,
                "xref_instructions": xref_instructions
            })

        duration = time.time() - start_time
        logger.info("string_references_found",
                   string_count=len(references),
                   total_xrefs=sum(len(r['xrefs']) for r in references),
                   duration=duration)
        metrics_collector.record_operation_duration("find_string_references", duration)

        return references

    def _instruction_references_address(self, insn: capstone.CsInsn, target_address: int) -> bool:
        """
        Check if an instruction references a specific address.

        Args:
            insn: Capstone instruction object
            target_address: Target virtual address to check for

        Returns:
            True if instruction references the address, False otherwise
        """
        # Check immediate operands
        if insn.operands:
            for op in insn.operands:
                # Check immediate values
                if op.type == capstone.x86.X86_OP_IMM:
                    if op.imm == target_address:
                        return True
                # Check memory operands with displacement
                elif op.type == capstone.x86.X86_OP_MEM:
                    if op.mem.disp == target_address:
                        return True

        # Check for RIP-relative addressing (x64)
        # Calculate effective address for RIP-relative instructions
        if insn.operands:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    # RIP-relative: base is RIP register
                    if op.mem.base == capstone.x86.X86_REG_RIP:
                        # Effective address = RIP + displacement
                        # RIP points to next instruction
                        effective_addr = insn.address + insn.size + op.mem.disp
                        if effective_addr == target_address:
                            return True

        return False
    
    def analyze_control_flow(
        self,
        start_address: int,
        max_depth: int = 50
    ) -> Dict:
        """
        Analyze control flow from a starting address.
        
        Args:
            start_address: Starting address
            max_depth: Maximum depth to analyze
            
        Returns:
            Control flow graph information
        """
        visited = set()
        branches = []
        calls = []
        
        def analyze_block(address: int, depth: int = 0):
            if depth >= max_depth or address in visited:
                return
            
            visited.add(address)
            instructions = self.disassemble_at_address(address, 20)
            
            for instr in instructions:
                mnemonic = instr["mnemonic"]
                
                # Track branches
                if mnemonic.startswith("j"):  # Jump instructions
                    branches.append({
                        "from": instr["address"],
                        "type": mnemonic,
                        "operand": instr["op_str"]
                    })
                
                # Track calls
                elif mnemonic == "call":
                    calls.append({
                        "from": instr["address"],
                        "target": instr["op_str"]
                    })
                
                # Stop at return
                elif mnemonic == "ret":
                    break
        
        analyze_block(start_address)
        
        return {
            "start_address": f"0x{start_address:x}",
            "blocks_analyzed": len(visited),
            "branches": branches,
            "calls": calls
        }
    
    def get_disassembly_text(
        self,
        instructions: List[Dict]
    ) -> str:
        """
        Convert instruction list to formatted text.
        
        Args:
            instructions: List of instruction dicts
            
        Returns:
            Formatted disassembly text
        """
        lines = []
        for instr in instructions:
            addr = instr["address"]
            full = instr["full"]
            bytes_hex = instr["bytes"]
            lines.append(f"{addr}:  {bytes_hex:20s}  {full}")
        
        return "\n".join(lines)
    
    def cache_disassembly(
        self,
        binary_id: int,
        instructions: List[Dict]
    ):
        """
        Cache disassembly results in database.
        
        Args:
            binary_id: Binary ID in database
            instructions: List of instructions to cache
        """
        if not self.db:
            return
        
        start_time = time.time()
        
        for instr in instructions:
            query = """
                INSERT INTO raverse.disassembly_cache
                (binary_id, address, instruction, opcode, operands, disassembly_text, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (binary_id, address) DO NOTHING
            """
            
            self.db.execute_query(
                query,
                (
                    binary_id,
                    instr["address"],
                    instr["full"],
                    instr["mnemonic"],
                    instr["op_str"],
                    instr["full"],
                    {"bytes": instr["bytes"], "size": instr["size"]}
                )
            )
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('cache_disassembly', duration)

