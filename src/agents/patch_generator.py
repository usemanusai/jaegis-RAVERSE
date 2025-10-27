"""
Patch Generator Agent for RAVERSE
Date: October 25, 2025

This module provides automated patch generation with multiple strategies
and validation capabilities.
"""

import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import hashlib
from utils.binary_utils import BinaryAnalyzer
from utils.database import DatabaseManager
from utils.metrics import metrics_collector
import time


class PatchType(Enum):
    """Types of patches that can be applied."""
    NOP = "nop"  # Replace with NOP instructions
    JMP = "jmp"  # Modify jump instructions
    RET = "ret"  # Replace with return
    MOV = "mov"  # Modify move instructions
    XOR = "xor"  # XOR register with itself (set to 0)
    BRANCH_INVERT = "branch_invert"  # Invert conditional branch


@dataclass
class PatchStrategy:
    """Represents a patch strategy."""
    name: str
    patch_type: PatchType
    target_address: int
    original_bytes: bytes
    patched_bytes: bytes
    description: str
    confidence: float  # 0-1
    risks: List[str]
    metadata: Dict[str, Any]


class PatchGenerator:
    """
    Generates and applies binary patches with validation.
    """
    
    def __init__(
        self,
        binary_analyzer: BinaryAnalyzer,
        db_manager: Optional[DatabaseManager] = None
    ):
        """
        Initialize patch generator.
        
        Args:
            binary_analyzer: Binary analyzer instance
            db_manager: Optional database manager for storing strategies
        """
        self.analyzer = binary_analyzer
        self.db = db_manager
    
    def generate_nop_patch(
        self,
        address: int,
        num_bytes: int
    ) -> PatchStrategy:
        """
        Generate NOP patch strategy.
        
        Args:
            address: Target address
            num_bytes: Number of bytes to NOP
            
        Returns:
            PatchStrategy for NOPing instructions
        """
        original_bytes = self.analyzer.read_bytes(address, num_bytes)
        
        # x86/x64 NOP is 0x90
        patched_bytes = b'\x90' * num_bytes
        
        return PatchStrategy(
            name="NOP Replacement",
            patch_type=PatchType.NOP,
            target_address=address,
            original_bytes=original_bytes,
            patched_bytes=patched_bytes,
            description=f"Replace {num_bytes} bytes at 0x{address:x} with NOP instructions",
            confidence=0.9,
            risks=["May cause unexpected behavior if NOPed code is critical"],
            metadata={"num_bytes": num_bytes}
        )
    
    def generate_jmp_patch(
        self,
        address: int,
        target_address: int
    ) -> PatchStrategy:
        """
        Generate unconditional jump patch.
        
        Args:
            address: Address to patch
            target_address: Address to jump to
            
        Returns:
            PatchStrategy for jump modification
        """
        original_bytes = self.analyzer.read_bytes(address, 5)
        
        # Calculate relative offset for JMP
        offset = target_address - (address + 5)
        
        # x86/x64 JMP rel32: E9 [offset]
        patched_bytes = b'\xE9' + struct.pack('<i', offset)
        
        return PatchStrategy(
            name="Unconditional Jump",
            patch_type=PatchType.JMP,
            target_address=address,
            original_bytes=original_bytes,
            patched_bytes=patched_bytes,
            description=f"Replace instruction at 0x{address:x} with JMP to 0x{target_address:x}",
            confidence=0.85,
            risks=["May skip important code", "Offset calculation must be precise"],
            metadata={"target": target_address, "offset": offset}
        )
    
    def generate_ret_patch(self, address: int) -> PatchStrategy:
        """
        Generate return patch strategy.
        
        Args:
            address: Address to patch
            
        Returns:
            PatchStrategy for early return
        """
        original_bytes = self.analyzer.read_bytes(address, 1)
        
        # x86/x64 RET: C3
        patched_bytes = b'\xC3'
        
        return PatchStrategy(
            name="Early Return",
            patch_type=PatchType.RET,
            target_address=address,
            original_bytes=original_bytes,
            patched_bytes=patched_bytes,
            description=f"Replace instruction at 0x{address:x} with RET",
            confidence=0.8,
            risks=["May cause stack imbalance", "May skip cleanup code"],
            metadata={}
        )
    
    def generate_xor_patch(
        self,
        address: int,
        register: str = "eax"
    ) -> PatchStrategy:
        """
        Generate XOR register patch (sets register to 0).
        
        Args:
            address: Address to patch
            register: Register to XOR (default: eax)
            
        Returns:
            PatchStrategy for XOR operation
        """
        original_bytes = self.analyzer.read_bytes(address, 2)
        
        # x86/x64 XOR EAX, EAX: 31 C0
        # XOR EBX, EBX: 31 DB
        # XOR ECX, ECX: 31 C9
        register_codes = {
            "eax": b'\x31\xC0',
            "ebx": b'\x31\xDB',
            "ecx": b'\x31\xC9',
            "edx": b'\x31\xD2'
        }
        
        patched_bytes = register_codes.get(register.lower(), b'\x31\xC0')
        
        return PatchStrategy(
            name=f"XOR {register.upper()}",
            patch_type=PatchType.XOR,
            target_address=address,
            original_bytes=original_bytes,
            patched_bytes=patched_bytes,
            description=f"Set {register.upper()} to 0 at 0x{address:x}",
            confidence=0.85,
            risks=["May affect subsequent operations using this register"],
            metadata={"register": register}
        )
    
    def generate_branch_invert_patch(self, address: int) -> PatchStrategy:
        """
        Generate conditional branch inversion patch.
        
        Args:
            address: Address of conditional jump
            
        Returns:
            PatchStrategy for inverting branch
        """
        original_bytes = self.analyzer.read_bytes(address, 2)
        
        # Common conditional jumps and their inverses
        inversions = {
            b'\x74': b'\x75',  # JE -> JNE
            b'\x75': b'\x74',  # JNE -> JE
            b'\x7C': b'\x7D',  # JL -> JGE
            b'\x7D': b'\x7C',  # JGE -> JL
            b'\x7E': b'\x7F',  # JLE -> JG
            b'\x7F': b'\x7E',  # JG -> JLE
        }
        
        opcode = original_bytes[0:1]
        inverted_opcode = inversions.get(opcode, opcode)
        patched_bytes = inverted_opcode + original_bytes[1:2]
        
        return PatchStrategy(
            name="Invert Conditional Branch",
            patch_type=PatchType.BRANCH_INVERT,
            target_address=address,
            original_bytes=original_bytes,
            patched_bytes=patched_bytes,
            description=f"Invert conditional jump at 0x{address:x}",
            confidence=0.9,
            risks=["May cause logic inversion", "Ensure correct branch identified"],
            metadata={"original_opcode": opcode.hex(), "inverted_opcode": inverted_opcode.hex()}
        )
    
    def generate_patch_strategies(
        self,
        analysis: Dict[str, Any]
    ) -> List[PatchStrategy]:
        """
        Generate multiple patch strategies based on analysis.
        
        Args:
            analysis: Analysis results from LLM or other agents
            
        Returns:
            List of patch strategies
        """
        strategies = []
        
        # Extract target addresses from analysis
        if "comparison_location" in analysis:
            addr = analysis["comparison_location"]
            if isinstance(addr, str):
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            
            # Generate multiple strategies for this location
            strategies.append(self.generate_nop_patch(addr, 6))
            strategies.append(self.generate_branch_invert_patch(addr))
            strategies.append(self.generate_xor_patch(addr))
        
        if "target_instructions" in analysis:
            for instr in analysis["target_instructions"]:
                if isinstance(instr, dict) and "address" in instr:
                    addr = instr["address"]
                    if isinstance(addr, str):
                        addr = int(addr, 16) if addr.startswith("0x") else int(addr)
                    
                    strategies.append(self.generate_nop_patch(addr, 2))
        
        return strategies
    
    def apply_patch(
        self,
        binary_data: bytes,
        strategy: PatchStrategy
    ) -> bytes:
        """
        Apply patch to binary data.
        
        Args:
            binary_data: Original binary data
            strategy: Patch strategy to apply
            
        Returns:
            Patched binary data
        """
        # Convert address to file offset
        offset = self.analyzer.va_to_offset(strategy.target_address)
        
        # Create mutable copy
        patched = bytearray(binary_data)
        
        # Apply patch
        patch_len = len(strategy.patched_bytes)
        patched[offset:offset + patch_len] = strategy.patched_bytes
        
        return bytes(patched)
    
    def validate_patch(
        self,
        original: bytes,
        patched: bytes,
        strategy: PatchStrategy
    ) -> Dict[str, Any]:
        """
        Validate that patch was applied correctly.
        
        Args:
            original: Original binary data
            patched: Patched binary data
            strategy: Patch strategy that was applied
            
        Returns:
            Validation results
        """
        offset = self.analyzer.va_to_offset(strategy.target_address)
        patch_len = len(strategy.patched_bytes)
        
        # Check that patch was applied
        patched_bytes = patched[offset:offset + patch_len]
        is_applied = patched_bytes == strategy.patched_bytes
        
        # Check that only target bytes were modified
        before = original[:offset]
        after = original[offset + patch_len:]
        
        before_unchanged = patched[:offset] == before
        after_unchanged = patched[offset + patch_len:] == after
        
        # Calculate hash
        patched_hash = hashlib.sha256(patched).hexdigest()
        
        return {
            "is_applied": is_applied,
            "before_unchanged": before_unchanged,
            "after_unchanged": after_unchanged,
            "patched_hash": patched_hash,
            "patch_location": f"0x{strategy.target_address:x}",
            "patch_size": patch_len,
            "success": is_applied and before_unchanged and after_unchanged
        }
    
    def store_strategy(self, strategy: PatchStrategy, success: bool):
        """
        Store patch strategy in database for learning.
        
        Args:
            strategy: Patch strategy
            success: Whether the strategy was successful
        """
        if not self.db:
            return
        
        start_time = time.time()
        
        # Check if strategy exists
        query = """
            SELECT id, success_count, failure_count
            FROM raverse.patch_strategies
            WHERE strategy_name = %s AND strategy_type = %s
        """
        
        result = self.db.execute_query(
            query,
            (strategy.name, strategy.patch_type.value)
        )
        
        if result:
            # Update existing strategy
            strategy_id = result[0]['id']
            if success:
                update_query = """
                    UPDATE raverse.patch_strategies
                    SET success_count = success_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """
            else:
                update_query = """
                    UPDATE raverse.patch_strategies
                    SET failure_count = failure_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """
            self.db.execute_query(update_query, (strategy_id,))
        else:
            # Insert new strategy
            insert_query = """
                INSERT INTO raverse.patch_strategies
                (strategy_name, strategy_type, description, success_count, failure_count, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            self.db.execute_query(
                insert_query,
                (
                    strategy.name,
                    strategy.patch_type.value,
                    strategy.description,
                    1 if success else 0,
                    0 if success else 1,
                    strategy.metadata
                )
            )
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('store_strategy', duration)

