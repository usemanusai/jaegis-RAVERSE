"""
Validation Agent for RAVERSE
Date: October 25, 2025

This module provides validation capabilities for patched binaries.
"""

from typing import Dict, List, Optional, Tuple
import hashlib
import subprocess
import os
import tempfile
from utils.binary_utils import BinaryAnalyzer
from agents.disassembly_agent import DisassemblyAgent
from utils.metrics import metrics_collector


class ValidationAgent:
    """
    Specialized agent for validating patched binaries.
    """
    
    def __init__(
        self,
        binary_analyzer: BinaryAnalyzer,
        disassembly_agent: DisassemblyAgent
    ):
        """
        Initialize validation agent.
        
        Args:
            binary_analyzer: Binary analyzer instance
            disassembly_agent: Disassembly agent instance
        """
        self.analyzer = binary_analyzer
        self.disasm = disassembly_agent
    
    def validate_patch_integrity(
        self,
        original: bytes,
        patched: bytes,
        patch_address: int,
        patch_size: int
    ) -> Dict:
        """
        Validate that patch was applied correctly without corruption.
        
        Args:
            original: Original binary data
            patched: Patched binary data
            patch_address: Address where patch was applied
            patch_size: Size of patch in bytes
            
        Returns:
            Validation results
        """
        # Convert VA to offset
        offset = self.analyzer.va_to_offset(patch_address)
        
        # Check sizes match
        if len(original) != len(patched):
            return {
                "valid": False,
                "error": "Binary size mismatch",
                "original_size": len(original),
                "patched_size": len(patched)
            }
        
        # Check that only patch location was modified
        before_patch = original[:offset]
        after_patch = original[offset + patch_size:]
        
        before_unchanged = patched[:offset] == before_patch
        after_unchanged = patched[offset + patch_size:] == after_patch
        
        # Calculate hashes
        original_hash = hashlib.sha256(original).hexdigest()
        patched_hash = hashlib.sha256(patched).hexdigest()
        
        # Check patch location
        patch_bytes = patched[offset:offset + patch_size]
        
        return {
            "valid": before_unchanged and after_unchanged,
            "before_unchanged": before_unchanged,
            "after_unchanged": after_unchanged,
            "original_hash": original_hash,
            "patched_hash": patched_hash,
            "patch_location": f"0x{patch_address:x}",
            "patch_size": patch_size,
            "patch_bytes": patch_bytes.hex()
        }
    
    def validate_pe_structure(self, binary_data: bytes) -> Dict:
        """
        Validate PE file structure after patching.
        
        Args:
            binary_data: Patched binary data
            
        Returns:
            PE structure validation results
        """
        try:
            import pefile
            pe = pefile.PE(data=binary_data)
            
            # Check basic PE structure
            is_valid = True
            errors = []
            warnings = []
            
            # Verify DOS header
            if pe.DOS_HEADER.e_magic != 0x5A4D:  # "MZ"
                is_valid = False
                errors.append("Invalid DOS header magic")
            
            # Verify PE signature
            if pe.NT_HEADERS.Signature != 0x4550:  # "PE"
                is_valid = False
                errors.append("Invalid PE signature")
            
            # Check sections
            for section in pe.sections:
                # Verify section alignment
                if section.VirtualAddress % pe.OPTIONAL_HEADER.SectionAlignment != 0:
                    warnings.append(f"Section {section.Name.decode().rstrip(chr(0))} not aligned")
            
            # Verify checksum (optional)
            calculated_checksum = pe.generate_checksum()
            stored_checksum = pe.OPTIONAL_HEADER.CheckSum
            
            if stored_checksum != 0 and calculated_checksum != stored_checksum:
                warnings.append(f"Checksum mismatch (stored: {stored_checksum}, calculated: {calculated_checksum})")
            
            return {
                "valid": is_valid,
                "file_type": "PE",
                "architecture": "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86",
                "num_sections": len(pe.sections),
                "entry_point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def validate_elf_structure(self, binary_data: bytes) -> Dict:
        """
        Validate ELF file structure after patching.
        
        Args:
            binary_data: Patched binary data
            
        Returns:
            ELF structure validation results
        """
        try:
            from elftools.elf.elffile import ELFFile
            from io import BytesIO
            
            elf = ELFFile(BytesIO(binary_data))
            
            is_valid = True
            errors = []
            warnings = []
            
            # Verify ELF magic
            if elf.e_ident_raw[:4] != b'\x7fELF':
                is_valid = False
                errors.append("Invalid ELF magic")
            
            # Check sections
            for section in elf.iter_sections():
                # Verify section alignment
                if section['sh_addralign'] > 0:
                    if section['sh_addr'] % section['sh_addralign'] != 0:
                        warnings.append(f"Section {section.name} not aligned")
            
            return {
                "valid": is_valid,
                "file_type": "ELF",
                "architecture": elf.get_machine_arch(),
                "num_sections": elf.num_sections(),
                "entry_point": f"0x{elf['e_entry']:x}",
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def validate_disassembly(
        self,
        patched_data: bytes,
        patch_address: int,
        num_instructions: int = 10
    ) -> Dict:
        """
        Validate that patched code disassembles correctly.
        
        Args:
            patched_data: Patched binary data
            patch_address: Address of patch
            num_instructions: Number of instructions to check
            
        Returns:
            Disassembly validation results
        """
        try:
            # Temporarily update analyzer with patched data
            original_data = self.analyzer.binary_data
            self.analyzer.binary_data = patched_data
            
            # Disassemble at patch location
            instructions = self.disasm.disassemble_at_address(
                patch_address,
                num_instructions
            )
            
            # Restore original data
            self.analyzer.binary_data = original_data
            
            # Check for valid instructions
            is_valid = len(instructions) > 0
            
            return {
                "valid": is_valid,
                "num_instructions": len(instructions),
                "instructions": instructions,
                "disassembly_text": self.disasm.get_disassembly_text(instructions)
            }
            
        except Exception as e:
            self.analyzer.binary_data = original_data
            return {
                "valid": False,
                "error": str(e)
            }
    
    def test_execution(
        self,
        patched_binary_path: str,
        test_args: Optional[List[str]] = None,
        timeout: int = 5
    ) -> Dict:
        """
        Test execution of patched binary (if safe).
        
        Args:
            patched_binary_path: Path to patched binary
            test_args: Optional command-line arguments
            timeout: Execution timeout in seconds
            
        Returns:
            Execution test results
        """
        if not os.path.exists(patched_binary_path):
            return {
                "executed": False,
                "error": "Binary file not found"
            }
        
        # Make executable (Unix)
        try:
            os.chmod(patched_binary_path, 0o755)
        except (OSError, PermissionError) as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to set executable permissions: path={patched_binary_path}, error={str(e)}, error_type={type(e).__name__}")
            metrics_collector.increment_counter("validation_chmod_failures")
        
        # Build command
        cmd = [patched_binary_path]
        if test_args:
            cmd.extend(test_args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                text=True
            )
            
            return {
                "executed": True,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timed_out": False
            }
            
        except subprocess.TimeoutExpired:
            return {
                "executed": True,
                "timed_out": True,
                "timeout": timeout
            }
        except Exception as e:
            return {
                "executed": False,
                "error": str(e)
            }
    
    def comprehensive_validation(
        self,
        original: bytes,
        patched: bytes,
        patch_address: int,
        patch_size: int,
        binary_path: Optional[str] = None
    ) -> Dict:
        """
        Perform comprehensive validation of patched binary.
        
        Args:
            original: Original binary data
            patched: Patched binary data
            patch_address: Patch address
            patch_size: Patch size
            binary_path: Optional path for execution testing
            
        Returns:
            Comprehensive validation results
        """
        results = {
            "timestamp": metrics_collector.record_database_query.__name__,
            "validations": {}
        }
        
        # 1. Patch integrity
        results["validations"]["integrity"] = self.validate_patch_integrity(
            original, patched, patch_address, patch_size
        )
        
        # 2. File structure
        if self.analyzer.file_type == "PE":
            results["validations"]["structure"] = self.validate_pe_structure(patched)
        elif self.analyzer.file_type == "ELF":
            results["validations"]["structure"] = self.validate_elf_structure(patched)
        
        # 3. Disassembly
        results["validations"]["disassembly"] = self.validate_disassembly(
            patched, patch_address
        )
        
        # 4. Execution (if path provided)
        if binary_path:
            # Write patched binary to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
                f.write(patched)
                temp_path = f.name
            
            try:
                results["validations"]["execution"] = self.test_execution(temp_path)
            finally:
                try:
                    os.unlink(temp_path)
                except (OSError, PermissionError, FileNotFoundError) as e:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning("failed_to_delete_temp_file",
                                  path=temp_path,
                                  error=str(e),
                                  error_type=type(e).__name__)
                    metrics_collector.increment_counter("validation_temp_cleanup_failures")
        
        # Overall validation
        all_valid = all(
            v.get("valid", False)
            for v in results["validations"].values()
            if "valid" in v
        )
        
        results["overall_valid"] = all_valid
        results["summary"] = self._generate_validation_summary(results)
        
        return results
    
    def _generate_validation_summary(self, results: Dict) -> str:
        """Generate human-readable validation summary."""
        lines = []
        lines.append("Validation Summary:")
        lines.append(f"  Overall: {'PASS' if results.get('overall_valid') else 'FAIL'}")
        
        for name, validation in results.get("validations", {}).items():
            status = "PASS" if validation.get("valid", False) else "FAIL"
            lines.append(f"  {name.capitalize()}: {status}")
            
            if "errors" in validation and validation["errors"]:
                for error in validation["errors"]:
                    lines.append(f"    ERROR: {error}")
            
            if "warnings" in validation and validation["warnings"]:
                for warning in validation["warnings"]:
                    lines.append(f"    WARNING: {warning}")
        
        return "\n".join(lines)

