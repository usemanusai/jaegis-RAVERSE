import os
import re
import shutil
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class PatchingExecutionAgent:
    """Agent that writes the patch opcode into the target binary at the jump address."""

    def __init__(self, openrouter_agent):
        """
        Initialize the Patching Execution Agent with the Orchestrating Agent.

        :param openrouter_agent: Instance of the Orchestrating Agent.
        """
        self.openrouter_agent = openrouter_agent

    def _validate_opcode_byte(self, s: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{2}", s or ""))

    def _validate_hex_addr(self, s: str) -> bool:
        return bool(re.fullmatch(r"0x[0-9a-fA-F]+", s or ""))

    def _va_to_file_offset_pe(self, binary_path: str, virtual_address: int) -> Optional[int]:
        """
        Convert virtual address to file offset for PE binaries.

        Args:
            binary_path: Path to the PE binary
            virtual_address: Virtual address to convert

        Returns:
            File offset or None if conversion fails
        """
        try:
            import pefile
            pe = pefile.PE(binary_path)

            # Use pefile's built-in method to convert RVA to file offset
            # First convert VA to RVA by subtracting image base
            rva = virtual_address - pe.OPTIONAL_HEADER.ImageBase

            # Convert RVA to file offset
            file_offset = pe.get_offset_from_rva(rva)

            logger.info(f"PE: VA 0x{virtual_address:x} -> RVA 0x{rva:x} -> File Offset 0x{file_offset:x}")
            return file_offset

        except Exception as e:
            logger.error(f"PE VA-to-offset conversion failed: {e}")
            return None

    def _va_to_file_offset_elf(self, binary_path: str, virtual_address: int) -> Optional[int]:
        """
        Convert virtual address to file offset for ELF binaries.

        Args:
            binary_path: Path to the ELF binary
            virtual_address: Virtual address to convert

        Returns:
            File offset or None if conversion fails
        """
        try:
            from elftools.elf.elffile import ELFFile

            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)

                # Iterate through program headers to find the segment containing the VA
                for segment in elf.iter_segments():
                    # Check if VA is within this segment's virtual address range
                    seg_start = segment['p_vaddr']
                    seg_end = seg_start + segment['p_memsz']

                    if seg_start <= virtual_address < seg_end:
                        # Calculate offset within the segment
                        offset_in_segment = virtual_address - seg_start
                        # Add to segment's file offset
                        file_offset = segment['p_offset'] + offset_in_segment

                        logger.info(f"ELF: VA 0x{virtual_address:x} -> File Offset 0x{file_offset:x}")
                        return file_offset

                logger.error(f"VA 0x{virtual_address:x} not found in any ELF segment")
                return None

        except Exception as e:
            logger.error(f"ELF VA-to-offset conversion failed: {e}")
            return None

    def _detect_binary_format(self, binary_path: str) -> Optional[str]:
        """
        Detect if binary is PE or ELF format.

        Args:
            binary_path: Path to the binary

        Returns:
            'PE', 'ELF', or None if unknown
        """
        try:
            with open(binary_path, 'rb') as f:
                magic = f.read(4)

                # Check for PE signature (MZ header)
                if magic[:2] == b'MZ':
                    return 'PE'

                # Check for ELF signature
                if magic == b'\x7fELF':
                    return 'ELF'

                logger.warning(f"Unknown binary format (magic: {magic.hex()})")
                return None

        except Exception as e:
            logger.error(f"Binary format detection failed: {e}")
            return None

    def patch_binary(self, lima_output, binary_path):
        """
        Patch the binary file at the specified memory address.
        Automatically converts virtual addresses to file offsets for PE/ELF binaries.

        :param lima_output: Output from the Logic Identification & Mapping Agent.
        :param binary_path: Path to the binary file.
        :return: Path to the patched binary file.
        """
        try:
            # Validate inputs
            required = {"compare_addr", "jump_addr", "opcode"}
            if not isinstance(lima_output, dict) or not required.issubset(lima_output.keys()):
                logger.error("LIMA output missing required keys")
                return None
            jump_addr = lima_output.get('jump_addr', '0x0')
            opcode = lima_output.get('opcode', '00')
            if not self._validate_hex_addr(jump_addr):
                logger.error("Invalid jump_addr format")
                return None
            if not self._validate_opcode_byte(opcode):
                logger.error("Invalid opcode byte format")
                return None

            # Create backup before patching
            backup_path = f"{binary_path}.backup"
            if os.path.exists(binary_path) and not os.path.exists(backup_path):
                shutil.copy2(binary_path, backup_path)
                logger.info(f"Created backup: {backup_path}")

            # Convert virtual address to file offset
            virtual_address = int(jump_addr, 16)
            binary_format = self._detect_binary_format(binary_path)

            if binary_format == 'PE':
                file_offset = self._va_to_file_offset_pe(binary_path, virtual_address)
            elif binary_format == 'ELF':
                file_offset = self._va_to_file_offset_elf(binary_path, virtual_address)
            else:
                # Fallback: assume jump_addr is already a file offset
                logger.warning("Unknown binary format, assuming jump_addr is a file offset")
                file_offset = virtual_address

            if file_offset is None:
                logger.error("Failed to convert VA to file offset")
                return None

            # Apply the patch
            with open(binary_path, 'rb+') as f:
                f.seek(file_offset)
                f.write(bytes.fromhex(opcode))
                logger.info(f"Patched binary at file offset 0x{file_offset:x} with opcode 0x{opcode}")

            return binary_path

        except Exception as e:
            logger.error(f"Error during patching: {e}")
            return None

