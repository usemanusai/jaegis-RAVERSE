"""
Binary Analysis Utilities for RAVERSE
Provides file hashing, metadata extraction, and binary format detection
Date: October 25, 2025
"""

import os
import hashlib
import logging
from typing import Dict, Optional, Tuple
import struct


logger = logging.getLogger(__name__)


class BinaryAnalyzer:
    """
    Analyzes binary files and extracts metadata
    Supports PE (Windows) and ELF (Linux) formats

    Can be used as instance (loads binary) or static methods (utility functions).
    """

    # PE signature
    PE_SIGNATURE = b'MZ'

    # ELF signature
    ELF_SIGNATURE = b'\x7fELF'

    # Architecture mappings
    PE_MACHINE_TYPES = {
        0x014c: 'i386',
        0x8664: 'x86_64',
        0x01c0: 'ARM',
        0xaa64: 'ARM64'
    }

    ELF_MACHINE_TYPES = {
        0x03: 'i386',
        0x3e: 'x86_64',
        0x28: 'ARM',
        0xb7: 'ARM64'
    }

    def __init__(self, binary_path: Optional[str] = None):
        """
        Initialize binary analyzer.

        Args:
            binary_path: Optional path to binary file to load
        """
        self.binary_path = binary_path
        self.binary_data = None
        self.file_type = None
        self.arch = None
        self.pe = None
        self.elf = None
        self.entry_point = None

        if binary_path:
            self.load_binary(binary_path)

    def load_binary(self, binary_path: str):
        """
        Load binary file and parse headers.

        Args:
            binary_path: Path to binary file
        """
        self.binary_path = binary_path

        # Read binary data
        with open(binary_path, 'rb') as f:
            self.binary_data = f.read()

        # Detect file type and architecture
        self.file_type, arch = self.detect_file_type(binary_path)

        # Map architecture names
        if arch in ['i386', 'x86']:
            self.arch = 'x86'
        elif arch in ['x86_64', 'x64', 'amd64']:
            self.arch = 'x64'
        else:
            self.arch = arch

        # Parse format-specific headers
        if self.file_type == 'PE':
            self._parse_pe_headers()
        elif self.file_type == 'ELF':
            self._parse_elf_headers()

        logger.info(f"Loaded binary: {binary_path} ({self.file_type}/{self.arch})")

    def _parse_pe_headers(self):
        """Parse PE headers and extract metadata."""
        try:
            import pefile
            self.pe = pefile.PE(data=self.binary_data)
            self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.pe.OPTIONAL_HEADER.ImageBase
            logger.debug(f"PE entry point: 0x{self.entry_point:X}")
        except ImportError:
            logger.warning("pefile not available, PE parsing limited")
            self.pe = None
        except Exception as e:
            logger.error(f"PE parsing error: {e}")
            self.pe = None

    def _parse_elf_headers(self):
        """Parse ELF headers and extract metadata."""
        try:
            from elftools.elf.elffile import ELFFile
            from io import BytesIO
            self.elf = ELFFile(BytesIO(self.binary_data))
            self.entry_point = self.elf.header['e_entry']
            logger.debug(f"ELF entry point: 0x{self.entry_point:X}")
        except ImportError:
            logger.warning("pyelftools not available, ELF parsing limited")
            self.elf = None
        except Exception as e:
            logger.error(f"ELF parsing error: {e}")
            self.elf = None

    def va_to_offset(self, va: int) -> Optional[int]:
        """
        Convert virtual address to file offset.

        Args:
            va: Virtual address

        Returns:
            File offset or None if conversion fails
        """
        if self.file_type == 'PE' and self.pe:
            try:
                return self.pe.get_offset_from_rva(va - self.pe.OPTIONAL_HEADER.ImageBase)
            except Exception as e:
                logger.warning(f"VA to offset conversion failed: {e}")
                return None
        elif self.file_type == 'ELF' and self.elf:
            # Use program headers for ELF
            for segment in self.elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    vaddr = segment['p_vaddr']
                    memsz = segment['p_memsz']
                    offset = segment['p_offset']
                    if vaddr <= va < vaddr + memsz:
                        return va - vaddr + offset
            return None
        else:
            logger.warning("Cannot convert VA to offset without parsed headers")
            return None

    def offset_to_va(self, offset: int) -> Optional[int]:
        """
        Convert file offset to virtual address.

        Args:
            offset: File offset

        Returns:
            Virtual address or None if conversion fails
        """
        if self.file_type == 'PE' and self.pe:
            try:
                rva = self.pe.get_rva_from_offset(offset)
                return rva + self.pe.OPTIONAL_HEADER.ImageBase
            except Exception as e:
                logger.warning(f"Offset to VA conversion failed: {e}")
                return None
        elif self.file_type == 'ELF' and self.elf:
            # Use program headers for ELF
            for segment in self.elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    vaddr = segment['p_vaddr']
                    file_offset = segment['p_offset']
                    filesz = segment['p_filesz']
                    if file_offset <= offset < file_offset + filesz:
                        return offset - file_offset + vaddr
            return None
        else:
            logger.warning("Cannot convert offset to VA without parsed headers")
            return None
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate file hash
        
        Args:
            file_path: Path to binary file
            algorithm: Hash algorithm (sha256, sha1, md5)
        
        Returns:
            Hex digest of file hash
        """
        hash_func = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks for memory efficiency
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_func.update(chunk)
            
            file_hash = hash_func.hexdigest()
            logger.debug(f"Calculated {algorithm} hash: {file_hash}")
            return file_hash
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            raise
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"File size error: {e}")
            raise
    
    @staticmethod
    def detect_file_type(file_path: str) -> Tuple[str, str]:
        """
        Detect binary file type and architecture
        
        Args:
            file_path: Path to binary file
        
        Returns:
            Tuple of (file_type, architecture)
            file_type: 'PE', 'ELF', or 'UNKNOWN'
            architecture: 'i386', 'x86_64', 'ARM', 'ARM64', or 'UNKNOWN'
        """
        try:
            with open(file_path, 'rb') as f:
                # Read first 64 bytes for signature detection
                header = f.read(64)
                
                # Check PE signature
                if header.startswith(BinaryAnalyzer.PE_SIGNATURE):
                    # PE format
                    # Read PE header offset at 0x3C
                    if len(header) >= 0x40:
                        pe_offset = struct.unpack('<I', header[0x3C:0x40])[0]
                        
                        # Read machine type from COFF header
                        f.seek(pe_offset + 4)
                        machine_bytes = f.read(2)
                        if len(machine_bytes) == 2:
                            machine = struct.unpack('<H', machine_bytes)[0]
                            arch = BinaryAnalyzer.PE_MACHINE_TYPES.get(machine, 'UNKNOWN')
                            logger.info(f"Detected PE binary: {arch}")
                            return ('PE', arch)
                    
                    return ('PE', 'UNKNOWN')
                
                # Check ELF signature
                elif header.startswith(BinaryAnalyzer.ELF_SIGNATURE):
                    # ELF format
                    # Read architecture from e_machine field (offset 0x12)
                    if len(header) >= 0x14:
                        machine_bytes = header[0x12:0x14]
                        machine = struct.unpack('<H', machine_bytes)[0]
                        arch = BinaryAnalyzer.ELF_MACHINE_TYPES.get(machine, 'UNKNOWN')
                        logger.info(f"Detected ELF binary: {arch}")
                        return ('ELF', arch)
                    
                    return ('ELF', 'UNKNOWN')
                
                else:
                    logger.warning(f"Unknown binary format: {file_path}")
                    return ('UNKNOWN', 'UNKNOWN')
        
        except Exception as e:
            logger.error(f"File type detection error: {e}")
            return ('UNKNOWN', 'UNKNOWN')
    
    @staticmethod
    def extract_metadata(file_path: str) -> Dict:
        """
        Extract comprehensive metadata from binary file
        
        Args:
            file_path: Path to binary file
        
        Returns:
            Dictionary containing file metadata
        """
        try:
            file_name = os.path.basename(file_path)
            file_size = BinaryAnalyzer.get_file_size(file_path)
            file_hash = BinaryAnalyzer.calculate_file_hash(file_path)
            file_type, architecture = BinaryAnalyzer.detect_file_type(file_path)
            
            metadata = {
                'file_name': file_name,
                'file_path': os.path.abspath(file_path),
                'file_hash': file_hash,
                'file_size': file_size,
                'file_type': file_type,
                'architecture': architecture,
                'exists': os.path.exists(file_path),
                'readable': os.access(file_path, os.R_OK),
                'writable': os.access(file_path, os.W_OK)
            }
            
            logger.info(f"Extracted metadata for {file_name}: {file_type}/{architecture}, {file_size} bytes")
            return metadata
        
        except Exception as e:
            logger.error(f"Metadata extraction error: {e}")
            raise
    
    @staticmethod
    def create_backup(file_path: str, backup_suffix: str = '.backup') -> str:
        """
        Create a backup copy of the binary file
        
        Args:
            file_path: Path to original file
            backup_suffix: Suffix for backup file (default: .backup)
        
        Returns:
            Path to backup file
        """
        backup_path = f"{file_path}{backup_suffix}"
        
        try:
            with open(file_path, 'rb') as src:
                with open(backup_path, 'wb') as dst:
                    dst.write(src.read())
            
            logger.info(f"Created backup: {backup_path}")
            return backup_path
        
        except Exception as e:
            logger.error(f"Backup creation error: {e}")
            raise
    
    @staticmethod
    def read_bytes_at_offset(file_path: str, offset: int, length: int) -> bytes:
        """
        Read bytes from file at specific offset
        
        Args:
            file_path: Path to binary file
            offset: File offset to read from
            length: Number of bytes to read
        
        Returns:
            Bytes read from file
        """
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(length)
                logger.debug(f"Read {len(data)} bytes at offset 0x{offset:X}")
                return data
        
        except Exception as e:
            logger.error(f"Read bytes error: {e}")
            raise
    
    @staticmethod
    def write_bytes_at_offset(file_path: str, offset: int, data: bytes) -> bool:
        """
        Write bytes to file at specific offset
        
        Args:
            file_path: Path to binary file
            offset: File offset to write to
            data: Bytes to write
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'r+b') as f:
                f.seek(offset)
                f.write(data)
                logger.info(f"Wrote {len(data)} bytes at offset 0x{offset:X}")
                return True
        
        except Exception as e:
            logger.error(f"Write bytes error: {e}")
            return False
    
    @staticmethod
    def va_to_file_offset_pe(va: int, image_base: int = 0x400000, 
                            section_headers: list = None) -> Optional[int]:
        """
        Convert Virtual Address to file offset for PE files
        
        Args:
            va: Virtual address
            image_base: Image base address (default: 0x400000)
            section_headers: List of section headers (if available)
        
        Returns:
            File offset or None if conversion fails
        
        Note: This is a simplified implementation
        For production use, parse PE headers properly
        """
        rva = va - image_base
        
        # If no section headers provided, use simple RVA = file offset assumption
        # This works for many simple executables but not all
        if not section_headers:
            logger.warning("No section headers provided, using RVA as file offset")
            return rva
        
        # Find the section containing this RVA
        for section in section_headers:
            virtual_address = section.get('VirtualAddress', 0)
            virtual_size = section.get('VirtualSize', 0)
            raw_address = section.get('PointerToRawData', 0)
            
            if virtual_address <= rva < virtual_address + virtual_size:
                file_offset = rva - virtual_address + raw_address
                logger.debug(f"VA 0x{va:X} -> File offset 0x{file_offset:X}")
                return file_offset
        
        logger.error(f"Could not convert VA 0x{va:X} to file offset")
        return None
    
    @staticmethod
    def va_to_file_offset_elf(va: int, program_headers: list = None) -> Optional[int]:
        """
        Convert Virtual Address to file offset for ELF files
        
        Args:
            va: Virtual address
            program_headers: List of program headers (if available)
        
        Returns:
            File offset or None if conversion fails
        
        Note: This is a simplified implementation
        For production use, parse ELF headers properly
        """
        if not program_headers:
            logger.warning("No program headers provided")
            return None
        
        # Find the segment containing this VA
        for segment in program_headers:
            vaddr = segment.get('p_vaddr', 0)
            memsz = segment.get('p_memsz', 0)
            offset = segment.get('p_offset', 0)
            
            if vaddr <= va < vaddr + memsz:
                file_offset = va - vaddr + offset
                logger.debug(f"VA 0x{va:X} -> File offset 0x{file_offset:X}")
                return file_offset
        
        logger.error(f"Could not convert VA 0x{va:X} to file offset")
        return None

