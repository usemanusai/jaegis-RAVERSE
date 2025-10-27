"""
Comprehensive tests for DisassemblyAgent
Date: October 25, 2025

Full test coverage with correct signatures and comprehensive scenarios.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, PropertyMock
import capstone

from agents.disassembly_agent import DisassemblyAgent
from utils.binary_utils import BinaryAnalyzer


class TestDisassemblyAgentInit:
    """Test DisassemblyAgent initialization."""
    
    def test_init_x86(self, mock_binary_analyzer):
        """Test initialization with x86 architecture."""
        type(mock_binary_analyzer).arch = PropertyMock(return_value="x86")
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        assert agent.cs.arch == capstone.CS_ARCH_X86
        assert agent.cs.mode == capstone.CS_MODE_32
        assert agent.cs.detail is True
    
    def test_init_x64(self, mock_binary_analyzer):
        """Test initialization with x64 architecture."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        assert agent.cs.arch == capstone.CS_ARCH_X86
        assert agent.cs.mode == capstone.CS_MODE_64
        assert agent.cs.detail is True
    
    def test_init_with_db(self, mock_binary_analyzer, mock_db_manager):
        """Test initialization with database manager."""
        agent = DisassemblyAgent(mock_binary_analyzer, mock_db_manager)
        
        assert agent.db == mock_db_manager


class TestIdentifyCodeSections:
    """Test identify_code_sections method."""
    
    def test_identify_sections_pe(self, mock_binary_analyzer):
        """Test identifying code sections in PE binary."""
        # Setup PE mock with all required attributes
        mock_section = Mock()
        mock_section.Name = b'.text\x00\x00\x00'
        mock_section.Characteristics = 0x20000000  # IMAGE_SCN_MEM_EXECUTE
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x5000
        mock_section.PointerToRawData = 0x400  # Add missing attribute for format string
        
        mock_pe = Mock()
        mock_pe.sections = [mock_section]
        mock_pe.OPTIONAL_HEADER = Mock()
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x400000
        
        type(mock_binary_analyzer).pe = PropertyMock(return_value=mock_pe)
        type(mock_binary_analyzer).file_type = PropertyMock(return_value="PE")
        
        agent = DisassemblyAgent(mock_binary_analyzer)
        sections = agent.identify_code_sections()

        assert len(sections) == 1
        assert sections[0]['name'] == '.text'
        assert sections[0]['start_address'] == 0x401000
        assert sections[0]['size'] == 0x5000
        assert sections[0]['file_offset'] == 0x400
    
    def test_identify_sections_elf(self, mock_binary_analyzer):
        """Test identifying code sections in ELF binary."""
        # Setup ELF mock with all required attributes
        mock_section = Mock()
        mock_section.name = '.text'
        mock_section.__getitem__ = lambda self, key: {
            'sh_addr': 0x401000,
            'sh_size': 0x3000,
            'sh_flags': 0x4,  # SHF_EXECINSTR
            'sh_offset': 0x1000
        }[key]
        
        mock_elf = Mock()
        mock_elf.iter_sections = Mock(return_value=[mock_section])
        type(mock_binary_analyzer).elf = PropertyMock(return_value=mock_elf)
        type(mock_binary_analyzer).file_type = PropertyMock(return_value="ELF")
        type(mock_binary_analyzer).pe = PropertyMock(return_value=None)
        
        agent = DisassemblyAgent(mock_binary_analyzer)
        sections = agent.identify_code_sections()
        
        assert len(sections) == 1
        assert sections[0]['name'] == '.text'
    
    def test_identify_sections_no_data(self, mock_binary_analyzer):
        """Test error when binary data not loaded."""
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=None)
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        with pytest.raises(ValueError, match="Binary data not loaded"):
            agent.identify_code_sections()


class TestFindStringReferences:
    """Test find_string_references method."""
    
    def test_find_strings_not_found(self, mock_binary_analyzer):
        """Test when string is not found."""
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=b'\x00' * 1000)
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        result = agent.find_string_references("NotFound")
        
        # Returns empty list when not found
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_find_strings_found(self, mock_binary_analyzer):
        """Test when string is found."""
        test_string = b"TestString\x00"
        binary_data = b'\x00' * 100 + test_string + b'\x00' * 900
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=binary_data)
        mock_binary_analyzer.offset_to_va.return_value = 0x401064
        mock_binary_analyzer.va_to_offset.return_value = None  # No code references
        
        agent = DisassemblyAgent(mock_binary_analyzer)
        result = agent.find_string_references("TestString")
        
        # Returns list with string info
        assert isinstance(result, list)
        assert len(result) >= 1
        # string_offset is returned as hex string
        assert result[0]['string_offset'] == '0x64'  # 100 in hex
    
    def test_find_strings_no_data(self, mock_binary_analyzer):
        """Test error when binary data not loaded."""
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=None)
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        with pytest.raises(ValueError, match="Binary data not loaded"):
            agent.find_string_references("test")


class TestInstructionReferencesAddress:
    """Test _instruction_references_address helper."""
    
    def test_immediate_operand(self, mock_binary_analyzer):
        """Test immediate operand reference."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        mock_insn = Mock()
        mock_insn.address = 0x401000
        mock_insn.size = 5
        
        mock_op = Mock()
        mock_op.type = capstone.x86.X86_OP_IMM
        mock_op.imm = 0x402000
        
        mock_insn.operands = [mock_op]
        
        assert agent._instruction_references_address(mock_insn, 0x402000) is True
        assert agent._instruction_references_address(mock_insn, 0x403000) is False
    
    def test_memory_operand(self, mock_binary_analyzer):
        """Test memory operand reference."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        mock_insn = Mock()
        mock_insn.address = 0x401000
        mock_insn.size = 6
        
        mock_op = Mock()
        mock_op.type = capstone.x86.X86_OP_MEM
        mock_op.mem = Mock()
        mock_op.mem.disp = 0x402000
        
        mock_insn.operands = [mock_op]
        
        assert agent._instruction_references_address(mock_insn, 0x402000) is True
    
    def test_rip_relative(self, mock_binary_analyzer):
        """Test RIP-relative addressing."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        mock_insn = Mock()
        mock_insn.address = 0x401000
        mock_insn.size = 7
        
        mock_op = Mock()
        mock_op.type = capstone.x86.X86_OP_MEM
        mock_op.mem = Mock()
        mock_op.mem.base = capstone.x86.X86_REG_RIP
        mock_op.mem.disp = 0x100
        
        mock_insn.operands = [mock_op]
        
        # Effective address = 0x401000 + 7 + 0x100 = 0x401107
        assert agent._instruction_references_address(mock_insn, 0x401107) is True
    
    def test_no_operands(self, mock_binary_analyzer):
        """Test instruction with no operands."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        
        mock_insn = Mock()
        mock_insn.operands = []
        
        assert agent._instruction_references_address(mock_insn, 0x402000) is False


class TestDisassemblyAgentIntegration:
    """Integration tests with real disassembly."""
    
    def test_real_x64_code(self, mock_binary_analyzer):
        """Test disassembling real x64 code."""
        # mov rax, 0x1234; ret
        code = b'\x48\xc7\xc0\x34\x12\x00\x00\xc3'
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=code)
        
        agent = DisassemblyAgent(mock_binary_analyzer)
        instructions = list(agent.cs.disasm(code, 0x401000))
        
        assert len(instructions) == 2
        assert instructions[0].mnemonic == 'mov'
        assert instructions[1].mnemonic == 'ret'


class TestDisassemblyAgentSmoke:
    """Smoke tests for basic functionality."""
    
    def test_smoke_init(self, mock_binary_analyzer):
        """Smoke: Can initialize."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        assert agent is not None
    
    def test_smoke_identify_sections(self, mock_binary_analyzer):
        """Smoke: Can identify sections."""
        mock_pe = Mock()
        mock_pe.sections = []
        type(mock_binary_analyzer).pe = PropertyMock(return_value=mock_pe)
        type(mock_binary_analyzer).file_type = PropertyMock(return_value="PE")
        
        agent = DisassemblyAgent(mock_binary_analyzer)
        sections = agent.identify_code_sections()
        assert isinstance(sections, list)
    
    def test_smoke_find_strings(self, mock_binary_analyzer):
        """Smoke: Can search for strings."""
        agent = DisassemblyAgent(mock_binary_analyzer)
        result = agent.find_string_references("test")
        assert isinstance(result, list)


@patch('agents.disassembly_agent.metrics_collector')
class TestDisassemblyAgentMetrics:
    """Test metrics collection."""
    
    def test_metrics_collected(self, mock_metrics, mock_binary_analyzer):
        """Test that metrics are collected."""
        test_string = b"Test\x00"
        binary_data = b'\x00' * 100 + test_string + b'\x00' * 900
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=binary_data)
        
        agent = DisassemblyAgent(mock_binary_analyzer)
        agent.find_string_references("Test")
        
        # Verify metrics were recorded
        assert mock_metrics.record_operation_duration.called


class TestDisassembleAtAddress:
    """Test disassemble_at_address method."""

    def test_disassemble_x64_code(self, mock_binary_analyzer):
        """Test disassembling x64 code at specific address."""
        # nop; ret
        code = b'\x90\xc3'
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=code)
        type(mock_binary_analyzer).arch = PropertyMock(return_value="x64")
        mock_binary_analyzer.va_to_offset = Mock(return_value=0)

        agent = DisassemblyAgent(mock_binary_analyzer)
        instructions = agent.disassemble_at_address(0x401000, num_instructions=2)

        assert len(instructions) > 0
        assert '0x401000' in instructions[0]['address']

    def test_disassemble_x86_code(self, mock_binary_analyzer):
        """Test disassembling x86 code at specific address."""
        # nop; ret
        code = b'\x90\xc3'
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=code)
        type(mock_binary_analyzer).arch = PropertyMock(return_value="x86")
        mock_binary_analyzer.va_to_offset = Mock(return_value=0)

        agent = DisassemblyAgent(mock_binary_analyzer)
        instructions = agent.disassemble_at_address(0x401000, num_instructions=2)

        assert len(instructions) > 0

    def test_disassemble_invalid_code(self, mock_binary_analyzer):
        """Test disassembling invalid code."""
        # Invalid opcodes
        code = b'\xff\xff\xff\xff'
        type(mock_binary_analyzer).binary_data = PropertyMock(return_value=code)
        mock_binary_analyzer.va_to_offset = Mock(return_value=0)

        agent = DisassemblyAgent(mock_binary_analyzer)
        instructions = agent.disassemble_at_address(0x401000, num_instructions=10)

        # Should handle invalid code gracefully
        assert isinstance(instructions, list)


class TestGetDisassemblyText:
    """Test get_disassembly_text method."""

    def test_format_instructions(self, mock_binary_analyzer):
        """Test formatting instructions as text."""
        agent = DisassemblyAgent(mock_binary_analyzer)

        instructions = [
            {'address': '0x401000', 'mnemonic': 'nop', 'op_str': '', 'full': 'nop', 'bytes': '90', 'size': 1},
            {'address': '0x401001', 'mnemonic': 'ret', 'op_str': '', 'full': 'ret', 'bytes': 'c3', 'size': 1}
        ]

        text = agent.get_disassembly_text(instructions)

        assert isinstance(text, str)
        assert 'nop' in text or '0x401000' in text

    def test_empty_instructions(self, mock_binary_analyzer):
        """Test formatting empty instruction list."""
        agent = DisassemblyAgent(mock_binary_analyzer)

        text = agent.get_disassembly_text([])

        assert isinstance(text, str)
