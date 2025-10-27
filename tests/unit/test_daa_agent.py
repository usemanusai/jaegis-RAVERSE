"""
Unit tests for DAAAgent (Disassembly Analysis Agent)
Tests binary format detection, disassembly, and pattern detection
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import psycopg2

from agents.online_daa_agent import DAAAgent


@pytest.fixture
def daa_agent():
    """Create a DAAAgent instance for testing."""
    with patch('agents.online_daa_agent.DatabaseManager'):
        agent = DAAAgent()
        agent.db_manager = Mock()
        return agent


class TestDAAAgent:
    """Test suite for DAAAgent."""
    
    def test_initialization(self, daa_agent):
        """Test agent initialization."""
        assert daa_agent.agent_type == "DAA"
        assert daa_agent.max_retries == 3
        assert daa_agent.retry_backoff == 2
    
    def test_analyze_binary_success(self, daa_agent):
        """Test successful binary analysis."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        daa_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(daa_agent, '_detect_format', return_value="PE"):
            with patch.object(daa_agent, '_detect_architecture', return_value="x64"):
                with patch.object(daa_agent, '_generate_disassembly', return_value="disassembly"):
                    result = daa_agent._analyze_binary({
                        "binary_path": "/path/to/binary.exe",
                        "binary_data": b"MZ\x90\x00"
                    })
        
        assert result["status"] == "success"
        assert "analysis_id" in result
        mock_cursor.execute.assert_called()
    
    def test_detect_format_pe(self, daa_agent):
        """Test PE format detection."""
        result = daa_agent._detect_format(b"MZ\x90\x00")
        assert result == "PE"
    
    def test_detect_format_elf(self, daa_agent):
        """Test ELF format detection."""
        result = daa_agent._detect_format(b"\x7fELF\x02\x01\x01\x00")
        assert result == "ELF"
    
    def test_detect_format_macho(self, daa_agent):
        """Test Mach-O format detection."""
        result = daa_agent._detect_format(b"\xfe\xed\xfa\xce")
        assert result == "Mach-O"
    
    def test_detect_format_unknown(self, daa_agent):
        """Test unknown format detection."""
        result = daa_agent._detect_format(b"\x00\x00\x00\x00")
        assert result == "Unknown"
    
    def test_detect_architecture_x86(self, daa_agent):
        """Test x86 architecture detection."""
        with patch('pefile.PE') as mock_pe:
            mock_pe_instance = Mock()
            mock_pe_instance.FILE_HEADER.Machine = 0x014c  # x86
            mock_pe.return_value = mock_pe_instance
            
            result = daa_agent._detect_architecture(b"MZ\x90\x00", "PE")
            assert result == "x86"
    
    def test_detect_architecture_x64(self, daa_agent):
        """Test x64 architecture detection."""
        with patch('pefile.PE') as mock_pe:
            mock_pe_instance = Mock()
            mock_pe_instance.FILE_HEADER.Machine = 0x8664  # x64
            mock_pe.return_value = mock_pe_instance
            
            result = daa_agent._detect_architecture(b"MZ\x90\x00", "PE")
            assert result == "x64"
    
    def test_generate_disassembly_success(self, daa_agent):
        """Test successful disassembly generation."""
        with patch('capstone.Cs') as mock_cs:
            mock_md = Mock()
            mock_md.disasm.return_value = [
                Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
                Mock(address=0x401003, mnemonic="ret", op_str="")
            ]
            mock_cs.return_value = mock_md
            
            result = daa_agent._generate_disassembly(b"\x90" * 100, "x64")
            
            assert result is not None
            assert len(result) > 0
    
    def test_identify_patterns_encryption(self, daa_agent):
        """Test encryption pattern detection."""
        result = daa_agent._identify_patterns({
            "disassembly": "aes_encrypt, aes_decrypt, rijndael"
        })
        
        assert result["status"] == "success"
        assert "patterns" in result
    
    def test_identify_patterns_network(self, daa_agent):
        """Test network pattern detection."""
        result = daa_agent._identify_patterns({
            "disassembly": "socket, connect, send, recv"
        })
        
        assert result["status"] == "success"
        assert "patterns" in result
    
    def test_identify_patterns_antidebug(self, daa_agent):
        """Test anti-debug pattern detection."""
        result = daa_agent._identify_patterns({
            "disassembly": "IsDebuggerPresent, ptrace, SIGTRAP"
        })
        
        assert result["status"] == "success"
        assert "patterns" in result
    
    def test_analyze_imports_success(self, daa_agent):
        """Test successful import analysis."""
        with patch('pefile.PE') as mock_pe:
            mock_pe_instance = Mock()
            mock_import = Mock()
            mock_import.dll = b"kernel32.dll"
            mock_import.imports = [Mock(name=b"CreateProcessA")]
            mock_pe_instance.DIRECTORY_ENTRY_IMPORT = [mock_import]
            mock_pe.return_value = mock_pe_instance
            
            result = daa_agent._analyze_imports(b"MZ\x90\x00", "PE")
            
            assert result["status"] == "success"
            assert "imports" in result
    
    def test_database_error_handling(self, daa_agent):
        """Test database error handling."""
        daa_agent.db_manager.get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(psycopg2.OperationalError):
            daa_agent._analyze_binary({
                "binary_path": "/path/to/binary.exe",
                "binary_data": b"MZ\x90\x00"
            })
    
    def test_execute_success(self, daa_agent):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        daa_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(daa_agent, '_detect_format', return_value="PE"):
            with patch.object(daa_agent, '_detect_architecture', return_value="x64"):
                with patch.object(daa_agent, '_generate_disassembly', return_value="disasm"):
                    result = daa_agent.execute({
                        "action": "analyze_binary",
                        "binary_path": "/path/to/binary.exe",
                        "binary_data": b"MZ\x90\x00"
                    })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "DAA"


class TestBinaryFormatDetection:
    """Test binary format detection."""
    
    def test_pe_magic_bytes(self, daa_agent):
        """Test PE magic bytes detection."""
        assert daa_agent._detect_format(b"MZ") == "PE"
    
    def test_elf_magic_bytes(self, daa_agent):
        """Test ELF magic bytes detection."""
        assert daa_agent._detect_format(b"\x7fELF") == "ELF"
    
    def test_macho_magic_bytes(self, daa_agent):
        """Test Mach-O magic bytes detection."""
        assert daa_agent._detect_format(b"\xfe\xed\xfa\xce") == "Mach-O"


class TestArchitectureDetection:
    """Test architecture detection."""
    
    def test_x86_detection(self, daa_agent):
        """Test x86 detection."""
        with patch('pefile.PE') as mock_pe:
            mock_pe_instance = Mock()
            mock_pe_instance.FILE_HEADER.Machine = 0x014c
            mock_pe.return_value = mock_pe_instance
            
            result = daa_agent._detect_architecture(b"MZ\x90\x00", "PE")
            assert result == "x86"
    
    def test_x64_detection(self, daa_agent):
        """Test x64 detection."""
        with patch('pefile.PE') as mock_pe:
            mock_pe_instance = Mock()
            mock_pe_instance.FILE_HEADER.Machine = 0x8664
            mock_pe.return_value = mock_pe_instance
            
            result = daa_agent._detect_architecture(b"MZ\x90\x00", "PE")
            assert result == "x64"


class TestPatternDetection:
    """Test pattern detection."""
    
    def test_encryption_patterns(self, daa_agent):
        """Test encryption pattern detection."""
        result = daa_agent._identify_patterns({
            "disassembly": "aes_encrypt, aes_decrypt"
        })
        
        assert result["status"] == "success"
    
    def test_network_patterns(self, daa_agent):
        """Test network pattern detection."""
        result = daa_agent._identify_patterns({
            "disassembly": "socket, connect"
        })
        
        assert result["status"] == "success"
    
    def test_antidebug_patterns(self, daa_agent):
        """Test anti-debug pattern detection."""
        result = daa_agent._identify_patterns({
            "disassembly": "IsDebuggerPresent"
        })
        
        assert result["status"] == "success"


class TestDAADatabaseOperations:
    """Test database operations in DAAAgent."""
    
    def test_analysis_persistence(self, daa_agent):
        """Test analysis persistence."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        daa_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(daa_agent, '_detect_format', return_value="PE"):
            with patch.object(daa_agent, '_detect_architecture', return_value="x64"):
                with patch.object(daa_agent, '_generate_disassembly', return_value="disasm"):
                    daa_agent._analyze_binary({
                        "binary_path": "/path/to/binary.exe",
                        "binary_data": b"MZ\x90\x00"
                    })
        
        # Verify database operation
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()


