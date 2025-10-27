"""
End-to-end tests for binary analysis workflow
Tests complete binary analysis pipeline
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from agents.online_daa_agent import DAAAgent
from agents.online_lima_agent import LIMAAgent


@pytest.fixture
def binary_analysis_agents():
    """Create binary analysis agents for E2E testing."""
    with patch('agents.online_daa_agent.DatabaseManager'):
        daa_agent = DAAAgent()
        daa_agent.db_manager = Mock()
    
    with patch('agents.online_lima_agent.DatabaseManager'):
        lima_agent = LIMAAgent()
        lima_agent.db_manager = Mock()
    
    return daa_agent, lima_agent


class TestBinaryAnalysisWorkflow:
    """Test complete binary analysis workflow."""
    
    def test_binary_analysis_pipeline(self, binary_analysis_agents):
        """Test complete binary analysis pipeline."""
        daa_agent, lima_agent = binary_analysis_agents
        
        # Mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        daa_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        lima_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        binary_data = b"MZ\x90\x00"
        
        # Step 1: DAA - Disassembly Analysis
        with patch.object(daa_agent, '_detect_format', return_value="PE"):
            with patch.object(daa_agent, '_detect_architecture', return_value="x64"):
                with patch.object(daa_agent, '_generate_disassembly', return_value="disasm"):
                    daa_result = daa_agent._analyze_binary({
                        "binary_path": "/path/to/binary.exe",
                        "binary_data": binary_data
                    })
        
        assert daa_result["status"] == "success"
        
        # Step 2: LIMA - Logic Identification & Mapping
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="ret", op_str="")
        ]
        
        with patch.object(lima_agent, '_analyze_control_flow', return_value={"cfg": "data"}):
            with patch.object(lima_agent, '_analyze_data_flow', return_value={"dfa": "data"}):
                lima_result = lima_agent._map_logic({
                    "disassembly": disassembly,
                    "binary_format": "PE",
                    "architecture": "x64"
                })
        
        assert lima_result["status"] == "success"
    
    def test_format_detection_workflow(self, binary_analysis_agents):
        """Test format detection workflow."""
        daa_agent, _ = binary_analysis_agents
        
        # Test PE format
        assert daa_agent._detect_format(b"MZ\x90\x00") == "PE"
        
        # Test ELF format
        assert daa_agent._detect_format(b"\x7fELF\x02\x01\x01\x00") == "ELF"
        
        # Test Mach-O format
        assert daa_agent._detect_format(b"\xfe\xed\xfa\xce") == "Mach-O"
    
    def test_architecture_detection_workflow(self, binary_analysis_agents):
        """Test architecture detection workflow."""
        daa_agent, _ = binary_analysis_agents
        
        with patch('pefile.PE') as mock_pe:
            # Test x86
            mock_pe_instance = Mock()
            mock_pe_instance.FILE_HEADER.Machine = 0x014c
            mock_pe.return_value = mock_pe_instance
            
            result = daa_agent._detect_architecture(b"MZ\x90\x00", "PE")
            assert result == "x86"
            
            # Test x64
            mock_pe_instance.FILE_HEADER.Machine = 0x8664
            result = daa_agent._detect_architecture(b"MZ\x90\x00", "PE")
            assert result == "x64"


class TestDisassemblyAnalysis:
    """Test disassembly analysis."""
    
    def test_disassembly_generation(self, binary_analysis_agents):
        """Test disassembly generation."""
        daa_agent, _ = binary_analysis_agents
        
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


class TestPatternDetection:
    """Test pattern detection."""
    
    def test_encryption_pattern_detection(self, binary_analysis_agents):
        """Test encryption pattern detection."""
        daa_agent, _ = binary_analysis_agents
        
        result = daa_agent._identify_patterns({
            "disassembly": "aes_encrypt, aes_decrypt, rijndael"
        })
        
        assert result["status"] == "success"
        assert "patterns" in result
    
    def test_network_pattern_detection(self, binary_analysis_agents):
        """Test network pattern detection."""
        daa_agent, _ = binary_analysis_agents
        
        result = daa_agent._identify_patterns({
            "disassembly": "socket, connect, send, recv"
        })
        
        assert result["status"] == "success"
        assert "patterns" in result
    
    def test_antidebug_pattern_detection(self, binary_analysis_agents):
        """Test anti-debug pattern detection."""
        daa_agent, _ = binary_analysis_agents
        
        result = daa_agent._identify_patterns({
            "disassembly": "IsDebuggerPresent, ptrace, SIGTRAP"
        })
        
        assert result["status"] == "success"
        assert "patterns" in result


class TestControlFlowAnalysis:
    """Test control flow analysis."""
    
    def test_cfg_generation(self, binary_analysis_agents):
        """Test CFG generation."""
        _, lima_agent = binary_analysis_agents
        
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="jmp", op_str="0x401010"),
            Mock(address=0x401010, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert "cfg" in result
    
    def test_branch_detection(self, binary_analysis_agents):
        """Test branch detection."""
        _, lima_agent = binary_analysis_agents
        
        disassembly = [
            Mock(address=0x401000, mnemonic="cmp", op_str="eax, 0"),
            Mock(address=0x401003, mnemonic="je", op_str="0x401010"),
            Mock(address=0x401005, mnemonic="jne", op_str="0x401020"),
            Mock(address=0x401010, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert len(result["branches"]) >= 2
    
    def test_loop_detection(self, binary_analysis_agents):
        """Test loop detection."""
        _, lima_agent = binary_analysis_agents
        
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="ecx, 10"),
            Mock(address=0x401003, mnemonic="mov", op_str="eax, 0"),
            Mock(address=0x401006, mnemonic="add", op_str="eax, 1"),
            Mock(address=0x401009, mnemonic="loop", op_str="0x401006"),
            Mock(address=0x40100b, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert "loops" in result


class TestDataFlowAnalysis:
    """Test data flow analysis."""
    
    def test_mov_instruction_tracking(self, binary_analysis_agents):
        """Test MOV instruction tracking."""
        _, lima_agent = binary_analysis_agents
        
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="mov", op_str="ebx, eax"),
            Mock(address=0x401006, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "mov_instructions" in result
    
    def test_arithmetic_instruction_tracking(self, binary_analysis_agents):
        """Test arithmetic instruction tracking."""
        _, lima_agent = binary_analysis_agents
        
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="add", op_str="eax, 2"),
            Mock(address=0x401006, mnemonic="sub", op_str="eax, 1"),
            Mock(address=0x401009, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "arithmetic_instructions" in result


