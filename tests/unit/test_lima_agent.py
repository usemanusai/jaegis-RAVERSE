"""
Unit tests for LIMAAgent (Logic Identification & Mapping Agent)
Tests control flow analysis, data flow analysis, and logic mapping
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import psycopg2

from agents.online_lima_agent import LIMAAgent


@pytest.fixture
def lima_agent():
    """Create a LIMAAgent instance for testing."""
    with patch('agents.online_lima_agent.DatabaseManager'):
        agent = LIMAAgent()
        agent.db_manager = Mock()
        return agent


class TestLIMAAgent:
    """Test suite for LIMAAgent."""
    
    def test_initialization(self, lima_agent):
        """Test agent initialization."""
        assert lima_agent.agent_type == "LIMA"
        assert lima_agent.max_retries == 3
        assert lima_agent.retry_backoff == 2
    
    def test_map_logic_success(self, lima_agent):
        """Test successful logic mapping."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        lima_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(lima_agent, '_analyze_control_flow', return_value={"cfg": "data"}):
            with patch.object(lima_agent, '_analyze_data_flow', return_value={"dfa": "data"}):
                result = lima_agent._map_logic({
                    "disassembly": "mov eax, 1\nret",
                    "binary_format": "PE",
                    "architecture": "x64"
                })
        
        assert result["status"] == "success"
        assert "logic_map_id" in result
        mock_cursor.execute.assert_called()
    
    def test_analyze_control_flow_success(self, lima_agent):
        """Test successful control flow analysis."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="jmp", op_str="0x401010"),
            Mock(address=0x401010, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert "cfg" in result
        assert "branches" in result
    
    def test_analyze_control_flow_branches(self, lima_agent):
        """Test branch detection in control flow."""
        disassembly = [
            Mock(address=0x401000, mnemonic="cmp", op_str="eax, 0"),
            Mock(address=0x401003, mnemonic="je", op_str="0x401010"),
            Mock(address=0x401005, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401010, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert len(result["branches"]) > 0
    
    def test_analyze_control_flow_loops(self, lima_agent):
        """Test loop detection in control flow."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="ecx, 10"),
            Mock(address=0x401003, mnemonic="mov", op_str="eax, 0"),
            Mock(address=0x401006, mnemonic="add", op_str="eax, ecx"),
            Mock(address=0x401009, mnemonic="loop", op_str="0x401006"),
            Mock(address=0x40100b, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert "loops" in result
    
    def test_analyze_data_flow_success(self, lima_agent):
        """Test successful data flow analysis."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="add", op_str="eax, 2"),
            Mock(address=0x401006, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "data_flow" in result
    
    def test_analyze_data_flow_mov_instructions(self, lima_agent):
        """Test MOV instruction tracking in data flow."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="mov", op_str="ebx, eax"),
            Mock(address=0x401006, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "mov_instructions" in result
    
    def test_analyze_data_flow_arithmetic(self, lima_agent):
        """Test arithmetic instruction tracking in data flow."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="add", op_str="eax, 2"),
            Mock(address=0x401006, mnemonic="sub", op_str="eax, 1"),
            Mock(address=0x401009, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "arithmetic_instructions" in result
    
    def test_database_error_handling(self, lima_agent):
        """Test database error handling."""
        lima_agent.db_manager.get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(psycopg2.OperationalError):
            lima_agent._map_logic({
                "disassembly": "mov eax, 1",
                "binary_format": "PE",
                "architecture": "x64"
            })
    
    def test_execute_success(self, lima_agent):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        lima_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(lima_agent, '_analyze_control_flow', return_value={"cfg": "data"}):
            with patch.object(lima_agent, '_analyze_data_flow', return_value={"dfa": "data"}):
                result = lima_agent.execute({
                    "action": "map_logic",
                    "disassembly": "mov eax, 1",
                    "binary_format": "PE",
                    "architecture": "x64"
                })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "LIMA"


class TestControlFlowAnalysis:
    """Test control flow analysis functionality."""
    
    def test_cfg_generation(self, lima_agent):
        """Test CFG generation."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="jmp", op_str="0x401010"),
            Mock(address=0x401010, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert "cfg" in result
    
    def test_branch_detection(self, lima_agent):
        """Test branch detection."""
        disassembly = [
            Mock(address=0x401000, mnemonic="cmp", op_str="eax, 0"),
            Mock(address=0x401003, mnemonic="je", op_str="0x401010"),
            Mock(address=0x401005, mnemonic="jne", op_str="0x401020"),
            Mock(address=0x401010, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_control_flow(disassembly)
        
        assert result["status"] == "success"
        assert len(result["branches"]) >= 2
    
    def test_loop_detection(self, lima_agent):
        """Test loop detection."""
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
    """Test data flow analysis functionality."""
    
    def test_mov_instruction_tracking(self, lima_agent):
        """Test MOV instruction tracking."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="mov", op_str="ebx, eax"),
            Mock(address=0x401006, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "mov_instructions" in result
    
    def test_arithmetic_instruction_tracking(self, lima_agent):
        """Test arithmetic instruction tracking."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="add", op_str="eax, 2"),
            Mock(address=0x401006, mnemonic="sub", op_str="eax, 1"),
            Mock(address=0x401009, mnemonic="mul", op_str="eax, 3"),
            Mock(address=0x40100c, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"
        assert "arithmetic_instructions" in result
    
    def test_register_tracking(self, lima_agent):
        """Test register tracking in data flow."""
        disassembly = [
            Mock(address=0x401000, mnemonic="mov", op_str="eax, 1"),
            Mock(address=0x401003, mnemonic="mov", op_str="ebx, eax"),
            Mock(address=0x401006, mnemonic="mov", op_str="ecx, ebx"),
            Mock(address=0x401009, mnemonic="ret", op_str="")
        ]
        
        result = lima_agent._analyze_data_flow(disassembly)
        
        assert result["status"] == "success"


class TestLIMADatabaseOperations:
    """Test database operations in LIMAAgent."""
    
    def test_logic_map_persistence(self, lima_agent):
        """Test logic map persistence."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        lima_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(lima_agent, '_analyze_control_flow', return_value={"cfg": "data"}):
            with patch.object(lima_agent, '_analyze_data_flow', return_value={"dfa": "data"}):
                lima_agent._map_logic({
                    "disassembly": "mov eax, 1",
                    "binary_format": "PE",
                    "architecture": "x64"
                })
        
        # Verify database operation
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()


