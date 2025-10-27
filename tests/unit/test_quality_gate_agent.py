"""
Unit tests for QualityGateAgent
Tests A.I.E.F.N.M.W. Sentry Protocol implementation
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import psycopg2

from agents.online_quality_gate_agent import QualityGateAgent


@pytest.fixture
def quality_gate_agent():
    """Create a QualityGateAgent instance for testing."""
    with patch('agents.online_quality_gate_agent.DatabaseManager'):
        agent = QualityGateAgent()
        agent.db_manager = Mock()
        return agent


class TestQualityGateAgent:
    """Test suite for QualityGateAgent."""
    
    def test_initialization(self, quality_gate_agent):
        """Test agent initialization."""
        assert quality_gate_agent.agent_type == "QualityGate"
        assert quality_gate_agent.max_retries == 3
        assert quality_gate_agent.retry_backoff == 2
    
    def test_validate_phase_success(self, quality_gate_agent):
        """Test successful phase validation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        quality_gate_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = quality_gate_agent._validate_phase({
            "phase_name": "Phase 1",
            "metrics": {
                "accuracy": 0.96,
                "integrity": 1.0,
                "efficiency": 0.92,
                "functionality": 1.0,
                "normalization": 1.0,
                "metadata": 1.0,
                "workflow": 1.0
            }
        })
        
        assert result["status"] == "success"
        assert "validation_id" in result
        mock_cursor.execute.assert_called()
    
    def test_check_accuracy_success(self, quality_gate_agent):
        """Test successful accuracy check."""
        result = quality_gate_agent._check_accuracy({
            "true_positives": 95,
            "false_positives": 5,
            "true_negatives": 90,
            "false_negatives": 10
        })
        
        assert result["status"] == "success"
        assert "f1_score" in result
        assert result["f1_score"] >= 0 and result["f1_score"] <= 1
    
    def test_check_accuracy_threshold(self, quality_gate_agent):
        """Test accuracy threshold validation."""
        result = quality_gate_agent._check_accuracy({
            "true_positives": 95,
            "false_positives": 5,
            "true_negatives": 90,
            "false_negatives": 10
        })
        
        # F1 score should be high
        assert result["f1_score"] > 0.85
    
    def test_check_efficiency_success(self, quality_gate_agent):
        """Test successful efficiency check."""
        result = quality_gate_agent._check_efficiency({
            "execution_time": 150,  # seconds
            "memory_usage": 1024,   # MB
            "cpu_usage": 65.5,      # percent
            "throughput": 100       # items/sec
        })
        
        assert result["status"] == "success"
        assert "efficiency_score" in result
    
    def test_check_efficiency_limits(self, quality_gate_agent):
        """Test efficiency limits."""
        # Test within limits
        result = quality_gate_agent._check_efficiency({
            "execution_time": 200,
            "memory_usage": 1500,
            "cpu_usage": 70,
            "throughput": 100
        })
        
        assert result["status"] == "success"
        
        # Test exceeding limits
        result = quality_gate_agent._check_efficiency({
            "execution_time": 400,  # Exceeds 300s limit
            "memory_usage": 3000,   # Exceeds 2048MB limit
            "cpu_usage": 95,        # Exceeds 80% limit
            "throughput": 100
        })
        
        assert result["efficiency_score"] < 0.9
    
    def test_validate_phase_database_error(self, quality_gate_agent):
        """Test phase validation with database error."""
        quality_gate_agent.db_manager.get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(psycopg2.OperationalError):
            quality_gate_agent._validate_phase({
                "phase_name": "Phase 1",
                "metrics": {}
            })
    
    def test_execute_success(self, quality_gate_agent):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        quality_gate_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = quality_gate_agent.execute({
            "action": "validate_phase",
            "phase_name": "Phase 1",
            "metrics": {
                "accuracy": 0.96,
                "integrity": 1.0,
                "efficiency": 0.92,
                "functionality": 1.0,
                "normalization": 1.0,
                "metadata": 1.0,
                "workflow": 1.0
            }
        })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "QualityGate"


class TestAIEFNMWSentryProtocol:
    """Test A.I.E.F.N.M.W. Sentry Protocol implementation."""
    
    def test_accuracy_threshold(self, quality_gate_agent):
        """Test accuracy threshold (0.95)."""
        # High accuracy
        result = quality_gate_agent._check_accuracy({
            "true_positives": 950,
            "false_positives": 50,
            "true_negatives": 900,
            "false_negatives": 100
        })
        assert result["f1_score"] > 0.9
    
    def test_integrity_threshold(self, quality_gate_agent):
        """Test integrity threshold (1.0)."""
        result = quality_gate_agent._check_integrity({
            "total_records": 1000,
            "complete_records": 1000,
            "consistent_records": 1000
        })
        assert result["integrity_score"] == 1.0
    
    def test_efficiency_threshold(self, quality_gate_agent):
        """Test efficiency threshold (0.90)."""
        result = quality_gate_agent._check_efficiency({
            "execution_time": 250,
            "memory_usage": 1500,
            "cpu_usage": 70,
            "throughput": 100
        })
        assert result["efficiency_score"] >= 0.9
    
    def test_functionality_threshold(self, quality_gate_agent):
        """Test functionality threshold (1.0)."""
        result = quality_gate_agent._check_functionality({
            "required_functions": 10,
            "executed_functions": 10
        })
        assert result["functionality_score"] == 1.0
    
    def test_normalization_threshold(self, quality_gate_agent):
        """Test normalization threshold (1.0)."""
        result = quality_gate_agent._check_normalization({
            "total_records": 1000,
            "normalized_records": 1000
        })
        assert result["normalization_score"] == 1.0
    
    def test_metadata_threshold(self, quality_gate_agent):
        """Test metadata threshold (1.0)."""
        result = quality_gate_agent._check_metadata({
            "total_records": 1000,
            "records_with_metadata": 1000
        })
        assert result["metadata_score"] == 1.0
    
    def test_workflow_threshold(self, quality_gate_agent):
        """Test workflow threshold (1.0)."""
        result = quality_gate_agent._check_workflow({
            "total_steps": 10,
            "completed_steps": 10,
            "correct_order": True
        })
        assert result["workflow_score"] == 1.0


class TestQualityGateDatabaseOperations:
    """Test database operations in QualityGateAgent."""
    
    def test_checkpoint_persistence(self, quality_gate_agent):
        """Test checkpoint persistence."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        quality_gate_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        quality_gate_agent._validate_phase({
            "phase_name": "Phase 1",
            "metrics": {
                "accuracy": 0.96,
                "integrity": 1.0,
                "efficiency": 0.92,
                "functionality": 1.0,
                "normalization": 1.0,
                "metadata": 1.0,
                "workflow": 1.0
            }
        })
        
        # Verify database operation
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()


