"""
Unit tests for GovernanceAgent
Tests A2A communication, approval workflows, and governance audit logging
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import psycopg2

from agents.online_governance_agent import GovernanceAgent


@pytest.fixture
def governance_agent():
    """Create a GovernanceAgent instance for testing."""
    with patch('agents.online_governance_agent.DatabaseManager'):
        with patch('agents.online_governance_agent.CacheManager'):
            agent = GovernanceAgent()
            agent.db_manager = Mock()
            agent.cache_manager = Mock()
            agent.cache_manager.client = Mock()
            return agent


class TestGovernanceAgent:
    """Test suite for GovernanceAgent."""
    
    def test_initialization(self, governance_agent):
        """Test agent initialization."""
        assert governance_agent.agent_type == "Governance"
        assert governance_agent.approval_timeout_hours == 24
    
    def test_create_approval_request_success(self, governance_agent):
        """Test successful approval request creation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2", "agent3"],
            "description": "Request for data access"
        })
        
        assert result["status"] == "success"
        assert "request_id" in result
        mock_cursor.execute.assert_called()
        governance_agent.cache_manager.client.publish.assert_called()
    
    def test_approve_request_success(self, governance_agent):
        """Test successful request approval."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent._approve_request({
            "request_id": "req123",
            "approver": "agent2",
            "decision": "approved",
            "comments": "Approved"
        })
        
        assert result["status"] == "success"
        mock_cursor.execute.assert_called()
        governance_agent.cache_manager.client.publish.assert_called()
    
    def test_reject_request_success(self, governance_agent):
        """Test successful request rejection."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent._reject_request({
            "request_id": "req123",
            "approver": "agent2",
            "reason": "Insufficient permissions"
        })
        
        assert result["status"] == "success"
        mock_cursor.execute.assert_called()
        governance_agent.cache_manager.client.publish.assert_called()
    
    def test_redis_pub_sub_integration(self, governance_agent):
        """Test Redis pub/sub integration."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify Redis publish was called
        assert governance_agent.cache_manager.client.publish.called
    
    def test_message_persistence(self, governance_agent):
        """Test message persistence to database."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify database operation
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()
    
    def test_approval_timeout_configuration(self, governance_agent):
        """Test approval timeout configuration."""
        assert governance_agent.approval_timeout_hours == 24
    
    def test_execute_success(self, governance_agent):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent.execute({
            "action": "create_approval_request",
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "Governance"


class TestA2ACommunication:
    """Test A2A communication protocol."""
    
    def test_message_schema(self, governance_agent):
        """Test message schema validation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify message was published
        call_args = governance_agent.cache_manager.client.publish.call_args
        assert call_args is not None
    
    def test_correlation_id_tracking(self, governance_agent):
        """Test correlation ID tracking."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        assert "request_id" in result
    
    def test_message_types(self, governance_agent):
        """Test different message types."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        # Test approval_request message
        governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Test approval message
        governance_agent._approve_request({
            "request_id": "req123",
            "approver": "agent2",
            "decision": "approved",
            "comments": "OK"
        })
        
        # Verify both message types were published
        assert governance_agent.cache_manager.client.publish.call_count >= 2


class TestApprovalWorkflow:
    """Test approval workflow functionality."""
    
    def test_approval_workflow_creation(self, governance_agent):
        """Test approval workflow creation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2", "agent3"],
            "description": "Test"
        })
        
        assert result["status"] == "success"
    
    def test_approval_workflow_decision(self, governance_agent):
        """Test approval workflow decision."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        result = governance_agent._approve_request({
            "request_id": "req123",
            "approver": "agent2",
            "decision": "approved",
            "comments": "OK"
        })
        
        assert result["status"] == "success"


class TestGovernanceAuditLogging:
    """Test governance audit logging."""
    
    def test_audit_log_creation(self, governance_agent):
        """Test audit log creation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        governance_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        governance_agent.cache_manager.client.publish.return_value = 1
        
        governance_agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify audit log was created
        mock_cursor.execute.assert_called()


