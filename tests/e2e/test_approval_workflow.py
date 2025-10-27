"""
End-to-end tests for approval workflow
Tests complete approval request lifecycle
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from agents.online_governance_agent import GovernanceAgent


@pytest.fixture
def governance_e2e():
    """Create GovernanceAgent for E2E testing."""
    with patch('agents.online_governance_agent.DatabaseManager'):
        with patch('agents.online_governance_agent.CacheManager'):
            agent = GovernanceAgent()
            agent.db_manager = Mock()
            agent.cache_manager = Mock()
            agent.cache_manager.client = Mock()
            return agent


class TestApprovalWorkflowE2E:
    """Test complete approval workflow."""
    
    def test_approval_request_lifecycle(self, governance_e2e):
        """Test complete approval request lifecycle."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        # Mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Step 1: Create approval request
        create_result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2", "agent3"],
            "description": "Request for data access"
        })
        
        assert create_result["status"] == "success"
        request_id = create_result["request_id"]
        
        # Step 2: First approver approves
        approve_result1 = agent._approve_request({
            "request_id": request_id,
            "approver": "agent2",
            "decision": "approved",
            "comments": "Approved by agent2"
        })
        
        assert approve_result1["status"] == "success"
        
        # Step 3: Second approver approves
        approve_result2 = agent._approve_request({
            "request_id": request_id,
            "approver": "agent3",
            "decision": "approved",
            "comments": "Approved by agent3"
        })
        
        assert approve_result2["status"] == "success"
        
        # Verify multiple messages were published
        assert agent.cache_manager.client.publish.call_count >= 3
    
    def test_approval_request_rejection(self, governance_e2e):
        """Test approval request rejection."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Create request
        create_result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        request_id = create_result["request_id"]
        
        # Reject request
        reject_result = agent._reject_request({
            "request_id": request_id,
            "approver": "agent2",
            "reason": "Insufficient permissions"
        })
        
        assert reject_result["status"] == "success"
        agent.cache_manager.client.publish.assert_called()
    
    def test_approval_request_with_multiple_approvers(self, governance_e2e):
        """Test approval request with multiple approvers."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Create request with 3 approvers
        create_result = agent._create_approval_request({
            "request_type": "system_modification",
            "requester": "agent1",
            "approvers": ["agent2", "agent3", "agent4"],
            "description": "System modification request"
        })
        
        assert create_result["status"] == "success"
        
        # Verify request was created
        mock_cursor.execute.assert_called()


class TestApprovalMessaging:
    """Test approval messaging."""
    
    def test_approval_messages_published(self, governance_e2e):
        """Test approval messages are published."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Create request
        agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify messages were published
        assert agent.cache_manager.client.publish.called
    
    def test_approval_decision_messages(self, governance_e2e):
        """Test approval decision messages."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Create and approve
        create_result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        agent._approve_request({
            "request_id": create_result["request_id"],
            "approver": "agent2",
            "decision": "approved",
            "comments": "OK"
        })
        
        # Verify multiple publish calls
        assert agent.cache_manager.client.publish.call_count >= 2


class TestApprovalPersistence:
    """Test approval persistence."""
    
    def test_approval_request_persisted(self, governance_e2e):
        """Test approval request is persisted."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify database operation
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()
    
    def test_approval_decision_persisted(self, governance_e2e):
        """Test approval decision is persisted."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        create_result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        agent._approve_request({
            "request_id": create_result["request_id"],
            "approver": "agent2",
            "decision": "approved",
            "comments": "OK"
        })
        
        # Verify database operations
        assert mock_cursor.execute.call_count >= 2
        assert mock_conn.commit.call_count >= 2


class TestApprovalAuditLogging:
    """Test approval audit logging."""
    
    def test_audit_log_created(self, governance_e2e):
        """Test audit log is created."""
        agent = governance_e2e
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify audit log was created
        mock_cursor.execute.assert_called()


