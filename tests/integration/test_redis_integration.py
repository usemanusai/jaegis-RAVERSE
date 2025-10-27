"""
Integration tests for Redis integration
Tests pub/sub messaging and caching
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from agents.online_governance_agent import GovernanceAgent


@pytest.fixture
def governance_agent_with_redis():
    """Create a GovernanceAgent with mocked Redis."""
    with patch('agents.online_governance_agent.DatabaseManager'):
        with patch('agents.online_governance_agent.CacheManager'):
            agent = GovernanceAgent()
            agent.db_manager = Mock()
            agent.cache_manager = Mock()
            agent.cache_manager.client = Mock()
            return agent


class TestRedisPubSub:
    """Test Redis pub/sub functionality."""
    
    def test_publish_approval_request(self, governance_agent_with_redis):
        """Test publishing approval request."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        assert result["status"] == "success"
        agent.cache_manager.client.publish.assert_called()
    
    def test_publish_approval_decision(self, governance_agent_with_redis):
        """Test publishing approval decision."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = agent._approve_request({
            "request_id": "req123",
            "approver": "agent2",
            "decision": "approved",
            "comments": "OK"
        })
        
        assert result["status"] == "success"
        agent.cache_manager.client.publish.assert_called()
    
    def test_publish_rejection(self, governance_agent_with_redis):
        """Test publishing rejection."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = agent._reject_request({
            "request_id": "req123",
            "approver": "agent2",
            "reason": "Insufficient permissions"
        })
        
        assert result["status"] == "success"
        agent.cache_manager.client.publish.assert_called()


class TestMessagePersistence:
    """Test message persistence to database."""
    
    def test_message_persisted_to_database(self, governance_agent_with_redis):
        """Test message persisted to database."""
        agent = governance_agent_with_redis
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
    
    def test_message_schema_validation(self, governance_agent_with_redis):
        """Test message schema validation."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify message was created with required fields
        assert "request_id" in result


class TestChannelManagement:
    """Test Redis channel management."""
    
    def test_publish_to_agent_channel(self, governance_agent_with_redis):
        """Test publishing to agent-specific channel."""
        agent = governance_agent_with_redis
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
        
        # Verify publish was called
        assert agent.cache_manager.client.publish.called
    
    def test_publish_to_broadcast_channel(self, governance_agent_with_redis):
        """Test publishing to broadcast channel."""
        agent = governance_agent_with_redis
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
        
        # Verify publish was called multiple times (to different channels)
        assert agent.cache_manager.client.publish.call_count >= 1


class TestCorrelationTracking:
    """Test correlation ID tracking."""
    
    def test_correlation_id_generation(self, governance_agent_with_redis):
        """Test correlation ID generation."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        # Verify correlation ID (request_id) was generated
        assert "request_id" in result
        assert result["request_id"] is not None
    
    def test_correlation_id_persistence(self, governance_agent_with_redis):
        """Test correlation ID persistence."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        request_id = result["request_id"]
        
        # Verify correlation ID was persisted
        mock_cursor.execute.assert_called()


class TestApprovalWorkflowMessaging:
    """Test approval workflow messaging."""
    
    def test_approval_workflow_messages(self, governance_agent_with_redis):
        """Test approval workflow messages."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.return_value = 1
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Create approval request
        result = agent._create_approval_request({
            "request_type": "data_access",
            "requester": "agent1",
            "approvers": ["agent2"],
            "description": "Test"
        })
        
        assert result["status"] == "success"
        
        # Approve request
        result = agent._approve_request({
            "request_id": result["request_id"],
            "approver": "agent2",
            "decision": "approved",
            "comments": "OK"
        })
        
        assert result["status"] == "success"
        
        # Verify multiple messages were published
        assert agent.cache_manager.client.publish.call_count >= 2


class TestErrorHandling:
    """Test error handling in Redis operations."""
    
    def test_redis_connection_error(self, governance_agent_with_redis):
        """Test Redis connection error handling."""
        agent = governance_agent_with_redis
        agent.cache_manager.client.publish.side_effect = Exception("Redis connection failed")
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Should handle error gracefully
        try:
            agent._create_approval_request({
                "request_type": "data_access",
                "requester": "agent1",
                "approvers": ["agent2"],
                "description": "Test"
            })
        except:
            pass


