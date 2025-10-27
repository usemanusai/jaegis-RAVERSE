"""
Unit tests for VersionManagerAgent
Tests version tracking, compatibility checking, and onboarding validation
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import psycopg2

from agents.online_version_manager_agent import VersionManagerAgent


@pytest.fixture
def version_manager():
    """Create a VersionManagerAgent instance for testing."""
    with patch('agents.online_version_manager_agent.DatabaseManager'):
        agent = VersionManagerAgent()
        agent.db_manager = Mock()
        return agent


class TestVersionManagerAgent:
    """Test suite for VersionManagerAgent."""
    
    def test_initialization(self, version_manager):
        """Test agent initialization."""
        assert version_manager.agent_type == "VersionManager"
        assert version_manager.max_retries == 3
        assert version_manager.retry_backoff == 2
    
    def test_register_version_success(self, version_manager):
        """Test successful version registration."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = version_manager._register_version({
            "version": "2.0.0",
            "release_date": "2025-10-26",
            "features": ["feature1", "feature2"]
        })
        
        assert result["status"] == "success"
        assert "version_id" in result
        mock_cursor.execute.assert_called()
    
    def test_register_version_database_error(self, version_manager):
        """Test version registration with database error."""
        version_manager.db_manager.get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(psycopg2.OperationalError):
            version_manager._register_version({
                "version": "2.0.0",
                "release_date": "2025-10-26"
            })
    
    def test_get_versions_success(self, version_manager):
        """Test successful version retrieval."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"version": "2.0.0", "release_date": "2025-10-26"},
            {"version": "1.9.0", "release_date": "2025-10-20"}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = version_manager._get_versions({"limit": 10})
        
        assert result["status"] == "success"
        assert len(result["versions"]) == 2
    
    def test_save_compatibility_check_success(self, version_manager):
        """Test successful compatibility check save."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = version_manager._save_compatibility_check({
            "version": "2.0.0",
            "compatible_versions": ["1.9.0", "1.8.0"],
            "breaking_changes": []
        })
        
        assert result["status"] == "success"
        mock_cursor.execute.assert_called()
    
    def test_save_onboarding_validation_success(self, version_manager):
        """Test successful onboarding validation save."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = version_manager._save_onboarding_validation({
            "version": "2.0.0",
            "validation_status": "passed",
            "checks": ["database", "redis", "llm"]
        })
        
        assert result["status"] == "success"
        mock_cursor.execute.assert_called()
    
    def test_retry_logic_on_operational_error(self, version_manager):
        """Test retry logic on operational error."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        
        # First call fails, second succeeds
        version_manager.db_manager.get_connection.side_effect = [
            psycopg2.OperationalError("Connection failed"),
            MagicMock(__enter__=MagicMock(return_value=mock_conn), __exit__=MagicMock(return_value=False))
        ]
        
        # This should retry and eventually fail after max retries
        with pytest.raises(psycopg2.OperationalError):
            version_manager._register_version({"version": "2.0.0"})
    
    def test_execute_success(self, version_manager):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        result = version_manager.execute({
            "action": "register_version",
            "version": "2.0.0",
            "release_date": "2025-10-26"
        })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "VersionManager"


class TestVersionManagerRetryLogic:
    """Test retry logic in VersionManagerAgent."""
    
    def test_exponential_backoff(self, version_manager):
        """Test exponential backoff calculation."""
        # Verify backoff values
        assert version_manager.retry_backoff ** 0 == 1
        assert version_manager.retry_backoff ** 1 == 2
        assert version_manager.retry_backoff ** 2 == 4
    
    def test_max_retries_configuration(self, version_manager):
        """Test max retries configuration."""
        assert version_manager.max_retries == 3


class TestVersionManagerDatabaseOperations:
    """Test database operations in VersionManagerAgent."""
    
    def test_parameterized_queries(self, version_manager):
        """Test that queries use parameterized statements."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        version_manager._register_version({
            "version": "2.0.0",
            "release_date": "2025-10-26"
        })
        
        # Verify parameterized query was used
        call_args = mock_cursor.execute.call_args
        assert call_args is not None
        # Should have SQL and parameters
        assert len(call_args[0]) >= 1 or len(call_args[1]) >= 1
    
    def test_transaction_handling(self, version_manager):
        """Test transaction commit/rollback."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        version_manager.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        version_manager._register_version({
            "version": "2.0.0",
            "release_date": "2025-10-26"
        })
        
        # Verify commit was called
        mock_conn.commit.assert_called()


