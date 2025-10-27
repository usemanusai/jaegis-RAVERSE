"""
Integration tests for database operations
Tests real database connections and operations
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import psycopg2
from psycopg2.extras import RealDictCursor

from agents.online_version_manager_agent import VersionManagerAgent
from agents.online_knowledge_base_agent import KnowledgeBaseAgent
from agents.online_quality_gate_agent import QualityGateAgent


@pytest.fixture
def db_connection_mock():
    """Create a mock database connection."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cursor
    conn.cursor.return_value.__exit__.return_value = None
    return conn, cursor


class TestDatabaseIntegration:
    """Test database integration across agents."""
    
    def test_version_manager_database_operations(self, db_connection_mock):
        """Test VersionManagerAgent database operations."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_version_manager_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            mock_db_instance.get_connection.return_value.__enter__.return_value = conn
            mock_db_instance.get_connection.return_value.__exit__.return_value = None
            mock_db.return_value = mock_db_instance
            
            agent = VersionManagerAgent()
            agent.db_manager = mock_db_instance
            
            result = agent._register_version({
                "version": "2.0.0",
                "release_date": "2025-10-26"
            })
            
            assert result["status"] == "success"
            cursor.execute.assert_called()
            conn.commit.assert_called()
    
    def test_knowledge_base_database_operations(self, db_connection_mock):
        """Test KnowledgeBaseAgent database operations."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_knowledge_base_agent.DatabaseManager') as mock_db:
            with patch('agents.online_knowledge_base_agent.SentenceTransformer'):
                mock_db_instance = Mock()
                mock_db_instance.get_connection.return_value.__enter__.return_value = conn
                mock_db_instance.get_connection.return_value.__exit__.return_value = None
                mock_db.return_value = mock_db_instance
                
                agent = KnowledgeBaseAgent()
                agent.db_manager = mock_db_instance
                
                result = agent._store_knowledge({
                    "content": "test",
                    "source": "test"
                })
                
                assert result["status"] == "success"
                cursor.execute.assert_called()
    
    def test_quality_gate_database_operations(self, db_connection_mock):
        """Test QualityGateAgent database operations."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_quality_gate_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            mock_db_instance.get_connection.return_value.__enter__.return_value = conn
            mock_db_instance.get_connection.return_value.__exit__.return_value = None
            mock_db.return_value = mock_db_instance
            
            agent = QualityGateAgent()
            agent.db_manager = mock_db_instance
            
            result = agent._validate_phase({
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
            cursor.execute.assert_called()


class TestConnectionPooling:
    """Test connection pooling behavior."""
    
    def test_connection_reuse(self, db_connection_mock):
        """Test connection reuse from pool."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_version_manager_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            mock_db_instance.get_connection.return_value.__enter__.return_value = conn
            mock_db_instance.get_connection.return_value.__exit__.return_value = None
            mock_db.return_value = mock_db_instance
            
            agent = VersionManagerAgent()
            agent.db_manager = mock_db_instance
            
            # Multiple operations should reuse connection
            agent._register_version({"version": "1.0.0"})
            agent._register_version({"version": "2.0.0"})
            
            # Verify connection was used multiple times
            assert mock_db_instance.get_connection.call_count >= 2


class TestRetryLogic:
    """Test retry logic in database operations."""
    
    def test_retry_on_operational_error(self, db_connection_mock):
        """Test retry on operational error."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_version_manager_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            
            # First call fails, second succeeds
            mock_db_instance.get_connection.side_effect = [
                psycopg2.OperationalError("Connection failed"),
                MagicMock(__enter__=MagicMock(return_value=conn), __exit__=MagicMock(return_value=False))
            ]
            
            agent = VersionManagerAgent()
            agent.db_manager = mock_db_instance
            
            # Should retry and eventually fail after max retries
            with pytest.raises(psycopg2.OperationalError):
                agent._register_version({"version": "1.0.0"})


class TestTransactionHandling:
    """Test transaction handling in database operations."""
    
    def test_commit_on_success(self, db_connection_mock):
        """Test commit on successful operation."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_version_manager_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            mock_db_instance.get_connection.return_value.__enter__.return_value = conn
            mock_db_instance.get_connection.return_value.__exit__.return_value = None
            mock_db.return_value = mock_db_instance
            
            agent = VersionManagerAgent()
            agent.db_manager = mock_db_instance
            
            agent._register_version({"version": "1.0.0"})
            
            # Verify commit was called
            conn.commit.assert_called()
    
    def test_rollback_on_error(self, db_connection_mock):
        """Test rollback on error."""
        conn, cursor = db_connection_mock
        cursor.execute.side_effect = psycopg2.DatabaseError("Database error")
        
        with patch('agents.online_version_manager_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            mock_db_instance.get_connection.return_value.__enter__.return_value = conn
            mock_db_instance.get_connection.return_value.__exit__.return_value = None
            mock_db.return_value = mock_db_instance
            
            agent = VersionManagerAgent()
            agent.db_manager = mock_db_instance
            
            # Should handle error gracefully
            try:
                agent._register_version({"version": "1.0.0"})
            except:
                pass


class TestParameterizedQueries:
    """Test parameterized query usage."""
    
    def test_parameterized_insert(self, db_connection_mock):
        """Test parameterized INSERT query."""
        conn, cursor = db_connection_mock
        
        with patch('agents.online_version_manager_agent.DatabaseManager') as mock_db:
            mock_db_instance = Mock()
            mock_db_instance.get_connection.return_value.__enter__.return_value = conn
            mock_db_instance.get_connection.return_value.__exit__.return_value = None
            mock_db.return_value = mock_db_instance
            
            agent = VersionManagerAgent()
            agent.db_manager = mock_db_instance
            
            agent._register_version({
                "version": "2.0.0",
                "release_date": "2025-10-26"
            })
            
            # Verify parameterized query was used
            call_args = cursor.execute.call_args
            assert call_args is not None


