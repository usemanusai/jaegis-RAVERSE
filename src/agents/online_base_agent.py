"""
Base class for all RAVERSE Online agents.
Provides common functionality for remote target analysis.
Includes database persistence, Redis caching, metrics collection, and state management.
"""

import logging
import json
import time
import os
import redis
import psycopg2
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
import uuid
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class OnlineBaseAgent(ABC):
    """
    Abstract base class for all RAVERSE Online agents.
    Handles common operations: logging, state management, error handling, caching, database persistence.
    """

    def __init__(self, name: str, agent_type: str, orchestrator=None):
        """
        Initialize base agent with database and caching support.

        Args:
            name: Agent name (e.g., "Reconnaissance Agent")
            agent_type: Agent type code (e.g., "RECON")
            orchestrator: Reference to orchestration agent
        """
        self.name = name
        self.agent_type = agent_type
        self.orchestrator = orchestrator
        self.logger = logging.getLogger(f"RAVERSE.{agent_type}")
        self.agent_id = str(uuid.uuid4())

        # State tracking
        self.state = "idle"  # idle, running, succeeded, failed, skipped
        self.progress = 0.0  # 0.0 to 1.0
        self.start_time = None
        self.end_time = None
        self.error = None
        self.run_id = None

        # Results storage
        self.results = {}
        self.artifacts = []
        self.metrics = {}

        # Database and caching
        self._init_database()
        self._init_redis()

    def _init_database(self):
        """Initialize PostgreSQL database connection."""
        try:
            self.db_url = os.getenv("POSTGRES_URL", "postgresql://raverse:raverse_secure_password@localhost:5432/raverse_online")
            self.db_conn = None
            self.logger.debug(f"Database URL configured: {self.db_url[:50]}...")
        except Exception as e:
            self.logger.warning(f"Database initialization failed: {e}")
            self.db_conn = None

    def _init_redis(self):
        """Initialize Redis cache connection."""
        try:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            self.redis_client.ping()
            self.logger.debug("Redis connection established")
        except Exception as e:
            self.logger.warning(f"Redis initialization failed: {e}")
            self.redis_client = None

    @contextmanager
    def _get_db_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            if self.db_url:
                conn = psycopg2.connect(self.db_url)
                yield conn
            else:
                yield None
        except Exception as e:
            self.logger.error(f"Database connection error: {e}")
            if conn:
                conn.rollback()
            yield None
        finally:
            if conn:
                conn.close()

    def _save_state_to_db(self, run_id: str):
        """Save agent state to PostgreSQL."""
        try:
            if not self.db_url:
                return

            with self._get_db_connection() as conn:
                if not conn:
                    return

                cursor = conn.cursor()
                state_data = {
                    "agent_id": self.agent_id,
                    "agent_type": self.agent_type,
                    "run_id": run_id,
                    "state": self.state,
                    "progress": self.progress,
                    "start_time": self.start_time.isoformat() if self.start_time else None,
                    "end_time": self.end_time.isoformat() if self.end_time else None,
                    "error": self.error,
                    "metrics": json.dumps(self.metrics),
                    "artifact_count": len(self.artifacts)
                }

                cursor.execute("""
                    INSERT INTO agent_states (agent_id, agent_type, run_id, state, progress,
                                             start_time, end_time, error, metrics, artifact_count)
                    VALUES (%(agent_id)s, %(agent_type)s, %(run_id)s, %(state)s, %(progress)s,
                            %(start_time)s, %(end_time)s, %(error)s, %(metrics)s, %(artifact_count)s)
                    ON CONFLICT (agent_id, run_id) DO UPDATE SET
                        state = EXCLUDED.state,
                        progress = EXCLUDED.progress,
                        end_time = EXCLUDED.end_time,
                        error = EXCLUDED.error,
                        metrics = EXCLUDED.metrics,
                        artifact_count = EXCLUDED.artifact_count
                """, state_data)

                conn.commit()
                self.logger.debug(f"Agent state saved to database for run {run_id}")
        except Exception as e:
            self.logger.warning(f"Failed to save state to database: {e}")

    def _cache_result(self, key: str, value: Any, ttl: int = 3600):
        """Cache result in Redis."""
        try:
            if not self.redis_client:
                return

            self.redis_client.setex(key, ttl, json.dumps(value, default=str))
            self.logger.debug(f"Cached result: {key}")
        except Exception as e:
            self.logger.warning(f"Failed to cache result: {e}")

    def _get_cached_result(self, key: str) -> Optional[Any]:
        """Retrieve cached result from Redis."""
        try:
            if not self.redis_client:
                return None

            cached = self.redis_client.get(key)
            if cached:
                self.logger.debug(f"Retrieved cached result: {key}")
                return json.loads(cached)
        except Exception as e:
            self.logger.warning(f"Failed to retrieve cached result: {e}")

        return None

    def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute agent task with state persistence and caching.

        Args:
            task: Task configuration dictionary

        Returns:
            Dictionary with results, artifacts, and metadata
        """
        self.run_id = task.get("run_id", str(uuid.uuid4()))
        self.state = "running"
        self.start_time = datetime.now()
        self.progress = 0.0

        # Check cache first
        cache_key = f"{self.agent_type}:{self.run_id}:{hashlib.md5(json.dumps(task, sort_keys=True, default=str).encode()).hexdigest()}"
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            self.logger.info(f"Using cached result for {self.name}")
            return cached_result

        try:
            self.logger.info(f"Starting {self.name} execution (Run: {self.run_id})")
            result = self._execute_impl(task)

            self.state = "succeeded"
            self.progress = 1.0
            self.end_time = datetime.now()

            self.logger.info(f"{self.name} completed successfully in {(self.end_time - self.start_time).total_seconds():.2f}s")

            # Save state and cache result
            self._save_state_to_db(self.run_id)
            formatted_result = self._format_result(result)
            self._cache_result(cache_key, formatted_result)

            return formatted_result

        except Exception as e:
            self.state = "failed"
            self.error = str(e)
            self.end_time = datetime.now()

            self.logger.error(f"{self.name} failed: {e}", exc_info=True)
            self._save_state_to_db(self.run_id)

            return self._format_error(e)

    @abstractmethod
    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implementation of agent-specific logic.
        Must be overridden by subclasses.
        """
        pass

    def _format_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Format successful result with metadata."""
        return {
            "agent": self.agent_type,
            "name": self.name,
            "status": "success",
            "state": self.state,
            "progress": self.progress,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
            "result": result,
            "artifacts": self.artifacts,
            "metrics": self.metrics
        }

    def _format_error(self, error: Exception) -> Dict[str, Any]:
        """Format error result with metadata."""
        return {
            "agent": self.agent_type,
            "name": self.name,
            "status": "failed",
            "state": self.state,
            "progress": self.progress,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
            "error": str(error),
            "error_type": type(error).__name__,
            "artifacts": self.artifacts,
            "metrics": self.metrics
        }

    def report_progress(self, progress: float, message: str = ""):
        """Report progress to orchestrator."""
        self.progress = min(1.0, max(0.0, progress))
        if message:
            self.logger.info(f"Progress: {self.progress*100:.1f}% - {message}")
        
        if self.orchestrator:
            self.orchestrator.report_agent_progress(self.agent_type, self.progress, message)

    def add_artifact(self, artifact_type: str, data: Any, description: str = ""):
        """Add artifact to results."""
        artifact = {
            "type": artifact_type,
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "data": data
        }
        self.artifacts.append(artifact)
        self.logger.debug(f"Added artifact: {artifact_type}")

    def set_metric(self, metric_name: str, value: Any):
        """Set performance metric and export to Prometheus."""
        self.metrics[metric_name] = value
        self.logger.debug(f"Metric {metric_name}: {value}")

        # Export to Prometheus format
        try:
            if self.redis_client:
                prometheus_key = f"prometheus:metric:{self.agent_type}:{metric_name}"
                self.redis_client.set(prometheus_key, value)
        except Exception as e:
            self.logger.debug(f"Failed to export metric to Prometheus: {e}")

    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        lines.append(f"# HELP raverse_agent_execution_time Agent execution time in seconds")
        lines.append(f"# TYPE raverse_agent_execution_time gauge")

        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
            lines.append(f'raverse_agent_execution_time{{agent="{self.agent_type}",run_id="{self.run_id}"}} {duration}')

        lines.append(f"# HELP raverse_agent_progress Agent progress (0-1)")
        lines.append(f"# TYPE raverse_agent_progress gauge")
        lines.append(f'raverse_agent_progress{{agent="{self.agent_type}",run_id="{self.run_id}"}} {self.progress}')

        for metric_name, value in self.metrics.items():
            lines.append(f"# HELP raverse_{metric_name} {metric_name}")
            lines.append(f"# TYPE raverse_{metric_name} gauge")
            try:
                numeric_value = float(value)
                lines.append(f'raverse_{metric_name}{{agent="{self.agent_type}",run_id="{self.run_id}"}} {numeric_value}')
            except (ValueError, TypeError):
                pass

        return "\n".join(lines)

    def skip(self, reason: str = ""):
        """Skip agent execution."""
        self.state = "skipped"
        self.progress = 0.0
        self.end_time = datetime.now()
        self.logger.info(f"{self.name} skipped: {reason}")
        
        return {
            "agent": self.agent_type,
            "name": self.name,
            "status": "skipped",
            "state": self.state,
            "reason": reason,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None
        }

    def hash_data(self, data: str) -> str:
        """Generate SHA-256 hash of data."""
        return hashlib.sha256(data.encode()).hexdigest()

    def validate_authorization(self, target: str, scope: Dict[str, Any]) -> bool:
        """
        Validate that target is within authorized scope.
        
        Args:
            target: Target URL or resource
            scope: Scope configuration
            
        Returns:
            True if authorized, False otherwise
        """
        if not scope:
            self.logger.warning("No scope defined - authorization check skipped")
            return False
        
        allowed_domains = scope.get("allowed_domains", [])
        allowed_paths = scope.get("allowed_paths", [])
        
        # Simple validation - can be extended
        for domain in allowed_domains:
            if domain in target:
                return True
        
        self.logger.warning(f"Target {target} not in authorized scope")
        return False

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent": self.agent_type,
            "name": self.name,
            "state": self.state,
            "progress": self.progress,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "error": self.error,
            "artifact_count": len(self.artifacts),
            "metric_count": len(self.metrics)
        }

    # ==================== Agent-to-Agent (A2A) Communication ====================

    def _publish_message(self, receiver: str, message_type: str,
                        payload: Dict[str, Any], priority: str = "normal") -> str:
        """
        Publish A2A message via Redis pub/sub.

        Args:
            receiver: Receiver agent name
            message_type: Type of message (task_complete, data_request, data_share, error, status_update, ack)
            payload: Message payload
            priority: Message priority (high, normal, low)

        Returns:
            Message ID
        """
        try:
            if not self.redis_client:
                self.logger.warning("Redis not available for A2A messaging")
                return ""

            message = {
                "message_id": str(uuid.uuid4()),
                "sender_agent": self.agent_type,
                "receiver_agent": receiver,
                "message_type": message_type,
                "payload": payload,
                "timestamp": datetime.utcnow().isoformat(),
                "correlation_id": self.run_id or str(uuid.uuid4()),
                "priority": priority,
                "ttl_seconds": 3600,
                "retry_count": 0,
                "max_retries": 3
            }

            # Publish to Redis
            channel = f"agent:messages:{receiver}"
            self.redis_client.publish(channel, json.dumps(message))

            # Log to PostgreSQL
            self._save_message_to_db(message)

            self.logger.debug(f"Published A2A message to {receiver}: {message_type}")
            return message["message_id"]

        except Exception as e:
            self.logger.error(f"Failed to publish A2A message: {e}")
            return ""

    def _subscribe_to_channel(self, channel: str, callback=None, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """
        Subscribe to Redis channel and wait for message.

        Args:
            channel: Channel name to subscribe to
            callback: Optional callback function for message processing
            timeout: Timeout in seconds

        Returns:
            Received message or None
        """
        try:
            if not self.redis_client:
                self.logger.warning("Redis not available for A2A messaging")
                return None

            pubsub = self.redis_client.pubsub()
            pubsub.subscribe(channel)

            start_time = time.time()
            for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])

                        if callback:
                            callback(data)

                        self.logger.debug(f"Received A2A message on {channel}")
                        return data

                    except Exception as e:
                        self.logger.error(f"Error processing A2A message: {e}")

                # Check timeout
                if time.time() - start_time > timeout:
                    self.logger.warning(f"A2A subscription timeout on {channel}")
                    break

            pubsub.unsubscribe(channel)
            return None

        except Exception as e:
            self.logger.error(f"Failed to subscribe to A2A channel: {e}")
            return None

    def _save_message_to_db(self, message: Dict[str, Any]) -> bool:
        """
        Save A2A message to PostgreSQL audit log.

        Args:
            message: Message to save

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.db_url:
                return False

            with self._get_db_connection() as conn:
                if not conn:
                    return False

                cursor = conn.cursor()

                # Create table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS agent_messages (
                        message_id UUID PRIMARY KEY,
                        sender_agent VARCHAR(255) NOT NULL,
                        receiver_agent VARCHAR(255) NOT NULL,
                        message_type VARCHAR(50) NOT NULL,
                        payload JSONB NOT NULL,
                        timestamp TIMESTAMPTZ NOT NULL,
                        correlation_id UUID NOT NULL,
                        priority VARCHAR(20),
                        status VARCHAR(50) DEFAULT 'pending',
                        retry_count INT DEFAULT 0,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        INDEX idx_correlation_id (correlation_id),
                        INDEX idx_sender_agent (sender_agent),
                        INDEX idx_receiver_agent (receiver_agent),
                        INDEX idx_timestamp (timestamp)
                    )
                """)

                # Insert message
                cursor.execute("""
                    INSERT INTO agent_messages
                    (message_id, sender_agent, receiver_agent, message_type, payload,
                     timestamp, correlation_id, priority, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (message_id) DO NOTHING
                """, (
                    message["message_id"],
                    message["sender_agent"],
                    message["receiver_agent"],
                    message["message_type"],
                    json.dumps(message["payload"]),
                    message["timestamp"],
                    message["correlation_id"],
                    message["priority"],
                    "pending"
                ))

                conn.commit()
                return True

        except Exception as e:
            self.logger.warning(f"Failed to save A2A message to database: {e}")
            return False

    def _get_messages_for_agent(self, agent_type: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve messages for a specific agent from database.

        Args:
            agent_type: Agent type to retrieve messages for
            limit: Maximum number of messages to retrieve

        Returns:
            List of messages
        """
        try:
            if not self.db_url:
                return []

            with self._get_db_connection() as conn:
                if not conn:
                    return []

                cursor = conn.cursor()
                cursor.execute("""
                    SELECT message_id, sender_agent, receiver_agent, message_type,
                           payload, timestamp, correlation_id, priority
                    FROM agent_messages
                    WHERE receiver_agent = %s AND status = 'pending'
                    ORDER BY priority DESC, timestamp ASC
                    LIMIT %s
                """, (agent_type, limit))

                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        "message_id": str(row[0]),
                        "sender_agent": row[1],
                        "receiver_agent": row[2],
                        "message_type": row[3],
                        "payload": json.loads(row[4]) if isinstance(row[4], str) else row[4],
                        "timestamp": row[5].isoformat() if row[5] else None,
                        "correlation_id": str(row[6]),
                        "priority": row[7]
                    })

                return messages

        except Exception as e:
            self.logger.warning(f"Failed to retrieve A2A messages: {e}")
            return []

