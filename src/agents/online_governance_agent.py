"""
Governance Agent for RAVERSE 2.0
Implements A2A Strategic Governance Protocol for approval workflows and compliance.
"""

import logging
import json
import time
import psycopg2
import redis
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import uuid
import os
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

from .base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager
from utils.cache import CacheManager

logger = logging.getLogger(__name__)


class GovernanceAgent(BaseMemoryAgent):
    """
    Governance Agent - Manages approval workflows and compliance.
    Implements A2A Strategic Governance Protocol with real Redis pub/sub and database persistence.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "hierarchical")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize Governance Agent.

        Args:
            orchestrator: Reference to orchestration agent
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="Governance Manager",
            agent_type="GOVERNANCE",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.logger = logging.getLogger("RAVERSE.GOVERNANCE")
        self.db_manager = DatabaseManager()
        self.cache_manager = CacheManager()
        self.max_retries = 3
        self.retry_backoff = 2
        self.approval_timeout_hours = 24

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute governance task."""
        action = task.get("action", "create_approval_request")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        if action == "create_approval_request":
            result = self._create_approval_request(task)
        elif action == "approve_request":
            result = self._approve_request(task)
        elif action == "reject_request":
            result = self._reject_request(task)
        elif action == "get_approval_status":
            result = self._get_approval_status(task)
        elif action == "audit_log":
            result = self._audit_log(task)
        elif action == "create_policy":
            result = self._create_policy(task)
        elif action == "list_policies":
            result = self._list_policies(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _create_approval_request(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Create an approval request with real database and Redis pub/sub."""
        try:
            request_type = task.get("request_type", "")
            description = task.get("description", "")
            requester = task.get("requester", "")
            approvers = task.get("approvers", [])
            priority = task.get("priority", "normal")

            if not request_type or not approvers:
                return {"status": "error", "error": "request_type and approvers are required"}

            request_id = str(uuid.uuid4())
            workflow_id = str(uuid.uuid4())
            correlation_id = str(uuid.uuid4())

            # Create approval workflow with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            # Insert approval workflow
                            cur.execute("""
                                INSERT INTO approval_workflows
                                (workflow_id, request_id, request_type, description, requester,
                                 approvers, priority, status, created_at, expires_at)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """, (
                                workflow_id,
                                request_id,
                                request_type,
                                description,
                                requester,
                                json.dumps(approvers),
                                priority,
                                "pending",
                                datetime.utcnow(),
                                datetime.utcnow() + timedelta(hours=self.approval_timeout_hours)
                            ))

                            # Log governance event
                            cur.execute("""
                                INSERT INTO governance_audit_log
                                (event_id, event_type, event_data, correlation_id, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                "approval_request_created",
                                json.dumps({
                                    "request_id": request_id,
                                    "request_type": request_type,
                                    "requester": requester,
                                    "approvers": approvers,
                                    "priority": priority
                                }),
                                correlation_id,
                                datetime.utcnow()
                            ))
                        conn.commit()

                    # Publish to Redis for real-time notification
                    message = {
                        "message_id": str(uuid.uuid4()),
                        "sender_agent": self.agent_type,
                        "message_type": "approval_request",
                        "payload": {
                            "request_id": request_id,
                            "request_type": request_type,
                            "description": description,
                            "priority": priority,
                            "correlation_id": correlation_id
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }

                    # Publish to each approver's channel
                    for approver in approvers:
                        channel = f"agent:messages:{approver}"
                        self.cache_manager.client.publish(channel, json.dumps(message))

                    # Also publish to governance channel
                    self.cache_manager.client.publish("governance:approvals", json.dumps(message))

                    self.logger.info(f"Created approval request {request_id} of type {request_type}")

                    return {
                        "status": "success",
                        "request_id": request_id,
                        "workflow_id": workflow_id,
                        "correlation_id": correlation_id,
                        "approvers": approvers,
                        "approval_status": "pending",
                        "expires_at": (datetime.utcnow() + timedelta(hours=self.approval_timeout_hours)).isoformat()
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Approval request creation failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _approve_request(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Approve an approval request with real database and Redis notification."""
        try:
            request_id = task.get("request_id", "")
            approver = task.get("approver", "")
            comments = task.get("comments", "")

            if not request_id or not approver:
                return {"status": "error", "error": "request_id and approver are required"}

            correlation_id = str(uuid.uuid4())

            # Update workflow status with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                            # Get workflow details
                            cur.execute("""
                                SELECT workflow_id, request_type, requester FROM approval_workflows
                                WHERE request_id = %s
                            """, (request_id,))
                            workflow = cur.fetchone()

                            if not workflow:
                                return {"status": "error", "error": f"Workflow {request_id} not found"}

                            # Update workflow status
                            cur.execute("""
                                UPDATE approval_workflows
                                SET status = %s, updated_at = %s
                                WHERE request_id = %s
                            """, ("approved", datetime.utcnow(), request_id))

                            # Record approval decision
                            cur.execute("""
                                INSERT INTO approval_decisions
                                (decision_id, workflow_id, approver, decision, comments, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                workflow['workflow_id'],
                                approver,
                                "approved",
                                comments,
                                datetime.utcnow()
                            ))

                            # Log governance event
                            cur.execute("""
                                INSERT INTO governance_audit_log
                                (event_id, event_type, event_data, correlation_id, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                "request_approved",
                                json.dumps({
                                    "request_id": request_id,
                                    "approver": approver,
                                    "comments": comments
                                }),
                                correlation_id,
                                datetime.utcnow()
                            ))
                        conn.commit()

                    # Publish approval to Redis
                    message = {
                        "message_id": str(uuid.uuid4()),
                        "sender_agent": self.agent_type,
                        "message_type": "approval_decision",
                        "payload": {
                            "request_id": request_id,
                            "decision": "approved",
                            "approver": approver,
                            "comments": comments,
                            "correlation_id": correlation_id
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }

                    # Notify requester
                    if workflow['requester']:
                        channel = f"agent:messages:{workflow['requester']}"
                        self.cache_manager.client.publish(channel, json.dumps(message))

                    # Publish to governance channel
                    self.cache_manager.client.publish("governance:approvals", json.dumps(message))

                    self.logger.info(f"Request {request_id} approved by {approver}")

                    return {
                        "status": "success",
                        "request_id": request_id,
                        "approver": approver,
                        "action": "approved",
                        "correlation_id": correlation_id
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Request approval failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _reject_request(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Reject an approval request with real database and Redis notification."""
        try:
            request_id = task.get("request_id", "")
            rejector = task.get("rejector", "")
            reason = task.get("reason", "")

            if not request_id or not rejector:
                return {"status": "error", "error": "request_id and rejector are required"}

            correlation_id = str(uuid.uuid4())

            # Update workflow status with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                            # Get workflow details
                            cur.execute("""
                                SELECT workflow_id, request_type, requester FROM approval_workflows
                                WHERE request_id = %s
                            """, (request_id,))
                            workflow = cur.fetchone()

                            if not workflow:
                                return {"status": "error", "error": f"Workflow {request_id} not found"}

                            # Update workflow status
                            cur.execute("""
                                UPDATE approval_workflows
                                SET status = %s, updated_at = %s
                                WHERE request_id = %s
                            """, ("rejected", datetime.utcnow(), request_id))

                            # Record rejection decision
                            cur.execute("""
                                INSERT INTO approval_decisions
                                (decision_id, workflow_id, approver, decision, comments, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                workflow['workflow_id'],
                                rejector,
                                "rejected",
                                reason,
                                datetime.utcnow()
                            ))

                            # Log governance event
                            cur.execute("""
                                INSERT INTO governance_audit_log
                                (event_id, event_type, event_data, correlation_id, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                "request_rejected",
                                json.dumps({
                                    "request_id": request_id,
                                    "rejector": rejector,
                                    "reason": reason
                                }),
                                correlation_id,
                                datetime.utcnow()
                            ))
                        conn.commit()

                    # Publish rejection to Redis
                    message = {
                        "message_id": str(uuid.uuid4()),
                        "sender_agent": self.agent_type,
                        "message_type": "approval_decision",
                        "payload": {
                            "request_id": request_id,
                            "decision": "rejected",
                            "rejector": rejector,
                            "reason": reason,
                            "correlation_id": correlation_id
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }

                    # Notify requester
                    if workflow['requester']:
                        channel = f"agent:messages:{workflow['requester']}"
                        self.cache_manager.client.publish(channel, json.dumps(message))

                    # Publish to governance channel
                    self.cache_manager.client.publish("governance:approvals", json.dumps(message))

                    self.logger.info(f"Request {request_id} rejected by {rejector}")

                    return {
                        "status": "success",
                        "request_id": request_id,
                        "rejector": rejector,
                        "action": "rejected",
                        "reason": reason,
                        "correlation_id": correlation_id
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Request rejection failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _get_approval_status(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Get approval request status."""
        try:
            request_id = task.get("request_id", "")
            
            query = """
            SELECT workflow_id, request_id, approvers, status, created_at, updated_at
            FROM approval_workflows
            WHERE request_id = %s
            """
            
            cursor = self.db_connection.cursor()
            cursor.execute(query, (request_id,))
            row = cursor.fetchone()
            
            if not row:
                return {"status": "error", "error": f"Request {request_id} not found"}
            
            return {
                "status": "success",
                "workflow_id": row[0],
                "request_id": row[1],
                "approvers": json.loads(row[2]) if row[2] else [],
                "approval_status": row[3],
                "created_at": row[4].isoformat() if row[4] else None,
                "updated_at": row[5].isoformat() if row[5] else None
            }
        except Exception as e:
            self.logger.error(f"Get approval status failed: {e}")
            return {"status": "error", "error": str(e)}

    def _audit_log(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Get audit log."""
        try:
            limit = task.get("limit", 100)
            
            query = """
            SELECT event_id, event_type, event_data, created_at
            FROM governance_audit_log
            ORDER BY created_at DESC
            LIMIT %s
            """
            
            cursor = self.db_connection.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            
            audit_entries = []
            for row in rows:
                audit_entries.append({
                    "event_id": row[0],
                    "event_type": row[1],
                    "event_data": json.loads(row[2]) if row[2] else {},
                    "created_at": row[3].isoformat() if row[3] else None
                })
            
            return {
                "status": "success",
                "audit_entries": audit_entries,
                "total": len(audit_entries)
            }
        except Exception as e:
            self.logger.error(f"Audit log retrieval failed: {e}")
            return {"status": "error", "error": str(e)}

    def _create_policy(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Create a governance policy."""
        try:
            policy_name = task.get("policy_name", "")
            rules = task.get("rules", {})
            enforcement_level = task.get("enforcement_level", "strict")
            
            policy_id = str(uuid.uuid4())
            
            query = """
            INSERT INTO governance_policies 
            (policy_id, policy_name, rules, enforcement_level, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """
            
            self.db_connection.execute(query, (
                policy_id,
                policy_name,
                json.dumps(rules),
                enforcement_level,
                datetime.utcnow()
            ))
            
            self.db_connection.commit()
            
            self.logger.info(f"Created policy {policy_name}")
            
            return {
                "status": "success",
                "policy_id": policy_id,
                "policy_name": policy_name,
                "enforcement_level": enforcement_level
            }
        except Exception as e:
            self.logger.error(f"Policy creation failed: {e}")
            return {"status": "error", "error": str(e)}

    def _list_policies(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """List all governance policies."""
        try:
            query = """
            SELECT policy_id, policy_name, enforcement_level, created_at
            FROM governance_policies
            ORDER BY created_at DESC
            """
            
            cursor = self.db_connection.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            
            policies = []
            for row in rows:
                policies.append({
                    "policy_id": row[0],
                    "policy_name": row[1],
                    "enforcement_level": row[2],
                    "created_at": row[3].isoformat() if row[3] else None
                })
            
            return {
                "status": "success",
                "policies": policies,
                "total": len(policies)
            }
        except Exception as e:
            self.logger.error(f"List policies failed: {e}")
            return {"status": "error", "error": str(e)}

    def _log_governance_event(self, event_data: Dict[str, Any]) -> None:
        """Log a governance event."""
        try:
            query = """
            INSERT INTO governance_audit_log (event_id, event_type, event_data, created_at)
            VALUES (%s, %s, %s, %s)
            """
            
            self.db_connection.execute(query, (
                str(uuid.uuid4()),
                event_data.get("event_type", "unknown"),
                json.dumps(event_data),
                datetime.utcnow()
            ))
            
            self.db_connection.commit()
        except Exception as e:
            self.logger.error(f"Failed to log governance event: {e}")

