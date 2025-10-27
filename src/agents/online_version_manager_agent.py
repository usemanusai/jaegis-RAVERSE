"""
Version Manager Agent for RAVERSE 2.0
Manages system versions, compatibility, and onboarding.
"""

import logging
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

from .base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)


class VersionManagerAgent(BaseMemoryAgent):
    """
    Version Manager Agent - Manages system versions and compatibility.
    Tracks component versions, validates compatibility, and manages onboarding.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "hierarchical")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        api_key: Optional[str] = None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize Version Manager Agent.

        Args:
            orchestrator: Reference to orchestration agent
            api_key: OpenRouter API key
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="Version Manager",
            agent_type="VERSION_MANAGER",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.logger = logging.getLogger("RAVERSE.VERSION_MANAGER")
        self.db_manager = DatabaseManager()
        self.max_retries = 3
        self.retry_backoff = 2

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute version management task."""
        action = task.get("action", "check_compatibility")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        result = None
        if action == "check_compatibility":
            result = self._check_compatibility(task)
        elif action == "register_version":
            result = self._register_version(task)
        elif action == "get_versions":
            result = self._get_versions(task)
        elif action == "validate_onboarding":
            result = self._validate_onboarding(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _check_compatibility(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check compatibility between components."""
        try:
            components = task.get("components", {})
            compatibility_matrix = self._build_compatibility_matrix()
            
            issues = []
            for component, version in components.items():
                if not self._is_compatible(component, version, compatibility_matrix):
                    issues.append({
                        "component": component,
                        "version": version,
                        "issue": "Incompatible version"
                    })
            
            compatible = len(issues) == 0
            
            # Store in database
            self._save_compatibility_check({
                "components": components,
                "compatible": compatible,
                "issues": issues,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return {
                "status": "success",
                "compatible": compatible,
                "issues": issues,
                "compatibility_matrix": compatibility_matrix
            }
        except Exception as e:
            self.logger.error(f"Compatibility check failed: {e}")
            return {"status": "error", "error": str(e)}

    def _register_version(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Register a component version with retry logic."""
        try:
            component_name = task.get("component_name")
            version = task.get("version")
            metadata = task.get("metadata", {})

            if not component_name or not version:
                return {"status": "error", "error": "Missing component_name or version"}

            version_id = str(uuid.uuid4())

            # Execute with retry logic for transient failures
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO system_versions
                                (version_id, component_name, version, metadata, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                                ON CONFLICT (component_name) DO UPDATE
                                SET version = EXCLUDED.version,
                                    metadata = EXCLUDED.metadata,
                                    updated_at = NOW()
                            """, (
                                version_id,
                                component_name,
                                version,
                                json.dumps(metadata),
                                datetime.utcnow()
                            ))
                        conn.commit()

                    self.logger.info(f"Registered {component_name} v{version}")
                    return {
                        "status": "success",
                        "version_id": version_id,
                        "component": component_name,
                        "version": version
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Version registration failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _get_versions(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Get all registered versions with retry logic."""
        try:
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                            cur.execute("""
                                SELECT version_id, component_name, version, metadata,
                                       created_at, updated_at
                                FROM system_versions
                                ORDER BY created_at DESC
                                LIMIT 100
                            """)
                            rows = cur.fetchall()

                    versions = []
                    for row in rows:
                        versions.append({
                            "version_id": row['version_id'],
                            "component": row['component_name'],
                            "version": row['version'],
                            "metadata": json.loads(row['metadata']) if row['metadata'] else {},
                            "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                            "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None
                        })

                    return {
                        "status": "success",
                        "versions": versions,
                        "total": len(versions)
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Get versions failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _validate_onboarding(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Validate system onboarding."""
        try:
            required_components = {
                "postgresql": "17.0+",
                "redis": "8.0+",
                "python": "3.13+",
                "docker": "24.0+",
                "openrouter_api": "1.0+"
            }
            
            validation_results = {}
            all_valid = True
            
            for component, min_version in required_components.items():
                is_valid = self._validate_component(component, min_version)
                validation_results[component] = is_valid
                if not is_valid:
                    all_valid = False
            
            # Store validation result
            self._save_onboarding_validation({
                "validation_results": validation_results,
                "all_valid": all_valid,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return {
                "status": "success",
                "onboarding_valid": all_valid,
                "validation_results": validation_results
            }
        except Exception as e:
            self.logger.error(f"Onboarding validation failed: {e}")
            return {"status": "error", "error": str(e)}

    def _build_compatibility_matrix(self) -> Dict[str, Any]:
        """Build compatibility matrix."""
        return {
            "postgresql": {
                "min_version": "17.0",
                "compatible_with": ["redis:8.0+", "python:3.13+"]
            },
            "redis": {
                "min_version": "8.0",
                "compatible_with": ["postgresql:17.0+", "python:3.13+"]
            },
            "python": {
                "min_version": "3.13",
                "compatible_with": ["postgresql:17.0+", "redis:8.0+"]
            },
            "docker": {
                "min_version": "24.0",
                "compatible_with": ["docker-compose:2.0+"]
            }
        }

    def _is_compatible(self, component: str, version: str, matrix: Dict[str, Any]) -> bool:
        """Check if component version is compatible."""
        if component not in matrix:
            return False
        
        min_version = matrix[component].get("min_version", "0.0")
        return self._compare_versions(version, min_version) >= 0

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
        try:
            parts1 = [int(x) for x in v1.split("+")[0].split(".")]
            parts2 = [int(x) for x in v2.split("+")[0].split(".")]
            
            for i in range(max(len(parts1), len(parts2))):
                p1 = parts1[i] if i < len(parts1) else 0
                p2 = parts2[i] if i < len(parts2) else 0
                
                if p1 > p2:
                    return 1
                elif p1 < p2:
                    return -1
            
            return 0
        except Exception:
            return 0

    def _validate_component(self, component: str, min_version: str) -> bool:
        """Validate a component is installed and meets minimum version."""
        try:
            if component == "postgresql":
                query = "SELECT version()"
                cursor = self.db_connection.cursor()
                cursor.execute(query)
                result = cursor.fetchone()
                return result is not None
            elif component == "redis":
                return self.redis_client is not None
            elif component == "python":
                import sys
                version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                return self._compare_versions(version, min_version) >= 0
            elif component == "docker":
                return os.path.exists("/var/run/docker.sock") or os.path.exists("//./pipe/docker_engine")
            elif component == "openrouter_api":
                return self.api_key is not None
            return False
        except Exception as e:
            self.logger.error(f"Component validation failed for {component}: {e}")
            return False

    def _save_compatibility_check(self, data: Dict[str, Any]) -> None:
        """Save compatibility check to database with retry logic."""
        try:
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO compatibility_checks
                                (check_id, components, compatible, issues, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                json.dumps(data.get("components", {})),
                                data.get("compatible", False),
                                json.dumps(data.get("issues", [])),
                                datetime.utcnow()
                            ))
                        conn.commit()
                    return

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Failed to save compatibility check: {e}", exc_info=True)

    def _save_onboarding_validation(self, data: Dict[str, Any]) -> None:
        """Save onboarding validation to database with retry logic."""
        try:
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO onboarding_validations
                                (validation_id, validation_results, all_valid, created_at)
                                VALUES (%s, %s, %s, %s)
                            """, (
                                str(uuid.uuid4()),
                                json.dumps(data.get("validation_results", {})),
                                data.get("all_valid", False),
                                datetime.utcnow()
                            ))
                        conn.commit()
                    return

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Failed to save onboarding validation: {e}", exc_info=True)

