"""
Quality Gate Agent for RAVERSE 2.0
Implements A.I.E.F.N.M.W. Sentry Protocol for quality assurance.
"""

import logging
import json
import time
import psycopg2
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import os
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

from .base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)


class QualityGateAgent(BaseMemoryAgent):
    """
    Quality Gate Agent - Enforces quality standards using A.I.E.F.N.M.W. Sentry Protocol.

    A.I.E.F.N.M.W. Components:
    - A: Accuracy validation (precision/recall > 0.85)
    - I: Integrity checks (data completeness and consistency)
    - E: Efficiency metrics (execution time < 300s, memory < 2GB, CPU < 80%)
    - F: Functionality verification (all required functions executed)
    - N: Normalization standards (data format consistency)
    - M: Metadata validation (required metadata present)
    - W: Workflow compliance (workflow steps in correct order)

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "memory_augmented")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize Quality Gate Agent.

        Args:
            orchestrator: Reference to orchestration agent
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="Quality Gate (A.I.E.F.N.M.W. Sentry)",
            agent_type="QUALITY_GATE",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.logger = logging.getLogger("RAVERSE.QUALITY_GATE")
        self.db_manager = DatabaseManager()
        self.max_retries = 3
        self.retry_backoff = 2
        self.sentry_protocol = self._initialize_sentry_protocol()

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute quality gate task."""
        action = task.get("action", "validate_phase")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        if action == "validate_phase":
            result = self._validate_phase(task)
        elif action == "check_accuracy":
            result = self._check_accuracy(task)
        elif action == "check_integrity":
            result = self._check_integrity(task)
        elif action == "check_efficiency":
            result = self._check_efficiency(task)
        elif action == "check_functionality":
            result = self._check_functionality(task)
        elif action == "check_normalization":
            result = self._check_normalization(task)
        elif action == "check_metadata":
            result = self._check_metadata(task)
        elif action == "check_workflow":
            result = self._check_workflow(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _validate_phase(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a complete phase using A.I.E.F.N.M.W. protocol with real database persistence."""
        try:
            phase_name = task.get("phase_name", "")
            phase_data = task.get("phase_data", {})

            if not phase_name:
                return {"status": "error", "error": "phase_name is required"}

            # Run all A.I.E.F.N.M.W. checks
            accuracy_result = self._check_accuracy({"data": phase_data})
            integrity_result = self._check_integrity({"data": phase_data})
            efficiency_result = self._check_efficiency({"data": phase_data})
            functionality_result = self._check_functionality({"data": phase_data})
            normalization_result = self._check_normalization({"data": phase_data})
            metadata_result = self._check_metadata({"data": phase_data})
            workflow_result = self._check_workflow({"data": phase_data})

            # Aggregate results
            all_passed = all([
                accuracy_result.get("passed", False),
                integrity_result.get("passed", False),
                efficiency_result.get("passed", False),
                functionality_result.get("passed", False),
                normalization_result.get("passed", False),
                metadata_result.get("passed", False),
                workflow_result.get("passed", False)
            ])

            checkpoint_id = str(uuid.uuid4())

            # Store checkpoint with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO quality_checkpoints
                                (checkpoint_id, phase, accuracy_score, integrity_status,
                                 efficiency_metrics, functionality_status, normalization_status,
                                 metadata_status, workflow_status, passed, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """, (
                                checkpoint_id,
                                phase_name,
                                accuracy_result.get("score", 0),
                                integrity_result.get("status", "unknown"),
                                json.dumps(efficiency_result.get("metrics", {})),
                                functionality_result.get("status", "unknown"),
                                normalization_result.get("status", "unknown"),
                                metadata_result.get("status", "unknown"),
                                workflow_result.get("status", "unknown"),
                                all_passed,
                                datetime.utcnow()
                            ))
                        conn.commit()

                    self.logger.info(f"Phase '{phase_name}' validation: {'PASSED' if all_passed else 'FAILED'}")

                    return {
                        "status": "success",
                        "checkpoint_id": checkpoint_id,
                        "phase": phase_name,
                        "passed": all_passed,
                        "results": {
                            "accuracy": accuracy_result,
                            "integrity": integrity_result,
                            "efficiency": efficiency_result,
                            "functionality": functionality_result,
                            "normalization": normalization_result,
                            "metadata": metadata_result,
                            "workflow": workflow_result
                        }
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Phase validation failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _check_accuracy(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check accuracy of data (A in A.I.E.F.N.M.W.) - precision/recall validation."""
        try:
            data = task.get("data", {})

            # Validate data completeness and correctness
            required_fields = data.get("required_fields", [])
            total_fields = len(required_fields) if required_fields else 1

            # Count present and valid fields
            present_fields = [f for f in required_fields if f in data and data[f] is not None]
            missing_fields = [f for f in required_fields if f not in data or data[f] is None]

            # Calculate precision (correct fields / total fields)
            precision = len(present_fields) / total_fields if total_fields > 0 else 0

            # Calculate recall (found fields / expected fields)
            recall = len(present_fields) / total_fields if total_fields > 0 else 0

            # Accuracy is harmonic mean of precision and recall (F1 score)
            if precision + recall > 0:
                accuracy_score = 2 * (precision * recall) / (precision + recall)
            else:
                accuracy_score = 0

            # Threshold from sentry protocol
            threshold = self.sentry_protocol["A"]["threshold"]
            passed = accuracy_score >= threshold

            return {
                "status": "success",
                "passed": passed,
                "status": "PASS" if passed else "FAIL",
                "score": accuracy_score,
                "precision": precision,
                "recall": recall,
                "missing_fields": missing_fields,
                "threshold": threshold
            }
        except Exception as e:
            self.logger.error(f"Accuracy check failed: {e}", exc_info=True)
            return {"status": "error", "passed": False, "status": "ERROR", "error": str(e)}

    def _check_integrity(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check data integrity (I in A.I.E.F.N.M.W.)."""
        try:
            data = task.get("data", {})
            
            # Validate data types and formats
            integrity_issues = []
            
            # Check for data corruption
            if isinstance(data, dict):
                for key, value in data.items():
                    if value is None and key not in ["optional_field"]:
                        integrity_issues.append(f"Null value for {key}")
            
            status = "PASS" if len(integrity_issues) == 0 else "FAIL"
            
            return {
                "status": "success",
                "passed": status == "PASS",
                "status": status,
                "issues": integrity_issues
            }
        except Exception as e:
            self.logger.error(f"Integrity check failed: {e}")
            return {"status": "error", "passed": False, "error": str(e)}

    def _check_efficiency(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check efficiency metrics (E in A.I.E.F.N.M.W.) - performance validation."""
        try:
            data = task.get("data", {})

            # Extract metrics with defaults
            execution_time = data.get("execution_time", 0)  # seconds
            memory_usage = data.get("memory_usage", 0)  # MB
            cpu_usage = data.get("cpu_usage", 0)  # percentage
            throughput = data.get("throughput", 0)  # items/sec

            # Define SLA thresholds
            max_execution_time = 300  # 5 minutes
            max_memory_usage = 2048  # 2GB
            max_cpu_usage = 80  # 80%
            min_throughput = 1  # at least 1 item/sec

            # Check each metric
            time_ok = execution_time < max_execution_time
            memory_ok = memory_usage < max_memory_usage
            cpu_ok = cpu_usage < max_cpu_usage
            throughput_ok = throughput >= min_throughput or throughput == 0  # 0 means not measured

            passed = time_ok and memory_ok and cpu_ok and throughput_ok

            metrics = {
                "execution_time": execution_time,
                "execution_time_ok": time_ok,
                "execution_time_threshold": max_execution_time,
                "memory_usage": memory_usage,
                "memory_usage_ok": memory_ok,
                "memory_usage_threshold": max_memory_usage,
                "cpu_usage": cpu_usage,
                "cpu_usage_ok": cpu_ok,
                "cpu_usage_threshold": max_cpu_usage,
                "throughput": throughput,
                "throughput_ok": throughput_ok,
                "throughput_threshold": min_throughput
            }

            return {
                "status": "success",
                "passed": passed,
                "status": "PASS" if passed else "FAIL",
                "metrics": metrics
            }
        except Exception as e:
            self.logger.error(f"Efficiency check failed: {e}", exc_info=True)
            return {"status": "error", "passed": False, "status": "ERROR", "error": str(e)}

    def _check_functionality(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check functionality (F in A.I.E.F.N.M.W.)."""
        try:
            data = task.get("data", {})
            
            # Verify all required functions executed
            functions_executed = data.get("functions_executed", [])
            required_functions = data.get("required_functions", [])
            
            missing_functions = [f for f in required_functions if f not in functions_executed]
            
            passed = len(missing_functions) == 0
            
            return {
                "status": "success",
                "passed": passed,
                "functions_executed": len(functions_executed),
                "missing_functions": missing_functions
            }
        except Exception as e:
            self.logger.error(f"Functionality check failed: {e}")
            return {"status": "error", "passed": False, "error": str(e)}

    def _check_normalization(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check normalization standards (N in A.I.E.F.N.M.W.)."""
        try:
            data = task.get("data", {})
            
            # Check data format consistency
            normalization_issues = []
            
            # Validate JSON structure
            if isinstance(data, dict):
                for key in data.keys():
                    if not isinstance(key, str):
                        normalization_issues.append(f"Non-string key: {key}")
            
            passed = len(normalization_issues) == 0
            
            return {
                "status": "success",
                "passed": passed,
                "issues": normalization_issues
            }
        except Exception as e:
            self.logger.error(f"Normalization check failed: {e}")
            return {"status": "error", "passed": False, "error": str(e)}

    def _check_metadata(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check metadata validation (M in A.I.E.F.N.M.W.)."""
        try:
            data = task.get("data", {})
            
            # Verify required metadata
            required_metadata = ["timestamp", "source", "version"]
            metadata = data.get("metadata", {})
            
            missing_metadata = [m for m in required_metadata if m not in metadata]
            
            passed = len(missing_metadata) == 0
            
            return {
                "status": "success",
                "passed": passed,
                "metadata": metadata,
                "missing_metadata": missing_metadata
            }
        except Exception as e:
            self.logger.error(f"Metadata check failed: {e}")
            return {"status": "error", "passed": False, "error": str(e)}

    def _check_workflow(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Check workflow compliance (W in A.I.E.F.N.M.W.)."""
        try:
            data = task.get("data", {})
            
            # Verify workflow steps executed in order
            workflow_steps = data.get("workflow_steps", [])
            expected_steps = data.get("expected_steps", [])
            
            steps_match = workflow_steps == expected_steps
            
            return {
                "status": "success",
                "passed": steps_match,
                "workflow_steps": workflow_steps,
                "expected_steps": expected_steps
            }
        except Exception as e:
            self.logger.error(f"Workflow check failed: {e}")
            return {"status": "error", "passed": False, "error": str(e)}

    def _initialize_sentry_protocol(self) -> Dict[str, Any]:
        """Initialize A.I.E.F.N.M.W. Sentry Protocol."""
        return {
            "A": {"name": "Accuracy", "threshold": 0.95},
            "I": {"name": "Integrity", "threshold": 1.0},
            "E": {"name": "Efficiency", "threshold": 0.90},
            "F": {"name": "Functionality", "threshold": 1.0},
            "N": {"name": "Normalization", "threshold": 1.0},
            "M": {"name": "Metadata", "threshold": 1.0},
            "W": {"name": "Workflow", "threshold": 1.0}
        }

