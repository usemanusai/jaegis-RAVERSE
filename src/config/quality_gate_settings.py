"""
Quality Gate Configuration for RAVERSE 2.0
A.I.E.F.N.M.W. Sentry Protocol thresholds and validation settings
"""

import os
from typing import Dict, Any

# A.I.E.F.N.M.W. Sentry Protocol Thresholds
# A: Accuracy - Precision/Recall F1 Score
ACCURACY_THRESHOLD = float(os.getenv("ACCURACY_THRESHOLD", "0.95"))

# I: Integrity - Data completeness and consistency
INTEGRITY_THRESHOLD = float(os.getenv("INTEGRITY_THRESHOLD", "1.0"))

# E: Efficiency - Execution time, memory, CPU, throughput
EFFICIENCY_THRESHOLD = float(os.getenv("EFFICIENCY_THRESHOLD", "0.90"))
EFFICIENCY_MAX_EXECUTION_TIME = int(os.getenv("EFFICIENCY_MAX_EXECUTION_TIME", "300"))  # seconds
EFFICIENCY_MAX_MEMORY = int(os.getenv("EFFICIENCY_MAX_MEMORY", "2048"))  # MB
EFFICIENCY_MAX_CPU = float(os.getenv("EFFICIENCY_MAX_CPU", "80.0"))  # percentage

# F: Functionality - All required functions executed
FUNCTIONALITY_THRESHOLD = float(os.getenv("FUNCTIONALITY_THRESHOLD", "1.0"))

# N: Normalization - Data format consistency
NORMALIZATION_THRESHOLD = float(os.getenv("NORMALIZATION_THRESHOLD", "1.0"))

# M: Metadata - Required metadata present
METADATA_THRESHOLD = float(os.getenv("METADATA_THRESHOLD", "1.0"))

# W: Workflow - Workflow steps in correct order
WORKFLOW_THRESHOLD = float(os.getenv("WORKFLOW_THRESHOLD", "1.0"))

# Checkpoint Configuration
CHECKPOINT_ENABLED = os.getenv("CHECKPOINT_ENABLED", "true").lower() == "true"
CHECKPOINT_INTERVAL = int(os.getenv("CHECKPOINT_INTERVAL", "60"))  # seconds

# Retry Configuration
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_BACKOFF = int(os.getenv("RETRY_BACKOFF", "2"))

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "raverse")
DB_PASSWORD = os.getenv("DB_PASSWORD", "raverse_password")
DB_NAME = os.getenv("DB_NAME", "raverse_db")

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/quality_gate.log")

# Validation Schema
QUALITY_GATE_SCHEMA = {
    "phase": {"type": "string", "required": True},
    "accuracy": {"type": "float", "required": True, "min": 0, "max": 1},
    "integrity": {"type": "float", "required": True, "min": 0, "max": 1},
    "efficiency": {"type": "float", "required": True, "min": 0, "max": 1},
    "functionality": {"type": "float", "required": True, "min": 0, "max": 1},
    "normalization": {"type": "float", "required": True, "min": 0, "max": 1},
    "metadata": {"type": "float", "required": True, "min": 0, "max": 1},
    "workflow": {"type": "float", "required": True, "min": 0, "max": 1},
    "status": {"type": "string", "required": True, "enum": ["PASS", "FAIL", "ERROR"]}
}

def get_config() -> Dict[str, Any]:
    """Get complete quality gate configuration."""
    return {
        "thresholds": {
            "accuracy": ACCURACY_THRESHOLD,
            "integrity": INTEGRITY_THRESHOLD,
            "efficiency": EFFICIENCY_THRESHOLD,
            "functionality": FUNCTIONALITY_THRESHOLD,
            "normalization": NORMALIZATION_THRESHOLD,
            "metadata": METADATA_THRESHOLD,
            "workflow": WORKFLOW_THRESHOLD
        },
        "efficiency_limits": {
            "max_execution_time": EFFICIENCY_MAX_EXECUTION_TIME,
            "max_memory": EFFICIENCY_MAX_MEMORY,
            "max_cpu": EFFICIENCY_MAX_CPU
        },
        "checkpoint": {
            "enabled": CHECKPOINT_ENABLED,
            "interval": CHECKPOINT_INTERVAL
        },
        "retry": {
            "max_retries": MAX_RETRIES,
            "backoff": RETRY_BACKOFF
        },
        "database": {
            "host": DB_HOST,
            "port": DB_PORT,
            "user": DB_USER,
            "database": DB_NAME
        }
    }

def validate_config() -> bool:
    """Validate configuration settings."""
    errors = []
    
    thresholds = {
        "ACCURACY": ACCURACY_THRESHOLD,
        "INTEGRITY": INTEGRITY_THRESHOLD,
        "EFFICIENCY": EFFICIENCY_THRESHOLD,
        "FUNCTIONALITY": FUNCTIONALITY_THRESHOLD,
        "NORMALIZATION": NORMALIZATION_THRESHOLD,
        "METADATA": METADATA_THRESHOLD,
        "WORKFLOW": WORKFLOW_THRESHOLD
    }
    
    for name, value in thresholds.items():
        if not (0 <= value <= 1):
            errors.append(f"{name}_THRESHOLD must be between 0 and 1")
    
    if EFFICIENCY_MAX_EXECUTION_TIME <= 0:
        errors.append("EFFICIENCY_MAX_EXECUTION_TIME must be positive")
    
    if EFFICIENCY_MAX_MEMORY <= 0:
        errors.append("EFFICIENCY_MAX_MEMORY must be positive")
    
    if not (0 <= EFFICIENCY_MAX_CPU <= 100):
        errors.append("EFFICIENCY_MAX_CPU must be between 0 and 100")
    
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return True


