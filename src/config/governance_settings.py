"""
Governance Configuration for RAVERSE 2.0
A2A Strategic Governance Protocol settings and approval workflow configuration
"""

import os
from typing import Dict, Any, List

# Approval Workflow Configuration
APPROVAL_TIMEOUT_HOURS = int(os.getenv("APPROVAL_TIMEOUT_HOURS", "24"))
APPROVAL_REQUIRED_APPROVERS = int(os.getenv("APPROVAL_REQUIRED_APPROVERS", "1"))
APPROVAL_ESCALATION_ENABLED = os.getenv("APPROVAL_ESCALATION_ENABLED", "true").lower() == "true"
APPROVAL_ESCALATION_TIMEOUT_HOURS = int(os.getenv("APPROVAL_ESCALATION_TIMEOUT_HOURS", "48"))

# Priority Levels
PRIORITY_LEVELS = {
    "critical": {"timeout_hours": 1, "required_approvers": 3},
    "high": {"timeout_hours": 4, "required_approvers": 2},
    "normal": {"timeout_hours": 24, "required_approvers": 1},
    "low": {"timeout_hours": 72, "required_approvers": 1}
}

# Request Types
REQUEST_TYPES = [
    "data_access",
    "system_modification",
    "security_policy_change",
    "resource_allocation",
    "user_management",
    "audit_request",
    "compliance_check",
    "incident_response"
]

# Retry Configuration
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_BACKOFF = int(os.getenv("RETRY_BACKOFF", "2"))

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "raverse")
DB_PASSWORD = os.getenv("DB_PASSWORD", "raverse_password")
DB_NAME = os.getenv("DB_NAME", "raverse_db")

# Audit Configuration
AUDIT_ENABLED = os.getenv("AUDIT_ENABLED", "true").lower() == "true"
AUDIT_LOG_RETENTION_DAYS = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))

# Notification Configuration
NOTIFICATION_ENABLED = os.getenv("NOTIFICATION_ENABLED", "true").lower() == "true"
NOTIFICATION_CHANNELS = os.getenv("NOTIFICATION_CHANNELS", "redis,database").split(",")

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/governance.log")

# Validation Schema
APPROVAL_REQUEST_SCHEMA = {
    "request_type": {"type": "string", "required": True, "enum": REQUEST_TYPES},
    "description": {"type": "string", "required": True, "min_length": 10},
    "requester": {"type": "string", "required": True},
    "approvers": {"type": "list", "required": True, "min_length": 1},
    "priority": {"type": "string", "required": False, "enum": list(PRIORITY_LEVELS.keys()), "default": "normal"},
    "metadata": {"type": "dict", "required": False}
}

def get_config() -> Dict[str, Any]:
    """Get complete governance configuration."""
    return {
        "approval": {
            "timeout_hours": APPROVAL_TIMEOUT_HOURS,
            "required_approvers": APPROVAL_REQUIRED_APPROVERS,
            "escalation_enabled": APPROVAL_ESCALATION_ENABLED,
            "escalation_timeout_hours": APPROVAL_ESCALATION_TIMEOUT_HOURS
        },
        "priority_levels": PRIORITY_LEVELS,
        "request_types": REQUEST_TYPES,
        "retry": {
            "max_retries": MAX_RETRIES,
            "backoff": RETRY_BACKOFF
        },
        "redis": {
            "host": REDIS_HOST,
            "port": REDIS_PORT,
            "db": REDIS_DB
        },
        "database": {
            "host": DB_HOST,
            "port": DB_PORT,
            "user": DB_USER,
            "database": DB_NAME
        },
        "audit": {
            "enabled": AUDIT_ENABLED,
            "log_retention_days": AUDIT_LOG_RETENTION_DAYS
        },
        "notification": {
            "enabled": NOTIFICATION_ENABLED,
            "channels": NOTIFICATION_CHANNELS
        }
    }

def validate_config() -> bool:
    """Validate configuration settings."""
    errors = []
    
    if APPROVAL_TIMEOUT_HOURS <= 0:
        errors.append("APPROVAL_TIMEOUT_HOURS must be positive")
    
    if APPROVAL_REQUIRED_APPROVERS < 1:
        errors.append("APPROVAL_REQUIRED_APPROVERS must be at least 1")
    
    if APPROVAL_ESCALATION_TIMEOUT_HOURS <= APPROVAL_TIMEOUT_HOURS:
        errors.append("APPROVAL_ESCALATION_TIMEOUT_HOURS must be greater than APPROVAL_TIMEOUT_HOURS")
    
    for priority, config in PRIORITY_LEVELS.items():
        if config["timeout_hours"] <= 0:
            errors.append(f"Priority {priority} timeout_hours must be positive")
        if config["required_approvers"] < 1:
            errors.append(f"Priority {priority} required_approvers must be at least 1")
    
    if MAX_RETRIES < 1:
        errors.append("MAX_RETRIES must be at least 1")
    
    if AUDIT_LOG_RETENTION_DAYS < 1:
        errors.append("AUDIT_LOG_RETENTION_DAYS must be at least 1")
    
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return True


