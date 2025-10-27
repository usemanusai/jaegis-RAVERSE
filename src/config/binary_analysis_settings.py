"""
Binary Analysis Configuration for RAVERSE 2.0
DAA and LIMA agent settings for disassembly and logic identification
"""

import os
from typing import Dict, Any, List

# Supported Architectures
SUPPORTED_ARCHITECTURES = ["x86", "x64", "ARM", "ARM64", "MIPS"]
DEFAULT_ARCHITECTURE = os.getenv("DEFAULT_ARCHITECTURE", "x64")

# Supported Binary Formats
SUPPORTED_FORMATS = ["PE", "ELF", "Mach-O"]
DEFAULT_FORMAT = os.getenv("DEFAULT_FORMAT", "ELF")

# Capstone Disassembly Configuration
CAPSTONE_SYNTAX = os.getenv("CAPSTONE_SYNTAX", "intel")  # intel or att
CAPSTONE_DETAIL_MODE = os.getenv("CAPSTONE_DETAIL_MODE", "true").lower() == "true"

# Pattern Detection Configuration
PATTERN_DETECTION_ENABLED = os.getenv("PATTERN_DETECTION_ENABLED", "true").lower() == "true"
PATTERN_CONFIDENCE_THRESHOLD = float(os.getenv("PATTERN_CONFIDENCE_THRESHOLD", "0.70"))

# Pattern Signatures
ENCRYPTION_PATTERNS = [
    "AES", "RSA", "DES", "MD5", "SHA1", "SHA256",
    "EVP_", "CRYPTO_", "gcry_", "mbedtls_"
]

NETWORK_PATTERNS = [
    "socket", "connect", "send", "recv", "http", "https",
    "DNS", "TCP", "UDP", "inet_"
]

ANTIDEBUG_PATTERNS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "ptrace", "SIGTRAP", "int3", "0xCC"
]

OBFUSCATION_PATTERNS = [
    "UPX", "themida", "VMProtect", "Confuser",
    "ConfuserEx", "yoyo", "Eziriz"
]

# Control Flow Analysis Configuration
CFG_GENERATION_ENABLED = os.getenv("CFG_GENERATION_ENABLED", "true").lower() == "true"
LOOP_DETECTION_ENABLED = os.getenv("LOOP_DETECTION_ENABLED", "true").lower() == "true"
BRANCH_DETECTION_ENABLED = os.getenv("BRANCH_DETECTION_ENABLED", "true").lower() == "true"

# Data Flow Analysis Configuration
DFA_ENABLED = os.getenv("DFA_ENABLED", "true").lower() == "true"
REGISTER_TRACKING_ENABLED = os.getenv("REGISTER_TRACKING_ENABLED", "true").lower() == "true"
MEMORY_TRACKING_ENABLED = os.getenv("MEMORY_TRACKING_ENABLED", "true").lower() == "true"

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
LOG_FILE = os.getenv("LOG_FILE", "logs/binary_analysis.log")

# Validation Schema
BINARY_ANALYSIS_SCHEMA = {
    "binary_data": {"type": "bytes", "required": True},
    "format": {"type": "string", "required": False, "enum": SUPPORTED_FORMATS},
    "architecture": {"type": "string", "required": False, "enum": SUPPORTED_ARCHITECTURES},
    "metadata": {"type": "dict", "required": False}
}

def get_config() -> Dict[str, Any]:
    """Get complete binary analysis configuration."""
    return {
        "architectures": {
            "supported": SUPPORTED_ARCHITECTURES,
            "default": DEFAULT_ARCHITECTURE
        },
        "formats": {
            "supported": SUPPORTED_FORMATS,
            "default": DEFAULT_FORMAT
        },
        "capstone": {
            "syntax": CAPSTONE_SYNTAX,
            "detail_mode": CAPSTONE_DETAIL_MODE
        },
        "pattern_detection": {
            "enabled": PATTERN_DETECTION_ENABLED,
            "confidence_threshold": PATTERN_CONFIDENCE_THRESHOLD,
            "encryption": ENCRYPTION_PATTERNS,
            "network": NETWORK_PATTERNS,
            "antidebug": ANTIDEBUG_PATTERNS,
            "obfuscation": OBFUSCATION_PATTERNS
        },
        "control_flow": {
            "cfg_generation": CFG_GENERATION_ENABLED,
            "loop_detection": LOOP_DETECTION_ENABLED,
            "branch_detection": BRANCH_DETECTION_ENABLED
        },
        "data_flow": {
            "enabled": DFA_ENABLED,
            "register_tracking": REGISTER_TRACKING_ENABLED,
            "memory_tracking": MEMORY_TRACKING_ENABLED
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
    
    if DEFAULT_ARCHITECTURE not in SUPPORTED_ARCHITECTURES:
        errors.append(f"DEFAULT_ARCHITECTURE must be one of {SUPPORTED_ARCHITECTURES}")
    
    if DEFAULT_FORMAT not in SUPPORTED_FORMATS:
        errors.append(f"DEFAULT_FORMAT must be one of {SUPPORTED_FORMATS}")
    
    if not (0 <= PATTERN_CONFIDENCE_THRESHOLD <= 1):
        errors.append("PATTERN_CONFIDENCE_THRESHOLD must be between 0 and 1")
    
    if MAX_RETRIES < 1:
        errors.append("MAX_RETRIES must be at least 1")
    
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return True


