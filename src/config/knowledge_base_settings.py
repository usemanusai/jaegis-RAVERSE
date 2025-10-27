"""
Knowledge Base Configuration for RAVERSE 2.0
Embedding model settings, RAG parameters, and semantic search configuration
"""

import os
from typing import Dict, Any

# Embedding Model Configuration
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DIMENSION = 384  # all-MiniLM-L6-v2 produces 384-dimensional vectors
EMBEDDING_BATCH_SIZE = 32

# Semantic Search Configuration
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.5"))
SEARCH_LIMIT = int(os.getenv("SEARCH_LIMIT", "5"))
SEARCH_TIMEOUT = int(os.getenv("SEARCH_TIMEOUT", "30"))

# RAG (Retrieval-Augmented Generation) Configuration
RAG_MAX_ITERATIONS = int(os.getenv("RAG_MAX_ITERATIONS", "3"))
RAG_CONVERGENCE_THRESHOLD = float(os.getenv("RAG_CONVERGENCE_THRESHOLD", "0.85"))
RAG_QUERY_REFINEMENT_ENABLED = os.getenv("RAG_QUERY_REFINEMENT_ENABLED", "true").lower() == "true"

# LLM Configuration for Knowledge Base
LLM_MODEL = os.getenv("LLM_MODEL", "google/gemini-2.0-flash-exp:free")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1000"))
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))

# Retry Configuration
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_BACKOFF = int(os.getenv("RETRY_BACKOFF", "2"))

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "raverse")
DB_PASSWORD = os.getenv("DB_PASSWORD", "raverse_password")
DB_NAME = os.getenv("DB_NAME", "raverse_db")

# Cache Configuration
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))  # 1 hour
CACHE_ENABLED = os.getenv("CACHE_ENABLED", "true").lower() == "true"

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/knowledge_base.log")

# Validation Schema
KNOWLEDGE_BASE_SCHEMA = {
    "content": {"type": "string", "required": True, "min_length": 10},
    "source": {"type": "string", "required": True},
    "metadata": {"type": "dict", "required": False},
    "embedding": {"type": "list", "required": False, "length": EMBEDDING_DIMENSION}
}

# Default Metadata
DEFAULT_METADATA = {
    "version": "1.0",
    "created_by": "RAVERSE",
    "tags": []
}

def get_config() -> Dict[str, Any]:
    """Get complete knowledge base configuration."""
    return {
        "embedding": {
            "model": EMBEDDING_MODEL,
            "dimension": EMBEDDING_DIMENSION,
            "batch_size": EMBEDDING_BATCH_SIZE
        },
        "search": {
            "similarity_threshold": SIMILARITY_THRESHOLD,
            "limit": SEARCH_LIMIT,
            "timeout": SEARCH_TIMEOUT
        },
        "rag": {
            "max_iterations": RAG_MAX_ITERATIONS,
            "convergence_threshold": RAG_CONVERGENCE_THRESHOLD,
            "query_refinement_enabled": RAG_QUERY_REFINEMENT_ENABLED
        },
        "llm": {
            "model": LLM_MODEL,
            "temperature": LLM_TEMPERATURE,
            "max_tokens": LLM_MAX_TOKENS,
            "timeout": LLM_TIMEOUT
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
        },
        "cache": {
            "ttl": CACHE_TTL,
            "enabled": CACHE_ENABLED
        }
    }

def validate_config() -> bool:
    """Validate configuration settings."""
    errors = []
    
    if EMBEDDING_DIMENSION <= 0:
        errors.append("EMBEDDING_DIMENSION must be positive")
    
    if not (0 <= SIMILARITY_THRESHOLD <= 1):
        errors.append("SIMILARITY_THRESHOLD must be between 0 and 1")
    
    if RAG_MAX_ITERATIONS < 1:
        errors.append("RAG_MAX_ITERATIONS must be at least 1")
    
    if not (0 <= RAG_CONVERGENCE_THRESHOLD <= 1):
        errors.append("RAG_CONVERGENCE_THRESHOLD must be between 0 and 1")
    
    if MAX_RETRIES < 1:
        errors.append("MAX_RETRIES must be at least 1")
    
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return True


