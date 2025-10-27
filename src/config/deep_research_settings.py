"""
Deep Research Agent Configuration Settings
"""

import os
from typing import Dict, Any

# OpenRouter Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# BraveSearch Configuration
BRAVE_SEARCH_API_KEY = os.getenv("BRAVE_SEARCH_API_KEY", "")
BRAVE_SEARCH_BASE_URL = "https://api.search.brave.com/res/v1"

# Deep Research Agent Models
DEEP_RESEARCH_AGENTS = {
    "topic_enhancer": {
        "model": "anthropic/claude-3.5-sonnet:free",
        "temperature": 0.5,
        "max_tokens": 1000,
        "timeout": 30,
        "retry_attempts": 3,
        "retry_backoff": 2  # Exponential backoff multiplier
    },
    "web_researcher": {
        "model": "google/gemini-2.0-flash-exp:free",
        "temperature": 0.7,
        "max_tokens": 2000,
        "timeout": 30,
        "retry_attempts": 3,
        "retry_backoff": 2,
        "max_search_results": 10,
        "search_freshness": "1d"  # Last 24 hours
    },
    "content_analyzer": {
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "temperature": 0.6,
        "max_tokens": 2000,
        "timeout": 30,
        "retry_attempts": 3,
        "retry_backoff": 2
    }
}

# Fallback Models (if primary unavailable)
FALLBACK_MODELS = {
    "topic_enhancer": [
        "meta-llama/llama-3.3-70b-instruct:free",
        "mistralai/mistral-7b-instruct:free"
    ],
    "web_researcher": [
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen-2.5-72b-instruct:free"
    ],
    "content_analyzer": [
        "anthropic/claude-3.5-sonnet:free",
        "qwen/qwen-2.5-72b-instruct:free"
    ]
}

# Web Scraping Configuration
WEB_SCRAPING = {
    "timeout": 10,
    "max_retries": 3,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "follow_redirects": True,
    "verify_ssl": True
}

# A2A Communication Configuration
A2A_COMMUNICATION = {
    "redis_channel_prefix": "agent:messages",
    "broadcast_channel": "agent:broadcast",
    "error_channel": "agent:errors",
    "metrics_channel": "agent:metrics",
    "deadletter_channel": "agent:deadletter",
    "message_ttl_seconds": 3600,
    "subscription_timeout": 30,
    "max_retries": 3,
    "retry_backoff": 2
}

# Database Configuration
DATABASE = {
    "url": os.getenv("POSTGRES_URL", "postgresql://raverse:raverse_secure_password@localhost:5432/raverse_online"),
    "pool_size": 10,
    "max_overflow": 20,
    "pool_recycle": 3600,
    "echo": False
}

# Redis Configuration
REDIS = {
    "url": os.getenv("REDIS_URL", "redis://localhost:6379"),
    "decode_responses": True,
    "socket_connect_timeout": 5,
    "socket_timeout": 5,
    "retry_on_timeout": True
}

# Logging Configuration
LOGGING = {
    "level": os.getenv("LOG_LEVEL", "INFO"),
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/deep_research.log",
    "max_bytes": 10485760,  # 10MB
    "backup_count": 5
}

# Metrics Configuration
METRICS = {
    "enabled": True,
    "prometheus_port": 8001,
    "export_interval": 60,  # seconds
    "retention_days": 30
}

# Research Workflow Configuration
RESEARCH_WORKFLOW = {
    "max_search_results": 10,
    "max_sources_to_scrape": 3,
    "content_extraction_timeout": 10,
    "synthesis_timeout": 30,
    "analysis_timeout": 30,
    "total_workflow_timeout": 300  # 5 minutes
}

# Document Generation Configuration
DOCUMENT_GENERATION = {
    "formats": ["markdown", "html", "pdf", "docx"],
    "default_format": "markdown",
    "include_sources": True,
    "include_metadata": True,
    "pandoc_available": True
}

# Caching Configuration
CACHING = {
    "enabled": True,
    "ttl_seconds": 3600,
    "cache_key_prefix": "deep_research",
    "cache_strategies": {
        "search_results": 3600,  # 1 hour
        "scraped_content": 7200,  # 2 hours
        "analysis_results": 3600  # 1 hour
    }
}

# Rate Limiting Configuration
RATE_LIMITING = {
    "enabled": True,
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
    "burst_size": 10
}

# Error Handling Configuration
ERROR_HANDLING = {
    "retry_on_timeout": True,
    "retry_on_connection_error": True,
    "retry_on_rate_limit": True,
    "max_retries": 3,
    "backoff_factor": 2,
    "max_backoff": 60
}

# Feature Flags
FEATURES = {
    "enable_topic_enhancement": True,
    "enable_web_research": True,
    "enable_content_analysis": True,
    "enable_a2a_communication": True,
    "enable_caching": True,
    "enable_metrics": True,
    "enable_document_generation": True
}


def get_agent_config(agent_type: str) -> Dict[str, Any]:
    """Get configuration for specific agent."""
    agent_key = agent_type.lower().replace("deep_research_", "").replace("_agent", "")
    
    if agent_key in DEEP_RESEARCH_AGENTS:
        return DEEP_RESEARCH_AGENTS[agent_key]
    
    # Return default config
    return {
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "temperature": 0.5,
        "max_tokens": 1000,
        "timeout": 30,
        "retry_attempts": 3,
        "retry_backoff": 2
    }


def get_fallback_model(agent_type: str, primary_model: str) -> str:
    """Get fallback model for agent."""
    agent_key = agent_type.lower().replace("deep_research_", "").replace("_agent", "")
    
    if agent_key in FALLBACK_MODELS:
        fallback_list = FALLBACK_MODELS[agent_key]
        # Return first fallback that's not the primary model
        for model in fallback_list:
            if model != primary_model:
                return model
    
    return "meta-llama/llama-3.3-70b-instruct:free"


def validate_configuration() -> bool:
    """Validate configuration is complete."""
    required_keys = [
        "OPENROUTER_API_KEY",
        "DATABASE",
        "REDIS"
    ]
    
    for key in required_keys:
        if key == "OPENROUTER_API_KEY" and not OPENROUTER_API_KEY:
            print(f"Warning: {key} not configured")
            return False
    
    return True

