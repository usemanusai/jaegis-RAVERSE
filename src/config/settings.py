"""
RAVERSE Settings and Configuration
Centralized configuration management with environment variable support
Date: October 25, 2025
"""

import os
from typing import Optional
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()


class Settings:
    """
    Centralized settings for RAVERSE application
    All settings can be overridden via environment variables
    """
    
    # OpenRouter API Configuration
    OPENROUTER_API_KEY: str = os.getenv('OPENROUTER_API_KEY', '')
    OPENROUTER_BASE_URL: str = os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1')
    OPENROUTER_MODEL: str = os.getenv('OPENROUTER_MODEL', 'meta-llama/llama-3.2-3b-instruct:free')
    OPENROUTER_TIMEOUT: int = int(os.getenv('OPENROUTER_TIMEOUT', '60'))
    OPENROUTER_MAX_RETRIES: int = int(os.getenv('OPENROUTER_MAX_RETRIES', '3'))
    
    # PostgreSQL Configuration
    POSTGRES_HOST: str = os.getenv('POSTGRES_HOST', 'localhost')
    POSTGRES_PORT: int = int(os.getenv('POSTGRES_PORT', '5432'))
    POSTGRES_USER: str = os.getenv('POSTGRES_USER', 'raverse')
    POSTGRES_PASSWORD: str = os.getenv('POSTGRES_PASSWORD', 'raverse_secure_password_2025')
    POSTGRES_DB: str = os.getenv('POSTGRES_DB', 'raverse')
    POSTGRES_MIN_CONN: int = int(os.getenv('POSTGRES_MIN_CONN', '2'))
    POSTGRES_MAX_CONN: int = int(os.getenv('POSTGRES_MAX_CONN', '10'))
    
    # Redis Configuration
    REDIS_HOST: str = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT: int = int(os.getenv('REDIS_PORT', '6379'))
    REDIS_PASSWORD: str = os.getenv('REDIS_PASSWORD', 'raverse_redis_password_2025')
    REDIS_DB: int = int(os.getenv('REDIS_DB', '0'))
    REDIS_MAX_CONNECTIONS: int = int(os.getenv('REDIS_MAX_CONNECTIONS', '50'))
    
    # Application Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: str = os.getenv('LOG_FILE', 'raverse.log')
    
    # Cache Configuration
    CACHE_TTL_DISASSEMBLY: int = int(os.getenv('CACHE_TTL_DISASSEMBLY', '86400'))  # 24 hours
    CACHE_TTL_ANALYSIS: int = int(os.getenv('CACHE_TTL_ANALYSIS', '86400'))  # 24 hours
    CACHE_TTL_LLM: int = int(os.getenv('CACHE_TTL_LLM', '604800'))  # 7 days
    CACHE_TTL_SESSION: int = int(os.getenv('CACHE_TTL_SESSION', '3600'))  # 1 hour
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
    RATE_LIMIT_WINDOW: int = int(os.getenv('RATE_LIMIT_WINDOW', '60'))  # seconds
    
    # Binary Analysis Configuration
    BACKUP_SUFFIX: str = os.getenv('BACKUP_SUFFIX', '.backup')
    MAX_BINARY_SIZE: int = int(os.getenv('MAX_BINARY_SIZE', '104857600'))  # 100 MB
    
    # Verification Configuration
    VERIFICATION_TIMEOUT: int = int(os.getenv('VERIFICATION_TIMEOUT', '10'))  # seconds
    
    # Vector Search Configuration
    VECTOR_DIMENSION: int = int(os.getenv('VECTOR_DIMENSION', '1536'))
    VECTOR_SIMILARITY_THRESHOLD: float = float(os.getenv('VECTOR_SIMILARITY_THRESHOLD', '0.7'))
    
    # Docker Configuration (for containerized deployment)
    DOCKER_ENABLED: bool = os.getenv('DOCKER_ENABLED', 'false').lower() == 'true'
    
    @classmethod
    def validate(cls) -> bool:
        """
        Validate required settings
        Returns True if all required settings are present
        """
        errors = []
        
        if not cls.OPENROUTER_API_KEY:
            errors.append("OPENROUTER_API_KEY is required")
        
        if errors:
            for error in errors:
                print(f"Configuration Error: {error}")
            return False
        
        return True
    
    @classmethod
    def get_database_url(cls) -> str:
        """Get PostgreSQL connection URL"""
        return f"postgresql://{cls.POSTGRES_USER}:{cls.POSTGRES_PASSWORD}@{cls.POSTGRES_HOST}:{cls.POSTGRES_PORT}/{cls.POSTGRES_DB}"
    
    @classmethod
    def get_redis_url(cls) -> str:
        """Get Redis connection URL"""
        if cls.REDIS_PASSWORD:
            return f"redis://:{cls.REDIS_PASSWORD}@{cls.REDIS_HOST}:{cls.REDIS_PORT}/{cls.REDIS_DB}"
        return f"redis://{cls.REDIS_HOST}:{cls.REDIS_PORT}/{cls.REDIS_DB}"
    
    @classmethod
    def print_config(cls):
        """Print current configuration (excluding sensitive data)"""
        print("=" * 60)
        print("RAVERSE Configuration")
        print("=" * 60)
        print(f"OpenRouter Model: {cls.OPENROUTER_MODEL}")
        print(f"OpenRouter Timeout: {cls.OPENROUTER_TIMEOUT}s")
        print(f"PostgreSQL: {cls.POSTGRES_HOST}:{cls.POSTGRES_PORT}/{cls.POSTGRES_DB}")
        print(f"Redis: {cls.REDIS_HOST}:{cls.REDIS_PORT}/{cls.REDIS_DB}")
        print(f"Log Level: {cls.LOG_LEVEL}")
        print(f"Cache TTL (Disassembly): {cls.CACHE_TTL_DISASSEMBLY}s")
        print(f"Cache TTL (Analysis): {cls.CACHE_TTL_ANALYSIS}s")
        print(f"Cache TTL (LLM): {cls.CACHE_TTL_LLM}s")
        print(f"Rate Limit: {cls.RATE_LIMIT_REQUESTS} requests / {cls.RATE_LIMIT_WINDOW}s")
        print(f"Max Binary Size: {cls.MAX_BINARY_SIZE / 1024 / 1024:.1f} MB")
        print(f"Docker Enabled: {cls.DOCKER_ENABLED}")
        print("=" * 60)

