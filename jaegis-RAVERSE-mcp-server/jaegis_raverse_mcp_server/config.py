"""Configuration management for RAVERSE MCP Server"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, validator


class MCPServerConfig(BaseSettings):
    """MCP Server configuration"""

    # Server settings
    server_name: str = Field(default="jaegis-raverse-mcp-server", description="MCP server name")
    server_version: str = Field(default="1.0.4", description="MCP server version")
    log_level: str = Field(default="INFO", description="Logging level")

    # Database settings
    database_url: str = Field(
        default="postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse",
        description="PostgreSQL connection URL"
    )
    database_pool_size: int = Field(default=10, description="Database connection pool size")
    database_max_overflow: int = Field(default=20, description="Database max overflow connections")

    # Redis settings
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    redis_timeout: int = Field(default=5, description="Redis timeout in seconds")

    # LLM settings
    llm_api_key: Optional[str] = Field(default=None, description="LLM API key")
    llm_provider: str = Field(default="openrouter", description="LLM provider")
    llm_model: str = Field(default="meta-llama/llama-3.1-70b-instruct", description="LLM model name")
    llm_timeout: int = Field(default=30, description="LLM request timeout in seconds")

    # Embeddings settings
    embeddings_model: str = Field(
        default="all-MiniLM-L6-v2",
        description="Sentence transformers model for embeddings"
    )
    embeddings_dimension: int = Field(default=384, description="Embedding vector dimension")

    # Tool settings
    enable_binary_analysis: bool = Field(default=True, description="Enable binary analysis tools")
    enable_web_analysis: bool = Field(default=True, description="Enable web analysis tools")
    enable_knowledge_base: bool = Field(default=True, description="Enable knowledge base tools")
    enable_infrastructure: bool = Field(default=True, description="Enable infrastructure tools")

    # Performance settings
    max_concurrent_tasks: int = Field(default=10, description="Max concurrent task executions")
    cache_ttl_seconds: int = Field(default=3600, description="Cache TTL in seconds")
    request_timeout_seconds: int = Field(default=60, description="Request timeout in seconds")

    class Config:
        # Look for .env in the package directory (where setup wizard creates it)
        env_file = str(Path(__file__).parent.parent / ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level"""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()
    
    @validator("database_pool_size")
    def validate_pool_size(cls, v: int) -> int:
        """Validate database pool size"""
        if v < 1 or v > 100:
            raise ValueError("database_pool_size must be between 1 and 100")
        return v
    
    @validator("embeddings_dimension")
    def validate_embedding_dimension(cls, v: int) -> int:
        """Validate embedding dimension"""
        if v < 1 or v > 4096:
            raise ValueError("embeddings_dimension must be between 1 and 4096")
        return v


def get_config() -> MCPServerConfig:
    """Get MCP server configuration"""
    return MCPServerConfig()

