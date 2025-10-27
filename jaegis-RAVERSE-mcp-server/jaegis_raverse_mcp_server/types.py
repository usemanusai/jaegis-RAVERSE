"""Type definitions for RAVERSE MCP Server"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Result from a tool execution"""
    
    success: bool = Field(description="Whether the tool executed successfully")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Result data")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    error_code: Optional[str] = Field(default=None, description="Error code if failed")


class BinaryAnalysisResult(BaseModel):
    """Binary analysis result"""
    
    binary_hash: str = Field(description="SHA256 hash of binary")
    file_size: int = Field(description="Binary file size in bytes")
    architecture: str = Field(description="Binary architecture (x86, x64, ARM, etc.)")
    format: str = Field(description="Binary format (PE, ELF, Mach-O, etc.)")
    functions: List[Dict[str, Any]] = Field(default_factory=list, description="Identified functions")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class CodeEmbedding(BaseModel):
    """Code embedding result"""
    
    content_hash: str = Field(description="Hash of the content")
    embedding: List[float] = Field(description="Vector embedding")
    dimension: int = Field(description="Embedding dimension")
    model: str = Field(description="Model used for embedding")


class SemanticSearchResult(BaseModel):
    """Semantic search result"""
    
    query: str = Field(description="Original query")
    results: List[Dict[str, Any]] = Field(description="Search results with similarity scores")
    total_results: int = Field(description="Total number of results")
    threshold: float = Field(description="Similarity threshold used")


class APIEndpoint(BaseModel):
    """API endpoint definition"""
    
    method: str = Field(description="HTTP method (GET, POST, etc.)")
    path: str = Field(description="API path")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters")
    response_type: Optional[str] = Field(default=None, description="Response type")
    authentication: Optional[str] = Field(default=None, description="Authentication method")


class OpenAPISpec(BaseModel):
    """OpenAPI specification"""
    
    version: str = Field(description="OpenAPI version")
    title: str = Field(description="API title")
    endpoints: List[APIEndpoint] = Field(description="API endpoints")
    base_url: Optional[str] = Field(default=None, description="Base URL")


class VulnerabilityFinding(BaseModel):
    """Vulnerability finding"""
    
    id: str = Field(description="Finding ID")
    type: str = Field(description="Vulnerability type")
    severity: str = Field(description="Severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    description: str = Field(description="Description")
    location: Optional[Dict[str, Any]] = Field(default=None, description="Location in code")
    remediation: Optional[str] = Field(default=None, description="Remediation steps")
    cve_ids: List[str] = Field(default_factory=list, description="Associated CVE IDs")


class PatchInfo(BaseModel):
    """Patch information"""
    
    address: int = Field(description="Memory address to patch")
    original_bytes: str = Field(description="Original bytes (hex)")
    new_bytes: str = Field(description="New bytes (hex)")
    description: Optional[str] = Field(default=None, description="Patch description")


class KnowledgeBaseEntry(BaseModel):
    """Knowledge base entry"""
    
    id: str = Field(description="Entry ID")
    content: str = Field(description="Entry content")
    embedding: Optional[List[float]] = Field(default=None, description="Content embedding")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata")
    created_at: Optional[str] = Field(default=None, description="Creation timestamp")


class RAGQuery(BaseModel):
    """RAG query"""
    
    query: str = Field(description="Query text")
    context_limit: int = Field(default=5, description="Max context items to retrieve")
    threshold: float = Field(default=0.7, description="Similarity threshold")


class RAGResponse(BaseModel):
    """RAG response"""
    
    query: str = Field(description="Original query")
    context: List[KnowledgeBaseEntry] = Field(description="Retrieved context")
    response: str = Field(description="LLM-generated response")
    model: str = Field(description="Model used for generation")

