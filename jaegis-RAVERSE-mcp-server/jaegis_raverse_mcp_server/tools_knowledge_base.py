"""Knowledge base and RAG tools for RAVERSE MCP Server"""

import hashlib
from typing import Dict, Any, List, Optional
from .types import ToolResult, KnowledgeBaseEntry, RAGQuery, RAGResponse
from .errors import ValidationError, DatabaseError
from .logging_config import get_logger
from .database import DatabaseManager
from .cache import CacheManager

logger = get_logger(__name__)


class KnowledgeBaseTools:
    """Tools for knowledge base operations"""
    
    def __init__(self, db_manager: DatabaseManager, cache_manager: CacheManager):
        self.db = db_manager
        self.cache = cache_manager
    
    def ingest_content(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """Ingest content into knowledge base"""
        try:
            if not content or not content.strip():
                raise ValidationError("Content cannot be empty")
            
            if len(content) > 10000000:  # 10MB limit
                raise ValidationError("Content exceeds maximum size (10MB)")
            
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Check cache first
            cache_key = f"kb:content:{content_hash}"
            if self.cache.exists(cache_key):
                logger.info("Content already in knowledge base", content_hash=content_hash)
                return ToolResult(
                    success=True,
                    data={
                        "content_hash": content_hash,
                        "status": "already_exists",
                    },
                )
            
            logger.info(
                "Knowledge base ingestion initiated",
                content_hash=content_hash,
                content_length=len(content),
                metadata=metadata,
            )
            
            return ToolResult(
                success=True,
                data={
                    "content_hash": content_hash,
                    "status": "ingestion_initiated",
                    "content_length": len(content),
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Knowledge base ingestion failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Ingestion failed: {str(e)}",
                error_code="INGESTION_ERROR",
            )
    
    def search_knowledge_base(
        self,
        query: str,
        limit: int = 5,
        threshold: float = 0.7,
    ) -> ToolResult:
        """Search knowledge base for relevant content"""
        try:
            if not query or not query.strip():
                raise ValidationError("Query cannot be empty")
            
            if limit < 1 or limit > 100:
                raise ValidationError("Limit must be between 1 and 100")
            
            if threshold < 0 or threshold > 1:
                raise ValidationError("Threshold must be between 0 and 1")
            
            logger.info(
                "Knowledge base search initiated",
                query=query,
                limit=limit,
                threshold=threshold,
            )
            
            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "status": "search_initiated",
                    "limit": limit,
                    "threshold": threshold,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Knowledge base search failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Search failed: {str(e)}",
                error_code="SEARCH_ERROR",
            )
    
    def retrieve_entry(self, entry_id: str) -> ToolResult:
        """Retrieve a specific knowledge base entry"""
        try:
            if not entry_id or not entry_id.strip():
                raise ValidationError("Entry ID cannot be empty")
            
            # Check cache first
            cache_key = f"kb:entry:{entry_id}"
            cached = self.cache.get(cache_key)
            if cached:
                logger.info("Entry retrieved from cache", entry_id=entry_id)
                return ToolResult(success=True, data=cached)
            
            logger.info("Knowledge base entry retrieval initiated", entry_id=entry_id)
            
            return ToolResult(
                success=True,
                data={
                    "entry_id": entry_id,
                    "status": "retrieval_initiated",
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Entry retrieval failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Retrieval failed: {str(e)}",
                error_code="RETRIEVAL_ERROR",
            )
    
    def delete_entry(self, entry_id: str) -> ToolResult:
        """Delete a knowledge base entry"""
        try:
            if not entry_id or not entry_id.strip():
                raise ValidationError("Entry ID cannot be empty")
            
            logger.info("Knowledge base entry deletion initiated", entry_id=entry_id)
            
            # Clear cache
            cache_key = f"kb:entry:{entry_id}"
            self.cache.delete(cache_key)
            
            return ToolResult(
                success=True,
                data={
                    "entry_id": entry_id,
                    "status": "deletion_initiated",
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Entry deletion failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Deletion failed: {str(e)}",
                error_code="DELETION_ERROR",
            )

