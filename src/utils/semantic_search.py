"""
Semantic Search Module for RAVERSE
Date: October 25, 2025

This module provides semantic code search using vector embeddings
and pgvector for similarity search.
"""

import numpy as np
from typing import List, Dict, Optional, Tuple
from utils.database import DatabaseManager
from utils.embeddings_v2 import EmbeddingGenerator, get_embedding_generator
from utils.cache import CacheManager
from utils.metrics import metrics_collector
import time


class SemanticSearchEngine:
    """
    Semantic search engine for finding similar code patterns.
    Uses pgvector for efficient similarity search.
    """
    
    def __init__(
        self,
        db_manager: DatabaseManager,
        embedding_generator: Optional[EmbeddingGenerator] = None,
        cache_manager: Optional[CacheManager] = None
    ):
        """
        Initialize semantic search engine.
        
        Args:
            db_manager: Database manager instance
            embedding_generator: Optional embedding generator
            cache_manager: Optional cache manager
        """
        self.db = db_manager
        self.cache_manager = cache_manager
        
        if embedding_generator is None:
            self.embedding_gen = get_embedding_generator(cache_manager=cache_manager)
        else:
            self.embedding_gen = embedding_generator
    
    def store_code_embedding(
        self,
        binary_hash: str,
        code_snippet: str,
        metadata: Optional[Dict] = None
    ) -> int:
        """
        Store code snippet with its embedding.
        
        Args:
            binary_hash: Hash of the binary file
            code_snippet: Code snippet to store
            metadata: Optional metadata (JSON)
            
        Returns:
            ID of stored embedding
        """
        # Generate embedding
        embedding = self.embedding_gen.generate_code_embedding(code_snippet)
        
        # Store in database
        start_time = time.time()
        query = """
            INSERT INTO code_embeddings (binary_hash, code_snippet, embedding, metadata)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """
        
        result = self.db.execute_query(
            query,
            (binary_hash, code_snippet, embedding.tolist(), metadata)
        )
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('insert_embedding', duration)
        
        return result[0]['id'] if result else None
    
    def store_code_embeddings_batch(
        self,
        binary_hash: str,
        code_snippets: List[str],
        metadata_list: Optional[List[Dict]] = None
    ) -> List[int]:
        """
        Store multiple code snippets with embeddings.
        
        Args:
            binary_hash: Hash of the binary file
            code_snippets: List of code snippets
            metadata_list: Optional list of metadata dicts
            
        Returns:
            List of IDs
        """
        # Generate embeddings in batch
        embeddings = self.embedding_gen.generate_code_embeddings_batch(code_snippets)
        
        if metadata_list is None:
            metadata_list = [None] * len(code_snippets)
        
        # Store in database
        start_time = time.time()
        ids = []
        
        for code, embedding, metadata in zip(code_snippets, embeddings, metadata_list):
            query = """
                INSERT INTO code_embeddings (binary_hash, code_snippet, embedding, metadata)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """
            result = self.db.execute_query(
                query,
                (binary_hash, code, embedding.tolist(), metadata)
            )
            if result:
                ids.append(result[0]['id'])
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('batch_insert_embeddings', duration)
        
        return ids
    
    def find_similar_code(
        self,
        query: str,
        limit: int = 10,
        similarity_threshold: float = 0.7
    ) -> List[Dict]:
        """
        Find similar code snippets using semantic search.
        
        Args:
            query: Query text (code or natural language)
            limit: Maximum number of results
            similarity_threshold: Minimum similarity score (0-1)
            
        Returns:
            List of similar code snippets with metadata
        """
        # Generate query embedding
        query_embedding = self.embedding_gen.generate_embedding(query)
        
        # Search in database using cosine similarity
        start_time = time.time()
        search_query = """
            SELECT 
                id,
                binary_hash,
                code_snippet,
                metadata,
                1 - (embedding <=> %s::vector) AS similarity,
                created_at
            FROM code_embeddings
            WHERE 1 - (embedding <=> %s::vector) >= %s
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """
        
        embedding_list = query_embedding.tolist()
        results = self.db.execute_query(
            search_query,
            (embedding_list, embedding_list, similarity_threshold, embedding_list, limit)
        )
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('semantic_search', duration)
        
        return results if results else []
    
    def find_similar_patterns(
        self,
        binary_hash: str,
        limit: int = 10
    ) -> List[Dict]:
        """
        Find similar patterns from other binaries.
        
        Args:
            binary_hash: Hash of the binary to find patterns for
            limit: Maximum number of results
            
        Returns:
            List of similar patterns from other binaries
        """
        # Get embeddings from this binary
        query = """
            SELECT embedding
            FROM code_embeddings
            WHERE binary_hash = %s
            LIMIT 1
        """
        
        result = self.db.execute_query(query, (binary_hash,))
        if not result:
            return []
        
        reference_embedding = np.array(result[0]['embedding'])
        
        # Find similar patterns from other binaries
        start_time = time.time()
        search_query = """
            SELECT 
                id,
                binary_hash,
                code_snippet,
                metadata,
                1 - (embedding <=> %s::vector) AS similarity,
                created_at
            FROM code_embeddings
            WHERE binary_hash != %s
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """
        
        embedding_list = reference_embedding.tolist()
        results = self.db.execute_query(
            search_query,
            (embedding_list, binary_hash, embedding_list, limit)
        )
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('find_similar_patterns', duration)
        
        return results if results else []
    
    def find_password_check_patterns(
        self,
        limit: int = 20
    ) -> List[Dict]:
        """
        Find known password check patterns.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of password check patterns
        """
        # Query for patterns tagged as password checks
        start_time = time.time()
        query = """
            SELECT 
                id,
                binary_hash,
                code_snippet,
                metadata,
                created_at
            FROM code_embeddings
            WHERE metadata->>'type' = 'password_check'
            ORDER BY created_at DESC
            LIMIT %s
        """
        
        results = self.db.execute_query(query, (limit,))
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('find_password_patterns', duration)
        
        return results if results else []
    
    def search_by_metadata(
        self,
        metadata_filter: Dict,
        limit: int = 10
    ) -> List[Dict]:
        """
        Search code embeddings by metadata.
        
        Args:
            metadata_filter: Metadata key-value pairs to filter by
            limit: Maximum number of results
            
        Returns:
            List of matching code snippets
        """
        # Build metadata filter query
        conditions = []
        params = []
        
        for key, value in metadata_filter.items():
            conditions.append(f"metadata->>%s = %s")
            params.extend([key, str(value)])
        
        where_clause = " AND ".join(conditions)
        params.append(limit)
        
        start_time = time.time()
        query = f"""
            SELECT 
                id,
                binary_hash,
                code_snippet,
                metadata,
                created_at
            FROM code_embeddings
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT %s
        """
        
        results = self.db.execute_query(query, tuple(params))
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('search_by_metadata', duration)
        
        return results if results else []
    
    def delete_embeddings_by_binary(self, binary_hash: str) -> int:
        """
        Delete all embeddings for a binary.
        
        Args:
            binary_hash: Hash of the binary
            
        Returns:
            Number of deleted embeddings
        """
        start_time = time.time()
        query = "DELETE FROM code_embeddings WHERE binary_hash = %s"
        
        self.db.execute_query(query, (binary_hash,))
        
        duration = time.time() - start_time
        metrics_collector.record_database_query('delete_embeddings', duration)
        
        # Return count (would need to modify execute_query to return rowcount)
        return 0


# Global semantic search engine instance
_search_engine: Optional[SemanticSearchEngine] = None


def get_search_engine(
    db_manager: DatabaseManager,
    cache_manager: Optional[CacheManager] = None
) -> SemanticSearchEngine:
    """
    Get or create global semantic search engine instance.
    
    Args:
        db_manager: Database manager
        cache_manager: Optional cache manager
        
    Returns:
        SemanticSearchEngine instance
    """
    global _search_engine
    if _search_engine is None:
        _search_engine = SemanticSearchEngine(
            db_manager=db_manager,
            cache_manager=cache_manager
        )
    return _search_engine

