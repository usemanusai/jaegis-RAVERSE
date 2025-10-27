"""
PostgreSQL Database Manager for RAVERSE
Handles connections, queries, and vector operations using pgvector
Date: October 25, 2025
"""

import os
import logging
import hashlib
import json
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from psycopg2.pool import ThreadedConnectionPool


logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages PostgreSQL connections and operations for RAVERSE
    Uses connection pooling for optimal performance
    """
    
    def __init__(self):
        """Initialize database connection pool"""
        self.host = os.getenv('POSTGRES_HOST', 'localhost')
        self.port = int(os.getenv('POSTGRES_PORT', 5432))
        self.user = os.getenv('POSTGRES_USER', 'raverse')
        self.password = os.getenv('POSTGRES_PASSWORD', 'raverse_secure_password_2025')
        self.database = os.getenv('POSTGRES_DB', 'raverse')
        
        # Create connection pool (min 2, max 10 connections)
        self.pool = ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            database=self.database,
            connect_timeout=10
        )
        
        logger.info(f"Database connection pool initialized: {self.host}:{self.port}/{self.database}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections
        Automatically returns connection to pool
        """
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            self.pool.putconn(conn)
    
    def create_binary_record(self, file_name: str, file_path: str, file_hash: str, 
                           file_size: int, file_type: str = None, 
                           architecture: str = None, metadata: Dict = None) -> int:
        """
        Create a new binary record in the database
        Returns the binary ID
        """
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO raverse.binaries 
                    (file_name, file_path, file_hash, file_size, file_type, architecture, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (file_hash) DO UPDATE 
                    SET updated_at = CURRENT_TIMESTAMP
                    RETURNING id
                """, (file_name, file_path, file_hash, file_size, file_type, 
                     architecture, json.dumps(metadata or {})))
                
                binary_id = cur.fetchone()[0]
                logger.info(f"Created binary record: {file_name} (ID: {binary_id})")
                return binary_id
    
    def get_binary_by_hash(self, file_hash: str) -> Optional[Dict]:
        """Get binary record by file hash"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM raverse.binaries WHERE file_hash = %s
                """, (file_hash,))
                return dict(cur.fetchone()) if cur.rowcount > 0 else None
    
    def update_binary_status(self, binary_id: int, status: str):
        """Update binary analysis status"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE raverse.binaries SET status = %s WHERE id = %s
                """, (status, binary_id))
                logger.info(f"Updated binary {binary_id} status to: {status}")
    
    def cache_disassembly(self, binary_id: int, address: str, instruction: str,
                         opcode: str = None, operands: str = None, 
                         disassembly_text: str = None, embedding: List[float] = None,
                         metadata: Dict = None):
        """Cache disassembly instruction with optional vector embedding"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO raverse.disassembly_cache
                    (binary_id, address, instruction, opcode, operands, 
                     disassembly_text, embedding, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (binary_id, address) DO UPDATE
                    SET instruction = EXCLUDED.instruction,
                        opcode = EXCLUDED.opcode,
                        operands = EXCLUDED.operands,
                        disassembly_text = EXCLUDED.disassembly_text,
                        embedding = EXCLUDED.embedding,
                        metadata = EXCLUDED.metadata
                """, (binary_id, address, instruction, opcode, operands,
                     disassembly_text, embedding, json.dumps(metadata or {})))
    
    def search_similar_instructions(self, embedding: List[float], 
                                   limit: int = 10) -> List[Dict]:
        """
        Search for similar instructions using vector similarity
        Uses cosine distance with HNSW index
        """
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        address, instruction, opcode, operands, disassembly_text,
                        1 - (embedding <=> %s::vector) as similarity
                    FROM raverse.disassembly_cache
                    WHERE embedding IS NOT NULL
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, (embedding, embedding, limit))
                return [dict(row) for row in cur.fetchall()]
    
    def save_analysis_result(self, binary_id: int, agent_name: str, 
                           analysis_type: str, result: Dict,
                           confidence_score: float = None, tokens_used: int = None,
                           execution_time_ms: int = None, metadata: Dict = None) -> int:
        """Save AI agent analysis result"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO raverse.analysis_results
                    (binary_id, agent_name, analysis_type, result, confidence_score,
                     tokens_used, execution_time_ms, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (binary_id, agent_name, analysis_type, json.dumps(result),
                     confidence_score, tokens_used, execution_time_ms, 
                     json.dumps(metadata or {})))
                
                result_id = cur.fetchone()[0]
                logger.info(f"Saved analysis result: {agent_name}/{analysis_type} (ID: {result_id})")
                return result_id
    
    def get_analysis_results(self, binary_id: int, 
                           agent_name: str = None) -> List[Dict]:
        """Get analysis results for a binary"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if agent_name:
                    cur.execute("""
                        SELECT * FROM raverse.analysis_results
                        WHERE binary_id = %s AND agent_name = %s
                        ORDER BY created_at DESC
                    """, (binary_id, agent_name))
                else:
                    cur.execute("""
                        SELECT * FROM raverse.analysis_results
                        WHERE binary_id = %s
                        ORDER BY created_at DESC
                    """, (binary_id,))
                return [dict(row) for row in cur.fetchall()]
    
    def save_patch_history(self, binary_id: int, patch_type: str, 
                          target_address: str, original_bytes: bytes,
                          patched_bytes: bytes, success: bool,
                          verification_result: Dict = None, 
                          metadata: Dict = None) -> int:
        """Save patch operation to history"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO raverse.patch_history
                    (binary_id, patch_type, target_address, original_bytes,
                     patched_bytes, success, verification_result, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (binary_id, patch_type, target_address, original_bytes,
                     patched_bytes, success, json.dumps(verification_result or {}),
                     json.dumps(metadata or {})))
                
                patch_id = cur.fetchone()[0]
                logger.info(f"Saved patch history: {target_address} (ID: {patch_id}, Success: {success})")
                return patch_id
    
    def get_llm_cache(self, prompt_hash: str) -> Optional[Dict]:
        """Get cached LLM response by prompt hash"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    UPDATE raverse.llm_cache
                    SET last_accessed_at = CURRENT_TIMESTAMP,
                        access_count = access_count + 1
                    WHERE prompt_hash = %s
                    RETURNING *
                """, (prompt_hash,))
                return dict(cur.fetchone()) if cur.rowcount > 0 else None
    
    def save_llm_cache(self, prompt_text: str, response_text: str,
                      model_name: str, tokens_used: int = None,
                      metadata: Dict = None):
        """Save LLM response to cache"""
        prompt_hash = hashlib.sha256(prompt_text.encode()).hexdigest()
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO raverse.llm_cache
                    (prompt_hash, prompt_text, response_text, model_name, 
                     tokens_used, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (prompt_hash) DO UPDATE
                    SET response_text = EXCLUDED.response_text,
                        tokens_used = EXCLUDED.tokens_used,
                        last_accessed_at = CURRENT_TIMESTAMP,
                        access_count = raverse.llm_cache.access_count + 1
                """, (prompt_hash, prompt_text, response_text, model_name,
                     tokens_used, json.dumps(metadata or {})))
                
                logger.debug(f"Cached LLM response (hash: {prompt_hash[:16]}...)")
    
    def cleanup_old_cache(self, days: int = 30):
        """Remove LLM cache entries older than specified days"""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM raverse.llm_cache
                    WHERE last_accessed_at < CURRENT_TIMESTAMP - INTERVAL '%s days'
                """, (days,))
                deleted = cur.rowcount
                logger.info(f"Cleaned up {deleted} old cache entries")
                return deleted
    
    def execute_query(self, query: str, params: Tuple = None):
        """
        Execute a query with parameters.

        Args:
            query: SQL query string
            params: Query parameters tuple
        """
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                logger.debug(f"Executed query: {query[:100]}...")

    def close(self):
        """Close all connections in the pool"""
        if self.pool:
            self.pool.closeall()
            logger.info("Database connection pool closed")

