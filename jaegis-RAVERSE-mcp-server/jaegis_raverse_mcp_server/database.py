"""Database utilities for RAVERSE MCP Server"""

import psycopg2
from psycopg2 import pool
import os
import tempfile
from urllib.parse import quote
import re


from typing import Optional, List, Dict, Any
from .config import MCPServerConfig
from .errors import DatabaseError
from .logging_config import get_logger

logger = get_logger(__name__)


class DatabaseManager:
    """Manages database connections and operations"""

    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.connection_pool: Optional[pool.ThreadedConnectionPool] = None
        self._ca_file_path: Optional[str] = None
        self._initialize_pool()

    def _initialize_pool(self) -> None:
        """Initialize connection pool"""
        try:
            dsn = self._build_dsn(self.config.database_url)
            self.connection_pool = pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=self.config.database_pool_size,
                dsn=dsn,
            )
            logger.info("Database connection pool initialized", pool_size=self.config.database_pool_size)
        except psycopg2.Error as e:
            raise DatabaseError(f"Failed to initialize database pool: {str(e)}")

    def _build_dsn(self, base_dsn: str) -> str:
        """Build DSN with optional CA cert and verify-full SSL"""
        dsn = base_dsn
        try:
            ca_content = getattr(self.config, "postgres_ca_cert", None)
            if ca_content:
                # Write CA content to a temporary file once per process
                if not getattr(self, "_ca_file_path", None):
                    # Support JSON-escaped newlines ("\n") commonly used in config files
                    if "\\n" in ca_content and "\n" not in ca_content.strip():
                        ca_content = ca_content.replace("\\n", "\n")
                    fd, temp_path = tempfile.mkstemp(prefix="aiven_ca_", suffix=".crt")
                    with os.fdopen(fd, "wb") as f:
                        f.write(ca_content.encode("utf-8"))
                    self._ca_file_path = temp_path
                # Ensure sslrootcert and sslmode are present
                sep = "&" if "?" in dsn else "?"
                # Append sslrootcert if not already provided
                if "sslrootcert=" not in dsn:
                    cert_path_url = quote(self._ca_file_path.replace("\\", "/"), safe="/:")
                    dsn = f"{dsn}{sep}sslrootcert={cert_path_url}"
                    sep = "&"
                # Enforce verify-full
                if "sslmode=" not in dsn:
                    dsn = f"{dsn}{sep}sslmode=verify-full"
                elif "sslmode=verify-full" not in dsn:
                    dsn = re.sub(r"sslmode=[^&]+", "sslmode=verify-full", dsn)
        except Exception as e:
            logger.warning(f"Failed to apply CA certificate to DSN: {str(e)}")
        return dsn

    def get_connection(self):
        """Get a connection from the pool"""
        if not self.connection_pool:
            raise DatabaseError("Connection pool not initialized")
        try:
            return self.connection_pool.getconn()
        except pool.PoolError as e:
            raise DatabaseError(f"Failed to get connection from pool: {str(e)}")

    def return_connection(self, conn) -> None:
        """Return a connection to the pool"""
        if self.connection_pool:
            self.connection_pool.putconn(conn)

    def execute_query(
        self,
        query: str,
        params: Optional[tuple] = None,
        fetch_one: bool = False,
    ) -> Optional[Any]:
        """Execute a query and return results"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params or ())

            if fetch_one:
                result = cursor.fetchone()
            else:
                result = cursor.fetchall()

            cursor.close()
            conn.commit()
            return result
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Query execution failed: {str(e)}", {"query": query})
        finally:
            if conn:
                self.return_connection(conn)

    def execute_update(
        self,
        query: str,
        params: Optional[tuple] = None,
    ) -> int:
        """Execute an update query and return affected rows"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            affected_rows = cursor.rowcount
            cursor.close()
            conn.commit()
            return affected_rows
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Update execution failed: {str(e)}", {"query": query})
        finally:
            if conn:
                self.return_connection(conn)

    def vector_search(
        self,
        table: str,
        embedding_column: str,
        query_embedding: List[float],
        limit: int = 5,
        threshold: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """Perform vector similarity search"""
        try:
            query = f"""
                SELECT *,
                       1 - (embedding <=> %s::vector) as similarity
                FROM {table}
                WHERE 1 - (embedding <=> %s::vector) > %s
                ORDER BY similarity DESC
                LIMIT %s
            """
            results = self.execute_query(
                query,
                (query_embedding, query_embedding, threshold, limit),
            )
            return results or []
        except DatabaseError:
            raise
        except Exception as e:
            raise DatabaseError(f"Vector search failed: {str(e)}")

    def close(self) -> None:
        """Close all connections in the pool and cleanup temp files"""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("Database connection pool closed")
        # Cleanup temporary CA file if created
        if getattr(self, "_ca_file_path", None):
            try:
                os.remove(self._ca_file_path)
            except OSError:
                pass
            self._ca_file_path = None

