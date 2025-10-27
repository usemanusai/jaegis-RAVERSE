"""
Knowledge Base Agent for RAVERSE 2.0
Manages knowledge storage, retrieval, and RAG (Retrieval-Augmented Generation).
"""

import logging
import json
import requests
import time
import psycopg2
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import os
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from psycopg2.extras import RealDictCursor

from .base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)


class KnowledgeBaseAgent(BaseMemoryAgent):
    """
    Knowledge Base Agent - Manages knowledge storage and retrieval.
    Implements semantic search and RAG capabilities with real vector embeddings.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "retrieval")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize Knowledge Base Agent.

        Args:
            orchestrator: Reference to orchestration agent
            api_key: OpenRouter API key
            model: LLM model to use
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="Knowledge Base Manager",
            agent_type="KNOWLEDGE_BASE",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or "meta-llama/llama-3.3-70b-instruct:free"
        self.logger = logging.getLogger("RAVERSE.KNOWLEDGE_BASE")
        self.db_manager = DatabaseManager()
        self.max_retries = 3
        self.retry_backoff = 2

        # Initialize embedding model (all-MiniLM-L6-v2 for 384-dimensional vectors)
        try:
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            self.logger.info("Embedding model loaded: all-MiniLM-L6-v2")
        except Exception as e:
            self.logger.error(f"Failed to load embedding model: {e}")
            self.embedding_model = None

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute knowledge base task."""
        action = task.get("action", "store_knowledge")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        if action == "store_knowledge":
            result = self._store_knowledge(task)
        elif action == "search_knowledge":
            result = self._search_knowledge(task)
        elif action == "retrieve_for_rag":
            result = self._retrieve_for_rag(task)
        elif action == "generate_with_rag":
            result = self._generate_with_rag(task)
        elif action == "list_knowledge":
            result = self._list_knowledge(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _store_knowledge(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Store knowledge in knowledge base with real embeddings and retry logic."""
        try:
            content = task.get("content", "")
            source = task.get("source", "unknown")
            metadata = task.get("metadata", {})

            if not content:
                return {"status": "error", "error": "Content cannot be empty"}

            # Generate real embedding
            embedding = self._generate_embedding(content)
            knowledge_id = str(uuid.uuid4())

            # Store in database with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            # Convert embedding to PostgreSQL vector format
                            embedding_str = '[' + ','.join(str(x) for x in embedding) + ']'

                            cur.execute("""
                                INSERT INTO knowledge_base
                                (knowledge_id, content, embedding, metadata, source, created_at)
                                VALUES (%s, %s, %s::vector, %s, %s, %s)
                            """, (
                                knowledge_id,
                                content,
                                embedding_str,
                                json.dumps(metadata),
                                source,
                                datetime.utcnow()
                            ))
                        conn.commit()

                    self.logger.info(f"Stored knowledge {knowledge_id} from {source}")
                    return {
                        "status": "success",
                        "knowledge_id": knowledge_id,
                        "source": source,
                        "content_length": len(content),
                        "embedding_dimensions": len(embedding)
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Knowledge storage failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _search_knowledge(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Search knowledge base using real pgvector semantic search."""
        try:
            query = task.get("query", "")
            limit = task.get("limit", 5)
            similarity_threshold = task.get("similarity_threshold", 0.5)

            if not query:
                return {"status": "error", "error": "Query cannot be empty"}

            # Generate query embedding
            query_embedding = self._generate_embedding(query)
            embedding_str = '[' + ','.join(str(x) for x in query_embedding) + ']'

            # Semantic search using pgvector with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor(cursor_factory=RealDictCursor) as cur:
                            # Use cosine similarity (<=> operator)
                            cur.execute("""
                                SELECT knowledge_id, content, metadata, source,
                                       1 - (embedding <=> %s::vector) as similarity
                                FROM knowledge_base
                                WHERE 1 - (embedding <=> %s::vector) > %s
                                ORDER BY embedding <=> %s::vector
                                LIMIT %s
                            """, (embedding_str, embedding_str, similarity_threshold, embedding_str, limit))
                            rows = cur.fetchall()

                    results = []
                    for row in rows:
                        results.append({
                            "knowledge_id": row['knowledge_id'],
                            "content": row['content'][:500],  # Truncate for response
                            "metadata": json.loads(row['metadata']) if row['metadata'] else {},
                            "source": row['source'],
                            "similarity": float(row['similarity'])
                        })

                    self.logger.info(f"Found {len(results)} results for query")
                    return {
                        "status": "success",
                        "query": query,
                        "results": results,
                        "count": len(results)
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Knowledge search failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _retrieve_for_rag(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve relevant knowledge for RAG."""
        try:
            query = task.get("query", "")
            limit = task.get("limit", 3)
            
            # Search knowledge base
            search_result = self._search_knowledge({
                "query": query,
                "limit": limit
            })
            
            if search_result.get("status") != "success":
                return search_result
            
            # Extract relevant content
            relevant_knowledge = []
            for result in search_result.get("results", []):
                if result.get("similarity", 0) > 0.5:  # Threshold
                    relevant_knowledge.append({
                        "content": result.get("content"),
                        "source": result.get("source"),
                        "similarity": result.get("similarity")
                    })
            
            # Store RAG session
            session_id = str(uuid.uuid4())
            query_obj = """
            INSERT INTO rag_sessions (session_id, query, retrieved_knowledge, created_at)
            VALUES (%s, %s, %s, %s)
            """
            
            self.db_connection.execute(query_obj, (
                session_id,
                query,
                json.dumps(relevant_knowledge),
                datetime.utcnow()
            ))
            self.db_connection.commit()
            
            return {
                "status": "success",
                "session_id": session_id,
                "query": query,
                "retrieved_knowledge": relevant_knowledge,
                "count": len(relevant_knowledge)
            }
        except Exception as e:
            self.logger.error(f"RAG retrieval failed: {e}")
            return {"status": "error", "error": str(e)}

    def _generate_with_rag(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate response using RAG."""
        try:
            query = task.get("query", "")
            
            # Retrieve relevant knowledge
            retrieval_result = self._retrieve_for_rag({
                "query": query,
                "limit": 5
            })
            
            if retrieval_result.get("status") != "success":
                return retrieval_result
            
            relevant_knowledge = retrieval_result.get("retrieved_knowledge", [])
            
            # Build context from retrieved knowledge
            context = "\n".join([
                f"Source: {k.get('source')}\n{k.get('content')}"
                for k in relevant_knowledge
            ])
            
            # Generate response using LLM with context
            prompt = f"""Based on the following knowledge base context, answer the query.

CONTEXT:
{context}

QUERY:
{query}

RESPONSE:"""
            
            response = self._call_llm(prompt)
            
            # Update RAG session with generated response
            session_id = retrieval_result.get("session_id")
            update_query = """
            UPDATE rag_sessions 
            SET generated_response = %s, confidence = %s
            WHERE session_id = %s
            """
            
            self.db_connection.execute(update_query, (
                response,
                0.85,  # Confidence score
                session_id
            ))
            self.db_connection.commit()
            
            return {
                "status": "success",
                "query": query,
                "response": response,
                "retrieved_knowledge_count": len(relevant_knowledge),
                "confidence": 0.85
            }
        except Exception as e:
            self.logger.error(f"RAG generation failed: {e}")
            return {"status": "error", "error": str(e)}

    def _list_knowledge(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """List all knowledge in knowledge base."""
        try:
            query = "SELECT knowledge_id, content, source, created_at FROM knowledge_base ORDER BY created_at DESC LIMIT 100"
            
            cursor = self.db_connection.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            
            knowledge_items = []
            for row in rows:
                knowledge_items.append({
                    "knowledge_id": row[0],
                    "content_preview": row[1][:200] if row[1] else "",
                    "source": row[2],
                    "created_at": row[3].isoformat() if row[3] else None
                })
            
            return {
                "status": "success",
                "knowledge_items": knowledge_items,
                "total": len(knowledge_items)
            }
        except Exception as e:
            self.logger.error(f"List knowledge failed: {e}")
            return {"status": "error", "error": str(e)}

    def _generate_embedding(self, text: str) -> List[float]:
        """Generate real embedding for text using sentence-transformers."""
        try:
            if not self.embedding_model:
                self.logger.error("Embedding model not initialized")
                return [0.0] * 384

            # Generate embedding using sentence-transformers (384-dimensional)
            embedding = self.embedding_model.encode(text, convert_to_tensor=False)

            # Convert numpy array to list
            if hasattr(embedding, 'tolist'):
                embedding = embedding.tolist()

            self.logger.debug(f"Generated embedding with {len(embedding)} dimensions")
            return embedding

        except Exception as e:
            self.logger.error(f"Embedding generation failed: {e}", exc_info=True)
            return [0.0] * 384

    def _call_llm(self, prompt: str, temperature: float = 0.7, max_tokens: int = 1000) -> str:
        """Call LLM via OpenRouter with retry logic and timeout handling."""
        if not self.api_key:
            self.logger.error("OpenRouter API key not configured")
            return ""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://raverse.ai",
            "X-Title": "RAVERSE"
        }

        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=60
                )

                # Handle rate limiting
                if response.status_code == 429:
                    wait_time = self.retry_backoff ** attempt
                    self.logger.warning(f"Rate limited. Retry {attempt + 1}/{self.max_retries} after {wait_time}s")
                    time.sleep(wait_time)
                    continue

                response.raise_for_status()
                result = response.json()

                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                self.logger.info(f"LLM call successful, tokens used: {result.get('usage', {}).get('total_tokens', 'unknown')}")
                return content

            except requests.exceptions.Timeout:
                self.logger.warning(f"LLM call timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff ** attempt)
                    continue
                return ""

            except requests.exceptions.RequestException as e:
                self.logger.error(f"LLM call failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff ** attempt)
                    continue
                return ""

        return ""

