"""
Enhanced Embeddings Module for RAVERSE
Date: October 25, 2025

This module provides semantic code embedding generation using
sentence-transformers for CPU-only operation.
"""

import numpy as np
from typing import List, Dict, Optional, Tuple
from sentence_transformers import SentenceTransformer
import hashlib
import time
from utils.metrics import metrics_collector
from utils.cache import CacheManager


class EmbeddingGenerator:
    """
    Generate embeddings for code snippets using sentence-transformers.
    Optimized for CPU-only operation with caching.
    """
    
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        cache_manager: Optional[CacheManager] = None,
        batch_size: int = 32
    ):
        """
        Initialize the embedding generator.
        
        Args:
            model_name: Name of the sentence-transformers model
            cache_manager: Optional cache manager for caching embeddings
            batch_size: Batch size for processing multiple embeddings
        """
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.cache_manager = cache_manager
        self.batch_size = batch_size
        self.embedding_dim = self.model.get_sentence_embedding_dimension()
    
    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        text_hash = hashlib.sha256(text.encode()).hexdigest()
        return f"embedding:{self.model_name}:{text_hash}"
    
    def generate_embedding(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Input text to embed
            
        Returns:
            Embedding vector as numpy array
        """
        # Check cache first
        if self.cache_manager:
            cache_key = self._get_cache_key(text)
            cached = self.cache_manager.get(cache_key)
            if cached is not None:
                metrics_collector.record_cache_hit('embedding')
                return np.frombuffer(cached, dtype=np.float32)
            metrics_collector.record_cache_miss('embedding')
        
        # Generate embedding
        start_time = time.time()
        embedding = self.model.encode(text, convert_to_numpy=True)
        duration = time.time() - start_time
        
        # Record metrics
        metrics_collector.record_embedding_generation(self.model_name, duration)
        
        # Cache the result
        if self.cache_manager:
            self.cache_manager.set(
                cache_key,
                embedding.tobytes(),
                ttl=604800  # 7 days
            )
        
        return embedding
    
    def generate_batch_embeddings(self, texts: List[str]) -> List[np.ndarray]:
        """
        Generate embeddings for multiple texts in batches.
        
        Args:
            texts: List of input texts
            
        Returns:
            List of embedding vectors
        """
        embeddings = []
        uncached_texts = []
        uncached_indices = []
        
        # Check cache for all texts
        if self.cache_manager:
            for i, text in enumerate(texts):
                cache_key = self._get_cache_key(text)
                cached = self.cache_manager.get(cache_key)
                if cached is not None:
                    metrics_collector.record_cache_hit('embedding')
                    embeddings.append(np.frombuffer(cached, dtype=np.float32))
                else:
                    metrics_collector.record_cache_miss('embedding')
                    uncached_texts.append(text)
                    uncached_indices.append(i)
                    embeddings.append(None)  # Temporary None, will be replaced after batch generation
        else:
            uncached_texts = texts
            uncached_indices = list(range(len(texts)))
            embeddings = [None] * len(texts)
        
        # Generate embeddings for uncached texts
        if uncached_texts:
            start_time = time.time()
            new_embeddings = self.model.encode(
                uncached_texts,
                batch_size=self.batch_size,
                convert_to_numpy=True,
                show_progress_bar=False
            )
            duration = time.time() - start_time
            
            # Record metrics
            for _ in uncached_texts:
                metrics_collector.record_embedding_generation(
                    self.model_name,
                    duration / len(uncached_texts)
                )
            
            # Cache and insert new embeddings
            for i, (idx, embedding) in enumerate(zip(uncached_indices, new_embeddings)):
                embeddings[idx] = embedding
                if self.cache_manager:
                    cache_key = self._get_cache_key(uncached_texts[i])
                    self.cache_manager.set(
                        cache_key,
                        embedding.tobytes(),
                        ttl=604800  # 7 days
                    )
        
        return embeddings
    
    def preprocess_code(self, code: str) -> str:
        """
        Preprocess code for embedding generation.
        
        Args:
            code: Raw code snippet
            
        Returns:
            Preprocessed code
        """
        # Remove excessive whitespace
        lines = [line.strip() for line in code.split('\n') if line.strip()]
        
        # Limit length to avoid token limits
        max_lines = 50
        if len(lines) > max_lines:
            lines = lines[:max_lines]
        
        return '\n'.join(lines)
    
    def generate_code_embedding(self, code: str) -> np.ndarray:
        """
        Generate embedding for code snippet with preprocessing.
        
        Args:
            code: Code snippet
            
        Returns:
            Embedding vector
        """
        preprocessed = self.preprocess_code(code)
        return self.generate_embedding(preprocessed)
    
    def generate_code_embeddings_batch(self, codes: List[str]) -> List[np.ndarray]:
        """
        Generate embeddings for multiple code snippets.
        
        Args:
            codes: List of code snippets
            
        Returns:
            List of embedding vectors
        """
        preprocessed = [self.preprocess_code(code) for code in codes]
        return self.generate_batch_embeddings(preprocessed)
    
    def compute_similarity(
        self,
        embedding1: np.ndarray,
        embedding2: np.ndarray
    ) -> float:
        """
        Compute cosine similarity between two embeddings.
        
        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector
            
        Returns:
            Cosine similarity score (0-1)
        """
        dot_product = np.dot(embedding1, embedding2)
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(dot_product / (norm1 * norm2))
    
    def find_most_similar(
        self,
        query_embedding: np.ndarray,
        candidate_embeddings: List[np.ndarray],
        top_k: int = 5
    ) -> List[Tuple[int, float]]:
        """
        Find most similar embeddings to query.
        
        Args:
            query_embedding: Query embedding vector
            candidate_embeddings: List of candidate embeddings
            top_k: Number of top results to return
            
        Returns:
            List of (index, similarity_score) tuples
        """
        similarities = [
            (i, self.compute_similarity(query_embedding, emb))
            for i, emb in enumerate(candidate_embeddings)
        ]
        
        # Sort by similarity (descending)
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        return similarities[:top_k]
    
    def get_embedding_dimension(self) -> int:
        """Get the dimension of embeddings."""
        return self.embedding_dim


# Global embedding generator instance
_embedding_generator: Optional[EmbeddingGenerator] = None


def get_embedding_generator(
    model_name: str = "all-MiniLM-L6-v2",
    cache_manager: Optional[CacheManager] = None
) -> EmbeddingGenerator:
    """
    Get or create global embedding generator instance.
    
    Args:
        model_name: Name of the model to use
        cache_manager: Optional cache manager
        
    Returns:
        EmbeddingGenerator instance
    """
    global _embedding_generator
    if _embedding_generator is None:
        _embedding_generator = EmbeddingGenerator(
            model_name=model_name,
            cache_manager=cache_manager
        )
    return _embedding_generator

