"""
Embedding Generator for RAVERSE
Generates vector embeddings for semantic search using sentence-transformers
Date: October 25, 2025
"""

import os
import logging
import hashlib
from typing import List, Optional
import numpy as np
from sentence_transformers import SentenceTransformer


logger = logging.getLogger(__name__)


class EmbeddingGenerator:
    """
    Generates vector embeddings for text using sentence-transformers.
    Uses local models for cost-free, fast embedding generation.
    Supports caching to reduce computation.
    """

    def __init__(self, api_key: Optional[str] = None, cache_manager=None, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding generator

        Args:
            api_key: Deprecated - kept for backward compatibility, not used
            cache_manager: Optional CacheManager instance for caching
            model_name: Name of the sentence-transformers model to use (default: all-MiniLM-L6-v2)
        """
        self.cache_manager = cache_manager
        self.model_name = model_name

        # Load sentence-transformers model (local, no API needed)
        logger.info(f"Loading sentence-transformers model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.embedding_dim = self.model.get_sentence_embedding_dimension()

        logger.info(f"Embedding generator initialized with {self.embedding_dim}-dimensional embeddings")
    
    def generate_embedding(self, text: str, use_cache: bool = True) -> Optional[List[float]]:
        """
        Generate embedding vector for text using sentence-transformers

        Args:
            text: Input text to embed
            use_cache: Whether to use cache (default True)

        Returns:
            List of floats representing the embedding vector
            None if generation fails
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for embedding")
            return None

        # Check cache first
        if use_cache and self.cache_manager:
            text_hash = hashlib.sha256(text.encode()).hexdigest()
            cache_key = f"embedding:{self.model_name}:{text_hash}"
            cached = self.cache_manager.get(cache_key)
            if cached:
                logger.debug(f"Embedding cache hit for text hash: {text_hash[:16]}...")
                # Convert bytes back to list if needed
                if isinstance(cached, bytes):
                    return np.frombuffer(cached, dtype=np.float32).tolist()
                return cached

        try:
            # Generate embedding using sentence-transformers
            embedding_array = self.model.encode(text, convert_to_numpy=True)
            embedding = embedding_array.tolist()

            # Cache the result
            if use_cache and self.cache_manager:
                text_hash = hashlib.sha256(text.encode()).hexdigest()
                cache_key = f"embedding:{self.model_name}:{text_hash}"
                # Store as bytes for efficiency
                self.cache_manager.set(cache_key, embedding_array.tobytes(), ttl=604800)  # 7 days

            logger.debug(f"Generated {len(embedding)}-dimensional embedding")
            return embedding

        except Exception as e:
            logger.error(f"Embedding generation error: {e}")
            return None
    
    def generate_batch_embeddings(self, texts: List[str],
                                 use_cache: bool = True,
                                 batch_size: int = 32) -> List[Optional[List[float]]]:
        """
        Generate embeddings for multiple texts efficiently using batching

        Args:
            texts: List of input texts
            use_cache: Whether to use cache
            batch_size: Number of texts to process in each batch

        Returns:
            List of embedding vectors (same order as input)
        """
        if not texts:
            return []

        embeddings: List[Optional[List[float]]] = [None] * len(texts)
        uncached_texts = []
        uncached_indices = []

        # Check cache for each text
        if use_cache and self.cache_manager:
            for i, text in enumerate(texts):
                if not text or not text.strip():
                    continue
                text_hash = hashlib.sha256(text.encode()).hexdigest()
                cache_key = f"embedding:{self.model_name}:{text_hash}"
                cached = self.cache_manager.get(cache_key)
                if cached:
                    if isinstance(cached, bytes):
                        embeddings[i] = np.frombuffer(cached, dtype=np.float32).tolist()
                    else:
                        embeddings[i] = cached
                else:
                    uncached_texts.append(text)
                    uncached_indices.append(i)
        else:
            uncached_texts = texts
            uncached_indices = list(range(len(texts)))

        # Generate embeddings for uncached texts in batches
        if uncached_texts:
            try:
                # Use sentence-transformers batch encoding for efficiency
                embedding_arrays = self.model.encode(uncached_texts,
                                                    batch_size=batch_size,
                                                    convert_to_numpy=True,
                                                    show_progress_bar=False)

                # Store results and cache
                for idx, embedding_array in zip(uncached_indices, embedding_arrays):
                    embedding = embedding_array.tolist()
                    embeddings[idx] = embedding

                    # Cache the result
                    if use_cache and self.cache_manager and texts[idx]:
                        text_hash = hashlib.sha256(texts[idx].encode()).hexdigest()
                        cache_key = f"embedding:{self.model_name}:{text_hash}"
                        self.cache_manager.set(cache_key, embedding_array.tobytes(), ttl=604800)

                logger.info(f"Generated {len(uncached_texts)} new embeddings, {len(texts) - len(uncached_texts)} from cache")
            except Exception as e:
                logger.error(f"Batch embedding generation error: {e}")
                # Fall back to individual generation
                for idx in uncached_indices:
                    embeddings[idx] = self.generate_embedding(texts[idx], use_cache=False)

        return embeddings
    
    def cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """
        Calculate cosine similarity between two vectors

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            Similarity score between -1 and 1 (1 = identical)
        """
        if len(vec1) != len(vec2):
            raise ValueError("Vectors must have same dimensions")

        # Use numpy for efficient computation
        vec1_array = np.array(vec1)
        vec2_array = np.array(vec2)

        dot_product = np.dot(vec1_array, vec2_array)
        magnitude1 = np.linalg.norm(vec1_array)
        magnitude2 = np.linalg.norm(vec2_array)

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return float(dot_product / (magnitude1 * magnitude2))


# Backward compatibility alias
LocalEmbeddingGenerator = EmbeddingGenerator

