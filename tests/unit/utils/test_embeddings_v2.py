import pytest
from unittest.mock import patch, MagicMock

import src.utils.embeddings_v2 as embeddings_v2
from src.utils.embeddings_v2 import get_embedding_generator, EmbeddingGenerator
from src.utils.cache import CacheManager

@pytest.fixture(autouse=True)
def reset_global_generator():
    """Reset the global _embedding_generator before and after each test."""
    embeddings_v2._embedding_generator = None
    yield
    embeddings_v2._embedding_generator = None

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_get_embedding_generator_default_params(mock_sentence_transformer):
    """Test get_embedding_generator with default parameters."""
    generator = get_embedding_generator()

    # Verify the object was created correctly
    assert isinstance(generator, EmbeddingGenerator)
    assert generator.model_name == "all-MiniLM-L6-v2"
    assert generator.cache_manager is None

    # Verify SentenceTransformer was initialized
    mock_sentence_transformer.assert_called_once_with("all-MiniLM-L6-v2")

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_get_embedding_generator_custom_params(mock_sentence_transformer):
    """Test get_embedding_generator with custom parameters."""
    mock_cache = MagicMock(spec=CacheManager)

    generator = get_embedding_generator(
        model_name="custom-model-name",
        cache_manager=mock_cache
    )

    assert generator.model_name == "custom-model-name"
    assert generator.cache_manager is mock_cache

    mock_sentence_transformer.assert_called_once_with("custom-model-name")

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_get_embedding_generator_singleton(mock_sentence_transformer):
    """Test that get_embedding_generator returns the same instance on subsequent calls."""
    # First call
    generator1 = get_embedding_generator()

    # Second call
    generator2 = get_embedding_generator()

    # Should be the exact same object
    assert generator1 is generator2

    # SentenceTransformer should only be instantiated once
    mock_sentence_transformer.assert_called_once()

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_find_most_similar_vectorized(mock_sentence_transformer):
    import numpy as np
    generator = get_embedding_generator()

    query = np.array([1.0, 0.0, 0.0])
    candidates = [
        np.array([1.0, 0.0, 0.0]),  # Exact match
        np.array([0.0, 1.0, 0.0]),  # Orthogonal
        np.array([0.5, 0.5, 0.0]),  # Partial match
        np.array([-1.0, 0.0, 0.0]), # Opposite
    ]

    results = generator.find_most_similar(query, candidates, top_k=2)
    assert len(results) == 2
    assert results[0][0] == 0  # First element is the exact match
    assert abs(results[0][1] - 1.0) < 1e-6
    assert results[1][0] == 2  # Second element is partial match
    assert abs(results[1][1] - 0.707106) < 1e-5

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_find_most_similar_empty_candidates(mock_sentence_transformer):
    import numpy as np
    generator = get_embedding_generator()
    query = np.array([1.0, 0.0])
    results = generator.find_most_similar(query, [], top_k=5)
    assert results == []

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_find_most_similar_zero_norm(mock_sentence_transformer):
    import numpy as np
    generator = get_embedding_generator()

    query = np.array([0.0, 0.0, 0.0])
    candidates = [np.array([1.0, 0.0, 0.0])]
    results = generator.find_most_similar(query, candidates)
    assert results == [(0, 0.0)]

    query2 = np.array([1.0, 0.0, 0.0])
    candidates2 = [np.array([0.0, 0.0, 0.0])]
    results2 = generator.find_most_similar(query2, candidates2)
    assert results2 == [(0, 0.0)]

@patch("src.utils.embeddings_v2.SentenceTransformer")
def test_find_most_similar_fallback(mock_sentence_transformer):
    import numpy as np
    generator = get_embedding_generator()
    query = np.array([1.0, 0.0])

    class UnstackableList(list):
        def __array__(self, dtype=None, copy=None):
            raise ValueError("Cannot stack")

    # Use a custom list that throws ValueError on np.array()
    candidates = UnstackableList([
        np.array([1.0, 0.0]),
        np.array([0.0, 1.0])
    ])

    results = generator.find_most_similar(query, candidates, top_k=2)
    assert len(results) == 2
    assert results[0][0] == 0
    assert abs(results[0][1] - 1.0) < 1e-6
    assert results[1][0] == 1
    assert abs(results[1][1] - 0.0) < 1e-6
