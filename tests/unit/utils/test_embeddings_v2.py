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
