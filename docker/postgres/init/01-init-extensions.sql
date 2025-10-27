-- RAVERSE PostgreSQL Initialization Script
-- Date: October 25, 2025
-- Purpose: Initialize pgvector extension and create schema for AI-powered binary analysis

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Create schema for RAVERSE
CREATE SCHEMA IF NOT EXISTS raverse;

-- Set search path
SET search_path TO raverse, public;

-- Table: binaries
-- Stores metadata about analyzed binaries
CREATE TABLE IF NOT EXISTS raverse.binaries (
    id SERIAL PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_hash VARCHAR(64) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    file_type VARCHAR(50),
    architecture VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Table: disassembly_cache
-- Caches disassembly results with vector embeddings for semantic search
CREATE TABLE IF NOT EXISTS raverse.disassembly_cache (
    id SERIAL PRIMARY KEY,
    binary_id INTEGER REFERENCES raverse.binaries(id) ON DELETE CASCADE,
    address VARCHAR(20) NOT NULL,
    instruction TEXT NOT NULL,
    opcode VARCHAR(50),
    operands TEXT,
    disassembly_text TEXT,
    embedding vector(1536),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb,
    UNIQUE(binary_id, address)
);

-- Table: analysis_results
-- Stores AI agent analysis results
CREATE TABLE IF NOT EXISTS raverse.analysis_results (
    id SERIAL PRIMARY KEY,
    binary_id INTEGER REFERENCES raverse.binaries(id) ON DELETE CASCADE,
    agent_name VARCHAR(100) NOT NULL,
    analysis_type VARCHAR(100) NOT NULL,
    result JSONB NOT NULL,
    confidence_score FLOAT,
    tokens_used INTEGER,
    execution_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Table: patch_history
-- Tracks all patching operations
CREATE TABLE IF NOT EXISTS raverse.patch_history (
    id SERIAL PRIMARY KEY,
    binary_id INTEGER REFERENCES raverse.binaries(id) ON DELETE CASCADE,
    patch_type VARCHAR(50) NOT NULL,
    target_address VARCHAR(20) NOT NULL,
    original_bytes BYTEA,
    patched_bytes BYTEA,
    success BOOLEAN DEFAULT FALSE,
    verification_result JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Table: llm_cache
-- Caches LLM responses to reduce API calls and costs
CREATE TABLE IF NOT EXISTS raverse.llm_cache (
    id SERIAL PRIMARY KEY,
    prompt_hash VARCHAR(64) NOT NULL UNIQUE,
    prompt_text TEXT NOT NULL,
    response_text TEXT NOT NULL,
    model_name VARCHAR(100) NOT NULL,
    tokens_used INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    access_count INTEGER DEFAULT 1,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Table: vector_search_index
-- Stores embeddings for semantic search across all analysis data
CREATE TABLE IF NOT EXISTS raverse.vector_search_index (
    id SERIAL PRIMARY KEY,
    content_type VARCHAR(50) NOT NULL,
    content_id INTEGER NOT NULL,
    content_text TEXT NOT NULL,
    embedding vector(1536),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Table: code_embeddings
-- Stores code snippets with embeddings for semantic search (384 dimensions for all-MiniLM-L6-v2)
CREATE TABLE IF NOT EXISTS raverse.code_embeddings (
    id SERIAL PRIMARY KEY,
    binary_hash VARCHAR(64) NOT NULL,
    code_snippet TEXT NOT NULL,
    embedding vector(384),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table: patch_strategies
-- Stores learned patch strategies for reuse
CREATE TABLE IF NOT EXISTS raverse.patch_strategies (
    id SERIAL PRIMARY KEY,
    strategy_name VARCHAR(100) NOT NULL,
    strategy_type VARCHAR(50) NOT NULL,
    description TEXT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    success_rate FLOAT GENERATED ALWAYS AS (
        CASE
            WHEN (success_count + failure_count) > 0
            THEN success_count::FLOAT / (success_count + failure_count)
            ELSE 0
        END
    ) STORED,
    pattern_embedding vector(384),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance optimization

-- Binaries table indexes
CREATE INDEX IF NOT EXISTS idx_binaries_file_hash ON raverse.binaries(file_hash);
CREATE INDEX IF NOT EXISTS idx_binaries_status ON raverse.binaries(status);
CREATE INDEX IF NOT EXISTS idx_binaries_created_at ON raverse.binaries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_binaries_metadata ON raverse.binaries USING gin(metadata);

-- Disassembly cache indexes
CREATE INDEX IF NOT EXISTS idx_disassembly_binary_id ON raverse.disassembly_cache(binary_id);
CREATE INDEX IF NOT EXISTS idx_disassembly_address ON raverse.disassembly_cache(address);
CREATE INDEX IF NOT EXISTS idx_disassembly_opcode ON raverse.disassembly_cache(opcode);
CREATE INDEX IF NOT EXISTS idx_disassembly_metadata ON raverse.disassembly_cache USING gin(metadata);

-- Vector index for semantic search (HNSW for better query performance)
CREATE INDEX IF NOT EXISTS idx_disassembly_embedding ON raverse.disassembly_cache 
USING hnsw (embedding vector_cosine_ops) 
WITH (m = 16, ef_construction = 64);

-- Analysis results indexes
CREATE INDEX IF NOT EXISTS idx_analysis_binary_id ON raverse.analysis_results(binary_id);
CREATE INDEX IF NOT EXISTS idx_analysis_agent_name ON raverse.analysis_results(agent_name);
CREATE INDEX IF NOT EXISTS idx_analysis_type ON raverse.analysis_results(analysis_type);
CREATE INDEX IF NOT EXISTS idx_analysis_created_at ON raverse.analysis_results(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_result ON raverse.analysis_results USING gin(result);

-- Patch history indexes
CREATE INDEX IF NOT EXISTS idx_patch_binary_id ON raverse.patch_history(binary_id);
CREATE INDEX IF NOT EXISTS idx_patch_address ON raverse.patch_history(target_address);
CREATE INDEX IF NOT EXISTS idx_patch_success ON raverse.patch_history(success);
CREATE INDEX IF NOT EXISTS idx_patch_created_at ON raverse.patch_history(created_at DESC);

-- LLM cache indexes
CREATE INDEX IF NOT EXISTS idx_llm_cache_hash ON raverse.llm_cache(prompt_hash);
CREATE INDEX IF NOT EXISTS idx_llm_cache_model ON raverse.llm_cache(model_name);
CREATE INDEX IF NOT EXISTS idx_llm_cache_last_accessed ON raverse.llm_cache(last_accessed_at DESC);

-- Vector search index
CREATE INDEX IF NOT EXISTS idx_vector_search_content ON raverse.vector_search_index(content_type, content_id);
CREATE INDEX IF NOT EXISTS idx_vector_search_embedding ON raverse.vector_search_index
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Code embeddings indexes
CREATE INDEX IF NOT EXISTS idx_code_embeddings_binary_hash ON raverse.code_embeddings(binary_hash);
CREATE INDEX IF NOT EXISTS idx_code_embeddings_created_at ON raverse.code_embeddings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_code_embeddings_metadata ON raverse.code_embeddings USING gin(metadata);
CREATE INDEX IF NOT EXISTS idx_code_embeddings_embedding ON raverse.code_embeddings
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Patch strategies indexes
CREATE INDEX IF NOT EXISTS idx_patch_strategies_type ON raverse.patch_strategies(strategy_type);
CREATE INDEX IF NOT EXISTS idx_patch_strategies_success_rate ON raverse.patch_strategies(success_rate DESC);
CREATE INDEX IF NOT EXISTS idx_patch_strategies_embedding ON raverse.patch_strategies
USING hnsw (pattern_embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION raverse.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for binaries table
CREATE TRIGGER update_binaries_updated_at
    BEFORE UPDATE ON raverse.binaries
    FOR EACH ROW
    EXECUTE FUNCTION raverse.update_updated_at_column();

-- Create function to update LLM cache access statistics
CREATE OR REPLACE FUNCTION raverse.update_llm_cache_access()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_accessed_at = CURRENT_TIMESTAMP;
    NEW.access_count = OLD.access_count + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create cache_entries table for L3 caching
CREATE TABLE IF NOT EXISTS raverse.cache_entries (
    id SERIAL PRIMARY KEY,
    namespace VARCHAR(255) NOT NULL,
    key VARCHAR(512) NOT NULL,
    value BYTEA NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(namespace, key)
);

-- Indexes for cache_entries
CREATE INDEX IF NOT EXISTS idx_cache_entries_namespace_key ON raverse.cache_entries(namespace, key);
CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at ON raverse.cache_entries(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cache_entries_created_at ON raverse.cache_entries(created_at DESC);

-- Cleanup expired cache entries (run periodically)
CREATE OR REPLACE FUNCTION raverse.cleanup_expired_cache()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM raverse.cache_entries
    WHERE expires_at IS NOT NULL AND expires_at < NOW();

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA raverse TO raverse;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA raverse TO raverse;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA raverse TO raverse;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA raverse GRANT ALL ON TABLES TO raverse;
ALTER DEFAULT PRIVILEGES IN SCHEMA raverse GRANT ALL ON SEQUENCES TO raverse;

-- Optimize PostgreSQL settings for vector operations
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET max_parallel_workers_per_gather = 4;
ALTER SYSTEM SET max_parallel_workers = 8;
ALTER SYSTEM SET random_page_cost = 1.1;

-- Log completion
DO $$
BEGIN
    RAISE NOTICE 'RAVERSE PostgreSQL initialization completed successfully';
    RAISE NOTICE 'Extensions enabled: vector, pg_trgm, btree_gin';
    RAISE NOTICE 'Schema created: raverse';
    RAISE NOTICE 'Tables created: 7';
    RAISE NOTICE 'Indexes created: 20+';
    RAISE NOTICE 'Vector indexes: HNSW with m=16, ef_construction=64';
END $$;

