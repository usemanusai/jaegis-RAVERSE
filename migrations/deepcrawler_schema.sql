-- DeepCrawler Schema Migration for RAVERSE 2.0
-- Creates tables for crawl sessions, URL frontier, discovered APIs, and audit trail
-- Date: October 26, 2025

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS raverse;

-- Crawl Sessions Table
-- Tracks overall crawl session metadata and progress
CREATE TABLE IF NOT EXISTS raverse.crawl_sessions (
    id SERIAL PRIMARY KEY,
    session_id UUID UNIQUE NOT NULL,
    target_url TEXT NOT NULL,
    max_depth INTEGER DEFAULT 3,
    status VARCHAR(50) DEFAULT 'running',
    urls_crawled INTEGER DEFAULT 0,
    apis_found INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_status CHECK (status IN ('running', 'paused', 'completed', 'failed'))
);

-- Create index on session_id for fast lookups
CREATE INDEX IF NOT EXISTS idx_crawl_sessions_session_id ON raverse.crawl_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_crawl_sessions_status ON raverse.crawl_sessions(status);
CREATE INDEX IF NOT EXISTS idx_crawl_sessions_created_at ON raverse.crawl_sessions(created_at);

-- URL Frontier Table
-- Stores URLs to be crawled with priority and status
CREATE TABLE IF NOT EXISTS raverse.crawl_urls (
    id SERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES raverse.crawl_sessions(session_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    depth INTEGER NOT NULL,
    priority FLOAT DEFAULT 0.5,
    status VARCHAR(50) DEFAULT 'pending',
    discovered_by VARCHAR(50),
    crawled_at TIMESTAMP,
    UNIQUE(session_id, url),
    CONSTRAINT valid_url_status CHECK (status IN ('pending', 'crawling', 'crawled', 'failed')),
    CONSTRAINT valid_depth CHECK (depth >= 0),
    CONSTRAINT valid_priority CHECK (priority >= 0.0 AND priority <= 1.0)
);

-- Create indexes for efficient frontier queries
CREATE INDEX IF NOT EXISTS idx_crawl_urls_session_id ON raverse.crawl_urls(session_id);
CREATE INDEX IF NOT EXISTS idx_crawl_urls_status ON raverse.crawl_urls(status);
CREATE INDEX IF NOT EXISTS idx_crawl_urls_priority ON raverse.crawl_urls(priority DESC);
CREATE INDEX IF NOT EXISTS idx_crawl_urls_depth ON raverse.crawl_urls(depth);
CREATE INDEX IF NOT EXISTS idx_crawl_urls_discovered_by ON raverse.crawl_urls(discovered_by);

-- Discovered APIs Table
-- Stores discovered API endpoints with metadata
CREATE TABLE IF NOT EXISTS raverse.discovered_apis (
    id SERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES raverse.crawl_sessions(session_id) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL,
    http_method VARCHAR(10),
    confidence_score FLOAT DEFAULT 0.5,
    discovery_method VARCHAR(100),
    request_example JSONB,
    response_example JSONB,
    authentication TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, endpoint_url, http_method),
    CONSTRAINT valid_http_method CHECK (http_method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')),
    CONSTRAINT valid_confidence CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0)
);

-- Create indexes for API queries
CREATE INDEX IF NOT EXISTS idx_discovered_apis_session_id ON raverse.discovered_apis(session_id);
CREATE INDEX IF NOT EXISTS idx_discovered_apis_endpoint_url ON raverse.discovered_apis(endpoint_url);
CREATE INDEX IF NOT EXISTS idx_discovered_apis_http_method ON raverse.discovered_apis(http_method);
CREATE INDEX IF NOT EXISTS idx_discovered_apis_confidence ON raverse.discovered_apis(confidence_score DESC);
CREATE INDEX IF NOT EXISTS idx_discovered_apis_discovery_method ON raverse.discovered_apis(discovery_method);
CREATE INDEX IF NOT EXISTS idx_discovered_apis_discovered_at ON raverse.discovered_apis(discovered_at);

-- Crawl History Table
-- Audit trail for all crawl events
CREATE TABLE IF NOT EXISTS raverse.crawl_history (
    id SERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES raverse.crawl_sessions(session_id) ON DELETE CASCADE,
    event_type VARCHAR(100),
    event_data JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for history queries
CREATE INDEX IF NOT EXISTS idx_crawl_history_session_id ON raverse.crawl_history(session_id);
CREATE INDEX IF NOT EXISTS idx_crawl_history_event_type ON raverse.crawl_history(event_type);
CREATE INDEX IF NOT EXISTS idx_crawl_history_timestamp ON raverse.crawl_history(timestamp);

-- Create function to update crawl_sessions.updated_at on modification
CREATE OR REPLACE FUNCTION raverse.update_crawl_sessions_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for automatic timestamp update
DROP TRIGGER IF EXISTS trigger_update_crawl_sessions_timestamp ON raverse.crawl_sessions;
CREATE TRIGGER trigger_update_crawl_sessions_timestamp
BEFORE UPDATE ON raverse.crawl_sessions
FOR EACH ROW
EXECUTE FUNCTION raverse.update_crawl_sessions_timestamp();

-- Grant permissions (adjust as needed for your setup)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON raverse.crawl_sessions TO raverse_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON raverse.crawl_urls TO raverse_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON raverse.discovered_apis TO raverse_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON raverse.crawl_history TO raverse_user;

-- Verify schema creation
SELECT 'DeepCrawler schema created successfully' AS status;

