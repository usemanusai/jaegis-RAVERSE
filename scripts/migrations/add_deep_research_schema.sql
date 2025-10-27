-- Deep Research Agent Schema Migration
-- Date: 2025-10-26
-- Purpose: Add tables for Deep Research agents and A2A communication

-- Create agent_messages table for A2A communication audit log
CREATE TABLE IF NOT EXISTS agent_messages (
    message_id UUID PRIMARY KEY,
    sender_agent VARCHAR(255) NOT NULL,
    receiver_agent VARCHAR(255) NOT NULL,
    message_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    correlation_id UUID NOT NULL,
    priority VARCHAR(20) DEFAULT 'normal',
    status VARCHAR(50) DEFAULT 'pending',
    retry_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_agent_messages_correlation_id 
    ON agent_messages(correlation_id);

CREATE INDEX IF NOT EXISTS idx_agent_messages_sender_agent 
    ON agent_messages(sender_agent);

CREATE INDEX IF NOT EXISTS idx_agent_messages_receiver_agent 
    ON agent_messages(receiver_agent);

CREATE INDEX IF NOT EXISTS idx_agent_messages_timestamp 
    ON agent_messages(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_agent_messages_status 
    ON agent_messages(status);

CREATE INDEX IF NOT EXISTS idx_agent_messages_message_type 
    ON agent_messages(message_type);

-- Create deep_research_runs table for tracking research workflows
CREATE TABLE IF NOT EXISTS deep_research_runs (
    run_id VARCHAR(255) PRIMARY KEY,
    original_topic VARCHAR(1000) NOT NULL,
    enhanced_topic VARCHAR(1000),
    status VARCHAR(50) DEFAULT 'pending',
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    duration_seconds FLOAT,
    phase_1_status VARCHAR(50),
    phase_2_status VARCHAR(50),
    phase_3_status VARCHAR(50),
    phase_1_result JSONB,
    phase_2_result JSONB,
    phase_3_result JSONB,
    final_synthesis TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for deep_research_runs
CREATE INDEX IF NOT EXISTS idx_deep_research_runs_status 
    ON deep_research_runs(status);

CREATE INDEX IF NOT EXISTS idx_deep_research_runs_created_at 
    ON deep_research_runs(created_at DESC);

-- Create deep_research_cache table for caching research results
CREATE TABLE IF NOT EXISTS deep_research_cache (
    cache_key VARCHAR(255) PRIMARY KEY,
    cache_value JSONB NOT NULL,
    ttl_seconds INT DEFAULT 3600,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '1 hour'
);

-- Create index for cache expiration cleanup
CREATE INDEX IF NOT EXISTS idx_deep_research_cache_expires_at 
    ON deep_research_cache(expires_at);

-- Create deep_research_metrics table for performance tracking
CREATE TABLE IF NOT EXISTS deep_research_metrics (
    metric_id SERIAL PRIMARY KEY,
    run_id VARCHAR(255) NOT NULL,
    agent_type VARCHAR(255) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    metric_value FLOAT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (run_id) REFERENCES deep_research_runs(run_id) ON DELETE CASCADE
);

-- Create indexes for metrics
CREATE INDEX IF NOT EXISTS idx_deep_research_metrics_run_id 
    ON deep_research_metrics(run_id);

CREATE INDEX IF NOT EXISTS idx_deep_research_metrics_agent_type 
    ON deep_research_metrics(agent_type);

CREATE INDEX IF NOT EXISTS idx_deep_research_metrics_timestamp 
    ON deep_research_metrics(timestamp DESC);

-- Create deep_research_sources table for tracking research sources
CREATE TABLE IF NOT EXISTS deep_research_sources (
    source_id SERIAL PRIMARY KEY,
    run_id VARCHAR(255) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    title VARCHAR(1000),
    content TEXT,
    content_hash VARCHAR(64),
    source_type VARCHAR(50),
    relevance_score FLOAT,
    scraped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (run_id) REFERENCES deep_research_runs(run_id) ON DELETE CASCADE
);

-- Create indexes for sources
CREATE INDEX IF NOT EXISTS idx_deep_research_sources_run_id 
    ON deep_research_sources(run_id);

CREATE INDEX IF NOT EXISTS idx_deep_research_sources_url 
    ON deep_research_sources(url);

CREATE INDEX IF NOT EXISTS idx_deep_research_sources_content_hash 
    ON deep_research_sources(content_hash);

-- Create function to clean up expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_cache()
RETURNS void AS $$
BEGIN
    DELETE FROM deep_research_cache WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create function to update agent_messages updated_at timestamp
CREATE OR REPLACE FUNCTION update_agent_messages_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for agent_messages updated_at
DROP TRIGGER IF EXISTS agent_messages_update_timestamp ON agent_messages;
CREATE TRIGGER agent_messages_update_timestamp
    BEFORE UPDATE ON agent_messages
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_messages_timestamp();

-- Create function to update deep_research_runs updated_at timestamp
CREATE OR REPLACE FUNCTION update_deep_research_runs_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for deep_research_runs updated_at
DROP TRIGGER IF EXISTS deep_research_runs_update_timestamp ON deep_research_runs;
CREATE TRIGGER deep_research_runs_update_timestamp
    BEFORE UPDATE ON deep_research_runs
    FOR EACH ROW
    EXECUTE FUNCTION update_deep_research_runs_timestamp();

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_messages TO raverse;
GRANT SELECT, INSERT, UPDATE, DELETE ON deep_research_runs TO raverse;
GRANT SELECT, INSERT, UPDATE, DELETE ON deep_research_cache TO raverse;
GRANT SELECT, INSERT, UPDATE, DELETE ON deep_research_metrics TO raverse;
GRANT SELECT, INSERT, UPDATE, DELETE ON deep_research_sources TO raverse;

-- Log migration completion
INSERT INTO schema_migrations (name, executed_at) 
VALUES ('add_deep_research_schema', NOW())
ON CONFLICT DO NOTHING;

