-- RAVERSE Workflows D1 Database Schema
-- Stores workflow execution history, analysis results, and state

-- Analysis Results Table
CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL UNIQUE,
    binary_path TEXT NOT NULL,
    analysis_type TEXT NOT NULL,
    result TEXT NOT NULL,
    status TEXT DEFAULT 'completed',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_binary_path (binary_path),
    INDEX idx_analysis_type (analysis_type),
    INDEX idx_created_at (created_at)
);

-- Workflow Execution History
CREATE TABLE IF NOT EXISTS workflow_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL UNIQUE,
    workflow_type TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    duration_ms INTEGER,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    INDEX idx_workflow_type (workflow_type),
    INDEX idx_status (status),
    INDEX idx_start_time (start_time)
);

-- Cache Metadata
CREATE TABLE IF NOT EXISTS cache_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_key TEXT NOT NULL UNIQUE,
    binary_path TEXT,
    analysis_type TEXT,
    ttl_seconds INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    hit_count INTEGER DEFAULT 0,
    last_accessed DATETIME,
    INDEX idx_cache_key (cache_key),
    INDEX idx_expires_at (expires_at),
    INDEX idx_hit_count (hit_count)
);

-- Workflow Performance Metrics
CREATE TABLE IF NOT EXISTS performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    workflow_type TEXT NOT NULL,
    step_name TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    memory_used_mb REAL,
    cpu_percent REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_workflow_type (workflow_type),
    INDEX idx_step_name (step_name),
    INDEX idx_timestamp (timestamp)
);

-- Hybrid Routing Log
CREATE TABLE IF NOT EXISTS routing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    request_path TEXT NOT NULL,
    method TEXT NOT NULL,
    source TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    cache_hit BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_request_path (request_path),
    INDEX idx_source (source),
    INDEX idx_timestamp (timestamp)
);

-- Workflow State Storage
CREATE TABLE IF NOT EXISTS workflow_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL UNIQUE,
    state_data TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_workflow_id (workflow_id)
);

-- Error Log
CREATE TABLE IF NOT EXISTS error_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    error_type TEXT NOT NULL,
    error_message TEXT NOT NULL,
    stack_trace TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_workflow_id (workflow_id),
    INDEX idx_error_type (error_type),
    INDEX idx_timestamp (timestamp)
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_analysis_results_workflow_id ON analysis_results(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow_id ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_workflow_id ON performance_metrics(workflow_id);
CREATE INDEX IF NOT EXISTS idx_routing_log_workflow_id ON routing_log(workflow_id);

-- Create views for common queries
CREATE VIEW IF NOT EXISTS workflow_summary AS
SELECT 
    we.workflow_id,
    we.workflow_type,
    we.status,
    we.start_time,
    we.end_time,
    we.duration_ms,
    COUNT(pm.id) as step_count,
    AVG(pm.duration_ms) as avg_step_duration_ms
FROM workflow_executions we
LEFT JOIN performance_metrics pm ON we.workflow_id = pm.workflow_id
GROUP BY we.workflow_id;

CREATE VIEW IF NOT EXISTS cache_performance AS
SELECT 
    cache_key,
    hit_count,
    ttl_seconds,
    (CAST(hit_count AS FLOAT) / NULLIF((SELECT COUNT(*) FROM cache_metadata), 0)) * 100 as hit_rate_percent,
    created_at,
    expires_at
FROM cache_metadata
ORDER BY hit_count DESC;

CREATE VIEW IF NOT EXISTS recent_errors AS
SELECT 
    workflow_id,
    error_type,
    error_message,
    timestamp,
    ROW_NUMBER() OVER (PARTITION BY workflow_id ORDER BY timestamp DESC) as error_rank
FROM error_log
WHERE timestamp > datetime('now', '-24 hours');

