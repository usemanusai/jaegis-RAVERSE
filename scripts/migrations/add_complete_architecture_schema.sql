-- RAVERSE 2.0 Complete Architecture Schema Migration
-- Adds all tables for Layers 0-6

-- Layer 0: Version Management
CREATE TABLE IF NOT EXISTS system_versions (
    version_id UUID PRIMARY KEY,
    component_name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(component_name, version)
);

CREATE TABLE IF NOT EXISTS compatibility_checks (
    check_id UUID PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS onboarding_validations (
    validation_id UUID PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Layer 1: Knowledge Base & RAG
CREATE TABLE IF NOT EXISTS knowledge_base (
    knowledge_id UUID PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(1536),
    metadata JSONB,
    source VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_knowledge_embedding ON knowledge_base USING ivfflat (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS rag_sessions (
    session_id UUID PRIMARY KEY,
    query TEXT NOT NULL,
    retrieved_knowledge JSONB,
    generated_response TEXT,
    confidence FLOAT,
    created_at TIMESTAMPTZ NOT NULL
);

-- Layer 2: Quality Gate System
CREATE TABLE IF NOT EXISTS quality_checkpoints (
    checkpoint_id UUID PRIMARY KEY,
    phase VARCHAR(255) NOT NULL,
    accuracy_score FLOAT,
    integrity_status VARCHAR(50),
    efficiency_metrics JSONB,
    passed BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quality_phase ON quality_checkpoints(phase);
CREATE INDEX IF NOT EXISTS idx_quality_passed ON quality_checkpoints(passed);

-- Layer 3: Governance & Orchestration
CREATE TABLE IF NOT EXISTS governance_policies (
    policy_id UUID PRIMARY KEY,
    policy_name VARCHAR(255) NOT NULL,
    rules JSONB NOT NULL,
    enforcement_level VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(policy_name)
);

CREATE TABLE IF NOT EXISTS approval_workflows (
    workflow_id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    approvers TEXT[] NOT NULL,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approval_request ON approval_workflows(request_id);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_workflows(status);

CREATE TABLE IF NOT EXISTS governance_audit_log (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(255) NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_event_type ON governance_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created ON governance_audit_log(created_at);

-- Layer 5: Document Generation
CREATE TABLE IF NOT EXISTS generated_documents (
    document_id UUID PRIMARY KEY,
    document_type VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_document_type ON generated_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_document_created ON generated_documents(created_at);

-- RAG Research Sessions
CREATE TABLE IF NOT EXISTS rag_research_sessions (
    session_id UUID PRIMARY KEY,
    initial_query TEXT NOT NULL,
    iterations JSONB,
    synthesis JSONB,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rag_sessions_created ON rag_research_sessions(created_at);

-- Binary Analysis Results
CREATE TABLE IF NOT EXISTS binary_analyses (
    analysis_id UUID PRIMARY KEY,
    file_hash VARCHAR(64) NOT NULL,
    binary_format VARCHAR(50),
    architecture VARCHAR(50),
    metadata JSONB,
    disassembly JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(file_hash)
);

CREATE INDEX IF NOT EXISTS idx_binary_hash ON binary_analyses(file_hash);
CREATE INDEX IF NOT EXISTS idx_binary_format ON binary_analyses(binary_format);
CREATE INDEX IF NOT EXISTS idx_binary_arch ON binary_analyses(architecture);

-- Logic Mappings
CREATE TABLE IF NOT EXISTS logic_mappings (
    mapping_id UUID PRIMARY KEY,
    control_flow JSONB,
    data_flow JSONB,
    algorithms JSONB,
    flowchart JSONB,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_logic_created ON logic_mappings(created_at);

-- Existing tables (ensure they exist)
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
    retry_count INT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_agent_messages_receiver ON agent_messages(receiver_agent);
CREATE INDEX IF NOT EXISTS idx_agent_messages_correlation ON agent_messages(correlation_id);
CREATE INDEX IF NOT EXISTS idx_agent_messages_timestamp ON agent_messages(timestamp);

CREATE TABLE IF NOT EXISTS deep_research_runs (
    run_id VARCHAR(255) PRIMARY KEY,
    original_topic VARCHAR(1000) NOT NULL,
    enhanced_topic VARCHAR(1000),
    status VARCHAR(50) DEFAULT 'pending',
    phase_1_result JSONB,
    phase_2_result JSONB,
    phase_3_result JSONB,
    final_synthesis TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_states (
    agent_id VARCHAR(255) PRIMARY KEY,
    agent_type VARCHAR(255) NOT NULL,
    state JSONB NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL
);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO postgres;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_system_versions_component ON system_versions(component_name);
CREATE INDEX IF NOT EXISTS idx_knowledge_source ON knowledge_base(source);
CREATE INDEX IF NOT EXISTS idx_rag_sessions_created ON rag_sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_governance_policies_level ON governance_policies(enforcement_level);
CREATE INDEX IF NOT EXISTS idx_approval_workflows_created ON approval_workflows(created_at);

-- Add comments for documentation
COMMENT ON TABLE system_versions IS 'Layer 0: Version management and compatibility tracking';
COMMENT ON TABLE knowledge_base IS 'Layer 1: Knowledge base with vector embeddings for semantic search';
COMMENT ON TABLE rag_sessions IS 'Layer 1: RAG (Retrieval-Augmented Generation) session tracking';
COMMENT ON TABLE quality_checkpoints IS 'Layer 2: Quality gate checkpoints using A.I.E.F.N.M.W. protocol';
COMMENT ON TABLE governance_policies IS 'Layer 3: Governance policies and rules';
COMMENT ON TABLE approval_workflows IS 'Layer 3: Approval workflow tracking';
COMMENT ON TABLE governance_audit_log IS 'Layer 3: Audit log for governance events';
COMMENT ON TABLE generated_documents IS 'Layer 5: Generated documents (manifests, white papers, reports)';

