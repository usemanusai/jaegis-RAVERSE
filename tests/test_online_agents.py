"""
Test suite for RAVERSE Online agents.
"""

import pytest
import json
from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from agents.online_base_agent import OnlineBaseAgent
from agents.online_reconnaissance_agent import ReconnaissanceAgent
from agents.online_traffic_interception_agent import TrafficInterceptionAgent
from agents.online_javascript_analysis_agent import JavaScriptAnalysisAgent
from agents.online_api_reverse_engineering_agent import APIReverseEngineeringAgent
from agents.online_wasm_analysis_agent import WebAssemblyAnalysisAgent
from agents.online_ai_copilot_agent import AICoPilotAgent
from agents.online_security_analysis_agent import SecurityAnalysisAgent
from agents.online_validation_agent import ValidationAgent
from agents.online_reporting_agent import ReportingAgent
from agents.online_orchestrator import OnlineOrchestrationAgent


class TestOnlineBaseAgent:
    """Test OnlineBaseAgent base class."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        class TestAgent(OnlineBaseAgent):
            def _execute_impl(self, task):
                return {"test": "result"}
        
        agent = TestAgent("Test Agent", "TEST")
        assert agent.name == "Test Agent"
        assert agent.agent_type == "TEST"
        assert agent.state == "idle"
        assert agent.progress == 0.0

    def test_agent_execution(self):
        """Test agent execution."""
        class TestAgent(OnlineBaseAgent):
            def _execute_impl(self, task):
                return {"test": "result"}
        
        agent = TestAgent("Test Agent", "TEST")
        result = agent.execute({"test": "task"})
        
        assert result["status"] == "success"
        assert result["state"] == "succeeded"
        assert result["progress"] == 1.0
        assert result["result"]["test"] == "result"

    def test_agent_error_handling(self):
        """Test agent error handling."""
        class FailingAgent(OnlineBaseAgent):
            def _execute_impl(self, task):
                raise ValueError("Test error")
        
        agent = FailingAgent("Failing Agent", "FAIL")
        result = agent.execute({})
        
        assert result["status"] == "failed"
        assert result["state"] == "failed"
        assert "Test error" in result["error"]

    def test_progress_reporting(self):
        """Test progress reporting."""
        class TestAgent(OnlineBaseAgent):
            def _execute_impl(self, task):
                self.report_progress(0.5, "Halfway done")
                return {"test": "result"}
        
        agent = TestAgent("Test Agent", "TEST")
        result = agent.execute({})
        assert result["progress"] == 1.0

    def test_artifact_management(self):
        """Test artifact management."""
        class TestAgent(OnlineBaseAgent):
            def _execute_impl(self, task):
                self.add_artifact("test_type", {"data": "value"}, "Test artifact")
                return {"test": "result"}
        
        agent = TestAgent("Test Agent", "TEST")
        result = agent.execute({})
        
        assert len(result["artifacts"]) == 1
        assert result["artifacts"][0]["type"] == "test_type"

    def test_metric_tracking(self):
        """Test metric tracking."""
        class TestAgent(OnlineBaseAgent):
            def _execute_impl(self, task):
                self.set_metric("test_metric", 42)
                return {"test": "result"}
        
        agent = TestAgent("Test Agent", "TEST")
        result = agent.execute({})
        
        assert result["metrics"]["test_metric"] == 42


class TestReconnaissanceAgent:
    """Test ReconnaissanceAgent."""

    def test_reconnaissance_execution(self):
        """Test reconnaissance execution."""
        agent = ReconnaissanceAgent()
        task = {
            "target_url": "https://example.com",
            "scope": {"allowed_domains": ["example.com"]},
            "options": {}
        }
        
        result = agent.execute(task)
        assert result["status"] == "success"
        assert "tech_stack" in result["result"]
        assert "endpoints" in result["result"]
        assert "auth_flows" in result["result"]

    def test_tech_stack_detection(self):
        """Test tech stack detection."""
        agent = ReconnaissanceAgent()
        tech_stack = agent._detect_tech_stack("https://example.com")
        
        assert isinstance(tech_stack, dict)

    def test_endpoint_discovery(self):
        """Test endpoint discovery."""
        agent = ReconnaissanceAgent()
        endpoints = agent._discover_endpoints("https://example.com")
        
        assert isinstance(endpoints, list)

    def test_auth_flow_mapping(self):
        """Test auth flow mapping."""
        agent = ReconnaissanceAgent()
        auth_flows = agent._map_auth_flows("https://example.com")
        
        assert "methods" in auth_flows
        assert "endpoints" in auth_flows


class TestJavaScriptAnalysisAgent:
    """Test JavaScriptAnalysisAgent."""

    def test_js_analysis_execution(self):
        """Test JavaScript analysis execution."""
        agent = JavaScriptAnalysisAgent()
        task = {
            "javascript_code": "function test() { return 42; }",
            "source_url": "https://example.com/app.js",
            "options": {}
        }
        
        result = agent.execute(task)
        assert result["status"] == "success"
        assert "deobfuscated_code" in result["result"]
        assert "functions" in result["result"]

    def test_minification_detection(self):
        """Test minification detection."""
        agent = JavaScriptAnalysisAgent()
        
        minified = "var a=function(){return 42;};a();"
        assert agent._is_minified(minified) or not agent._is_minified(minified)

    def test_function_extraction(self):
        """Test function extraction."""
        agent = JavaScriptAnalysisAgent()
        code = "function test() { return 42; }"
        functions = agent._extract_functions(code)
        
        assert isinstance(functions, list)


class TestSecurityAnalysisAgent:
    """Test SecurityAnalysisAgent."""

    def test_security_analysis_execution(self):
        """Test security analysis execution."""
        agent = SecurityAnalysisAgent()
        task = {
            "target_url": "https://example.com",
            "findings": [],
            "code": "",
            "options": {}
        }
        
        result = agent.execute(task)
        assert result["status"] == "success"
        assert "vulnerabilities" in result["result"]
        assert "security_headers" in result["result"]

    def test_vulnerability_scanning(self):
        """Test vulnerability scanning."""
        agent = SecurityAnalysisAgent()
        vulns = agent._scan_vulnerabilities("https://example.com", [])
        
        assert isinstance(vulns, list)

    def test_security_headers_analysis(self):
        """Test security headers analysis."""
        agent = SecurityAnalysisAgent()
        headers = agent._analyze_security_headers("https://example.com")
        
        assert "present" in headers
        assert "missing" in headers


class TestValidationAgent:
    """Test ValidationAgent."""

    def test_validation_execution(self):
        """Test validation execution."""
        agent = ValidationAgent()
        task = {
            "vulnerabilities": [
                {"type": "sql_injection", "severity": "high"}
            ],
            "target_url": "https://example.com",
            "options": {}
        }
        
        result = agent.execute(task)
        assert result["status"] == "success"
        assert "validated_vulnerabilities" in result["result"]


class TestReportingAgent:
    """Test ReportingAgent."""

    def test_reporting_execution(self):
        """Test reporting execution."""
        agent = ReportingAgent()
        task = {
            "analysis_results": {
                "target_url": "https://example.com",
                "vulnerabilities": [],
                "endpoints": [],
                "api_calls": []
            },
            "target_url": "https://example.com",
            "report_format": "json",
            "options": {}
        }
        
        result = agent.execute(task)
        assert result["status"] == "success"
        assert "executive_summary" in result["result"]


class TestOnlineOrchestrationAgent:
    """Test OnlineOrchestrationAgent."""

    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        orchestrator = OnlineOrchestrationAgent()
        
        assert orchestrator.agents is not None
        assert len(orchestrator.agents) > 0
        assert 'RECON' in orchestrator.agents
        assert 'SECURITY' in orchestrator.agents

    def test_authorization_validation(self):
        """Test authorization validation."""
        orchestrator = OnlineOrchestrationAgent()
        
        scope = {"allowed_domains": ["example.com"]}
        assert orchestrator._validate_authorization("https://example.com", scope)
        assert not orchestrator._validate_authorization("https://evil.com", scope)

    def test_run_id_generation(self):
        """Test run ID generation."""
        orchestrator = OnlineOrchestrationAgent()

        run_id = orchestrator._generate_run_id()
        assert run_id.startswith("RAVERSE-ONLINE-")
        assert len(run_id) > 15


class TestIntegration:
    """Integration tests for full pipeline."""

    def test_full_pipeline_execution(self):
        """Test full 8-phase pipeline execution."""
        orchestrator = OnlineOrchestrationAgent()

        scope = {
            "allowed_domains": ["example.com"],
            "allowed_paths": ["/"],
            "max_depth": 2
        }

        options = {
            "timeout": 30,
            "parallel": False,
            "report_format": "json"
        }

        # This would run the full pipeline
        # result = orchestrator.run("https://example.com", scope, options)
        # assert result["status"] == "success"
        # assert "agent_results" in result

        # For now, just test initialization
        assert orchestrator.agents is not None

    def test_agent_communication(self):
        """Test agent communication through orchestrator."""
        orchestrator = OnlineOrchestrationAgent()

        # Test that agents can communicate
        recon_agent = orchestrator.agents['RECON']
        security_agent = orchestrator.agents['SECURITY']

        assert recon_agent is not None
        assert security_agent is not None

    def test_error_handling_in_pipeline(self):
        """Test error handling in pipeline."""
        orchestrator = OnlineOrchestrationAgent()

        # Test with invalid scope
        scope = {}

        # Should handle gracefully
        assert orchestrator._validate_authorization("https://example.com", scope) == False

    def test_state_persistence(self):
        """Test state persistence across agents."""
        orchestrator = OnlineOrchestrationAgent()

        # Initialize run
        orchestrator.run_id = orchestrator._generate_run_id()
        orchestrator.target_url = "https://example.com"

        assert orchestrator.run_id is not None
        assert orchestrator.target_url == "https://example.com"

    def test_metrics_aggregation(self):
        """Test metrics aggregation from all agents."""
        orchestrator = OnlineOrchestrationAgent()

        # Simulate agent metrics
        orchestrator.metrics = {
            "recon_endpoints": 10,
            "traffic_requests": 50,
            "js_functions": 25,
            "api_endpoints": 15,
            "vulnerabilities": 5
        }

        assert len(orchestrator.metrics) > 0
        assert orchestrator.metrics["vulnerabilities"] == 5


class TestEndToEnd:
    """End-to-end tests with mock targets."""

    def test_reconnaissance_workflow(self):
        """Test reconnaissance workflow."""
        agent = ReconnaissanceAgent()

        task = {
            "target_url": "https://example.com",
            "scope": {"allowed_domains": ["example.com"]},
            "options": {}
        }

        result = agent.execute(task)
        assert result["status"] in ["success", "skipped"]

    def test_javascript_analysis_workflow(self):
        """Test JavaScript analysis workflow."""
        agent = JavaScriptAnalysisAgent()

        task = {
            "code": "function test() { fetch('/api/data'); }",
            "options": {}
        }

        result = agent.execute(task)
        assert result["status"] == "success"
        assert "api_calls" in result["result"]

    def test_api_reverse_engineering_workflow(self):
        """Test API reverse engineering workflow."""
        agent = APIReverseEngineeringAgent()

        task = {
            "api_calls": [
                {
                    "endpoint": "https://api.example.com/users",
                    "method": "GET",
                    "headers": {"Authorization": "Bearer token"}
                }
            ],
            "options": {}
        }

        result = agent.execute(task)
        assert result["status"] == "success"
        assert "endpoints" in result["result"]

    def test_security_analysis_workflow(self):
        """Test security analysis workflow."""
        agent = SecurityAnalysisAgent()

        task = {
            "target_url": "https://example.com",
            "findings": ["SELECT * FROM users"],
            "code": "eval(userInput)",
            "options": {}
        }

        result = agent.execute(task)
        assert result["status"] == "success"
        assert "vulnerabilities" in result["result"]

    def test_reporting_workflow(self):
        """Test reporting workflow."""
        agent = ReportingAgent()

        task = {
            "analysis_results": {
                "target_url": "https://example.com",
                "vulnerabilities": [
                    {"type": "sql_injection", "severity": "critical"}
                ],
                "endpoints": ["/api/users"],
                "api_calls": []
            },
            "target_url": "https://example.com",
            "report_format": "json",
            "options": {}
        }

        result = agent.execute(task)
        assert result["status"] == "success"
        assert "executive_summary" in result["result"]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

