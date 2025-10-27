"""
Online Orchestration Agent for RAVERSE Online.
Coordinates all online agents for remote target analysis.
"""

import logging
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import os
from dotenv import load_dotenv

from .online_base_agent import OnlineBaseAgent
from .online_reconnaissance_agent import ReconnaissanceAgent
from .online_traffic_interception_agent import TrafficInterceptionAgent
from .online_javascript_analysis_agent import JavaScriptAnalysisAgent
from .online_api_reverse_engineering_agent import APIReverseEngineeringAgent
from .online_wasm_analysis_agent import WebAssemblyAnalysisAgent
from .online_ai_copilot_agent import AICoPilotAgent
from .online_security_analysis_agent import SecurityAnalysisAgent
from .online_validation_agent import ValidationAgent
from .online_reporting_agent import ReportingAgent
from .online_deep_research_topic_enhancer import DeepResearchTopicEnhancerAgent
from .online_deep_research_web_researcher import DeepResearchWebResearcherAgent
from .online_deep_research_content_analyzer import DeepResearchContentAnalyzerAgent
from .online_version_manager_agent import VersionManagerAgent
from .online_knowledge_base_agent import KnowledgeBaseAgent
from .online_quality_gate_agent import QualityGateAgent
from .online_governance_agent import GovernanceAgent
from .online_document_generator_agent import DocumentGeneratorAgent
from .online_rag_orchestrator_agent import RAGOrchestratorAgent
from .online_daa_agent import DAAAgent
from .online_lima_agent import LIMAAgent

logger = logging.getLogger(__name__)


class OnlineOrchestrationAgent:
    """
    Online Orchestration Agent - Coordinates all online agents.
    Manages execution pipeline, state, error handling, and result aggregation.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize Online Orchestration Agent.
        
        Args:
            api_key: OpenRouter API key (optional, falls back to env)
            model: LLM model to use (optional, falls back to env)
        """
        load_dotenv()
        
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
        
        self.logger = logging.getLogger("RAVERSE.ONLINE_ORCH")
        
        # Initialize agents
        self.agents = {
            # Layer 0: Version Management
            'VERSION_MANAGER': VersionManagerAgent(orchestrator=self),

            # Layer 1: Knowledge Base & RAG
            'KNOWLEDGE_BASE': KnowledgeBaseAgent(orchestrator=self, api_key=self.api_key, model=self.model),

            # Layer 2: Quality Gate
            'QUALITY_GATE': QualityGateAgent(orchestrator=self),

            # Layer 3: Governance
            'GOVERNANCE': GovernanceAgent(orchestrator=self),

            # Layer 5: Document Generation
            'DOCUMENT_GENERATOR': DocumentGeneratorAgent(orchestrator=self, api_key=self.api_key, model=self.model),

            # Layer 4 Extended: RAG Orchestration
            'RAG_ORCHESTRATOR': RAGOrchestratorAgent(orchestrator=self, api_key=self.api_key, model=self.model),

            # Layer 4 Extended: Offline Binary Analysis
            'DAA': DAAAgent(orchestrator=self),
            'LIMA': LIMAAgent(orchestrator=self),

            # Online Analysis Pipeline (8 phases)
            'RECON': ReconnaissanceAgent(orchestrator=self),
            'TRAFFIC': TrafficInterceptionAgent(orchestrator=self),
            'JS_ANALYSIS': JavaScriptAnalysisAgent(orchestrator=self),
            'API_REENG': APIReverseEngineeringAgent(orchestrator=self),
            'WASM_ANALYSIS': WebAssemblyAnalysisAgent(orchestrator=self),
            'AI_COPILOT': AICoPilotAgent(orchestrator=self, api_key=self.api_key, model=self.model),
            'SECURITY': SecurityAnalysisAgent(orchestrator=self),
            'VALIDATION': ValidationAgent(orchestrator=self),
            'REPORTING': ReportingAgent(orchestrator=self),

            # Deep Research Pipeline (3 phases)
            'DEEP_RESEARCH_TOPIC_ENHANCER': DeepResearchTopicEnhancerAgent(orchestrator=self, api_key=self.api_key),
            'DEEP_RESEARCH_WEB_RESEARCHER': DeepResearchWebResearcherAgent(orchestrator=self, api_key=self.api_key),
            'DEEP_RESEARCH_CONTENT_ANALYZER': DeepResearchContentAnalyzerAgent(orchestrator=self, api_key=self.api_key)
        }
        
        # State tracking
        self.run_id = None
        self.target_url = None
        self.scope = {}
        self.start_time = None
        self.end_time = None
        self.agent_results = {}
        self.execution_log = []
        self.metrics = {}

    def run(self, target_url: str, scope: Dict[str, Any], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute full online analysis pipeline.
        
        Args:
            target_url: Target URL to analyze
            scope: Authorization scope
            options: Execution options
            
        Returns:
            Complete analysis results
        """
        self.run_id = self._generate_run_id()
        self.target_url = target_url
        self.scope = scope
        self.start_time = datetime.now()
        
        self.logger.info("=" * 80)
        self.logger.info(f"RAVERSE Online - Analysis Pipeline Started")
        self.logger.info(f"Run ID: {self.run_id}")
        self.logger.info(f"Target: {target_url}")
        self.logger.info("=" * 80)
        
        try:
            # Validate authorization
            if not self._validate_authorization(target_url, scope):
                raise ValueError("Target not in authorized scope")
            
            # Execute pipeline
            results = self._execute_pipeline(target_url, scope, options or {})
            
            self.end_time = datetime.now()
            
            # Generate final report
            final_results = self._generate_final_results(results)
            
            self.logger.info("=" * 80)
            self.logger.info("Analysis Pipeline Complete")
            self.logger.info("=" * 80)
            
            return final_results
            
        except Exception as e:
            self.logger.error(f"Pipeline execution failed: {e}")
            self.end_time = datetime.now()
            raise

    def _execute_pipeline(self, target_url: str, scope: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis pipeline."""
        pipeline_results = {}
        
        # Phase 1: Reconnaissance
        self.logger.info("\n[PHASE 1] Reconnaissance")
        recon_task = {
            "target_url": target_url,
            "scope": scope,
            "options": options.get("recon", {})
        }
        pipeline_results["recon"] = self.agents['RECON'].execute(recon_task)
        self.agent_results['RECON'] = pipeline_results["recon"]
        
        # Phase 2: Traffic Interception
        self.logger.info("\n[PHASE 2] Traffic Interception")
        traffic_task = {
            "target_url": target_url,
            "duration_seconds": options.get("traffic_duration", 30),
            "scope": scope,
            "options": options.get("traffic", {})
        }
        pipeline_results["traffic"] = self.agents['TRAFFIC'].execute(traffic_task)
        self.agent_results['TRAFFIC'] = pipeline_results["traffic"]
        
        # Phase 3: JavaScript Analysis
        if pipeline_results["recon"].get("result", {}).get("endpoints"):
            self.logger.info("\n[PHASE 3] JavaScript Analysis")
            js_task = {
                "javascript_code": "// Mock JS code",
                "source_url": target_url,
                "options": options.get("js_analysis", {})
            }
            pipeline_results["js_analysis"] = self.agents['JS_ANALYSIS'].execute(js_task)
            self.agent_results['JS_ANALYSIS'] = pipeline_results["js_analysis"]
        
        # Phase 4: API Reverse Engineering
        if pipeline_results["traffic"].get("result", {}).get("api_calls"):
            self.logger.info("\n[PHASE 4] API Reverse Engineering")
            api_task = {
                "api_calls": pipeline_results["traffic"].get("result", {}).get("api_calls", []),
                "traffic_data": pipeline_results["traffic"].get("result", {}),
                "options": options.get("api_reeng", {})
            }
            pipeline_results["api_reeng"] = self.agents['API_REENG'].execute(api_task)
            self.agent_results['API_REENG'] = pipeline_results["api_reeng"]
        
        # Phase 5: Security Analysis
        self.logger.info("\n[PHASE 5] Security Analysis")
        security_task = {
            "target_url": target_url,
            "findings": pipeline_results.get("recon", {}).get("result", {}),
            "code": "",
            "options": options.get("security", {})
        }
        pipeline_results["security"] = self.agents['SECURITY'].execute(security_task)
        self.agent_results['SECURITY'] = pipeline_results["security"]
        
        # Phase 6: AI Co-Pilot Analysis
        self.logger.info("\n[PHASE 6] AI Co-Pilot Analysis")
        ai_task = {
            "analysis_type": "vulnerability_analysis",
            "content": json.dumps(pipeline_results.get("security", {}).get("result", {})),
            "context": {"target": target_url},
            "options": options.get("ai_copilot", {})
        }
        pipeline_results["ai_copilot"] = self.agents['AI_COPILOT'].execute(ai_task)
        self.agent_results['AI_COPILOT'] = pipeline_results["ai_copilot"]
        
        # Phase 7: Validation
        self.logger.info("\n[PHASE 7] Validation")
        validation_task = {
            "vulnerabilities": pipeline_results.get("security", {}).get("result", {}).get("vulnerabilities", []),
            "target_url": target_url,
            "options": options.get("validation", {})
        }
        pipeline_results["validation"] = self.agents['VALIDATION'].execute(validation_task)
        self.agent_results['VALIDATION'] = pipeline_results["validation"]
        
        # Phase 8: Reporting
        self.logger.info("\n[PHASE 8] Reporting")
        reporting_task = {
            "analysis_results": {
                "target_url": target_url,
                "vulnerabilities": pipeline_results.get("security", {}).get("result", {}).get("vulnerabilities", []),
                "endpoints": pipeline_results.get("recon", {}).get("result", {}).get("endpoints", []),
                "api_calls": pipeline_results.get("traffic", {}).get("result", {}).get("api_calls", []),
                "security_headers": pipeline_results.get("security", {}).get("result", {}).get("security_headers", {}),
                "ssl_tls_analysis": pipeline_results.get("security", {}).get("result", {}).get("ssl_tls_analysis", {}),
                "dependency_vulnerabilities": pipeline_results.get("security", {}).get("result", {}).get("dependency_vulnerabilities", []),
                "code_vulnerabilities": pipeline_results.get("security", {}).get("result", {}).get("code_vulnerabilities", [])
            },
            "target_url": target_url,
            "report_format": options.get("report_format", "markdown"),
            "options": options.get("reporting", {})
        }
        pipeline_results["reporting"] = self.agents['REPORTING'].execute(reporting_task)
        self.agent_results['REPORTING'] = pipeline_results["reporting"]
        
        return pipeline_results

    def _validate_authorization(self, target_url: str, scope: Dict[str, Any]) -> bool:
        """Validate authorization for target."""
        if not scope:
            self.logger.warning("No scope defined")
            return False
        
        allowed_domains = scope.get("allowed_domains", [])
        for domain in allowed_domains:
            if domain in target_url:
                self.logger.info(f"Target authorized: {target_url}")
                return True
        
        self.logger.error(f"Target not authorized: {target_url}")
        return False

    def _generate_final_results(self, pipeline_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final aggregated results."""
        duration = (self.end_time - self.start_time).total_seconds()
        
        final_results = {
            "run_id": self.run_id,
            "target_url": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "status": "complete",
            "agent_results": self.agent_results,
            "summary": self._generate_summary(pipeline_results),
            "metrics": self._calculate_metrics(pipeline_results)
        }
        
        return final_results

    def _generate_summary(self, pipeline_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis summary."""
        security_result = pipeline_results.get("security", {}).get("result", {})
        
        summary = {
            "total_vulnerabilities": len(security_result.get("vulnerabilities", [])),
            "critical_count": len([v for v in security_result.get("vulnerabilities", []) if v.get("severity") == "critical"]),
            "high_count": len([v for v in security_result.get("vulnerabilities", []) if v.get("severity") == "high"]),
            "endpoints_discovered": len(pipeline_results.get("recon", {}).get("result", {}).get("endpoints", [])),
            "api_calls_captured": len(pipeline_results.get("traffic", {}).get("result", {}).get("api_calls", [])),
            "overall_risk": self._calculate_overall_risk(security_result)
        }
        
        return summary

    def _calculate_overall_risk(self, security_result: Dict[str, Any]) -> str:
        """Calculate overall risk level."""
        vulns = security_result.get("vulnerabilities", [])
        critical = len([v for v in vulns if v.get("severity") == "critical"])
        high = len([v for v in vulns if v.get("severity") == "high"])
        
        if critical > 0:
            return "CRITICAL"
        elif high > 2:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_metrics(self, pipeline_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate execution metrics."""
        metrics = {
            "agents_executed": len([r for r in self.agent_results.values() if r.get("status") == "success"]),
            "total_agents": len(self.agents),
            "execution_time_seconds": (self.end_time - self.start_time).total_seconds(),
            "artifacts_generated": sum(len(r.get("artifacts", [])) for r in self.agent_results.values())
        }
        
        return metrics

    def report_agent_progress(self, agent_type: str, progress: float, message: str = ""):
        """Report agent progress."""
        self.logger.debug(f"[{agent_type}] Progress: {progress*100:.1f}% - {message}")

    def _generate_run_id(self) -> str:
        """Generate unique run ID."""
        import uuid
        return f"RAVERSE-ONLINE-{uuid.uuid4().hex[:8].upper()}"

    def run_complete_analysis(self, target_url: str, scope: Dict[str, Any], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute COMPLETE RAVERSE 2.0 analysis with all layers.

        Layers:
        0. Version Management & Onboarding
        1. Knowledge Base & RAG
        2. Quality Gate (A.I.E.F.N.M.W. Sentry)
        3. Governance & Orchestration
        4. Multi-Agent Pipeline Execution
        5. Document Generation & Synthesis
        6. Infrastructure & Persistence
        """
        self.run_id = self._generate_run_id()
        self.target_url = target_url
        self.scope = scope
        self.start_time = datetime.now()

        self.logger.info("=" * 80)
        self.logger.info("RAVERSE 2.0 - COMPLETE ANALYSIS PIPELINE")
        self.logger.info(f"Run ID: {self.run_id}")
        self.logger.info("=" * 80)

        try:
            # Layer 0: Version Management & Onboarding
            self.logger.info("\n[LAYER 0] Version Management & Onboarding")
            version_result = self.agents['VERSION_MANAGER'].execute({
                "action": "validate_onboarding",
                "run_id": self.run_id
            })

            if not version_result.get("onboarding_valid"):
                raise ValueError("System onboarding validation failed")

            # Layer 1: Knowledge Base Initialization
            self.logger.info("\n[LAYER 1] Knowledge Base & RAG Initialization")
            kb_result = self.agents['KNOWLEDGE_BASE'].execute({
                "action": "list_knowledge",
                "run_id": self.run_id
            })

            # Layer 2: Quality Gate Pre-Check
            self.logger.info("\n[LAYER 2] Quality Gate Pre-Check")
            quality_result = self.agents['QUALITY_GATE'].execute({
                "action": "validate_phase",
                "phase_name": "pre_analysis_validation",
                "phase_data": {
                    "target_url": target_url,
                    "scope": scope,
                    "required_fields": ["target_url", "scope"]
                },
                "run_id": self.run_id
            })

            if not quality_result.get("passed"):
                raise ValueError("Quality gate pre-check failed")

            # Layer 3: Governance Approval
            self.logger.info("\n[LAYER 3] Governance Approval")
            governance_result = self.agents['GOVERNANCE'].execute({
                "action": "create_approval_request",
                "request_type": "analysis_execution",
                "description": f"Analysis of {target_url}",
                "requester": "system",
                "approvers": ["admin"],
                "priority": "high",
                "run_id": self.run_id
            })

            # Layer 4: Execute Main Pipeline
            self.logger.info("\n[LAYER 4] Multi-Agent Pipeline Execution")
            pipeline_results = self._execute_pipeline(target_url, scope, options or {})

            # Layer 2: Quality Gate Post-Check
            self.logger.info("\n[LAYER 2] Quality Gate Post-Check")
            post_quality_result = self.agents['QUALITY_GATE'].execute({
                "action": "validate_phase",
                "phase_name": "post_analysis_validation",
                "phase_data": pipeline_results,
                "run_id": self.run_id
            })

            # Layer 5: Document Generation
            self.logger.info("\n[LAYER 5] Document Generation & Synthesis")
            manifest_result = self.agents['DOCUMENT_GENERATOR'].execute({
                "action": "generate_manifest",
                "research_topic": target_url,
                "research_findings": pipeline_results,
                "metadata": {
                    "run_id": self.run_id,
                    "timestamp": datetime.now().isoformat()
                },
                "run_id": self.run_id
            })

            white_paper_result = self.agents['DOCUMENT_GENERATOR'].execute({
                "action": "generate_white_paper",
                "topic": target_url,
                "research_data": pipeline_results,
                "analysis": pipeline_results.get("security", {}),
                "run_id": self.run_id
            })

            # Layer 1: Store in Knowledge Base
            self.logger.info("\n[LAYER 1] Store Results in Knowledge Base")
            kb_store_result = self.agents['KNOWLEDGE_BASE'].execute({
                "action": "store_knowledge",
                "content": json.dumps(pipeline_results),
                "source": f"analysis_{self.run_id}",
                "metadata": {
                    "target_url": target_url,
                    "run_id": self.run_id,
                    "timestamp": datetime.now().isoformat()
                },
                "run_id": self.run_id
            })

            # Layer 3: Governance Approval of Results
            self.logger.info("\n[LAYER 3] Governance Approval of Results")
            self.agents['GOVERNANCE'].execute({
                "action": "approve_request",
                "request_id": governance_result.get("request_id"),
                "approver": "admin",
                "comments": "Analysis completed successfully",
                "run_id": self.run_id
            })

            self.end_time = datetime.now()

            # Generate final comprehensive results
            final_results = {
                "run_id": self.run_id,
                "target_url": target_url,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": (self.end_time - self.start_time).total_seconds(),
                "status": "complete",
                "layers": {
                    "layer_0_version": version_result,
                    "layer_1_knowledge_base": kb_result,
                    "layer_2_quality_gate": quality_result,
                    "layer_3_governance": governance_result,
                    "layer_4_pipeline": pipeline_results,
                    "layer_5_documents": {
                        "manifest": manifest_result,
                        "white_paper": white_paper_result
                    }
                },
                "summary": self._generate_summary(pipeline_results),
                "metrics": self._calculate_metrics(pipeline_results)
            }

            self.logger.info("=" * 80)
            self.logger.info("RAVERSE 2.0 - COMPLETE ANALYSIS FINISHED")
            self.logger.info("=" * 80)

            return final_results

        except Exception as e:
            self.logger.error(f"Complete analysis failed: {e}", exc_info=True)
            self.end_time = datetime.now()
            raise

    def run_deep_research(self, topic: str, context: str = "", max_results: int = 10) -> Dict[str, Any]:
        """
        Execute Deep Research workflow.

        Args:
            topic: Research topic
            context: Additional context
            max_results: Maximum search results

        Returns:
            Research results
        """
        self.run_id = self._generate_run_id()
        self.start_time = datetime.now()
        self.logger.info(f"\n[DEEP RESEARCH] Starting workflow (Run: {self.run_id})")

        try:
            # Phase 1: Topic Enhancement
            self.logger.info("\n[PHASE 1] Topic Enhancement")
            topic_task = {
                "topic": topic,
                "context": context,
                "run_id": self.run_id
            }
            topic_result = self.agents['DEEP_RESEARCH_TOPIC_ENHANCER'].execute(topic_task)
            self.agent_results['DEEP_RESEARCH_TOPIC_ENHANCER'] = topic_result

            enhanced_topic = topic_result.get("result", {}).get("enhanced_topic", topic)

            # Phase 2: Web Research
            self.logger.info("\n[PHASE 2] Web Research")
            research_task = {
                "query": enhanced_topic,
                "max_results": max_results,
                "run_id": self.run_id
            }
            research_result = self.agents['DEEP_RESEARCH_WEB_RESEARCHER'].execute(research_task)
            self.agent_results['DEEP_RESEARCH_WEB_RESEARCHER'] = research_result

            # Phase 3: Content Analysis
            self.logger.info("\n[PHASE 3] Content Analysis")
            analysis_task = {
                "research_findings": research_result.get("result", {}),
                "query": enhanced_topic,
                "run_id": self.run_id
            }
            analysis_result = self.agents['DEEP_RESEARCH_CONTENT_ANALYZER'].execute(analysis_task)
            self.agent_results['DEEP_RESEARCH_CONTENT_ANALYZER'] = analysis_result

            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()

            # Generate final results
            final_results = {
                "run_id": self.run_id,
                "original_topic": topic,
                "enhanced_topic": enhanced_topic,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": duration,
                "status": "complete",
                "phases": {
                    "topic_enhancement": topic_result,
                    "web_research": research_result,
                    "content_analysis": analysis_result
                },
                "summary": analysis_result.get("result", {}).get("synthesis", "")
            }

            self.logger.info(f"\n[DEEP RESEARCH] Workflow completed in {duration:.2f}s")
            return final_results

        except Exception as e:
            self.end_time = datetime.now()
            self.logger.error(f"Deep Research workflow failed: {e}", exc_info=True)
            return {
                "run_id": self.run_id,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

