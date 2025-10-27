"""Main MCP Server implementation for RAVERSE"""

import sys
import asyncio
from typing import Any, Dict, Optional
from .config import get_config, MCPServerConfig
from .logging_config import setup_logging, get_logger
from .database import DatabaseManager
from .cache import CacheManager
from .tools_binary_analysis import BinaryAnalysisTools
from .tools_knowledge_base import KnowledgeBaseTools
from .tools_web_analysis import WebAnalysisTools
from .tools_infrastructure import InfrastructureTools
from .tools_analysis_advanced import AdvancedAnalysisTools
from .tools_management import ManagementTools
from .tools_utilities import UtilityTools
from .tools_system import SystemTools
from .tools_nlp_validation import NLPValidationTools
from .errors import RAVERSEMCPError

logger = get_logger(__name__)


class MCPServer:
    """RAVERSE MCP Server implementation"""
    
    def __init__(self, config: Optional[MCPServerConfig] = None):
        self.config = config or get_config()
        self.db_manager: Optional[DatabaseManager] = None
        self.cache_manager: Optional[CacheManager] = None
        self.binary_tools: Optional[BinaryAnalysisTools] = None
        self.kb_tools: Optional[KnowledgeBaseTools] = None
        self.web_tools: Optional[WebAnalysisTools] = None
        self.infra_tools: Optional[InfrastructureTools] = None
        self.advanced_tools: Optional[AdvancedAnalysisTools] = None
        self.management_tools: Optional[ManagementTools] = None
        self.utility_tools: Optional[UtilityTools] = None
        self.system_tools: Optional[SystemTools] = None
        self.nlp_tools: Optional[NLPValidationTools] = None

        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize server components"""
        try:
            logger.info(
                "Initializing RAVERSE MCP Server",
                version=self.config.server_version,
                log_level=self.config.log_level,
            )

            # Initialize database
            if self.config.enable_infrastructure:
                self.db_manager = DatabaseManager(self.config)
                self.cache_manager = CacheManager(self.config)

            # Initialize tool modules
            if self.config.enable_binary_analysis:
                self.binary_tools = BinaryAnalysisTools()

            if self.config.enable_knowledge_base and self.db_manager and self.cache_manager:
                self.kb_tools = KnowledgeBaseTools(self.db_manager, self.cache_manager)

            if self.config.enable_web_analysis:
                self.web_tools = WebAnalysisTools()

            if self.config.enable_infrastructure and self.db_manager and self.cache_manager:
                self.infra_tools = InfrastructureTools(self.db_manager, self.cache_manager)

            # Initialize advanced analysis tools
            self.advanced_tools = AdvancedAnalysisTools()

            # Initialize management tools
            self.management_tools = ManagementTools()

            # Initialize utility tools
            self.utility_tools = UtilityTools()

            # Initialize system tools
            self.system_tools = SystemTools()

            # Initialize NLP and validation tools
            self.nlp_tools = NLPValidationTools()

            logger.info("RAVERSE MCP Server initialized successfully with all 35 tools")
        except Exception as e:
            logger.error(f"Server initialization failed: {str(e)}")
            raise
    
    async def handle_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Handle a tool call"""
        try:
            logger.info(f"Tool call received: {tool_name}")
            
            # Binary Analysis Tools
            if tool_name == "disassemble_binary" and self.binary_tools:
                return self.binary_tools.disassemble_binary(
                    arguments.get("binary_path"),
                    arguments.get("architecture"),
                ).dict()
            
            elif tool_name == "generate_code_embedding" and self.binary_tools:
                return self.binary_tools.generate_code_embedding(
                    arguments.get("code_content"),
                    arguments.get("model", "all-MiniLM-L6-v2"),
                ).dict()
            
            elif tool_name == "apply_patch" and self.binary_tools:
                return self.binary_tools.apply_patch(
                    arguments.get("binary_path"),
                    arguments.get("patches", []),
                    arguments.get("backup", True),
                ).dict()
            
            elif tool_name == "verify_patch" and self.binary_tools:
                return self.binary_tools.verify_patch(
                    arguments.get("original_binary"),
                    arguments.get("patched_binary"),
                ).dict()
            
            # Knowledge Base Tools
            elif tool_name == "ingest_content" and self.kb_tools:
                return self.kb_tools.ingest_content(
                    arguments.get("content"),
                    arguments.get("metadata"),
                ).dict()
            
            elif tool_name == "search_knowledge_base" and self.kb_tools:
                return self.kb_tools.search_knowledge_base(
                    arguments.get("query"),
                    arguments.get("limit", 5),
                    arguments.get("threshold", 0.7),
                ).dict()
            
            elif tool_name == "retrieve_entry" and self.kb_tools:
                return self.kb_tools.retrieve_entry(
                    arguments.get("entry_id"),
                ).dict()
            
            elif tool_name == "delete_entry" and self.kb_tools:
                return self.kb_tools.delete_entry(
                    arguments.get("entry_id"),
                ).dict()
            
            # Web Analysis Tools
            elif tool_name == "reconnaissance" and self.web_tools:
                return self.web_tools.reconnaissance(
                    arguments.get("target_url"),
                ).dict()
            
            elif tool_name == "analyze_javascript" and self.web_tools:
                return self.web_tools.analyze_javascript(
                    arguments.get("js_code"),
                    arguments.get("deobfuscate", True),
                ).dict()
            
            elif tool_name == "reverse_engineer_api" and self.web_tools:
                return self.web_tools.reverse_engineer_api(
                    arguments.get("traffic_data", {}),
                    arguments.get("js_analysis"),
                ).dict()
            
            elif tool_name == "analyze_wasm" and self.web_tools:
                return self.web_tools.analyze_wasm(
                    arguments.get("wasm_data", b""),
                ).dict()
            
            elif tool_name == "security_analysis" and self.web_tools:
                return self.web_tools.security_analysis(
                    arguments.get("analysis_data", {}),
                    arguments.get("check_headers", True),
                    arguments.get("check_cves", True),
                ).dict()
            
            # Infrastructure Tools
            elif tool_name == "database_query" and self.infra_tools:
                return self.infra_tools.database_query(
                    arguments.get("query"),
                    arguments.get("params"),
                ).dict()
            
            elif tool_name == "cache_operation" and self.infra_tools:
                return self.infra_tools.cache_operation(
                    arguments.get("operation"),
                    arguments.get("key"),
                    arguments.get("value"),
                    arguments.get("ttl"),
                ).dict()
            
            elif tool_name == "publish_message" and self.infra_tools:
                return self.infra_tools.publish_message(
                    arguments.get("channel"),
                    arguments.get("message", {}),
                ).dict()
            
            elif tool_name == "fetch_content" and self.infra_tools:
                return self.infra_tools.fetch_content(
                    arguments.get("url"),
                    arguments.get("timeout", 30),
                    arguments.get("retries", 3),
                ).dict()
            
            elif tool_name == "record_metric" and self.infra_tools:
                return self.infra_tools.record_metric(
                    arguments.get("metric_name"),
                    arguments.get("value"),
                    arguments.get("labels"),
                ).dict()

            # Advanced Analysis Tools
            elif tool_name == "logic_identification" and self.advanced_tools:
                return self.advanced_tools.logic_identification(
                    arguments.get("disassembly_data", {}),
                    arguments.get("analyze_control_flow", True),
                    arguments.get("analyze_data_flow", True),
                ).dict()

            elif tool_name == "traffic_interception" and self.advanced_tools:
                return self.advanced_tools.traffic_interception(
                    arguments.get("target_url"),
                    arguments.get("ssl_intercept", True),
                    arguments.get("capture_duration", 60),
                ).dict()

            elif tool_name == "generate_report" and self.advanced_tools:
                return self.advanced_tools.generate_report(
                    arguments.get("analysis_results", {}),
                    arguments.get("format", "json"),
                    arguments.get("include_summary", True),
                ).dict()

            elif tool_name == "rag_orchestration" and self.advanced_tools:
                return self.advanced_tools.rag_orchestration(
                    arguments.get("query"),
                    arguments.get("context_limit", 5),
                    arguments.get("threshold", 0.7),
                ).dict()

            elif tool_name == "deep_research" and self.advanced_tools:
                return self.advanced_tools.deep_research(
                    arguments.get("topic"),
                    arguments.get("max_sources", 10),
                    arguments.get("synthesize", True),
                ).dict()

            # Management Tools
            elif tool_name == "version_management" and self.management_tools:
                return self.management_tools.version_management(
                    arguments.get("component_name"),
                    arguments.get("version"),
                    arguments.get("check_vulnerabilities", True),
                ).dict()

            elif tool_name == "quality_gate" and self.management_tools:
                return self.management_tools.quality_gate(
                    arguments.get("analysis_results", {}),
                    arguments.get("metrics", {}),
                    arguments.get("threshold", 0.8),
                ).dict()

            elif tool_name == "governance_check" and self.management_tools:
                return self.management_tools.governance_check(
                    arguments.get("action"),
                    arguments.get("context", {}),
                    arguments.get("require_approval", False),
                ).dict()

            elif tool_name == "generate_document" and self.management_tools:
                return self.management_tools.generate_document(
                    arguments.get("document_type"),
                    arguments.get("data", {}),
                    arguments.get("format", "markdown"),
                ).dict()

            # Utility Tools
            elif tool_name == "url_frontier_operation" and self.utility_tools:
                return self.utility_tools.url_frontier_operation(
                    arguments.get("operation"),
                    arguments.get("url"),
                    arguments.get("priority", 5),
                ).dict()

            elif tool_name == "api_pattern_matcher" and self.utility_tools:
                return self.utility_tools.api_pattern_matcher(
                    arguments.get("traffic_data", {}),
                    arguments.get("pattern_type", "rest"),
                ).dict()

            elif tool_name == "response_classifier" and self.utility_tools:
                return self.utility_tools.response_classifier(
                    arguments.get("response_data", {}),
                    arguments.get("infer_schema", True),
                ).dict()

            elif tool_name == "websocket_analyzer" and self.utility_tools:
                return self.utility_tools.websocket_analyzer(
                    arguments.get("websocket_data", {}),
                    arguments.get("analyze_handshake", True),
                ).dict()

            elif tool_name == "crawl_scheduler" and self.utility_tools:
                return self.utility_tools.crawl_scheduler(
                    arguments.get("operation"),
                    arguments.get("job_data"),
                    arguments.get("priority", 5),
                ).dict()

            # System Tools
            elif tool_name == "metrics_collector" and self.system_tools:
                return self.system_tools.metrics_collector(
                    arguments.get("metric_type"),
                    arguments.get("metric_name"),
                    arguments.get("value"),
                    arguments.get("labels"),
                ).dict()

            elif tool_name == "multi_level_cache" and self.system_tools:
                return self.system_tools.multi_level_cache(
                    arguments.get("operation"),
                    arguments.get("key"),
                    arguments.get("value"),
                    arguments.get("ttl", 3600),
                ).dict()

            elif tool_name == "configuration_service" and self.system_tools:
                return self.system_tools.configuration_service(
                    arguments.get("operation"),
                    arguments.get("key"),
                    arguments.get("value"),
                ).dict()

            elif tool_name == "llm_interface" and self.system_tools:
                return self.system_tools.llm_interface(
                    arguments.get("prompt"),
                    arguments.get("model", "gpt-4"),
                    arguments.get("max_tokens", 2048),
                    arguments.get("temperature", 0.7),
                ).dict()

            # NLP and Validation Tools
            elif tool_name == "natural_language_interface" and self.nlp_tools:
                return self.nlp_tools.natural_language_interface(
                    arguments.get("command"),
                    arguments.get("context"),
                ).dict()

            elif tool_name == "poc_validation" and self.nlp_tools:
                return self.nlp_tools.poc_validation(
                    arguments.get("vulnerability_finding", {}),
                    arguments.get("generate_poc", True),
                    arguments.get("execute_poc", False),
                ).dict()

            else:
                return {
                    "success": False,
                    "error": f"Unknown tool: {tool_name}",
                    "error_code": "UNKNOWN_TOOL",
                }
        
        except RAVERSEMCPError as e:
            logger.error(f"Tool execution error: {str(e)}")
            return e.to_dict()
        except Exception as e:
            logger.error(f"Unexpected error in tool call: {str(e)}")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "error_code": "INTERNAL_ERROR",
            }
    
    def shutdown(self) -> None:
        """Shutdown server and cleanup resources"""
        logger.info("Shutting down RAVERSE MCP Server")
        
        if self.db_manager:
            self.db_manager.close()
        
        if self.cache_manager:
            self.cache_manager.close()
        
        logger.info("RAVERSE MCP Server shutdown complete")


def main() -> int:
    """Main entry point"""
    try:
        config = get_config()
        setup_logging(config.log_level)
        
        logger.info(f"Starting RAVERSE MCP Server v{config.server_version}")
        
        server = MCPServer(config)
        
        # Keep server running
        try:
            asyncio.run(asyncio.sleep(float('inf')))
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
        finally:
            server.shutdown()
        
        return 0
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

