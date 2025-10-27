"""NLP and validation tools for RAVERSE MCP Server"""

from typing import Dict, Any, List, Optional
from .types import ToolResult
from .errors import ValidationError
from .logging_config import get_logger

logger = get_logger(__name__)


class NLPValidationTools:
    """NLP and validation tools (Natural Language Interface, PoC Validation)"""
    
    @staticmethod
    def natural_language_interface(
        command: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """Process natural language commands and route to appropriate tools"""
        try:
            if not command or not command.strip():
                raise ValidationError("Command cannot be empty")
            
            logger.info(
                "Natural language command processing initiated",
                command_length=len(command),
            )
            
            # Intent recognition and entity extraction
            intent = "analyze"  # Placeholder for NLP processing
            entities = {}  # Placeholder for entity extraction
            
            return ToolResult(
                success=True,
                data={
                    "status": "nlp_command_processed",
                    "intent": intent,
                    "entities": entities,
                    "command": command,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Natural language processing failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Natural language processing failed: {str(e)}",
                error_code="NLP_ERROR",
            )
    
    @staticmethod
    def poc_validation(
        vulnerability_finding: Dict[str, Any],
        generate_poc: bool = True,
        execute_poc: bool = False,
    ) -> ToolResult:
        """Validate vulnerabilities with proof-of-concept"""
        try:
            if not vulnerability_finding:
                raise ValidationError("Vulnerability finding cannot be empty")
            
            if "vulnerability_type" not in vulnerability_finding:
                raise ValidationError("Vulnerability type required in finding")
            
            logger.info(
                "PoC validation initiated",
                vulnerability_type=vulnerability_finding.get("vulnerability_type"),
                generate_poc=generate_poc,
                execute_poc=execute_poc,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "poc_validation_initiated",
                    "vulnerability_type": vulnerability_finding.get("vulnerability_type"),
                    "generate_poc": generate_poc,
                    "execute_poc": execute_poc,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"PoC validation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"PoC validation failed: {str(e)}",
                error_code="POC_VALIDATION_ERROR",
            )

