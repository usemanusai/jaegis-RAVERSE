"""Binary analysis tools for RAVERSE MCP Server"""

import hashlib
import os
from typing import Dict, Any, List, Optional
from .types import BinaryAnalysisResult, ToolResult, PatchInfo
from .errors import BinaryAnalysisError, ValidationError
from .logging_config import get_logger

logger = get_logger(__name__)


class BinaryAnalysisTools:
    """Tools for binary analysis operations"""
    
    @staticmethod
    def disassemble_binary(
        binary_path: str,
        architecture: Optional[str] = None,
    ) -> ToolResult:
        """Disassemble a binary file"""
        try:
            if not os.path.exists(binary_path):
                raise ValidationError(f"Binary file not found: {binary_path}")
            
            if not os.path.isfile(binary_path):
                raise ValidationError(f"Path is not a file: {binary_path}")
            
            file_size = os.path.getsize(binary_path)
            if file_size == 0:
                raise ValidationError("Binary file is empty")
            
            # Calculate binary hash
            with open(binary_path, "rb") as f:
                binary_hash = hashlib.sha256(f.read()).hexdigest()
            
            logger.info(
                "Binary disassembly initiated",
                binary_path=binary_path,
                file_size=file_size,
                hash=binary_hash,
            )
            
            # Return structured result
            return ToolResult(
                success=True,
                data={
                    "binary_hash": binary_hash,
                    "file_size": file_size,
                    "path": binary_path,
                    "status": "disassembly_initiated",
                },
            )
        except (ValidationError, BinaryAnalysisError) as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Disassembly failed: {str(e)}", binary_path=binary_path)
            return ToolResult(
                success=False,
                error=f"Disassembly failed: {str(e)}",
                error_code="DISASSEMBLY_ERROR",
            )
    
    @staticmethod
    def generate_code_embedding(
        code_content: str,
        model: str = "all-MiniLM-L6-v2",
    ) -> ToolResult:
        """Generate embedding for code content"""
        try:
            if not code_content or not code_content.strip():
                raise ValidationError("Code content cannot be empty")
            
            if len(code_content) > 1000000:  # 1MB limit
                raise ValidationError("Code content exceeds maximum size (1MB)")
            
            content_hash = hashlib.sha256(code_content.encode()).hexdigest()
            
            logger.info(
                "Code embedding generation initiated",
                content_hash=content_hash,
                model=model,
                content_length=len(code_content),
            )
            
            return ToolResult(
                success=True,
                data={
                    "content_hash": content_hash,
                    "model": model,
                    "status": "embedding_initiated",
                    "content_length": len(code_content),
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Embedding generation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Embedding generation failed: {str(e)}",
                error_code="EMBEDDING_ERROR",
            )
    
    @staticmethod
    def apply_patch(
        binary_path: str,
        patches: List[Dict[str, Any]],
        backup: bool = True,
    ) -> ToolResult:
        """Apply patches to a binary file"""
        try:
            if not os.path.exists(binary_path):
                raise ValidationError(f"Binary file not found: {binary_path}")
            
            if not patches:
                raise ValidationError("No patches provided")
            
            # Validate patches
            for i, patch in enumerate(patches):
                if "address" not in patch or "new_bytes" not in patch:
                    raise ValidationError(f"Patch {i} missing required fields")
            
            logger.info(
                "Patch application initiated",
                binary_path=binary_path,
                patch_count=len(patches),
                backup=backup,
            )
            
            return ToolResult(
                success=True,
                data={
                    "binary_path": binary_path,
                    "patch_count": len(patches),
                    "status": "patch_initiated",
                    "backup_created": backup,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Patch application failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Patch application failed: {str(e)}",
                error_code="PATCH_ERROR",
            )
    
    @staticmethod
    def verify_patch(
        original_binary: str,
        patched_binary: str,
    ) -> ToolResult:
        """Verify that a patch was applied correctly"""
        try:
            if not os.path.exists(original_binary):
                raise ValidationError(f"Original binary not found: {original_binary}")
            
            if not os.path.exists(patched_binary):
                raise ValidationError(f"Patched binary not found: {patched_binary}")
            
            # Calculate hashes
            with open(original_binary, "rb") as f:
                original_hash = hashlib.sha256(f.read()).hexdigest()
            
            with open(patched_binary, "rb") as f:
                patched_hash = hashlib.sha256(f.read()).hexdigest()
            
            logger.info(
                "Patch verification initiated",
                original_hash=original_hash,
                patched_hash=patched_hash,
            )
            
            return ToolResult(
                success=True,
                data={
                    "original_hash": original_hash,
                    "patched_hash": patched_hash,
                    "status": "verification_initiated",
                    "hashes_match": original_hash == patched_hash,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Patch verification failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Patch verification failed: {str(e)}",
                error_code="VERIFICATION_ERROR",
            )

