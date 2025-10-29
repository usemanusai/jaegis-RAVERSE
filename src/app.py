"""
RAVERSE Web Application - FastAPI wrapper for RAVERSE agents
Provides REST API endpoints for binary analysis and patching
"""

import logging
import os
import json
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tempfile
from pathlib import Path

# Configure logging to stderr (required for STDIO servers)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="RAVERSE API",
    description="AI Multi-Agent Binary Patching System",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lazy initialization flag
_initialized = False
_orchestrator = None


class AnalysisRequest(BaseModel):
    """Request model for binary analysis"""
    binary_path: str
    model: Optional[str] = None
    use_database: bool = False


class AnalysisResponse(BaseModel):
    """Response model for analysis results"""
    success: bool
    message: str
    results: Optional[Dict[str, Any]] = None


def initialize_app():
    """Lazy initialization of RAVERSE components"""
    global _initialized, _orchestrator
    
    if _initialized:
        return
    
    try:
        logger.info("Initializing RAVERSE application...")
        from agents.orchestrator import OrchestratingAgent
        
        # Initialize orchestrator with database disabled by default
        _orchestrator = OrchestratingAgent(use_database=False)
        _initialized = True
        logger.info("RAVERSE application initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize RAVERSE: {e}", exc_info=True)
        _initialized = True  # Mark as initialized to prevent repeated attempts


@app.on_event("startup")
async def startup_event():
    """Initialize app on startup"""
    initialize_app()


@app.get("/")
async def root():
    """Root endpoint - health check"""
    return {
        "status": "ok",
        "service": "RAVERSE API",
        "version": "1.0.0",
        "description": "AI Multi-Agent Binary Patching System"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "initialized": _initialized,
        "service": "RAVERSE"
    }


@app.get("/api/v1/status")
async def api_status():
    """Get API status"""
    return {
        "status": "operational",
        "version": "1.0.0",
        "initialized": _initialized,
        "features": [
            "binary_analysis",
            "pattern_detection",
            "patch_generation",
            "validation"
        ]
    }


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_binary(request: AnalysisRequest):
    """
    Analyze a binary file
    
    Args:
        request: AnalysisRequest with binary_path and optional model
        
    Returns:
        AnalysisResponse with analysis results
    """
    try:
        initialize_app()
        
        if not _orchestrator:
            raise HTTPException(
                status_code=500,
                detail="RAVERSE orchestrator not initialized"
            )
        
        # Validate binary path
        if not os.path.exists(request.binary_path):
            raise HTTPException(
                status_code=404,
                detail=f"Binary file not found: {request.binary_path}"
            )
        
        logger.info(f"Starting analysis of: {request.binary_path}")
        
        # Run analysis
        result = _orchestrator.run(request.binary_path)
        
        if result:
            logger.info(f"Analysis completed successfully")
            return AnalysisResponse(
                success=result.get('success', False),
                message=result.get('message', 'Analysis completed'),
                results=result
            )
        else:
            return AnalysisResponse(
                success=False,
                message="Analysis failed",
                results=None
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/api/v1/upload-and-analyze")
async def upload_and_analyze(file: UploadFile = File(...)):
    """
    Upload and analyze a binary file
    
    Args:
        file: Binary file to analyze
        
    Returns:
        Analysis results
    """
    try:
        initialize_app()
        
        if not _orchestrator:
            raise HTTPException(
                status_code=500,
                detail="RAVERSE orchestrator not initialized"
            )
        
        # Save uploaded file to temp directory
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        
        try:
            logger.info(f"Analyzing uploaded file: {file.filename}")
            
            # Run analysis
            result = _orchestrator.run(tmp_path)
            
            if result:
                logger.info(f"Analysis of {file.filename} completed")
                return AnalysisResponse(
                    success=result.get('success', False),
                    message=result.get('message', 'Analysis completed'),
                    results=result
                )
            else:
                return AnalysisResponse(
                    success=False,
                    message="Analysis failed",
                    results=None
                )
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload analysis error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Upload analysis failed: {str(e)}"
        )


@app.get("/api/v1/info")
async def api_info():
    """Get API information"""
    return {
        "name": "RAVERSE API",
        "version": "1.0.0",
        "description": "AI Multi-Agent Binary Patching System",
        "endpoints": {
            "health": "/health",
            "status": "/api/v1/status",
            "analyze": "/api/v1/analyze",
            "upload": "/api/v1/upload-and-analyze",
            "info": "/api/v1/info"
        }
    }


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8000))
    logger.info(f"Starting RAVERSE API on port {port}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )

