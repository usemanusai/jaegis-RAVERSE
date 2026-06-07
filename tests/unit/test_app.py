import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app import app
import app as app_module

# Override TestClient to properly catch exceptions for our custom exception handler test.
# FastApi TestClient by default raises server exceptions if we don't set raise_server_exceptions=False.
client = TestClient(app, raise_server_exceptions=False)

def test_analyze_binary_unhandled_exception():
    """Test the unhandled exception handler in the analyze_binary endpoint."""
    app_module._initialized = True
    with patch("app.os.path.exists", return_value=True):
        with patch("app._orchestrator") as mock_orch:
            # Mock the orchestrator to raise an exception
            mock_orch.run.side_effect = Exception("Test unexpected error analyze")

            response = client.post(
                "/api/v1/analyze",
                json={"binary_path": "/fake/path.exe"}
            )

            # Since the endpoint wraps Exception in HTTPException(status_code=500), we should get a 500 response
            assert response.status_code == 500
            assert "Test unexpected error analyze" in response.json()["detail"]

def test_upload_and_analyze_unhandled_exception():
    """Test the unhandled exception handler in the upload_and_analyze endpoint."""
    app_module._initialized = True
    with patch("app._orchestrator") as mock_orch:
        # Mock the orchestrator to raise an exception
        mock_orch.run.side_effect = Exception("Test unexpected error upload")

        response = client.post(
            "/api/v1/upload-and-analyze",
            files={"file": ("test.bin", b"fake binary data")}
        )

        # Similar wrapping happens here
        assert response.status_code == 500
        assert "Test unexpected error upload" in response.json()["detail"]

def test_general_exception_handler():
    """Test the global general_exception_handler that catches Exception on arbitrary routes."""
    app_module._initialized = True

    from fastapi import APIRouter
    router = APIRouter()
    @router.get("/api/v1/trigger_error")
    async def trigger_error():
        # Raise an arbitrary Exception
        raise Exception("Triggering general exception")

    # Include temporary router for testing the exception handler
    app.include_router(router)

    response = client.get("/api/v1/trigger_error")

    # The global handler should catch this and return a 500 with {"detail": "Internal server error"}
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
