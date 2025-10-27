"""Tests for RAVERSE MCP Server tools"""

import pytest
import tempfile
import os
from jaegis_raverse_mcp_server.tools_binary_analysis import BinaryAnalysisTools
from jaegis_raverse_mcp_server.tools_web_analysis import WebAnalysisTools
from jaegis_raverse_mcp_server.errors import ValidationError


class TestBinaryAnalysisTools:
    """Test binary analysis tools"""
    
    def test_disassemble_binary_missing_file(self):
        """Test disassemble with missing file"""
        result = BinaryAnalysisTools.disassemble_binary("/nonexistent/file")
        assert result.success is False
        assert "not found" in result.error.lower()
    
    def test_disassemble_binary_valid_file(self):
        """Test disassemble with valid file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test binary content")
            f.flush()
            
            try:
                result = BinaryAnalysisTools.disassemble_binary(f.name)
                assert result.success is True
                assert result.data is not None
                assert "binary_hash" in result.data
                assert "file_size" in result.data
            finally:
                os.unlink(f.name)
    
    def test_generate_code_embedding_empty_content(self):
        """Test embedding with empty content"""
        result = BinaryAnalysisTools.generate_code_embedding("")
        assert result.success is False
        assert "empty" in result.error.lower()
    
    def test_generate_code_embedding_valid_content(self):
        """Test embedding with valid content"""
        result = BinaryAnalysisTools.generate_code_embedding("int main() { return 0; }")
        assert result.success is True
        assert result.data is not None
        assert "content_hash" in result.data
    
    def test_apply_patch_missing_file(self):
        """Test patch with missing file"""
        result = BinaryAnalysisTools.apply_patch("/nonexistent/file", [])
        assert result.success is False
    
    def test_apply_patch_empty_patches(self):
        """Test patch with empty patches"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            f.flush()
            
            try:
                result = BinaryAnalysisTools.apply_patch(f.name, [])
                assert result.success is False
                assert "no patches" in result.error.lower()
            finally:
                os.unlink(f.name)
    
    def test_verify_patch_missing_files(self):
        """Test verify with missing files"""
        result = BinaryAnalysisTools.verify_patch("/nonexistent/1", "/nonexistent/2")
        assert result.success is False


class TestWebAnalysisTools:
    """Test web analysis tools"""
    
    def test_reconnaissance_empty_url(self):
        """Test reconnaissance with empty URL"""
        result = WebAnalysisTools.reconnaissance("")
        assert result.success is False
        assert "empty" in result.error.lower()
    
    def test_reconnaissance_invalid_url(self):
        """Test reconnaissance with invalid URL"""
        result = WebAnalysisTools.reconnaissance("not a url")
        assert result.success is False
        assert "invalid" in result.error.lower()
    
    def test_reconnaissance_valid_url(self):
        """Test reconnaissance with valid URL"""
        result = WebAnalysisTools.reconnaissance("https://example.com")
        assert result.success is True
        assert result.data is not None
        assert "target_url" in result.data
    
    def test_analyze_javascript_empty_code(self):
        """Test JS analysis with empty code"""
        result = WebAnalysisTools.analyze_javascript("")
        assert result.success is False
        assert "empty" in result.error.lower()
    
    def test_analyze_javascript_valid_code(self):
        """Test JS analysis with valid code"""
        js_code = "fetch('/api/users').then(r => r.json())"
        result = WebAnalysisTools.analyze_javascript(js_code)
        assert result.success is True
        assert result.data is not None
    
    def test_reverse_engineer_api_empty_data(self):
        """Test API reverse engineering with empty data"""
        result = WebAnalysisTools.reverse_engineer_api({})
        assert result.success is False
    
    def test_reverse_engineer_api_valid_data(self):
        """Test API reverse engineering with valid data"""
        traffic_data = {"entries": [{"method": "GET", "path": "/api/users"}]}
        result = WebAnalysisTools.reverse_engineer_api(traffic_data)
        assert result.success is True
    
    def test_analyze_wasm_empty_data(self):
        """Test WASM analysis with empty data"""
        result = WebAnalysisTools.analyze_wasm(b"")
        assert result.success is False
    
    def test_analyze_wasm_invalid_magic(self):
        """Test WASM analysis with invalid magic number"""
        result = WebAnalysisTools.analyze_wasm(b"invalid")
        assert result.success is False
        assert "magic" in result.error.lower()
    
    def test_analyze_wasm_valid_magic(self):
        """Test WASM analysis with valid magic number"""
        result = WebAnalysisTools.analyze_wasm(b"\x00asm\x01\x00\x00\x00")
        assert result.success is True
    
    def test_security_analysis_empty_data(self):
        """Test security analysis with empty data"""
        result = WebAnalysisTools.security_analysis({})
        assert result.success is False
    
    def test_security_analysis_valid_data(self):
        """Test security analysis with valid data"""
        analysis_data = {"headers": {}, "endpoints": []}
        result = WebAnalysisTools.security_analysis(analysis_data)
        assert result.success is True


class TestErrorHandling:
    """Test error handling"""
    
    def test_validation_error_to_dict(self):
        """Test ValidationError conversion to dict"""
        error = ValidationError("Test error", {"key": "value"})
        error_dict = error.to_dict()
        assert error_dict["error"] == "VALIDATION_ERROR"
        assert error_dict["message"] == "Test error"
        assert error_dict["details"]["key"] == "value"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

