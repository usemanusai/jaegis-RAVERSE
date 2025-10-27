"""
Pytest configuration and shared fixtures
Date: October 25, 2025

Provides shared fixtures for all test modules including structlog configuration.
"""

import json
import types
import builtins
import pytest
import structlog
from structlog.testing import LogCapture
from unittest.mock import Mock, PropertyMock
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from agents.orchestrator import OrchestratingAgent


@pytest.fixture(name="log_output")
def fixture_log_output():
    """Capture structlog output for testing."""
    return LogCapture()


@pytest.fixture(autouse=True)
def fixture_configure_structlog(log_output):
    """Configure structlog for testing with log capture."""
    structlog.configure(
        processors=[log_output],
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False  # Important for testing
    )


@pytest.fixture
def mock_binary_analyzer():
    """Create a properly configured mock BinaryAnalyzer."""
    analyzer = Mock()
    # Use PropertyMock for attributes to avoid AttributeError
    type(analyzer).arch = PropertyMock(return_value="x64")
    type(analyzer).binary_data = PropertyMock(return_value=b'\x90' * 1000)
    type(analyzer).file_type = PropertyMock(return_value="PE")
    type(analyzer).binary_path = PropertyMock(return_value="/path/to/binary.exe")
    type(analyzer).entry_point = PropertyMock(return_value=0x401000)

    # Mock PE object
    mock_pe = Mock()
    mock_pe.sections = []
    type(analyzer).pe = PropertyMock(return_value=mock_pe)
    type(analyzer).elf = PropertyMock(return_value=None)

    # Mock methods
    analyzer.va_to_offset = Mock(return_value=0x1000)
    analyzer.offset_to_va = Mock(return_value=0x401000)

    return analyzer


@pytest.fixture
def mock_redis_manager():
    """Create a mock Redis manager."""
    redis = Mock()
    redis.get = Mock(return_value=None)
    redis.set = Mock(return_value=True)
    redis.delete = Mock(return_value=True)
    redis.flushdb = Mock(return_value=True)
    redis.clear = Mock(return_value=True)
    return redis


@pytest.fixture
def mock_db_manager():
    """Create a mock Database manager."""
    db = Mock()
    db.execute_query = Mock(return_value=None)
    db.fetch_one = Mock(return_value=None)
    db.get_connection = Mock()
    return db


@pytest.fixture
def sample_disassembly_text():
    return "compare_addr: 0x401234, jump_addr: 0x401240, opcode: 74"


@pytest.fixture
def mock_openrouter_response():
    def _response(compare="0x401234", jump="0x401240", opcode="74"):
        return {
            "choices": [
                {"message": {"content": f"compare_addr: {compare}, jump_addr: {jump}, opcode: {opcode}"}}
            ]
        }
    return _response


@pytest.fixture
def temp_binary(tmp_path):
    # Create a 1KB temp binary file
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x00" * 1024)
    return str(p)


@pytest.fixture
def orchestrator_stub(monkeypatch):
    # Create a minimal OA that won't actually call network
    oa = OrchestratingAgent(openrouter_api_key="test-key")
    def fake_call_openrouter(prompt, max_retries=3, retry_delay=5):
        return {"choices": [{"message": {"content": "compare_addr: 0x0, jump_addr: 0x0, opcode: 00"}}]}
    monkeypatch.setattr(oa, "call_openrouter", fake_call_openrouter)
    return oa

