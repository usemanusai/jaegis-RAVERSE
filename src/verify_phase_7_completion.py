#!/usr/bin/env python3
"""
Verification script for Phase 7 completion
Verifies all test files exist and compile successfully
"""

import os
import sys
import py_compile
from pathlib import Path

def verify_test_files():
    """Verify all test files exist and compile."""
    
    test_files = {
        # Unit tests
        "tests/unit/test_version_manager_agent.py": "VersionManagerAgent unit tests",
        "tests/unit/test_knowledge_base_agent.py": "KnowledgeBaseAgent unit tests",
        "tests/unit/test_quality_gate_agent.py": "QualityGateAgent unit tests",
        "tests/unit/test_governance_agent.py": "GovernanceAgent unit tests",
        "tests/unit/test_document_generator_agent.py": "DocumentGeneratorAgent unit tests",
        "tests/unit/test_rag_orchestrator_agent.py": "RAGOrchestratorAgent unit tests",
        "tests/unit/test_daa_agent.py": "DAAAgent unit tests",
        "tests/unit/test_lima_agent.py": "LIMAAgent unit tests",
        
        # Integration tests
        "tests/integration/test_database_integration.py": "Database integration tests",
        "tests/integration/test_llm_integration.py": "LLM integration tests",
        "tests/integration/test_redis_integration.py": "Redis integration tests",
        
        # E2E tests
        "tests/e2e/test_knowledge_base_workflow.py": "Knowledge base E2E tests",
        "tests/e2e/test_approval_workflow.py": "Approval workflow E2E tests",
        "tests/e2e/test_binary_analysis_workflow.py": "Binary analysis E2E tests",
    }
    
    print("=" * 80)
    print("PHASE 7 COMPLETION VERIFICATION")
    print("=" * 80)
    print()
    
    all_pass = True
    compiled_count = 0
    
    for file_path, description in test_files.items():
        if os.path.exists(file_path):
            try:
                py_compile.compile(file_path, doraise=True)
                print(f"✅ {description}")
                print(f"   File: {file_path}")
                print(f"   Status: COMPILED SUCCESSFULLY")
                compiled_count += 1
            except py_compile.PyCompileError as e:
                print(f"❌ {description}")
                print(f"   File: {file_path}")
                print(f"   Error: {e}")
                all_pass = False
        else:
            print(f"❌ {description}")
            print(f"   File: {file_path}")
            print(f"   Status: FILE NOT FOUND")
            all_pass = False
        print()
    
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total test files: {len(test_files)}")
    print(f"Compiled successfully: {compiled_count}")
    print(f"Failed: {len(test_files) - compiled_count}")
    print()
    
    if all_pass:
        print("✅ PHASE 7 VERIFICATION: PASSED")
        print()
        print("All test files exist and compile successfully!")
        print()
        print("Next steps:")
        print("1. Run: pytest tests/ -v --cov=agents --cov-report=html")
        print("2. Verify code coverage >85%")
        print("3. Fix any failing tests")
        print("4. Proceed to Phase 8: Final Validation")
        return 0
    else:
        print("❌ PHASE 7 VERIFICATION: FAILED")
        print()
        print("Some test files are missing or have compilation errors.")
        return 1

if __name__ == "__main__":
    sys.exit(verify_test_files())


