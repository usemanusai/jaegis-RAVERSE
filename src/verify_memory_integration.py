#!/usr/bin/env python3
"""
Verification script for memory integration.
Tests that all agents can be imported and initialized with memory support.
"""

import sys
import json
from typing import List, Tuple

# Test imports
def test_imports() -> Tuple[bool, List[str]]:
    """Test that all agents can be imported."""
    errors = []
    
    agents_to_test = [
        ("agents.online_version_manager_agent", "VersionManagerAgent"),
        ("agents.online_knowledge_base_agent", "KnowledgeBaseAgent"),
        ("agents.online_quality_gate_agent", "QualityGateAgent"),
        ("agents.online_governance_agent", "GovernanceAgent"),
        ("agents.online_document_generator_agent", "DocumentGeneratorAgent"),
        ("agents.online_rag_orchestrator_agent", "RAGOrchestratorAgent"),
        ("agents.online_daa_agent", "DAAAgent"),
        ("agents.online_lima_agent", "LIMAAgent"),
        ("agents.online_reconnaissance_agent", "ReconnaissanceAgent"),
        ("agents.online_api_reverse_engineering_agent", "APIReverseEngineeringAgent"),
        ("agents.online_javascript_analysis_agent", "JavaScriptAnalysisAgent"),
        ("agents.online_wasm_analysis_agent", "WebAssemblyAnalysisAgent"),
        ("agents.online_security_analysis_agent", "SecurityAnalysisAgent"),
        ("agents.online_traffic_interception_agent", "TrafficInterceptionAgent"),
        ("agents.online_validation_agent", "ValidationAgent"),
        ("agents.online_reporting_agent", "ReportingAgent"),
        ("agents.online_deep_research_web_researcher", "DeepResearchWebResearcherAgent"),
        ("agents.online_deep_research_content_analyzer", "DeepResearchContentAnalyzerAgent"),
        ("agents.online_deep_research_topic_enhancer", "DeepResearchTopicEnhancerAgent"),
    ]
    
    for module_name, class_name in agents_to_test:
        try:
            module = __import__(module_name, fromlist=[class_name])
            agent_class = getattr(module, class_name)
            print(f"✅ {class_name} imported successfully")
        except Exception as e:
            error_msg = f"❌ {class_name}: {str(e)}"
            errors.append(error_msg)
            print(error_msg)
    
    return len(errors) == 0, errors


def test_memory_initialization() -> Tuple[bool, List[str]]:
    """Test that agents can be initialized with memory."""
    errors = []
    
    try:
        from agents.online_version_manager_agent import VersionManagerAgent
        
        # Test without memory
        agent1 = VersionManagerAgent(orchestrator=None)
        if agent1.has_memory_enabled():
            errors.append("❌ Agent should not have memory enabled by default")
        else:
            print("✅ Agent initialized without memory (default)")
        
        # Test with memory
        agent2 = VersionManagerAgent(
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        if not agent2.has_memory_enabled():
            errors.append("❌ Agent should have memory enabled when specified")
        else:
            print("✅ Agent initialized with sliding_window memory")
        
        # Test memory operations
        agent2.add_to_memory("test input", "test output")
        context = agent2.get_memory_context("test query")
        if not isinstance(context, str):
            errors.append("❌ Memory context should return string")
        else:
            print("✅ Memory operations working correctly")
            
    except Exception as e:
        errors.append(f"❌ Memory initialization test failed: {str(e)}")
    
    return len(errors) == 0, errors


def test_memory_config() -> Tuple[bool, List[str]]:
    """Test memory configuration."""
    errors = []
    
    try:
        from config.agent_memory_config import AGENT_MEMORY_CONFIG, MEMORY_PRESETS
        
        # Check presets
        presets = ["none", "light", "medium", "heavy"]
        for preset in presets:
            if preset not in MEMORY_PRESETS:
                errors.append(f"❌ Missing preset: {preset}")
            else:
                print(f"✅ Preset '{preset}' configured")
        
        # Check agent configs
        expected_agents = [
            "version_manager", "knowledge_base", "quality_gate",
            "governance", "document_generator", "rag_orchestrator",
            "daa", "lima", "reconnaissance", "api_reverse_engineering",
            "javascript_analysis", "wasm_analysis", "security_analysis",
            "traffic_interception", "validation", "reporting",
            "web_researcher", "content_analyzer", "topic_enhancer"
        ]
        
        for agent_name in expected_agents:
            if agent_name not in AGENT_MEMORY_CONFIG:
                errors.append(f"❌ Missing config for agent: {agent_name}")
            else:
                print(f"✅ Config for '{agent_name}' present")
                
    except Exception as e:
        errors.append(f"❌ Memory config test failed: {str(e)}")
    
    return len(errors) == 0, errors


def main():
    """Run all verification tests."""
    print("\n" + "="*80)
    print("MEMORY INTEGRATION VERIFICATION")
    print("="*80 + "\n")
    
    all_passed = True
    
    # Test 1: Imports
    print("TEST 1: Agent Imports")
    print("-" * 80)
    passed, errors = test_imports()
    all_passed = all_passed and passed
    if errors:
        print(f"\n{len(errors)} import errors found")
    print()
    
    # Test 2: Memory Initialization
    print("TEST 2: Memory Initialization")
    print("-" * 80)
    passed, errors = test_memory_initialization()
    all_passed = all_passed and passed
    if errors:
        print(f"\n{len(errors)} initialization errors found")
    print()
    
    # Test 3: Memory Configuration
    print("TEST 3: Memory Configuration")
    print("-" * 80)
    passed, errors = test_memory_config()
    all_passed = all_passed and passed
    if errors:
        print(f"\n{len(errors)} configuration errors found")
    print()
    
    # Summary
    print("="*80)
    if all_passed:
        print("✅ ALL TESTS PASSED - Memory integration is working correctly!")
        print("="*80)
        return 0
    else:
        print("❌ SOME TESTS FAILED - Please review errors above")
        print("="*80)
        return 1


if __name__ == "__main__":
    sys.exit(main())

