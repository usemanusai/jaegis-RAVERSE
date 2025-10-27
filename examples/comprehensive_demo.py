#!/usr/bin/env python3
"""
RAVERSE 2.0 - Comprehensive Demo
Date: October 25, 2025

This script demonstrates all the new AI-powered features:
- Semantic code search
- LLM-powered analysis
- Pattern recognition
- Automated patch generation
- Multi-level caching
- Monitoring & metrics
"""

import os
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.enhanced_orchestrator import EnhancedOrchestrator
from utils.database import DatabaseManager
from utils.cache import CacheManager
from utils.semantic_search import get_search_engine
from utils.multi_level_cache import get_multi_level_cache
from utils.metrics import metrics_collector, get_metrics


def print_section(title: str):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_comprehensive_analysis(binary_path: str):
    """Demonstrate comprehensive binary analysis."""
    print_section("1. COMPREHENSIVE BINARY ANALYSIS")
    
    # Initialize orchestrator
    print("Initializing enhanced orchestrator...")
    orchestrator = EnhancedOrchestrator(
        binary_path=binary_path,
        use_database=True,
        use_llm=True
    )
    
    # Perform analysis
    print(f"Analyzing binary: {os.path.basename(binary_path)}")
    start_time = time.time()
    
    analysis = orchestrator.analyze_binary(
        num_instructions=100
    )
    
    duration = time.time() - start_time
    
    # Print results
    print(f"\n✅ Analysis completed in {duration:.2f}s")
    print(f"   - Instructions analyzed: {analysis['disassembly']['num_instructions']}")
    print(f"   - Password checks found: {len(analysis['patterns']['password_checks'])}")
    
    if analysis.get('llm_analysis'):
        print(f"   - LLM analysis: Available")
    
    return orchestrator, analysis


def demo_semantic_search(orchestrator):
    """Demonstrate semantic code search."""
    print_section("2. SEMANTIC CODE SEARCH")
    
    if not orchestrator.semantic_search:
        print("⚠️  Semantic search not available (database required)")
        return
    
    # Search for similar code
    print("Searching for similar password check patterns...")
    
    results = orchestrator.semantic_search.find_password_check_patterns(limit=5)
    
    print(f"\n✅ Found {len(results)} similar patterns:")
    for i, result in enumerate(results, 1):
        print(f"\n{i}. Binary: {result['binary_hash'][:8]}...")
        print(f"   Code: {result['code_snippet'][:60]}...")
        if 'similarity' in result:
            print(f"   Similarity: {result['similarity']:.2%}")


def demo_patch_generation(orchestrator):
    """Demonstrate automated patch generation."""
    print_section("3. AUTOMATED PATCH GENERATION")
    
    # Generate patches
    print("Generating patch strategies...")
    strategies = orchestrator.generate_patches()
    
    print(f"\n✅ Generated {len(strategies)} patch strategies:")
    for i, strategy in enumerate(strategies[:5], 1):  # Show top 5
        print(f"\n{i}. {strategy.name}")
        print(f"   Type: {strategy.patch_type.value}")
        print(f"   Address: 0x{strategy.target_address:x}")
        print(f"   Confidence: {strategy.confidence:.2%}")
        print(f"   Description: {strategy.description}")
    
    return strategies


def demo_patch_application(orchestrator, strategies, output_dir: str):
    """Demonstrate patch application and validation."""
    print_section("4. PATCH APPLICATION & VALIDATION")
    
    if not strategies:
        print("⚠️  No strategies available")
        return
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Apply best strategy
    print("Applying best patch strategy...")
    output_path = os.path.join(output_dir, "patched_binary.exe")
    
    result = orchestrator.apply_and_validate_patch(
        strategy_index=0,
        output_path=output_path
    )
    
    # Print results
    print(f"\n✅ Patch application completed:")
    print(f"   Strategy: {result['strategy']['name']}")
    print(f"   Type: {result['strategy']['type']}")
    print(f"   Address: {result['strategy']['address']}")
    
    if result['validation']['overall_valid']:
        print(f"\n✅ Validation: PASSED")
        print(f"   Output: {result['output_path']}")
    else:
        print(f"\n❌ Validation: FAILED")
        print(result['validation']['summary'])


def demo_multi_level_cache():
    """Demonstrate multi-level caching."""
    print_section("5. MULTI-LEVEL CACHING")
    
    try:
        db = DatabaseManager()
        cache = CacheManager()
        
        ml_cache = get_multi_level_cache(
            redis_manager=cache,
            db_manager=db
        )
        
        # Test cache operations
        print("Testing cache operations...")
        
        # Set value
        ml_cache.set("demo", "test_key", "test_value")
        print("✅ Value cached")
        
        # Get value (should hit L1)
        value = ml_cache.get("demo", "test_key")
        print(f"✅ Value retrieved: {value}")
        
        # Get statistics
        stats = ml_cache.get_stats()
        print(f"\n📊 Cache Statistics:")
        print(f"   L1 Hit Rate: {stats['l1']['hit_rate']:.2%}")
        print(f"   L2 Hits: {stats['l2']['hits']}")
        print(f"   L3 Hits: {stats['l3']['hits']}")
        print(f"   Overall Hit Rate: {stats['overall']['hit_rate']:.2%}")
        
    except Exception as e:
        print(f"⚠️  Cache demo failed: {e}")


def demo_metrics():
    """Demonstrate metrics collection."""
    print_section("6. METRICS & MONITORING")
    
    # Record some metrics
    print("Recording metrics...")
    metrics_collector.record_patch_attempt("PE", "success")
    metrics_collector.record_api_call("openrouter", "llama-3.2-3b", "success", 2.5)
    metrics_collector.record_cache_hit("embedding")
    
    # Get metrics
    metrics = get_metrics()
    
    print("\n✅ Metrics recorded:")
    print("   - Patch attempts")
    print("   - API calls")
    print("   - Cache hits")
    
    print("\n📊 View metrics at:")
    print("   - Prometheus: http://localhost:9090")
    print("   - Grafana: http://localhost:3000")


def demo_comprehensive_report(orchestrator):
    """Demonstrate comprehensive report generation."""
    print_section("7. COMPREHENSIVE REPORT")
    
    report = orchestrator.get_analysis_report()
    
    print(report)
    
    # Save to file
    output_file = "output/analysis_report.txt"
    os.makedirs("output", exist_ok=True)
    
    with open(output_file, "w") as f:
        f.write(report)
    
    print(f"\n✅ Report saved to: {output_file}")


def main():
    """Main demo function."""
    print_section("RAVERSE 2.0 - COMPREHENSIVE DEMO")
    print("This demo showcases all AI-powered features")
    print("Date: October 25, 2025")
    
    # Check for binary path
    if len(sys.argv) < 2:
        print("\n❌ Usage: python comprehensive_demo.py <binary_path>")
        print("\nExample:")
        print("  python comprehensive_demo.py binaries/password_protected.exe")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"\n❌ Binary not found: {binary_path}")
        sys.exit(1)
    
    try:
        # Run all demos
        orchestrator, analysis = demo_comprehensive_analysis(binary_path)
        demo_semantic_search(orchestrator)
        strategies = demo_patch_generation(orchestrator)
        demo_patch_application(orchestrator, strategies, "output")
        demo_multi_level_cache()
        demo_metrics()
        demo_comprehensive_report(orchestrator)
        
        # Final summary
        print_section("DEMO COMPLETE")
        print("✅ All features demonstrated successfully!")
        print("\n📚 Next Steps:")
        print("   1. Review the analysis report in output/analysis_report.txt")
        print("   2. Check the patched binary in output/patched_binary.exe")
        print("   3. View metrics in Grafana (http://localhost:3000)")
        print("   4. Explore the database in pgAdmin (http://localhost:5050)")
        print("\n🎉 Happy Patching!")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

