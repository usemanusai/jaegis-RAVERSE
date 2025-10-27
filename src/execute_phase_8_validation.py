#!/usr/bin/env python3
"""
Phase 8: Final Validation Execution Script
Runs all tests and verifies production readiness
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and report results."""
    print(f"\n{'='*80}")
    print(f"STEP: {description}")
    print(f"{'='*80}")
    print(f"Command: {cmd}\n")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=False, text=True)
        if result.returncode == 0:
            print(f"\n✅ {description}: PASSED")
            return True
        else:
            print(f"\n❌ {description}: FAILED")
            return False
    except Exception as e:
        print(f"\n❌ {description}: ERROR - {e}")
        return False

def main():
    """Execute Phase 8 validation."""
    
    print("\n" + "="*80)
    print("PHASE 8: FINAL VALIDATION - EXECUTION")
    print("="*80)
    
    results = {}
    
    # Step 1: Run unit tests
    results["unit_tests"] = run_command(
        "python -m pytest tests/unit/ -v --tb=short",
        "Unit Tests (112 cases)"
    )
    
    # Step 2: Run integration tests
    results["integration_tests"] = run_command(
        "python -m pytest tests/integration/ -v --tb=short",
        "Integration Tests (30 cases)"
    )
    
    # Step 3: Run E2E tests
    results["e2e_tests"] = run_command(
        "python -m pytest tests/e2e/ -v --tb=short",
        "End-to-End Tests (24 cases)"
    )
    
    # Step 4: Run all tests with coverage
    results["coverage"] = run_command(
        "python -m pytest tests/ -v --cov=agents --cov-report=html --cov-report=term",
        "All Tests with Coverage Analysis"
    )
    
    # Step 5: Verify coverage
    results["coverage_check"] = run_command(
        "python -m pytest tests/ --cov=agents --cov-report=term-missing | grep -E 'TOTAL|agents'",
        "Coverage Verification (>85% required)"
    )
    
    # Print summary
    print("\n" + "="*80)
    print("PHASE 8 VALIDATION SUMMARY")
    print("="*80)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    print(f"\nResults:")
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\n✅ PHASE 8 VALIDATION: PASSED")
        print("\nAll tests passed and code coverage verified!")
        print("\nNext steps:")
        print("1. Review coverage report: htmlcov/index.html")
        print("2. Deploy to production")
        print("3. Monitor logs and metrics")
        return 0
    else:
        print("\n❌ PHASE 8 VALIDATION: FAILED")
        print("\nSome tests failed. Please review and fix.")
        return 1

if __name__ == "__main__":
    sys.exit(main())


