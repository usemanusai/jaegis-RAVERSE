#!/bin/bash
# RAVERSE Test Runner Script (Bash)
# Date: October 25, 2025
# Purpose: Run comprehensive test suite with coverage reporting

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
UNIT=false
INTEGRATION=false
ALL=false
COVERAGE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit)
            UNIT=true
            shift
            ;;
        --integration)
            INTEGRATION=true
            shift
            ;;
        --all)
            ALL=true
            shift
            ;;
        --coverage)
            COVERAGE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--unit|--integration|--all] [--coverage] [--verbose]"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}==========================================${NC}"
echo -e "${CYAN}RAVERSE Test Suite Runner${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}Activating virtual environment...${NC}"
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    else
        echo -e "${RED}Error: Virtual environment not found${NC}"
        echo -e "${YELLOW}Run: python3 -m venv .venv${NC}"
        exit 1
    fi
fi

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${YELLOW}Installing test dependencies...${NC}"
    pip install -r requirements.txt
fi

# Build pytest command
PYTEST_CMD="pytest"

if [ "$VERBOSE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -v"
else
    PYTEST_CMD="$PYTEST_CMD -q"
fi

if [ "$COVERAGE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=agents --cov=utils --cov-report=term-missing --cov-report=html"
fi

# Determine which tests to run
if [ "$UNIT" = true ]; then
    echo -e "${GREEN}Running unit tests only...${NC}"
    PYTEST_CMD="$PYTEST_CMD tests/test_orchestrator.py tests/test_lima.py tests/test_pea.py"
elif [ "$INTEGRATION" = true ]; then
    echo -e "${GREEN}Running integration tests only...${NC}"
    echo -e "${YELLOW}Note: Requires Docker running${NC}"
    PYTEST_CMD="$PYTEST_CMD tests/test_database.py tests/test_cache.py"
elif [ "$ALL" = true ]; then
    echo -e "${GREEN}Running all tests...${NC}"
    echo -e "${YELLOW}Note: Integration tests require Docker running${NC}"
    # Run all tests (no filter)
else
    # Default: run unit tests
    echo -e "${GREEN}Running unit tests (default)...${NC}"
    echo -e "${YELLOW}Use --all for all tests, --integration for integration tests${NC}"
    PYTEST_CMD="$PYTEST_CMD tests/test_orchestrator.py tests/test_lima.py tests/test_pea.py"
fi

echo ""
echo -e "${CYAN}Command: $PYTEST_CMD${NC}"
echo ""

# Run tests
$PYTEST_CMD
EXIT_CODE=$?

echo ""
echo -e "${CYAN}==========================================${NC}"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    if [ "$COVERAGE" = true ]; then
        echo ""
        echo -e "${YELLOW}Coverage report generated:${NC}"
        echo "  - Terminal: See above"
        echo "  - HTML: htmlcov/index.html"
    fi
else
    echo -e "${RED}Some tests failed!${NC}"
fi

echo -e "${CYAN}==========================================${NC}"

exit $EXIT_CODE

