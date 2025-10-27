# RAVERSE Test Runner Script (PowerShell)
# Date: October 25, 2025
# Purpose: Run comprehensive test suite with coverage reporting

param(
    [switch]$Unit,
    [switch]$Integration,
    [switch]$All,
    [switch]$Coverage,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "RAVERSE Test Suite Runner" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment is activated
if (-not $env:VIRTUAL_ENV) {
    Write-Host "Activating virtual environment..." -ForegroundColor Yellow
    if (Test-Path ".venv\Scripts\Activate.ps1") {
        & .\.venv\Scripts\Activate.ps1
    } else {
        Write-Host "Error: Virtual environment not found" -ForegroundColor Red
        Write-Host "Run: python -m venv .venv" -ForegroundColor Yellow
        exit 1
    }
}

# Check if pytest is installed
try {
    pytest --version | Out-Null
} catch {
    Write-Host "Installing test dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
}

# Build pytest command
$pytestCmd = "pytest"

if ($Verbose) {
    $pytestCmd += " -v"
} else {
    $pytestCmd += " -q"
}

if ($Coverage) {
    $pytestCmd += " --cov=agents --cov=utils --cov-report=term-missing --cov-report=html"
}

# Determine which tests to run
if ($Unit) {
    Write-Host "Running unit tests only..." -ForegroundColor Green
    $pytestCmd += " tests/test_orchestrator.py tests/test_lima.py tests/test_pea.py"
}
elseif ($Integration) {
    Write-Host "Running integration tests only..." -ForegroundColor Green
    Write-Host "Note: Requires Docker running" -ForegroundColor Yellow
    $pytestCmd += " tests/test_database.py tests/test_cache.py"
}
elseif ($All) {
    Write-Host "Running all tests..." -ForegroundColor Green
    Write-Host "Note: Integration tests require Docker running" -ForegroundColor Yellow
    # Run all tests
}
else {
    # Default: run unit tests
    Write-Host "Running unit tests (default)..." -ForegroundColor Green
    Write-Host "Use -All for all tests, -Integration for integration tests" -ForegroundColor Yellow
    $pytestCmd += " tests/test_orchestrator.py tests/test_lima.py tests/test_pea.py"
}

Write-Host ""
Write-Host "Command: $pytestCmd" -ForegroundColor Cyan
Write-Host ""

# Run tests
Invoke-Expression $pytestCmd

$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan

if ($exitCode -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    if ($Coverage) {
        Write-Host ""
        Write-Host "Coverage report generated:" -ForegroundColor Yellow
        Write-Host "  - Terminal: See above" -ForegroundColor White
        Write-Host "  - HTML: htmlcov\index.html" -ForegroundColor White
    }
} else {
    Write-Host "Some tests failed!" -ForegroundColor Red
}

Write-Host "==========================================" -ForegroundColor Cyan

exit $exitCode

