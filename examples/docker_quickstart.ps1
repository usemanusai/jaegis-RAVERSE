# RAVERSE Docker Quick Start Script (PowerShell)
# Date: October 25, 2025
# Purpose: Quick setup and deployment using Docker Compose

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "RAVERSE Docker Quick Start" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if Docker is installed
try {
    docker --version | Out-Null
} catch {
    Write-Host "Error: Docker is not installed" -ForegroundColor Red
    Write-Host "Please install Docker from https://docs.docker.com/get-docker/"
    exit 1
}

# Check if Docker Compose is installed
try {
    docker-compose --version | Out-Null
} catch {
    try {
        docker compose version | Out-Null
    } catch {
        Write-Host "Error: Docker Compose is not installed" -ForegroundColor Red
        Write-Host "Please install Docker Compose from https://docs.docker.com/compose/install/"
        exit 1
    }
}

# Check if .env file exists
if (-not (Test-Path .env)) {
    Write-Host "Creating .env file from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
    Write-Host "Please edit .env and set your OPENROUTER_API_KEY" -ForegroundColor Yellow
    Write-Host "Then run this script again"
    exit 1
}

# Check if OPENROUTER_API_KEY is set
$envContent = Get-Content .env -Raw
if ($envContent -match "OPENROUTER_API_KEY=(.+)") {
    $apiKey = $matches[1].Trim()
    if ([string]::IsNullOrWhiteSpace($apiKey) -or $apiKey -eq "sk-or-v1-your-api-key-here") {
        Write-Host "Error: OPENROUTER_API_KEY not set in .env file" -ForegroundColor Red
        Write-Host "Please edit .env and set your OpenRouter API key"
        exit 1
    }
} else {
    Write-Host "Error: OPENROUTER_API_KEY not found in .env file" -ForegroundColor Red
    exit 1
}

Write-Host "Starting RAVERSE services..." -ForegroundColor Green
Write-Host ""

# Build and start services
docker-compose up -d --build

Write-Host ""
Write-Host "Waiting for services to be healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check service status
docker-compose ps

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "RAVERSE Services Started Successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Services:" -ForegroundColor White
Write-Host "  - PostgreSQL: localhost:5432"
Write-Host "  - Redis: localhost:6379"
Write-Host "  - RAVERSE App: Running"
Write-Host ""
Write-Host "Optional Development Tools:" -ForegroundColor White
Write-Host "  - pgAdmin: http://localhost:5050"
Write-Host "  - RedisInsight: http://localhost:5540"
Write-Host ""
Write-Host "To start dev tools:" -ForegroundColor Yellow
Write-Host "  docker-compose --profile dev up -d"
Write-Host ""
Write-Host "To view logs:" -ForegroundColor Yellow
Write-Host "  docker-compose logs -f raverse-app"
Write-Host ""
Write-Host "To stop services:" -ForegroundColor Yellow
Write-Host "  docker-compose down"
Write-Host ""
Write-Host "To stop and remove volumes:" -ForegroundColor Yellow
Write-Host "  docker-compose down -v"
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan

