#Requires -Version 5.0

<#
.SYNOPSIS
    RAVERSE MCP Server - Automated Installation Script for Windows

.DESCRIPTION
    This script automates the complete setup process:
    - Checks for Docker
    - Starts PostgreSQL and Redis containers
    - Creates .env configuration
    - Verifies database connections
    - Starts the server

.PARAMETER ApiKey
    OpenRouter API key (optional, defaults to environment variable or placeholder)

.EXAMPLE
    .\install.ps1 -ApiKey "sk-or-v1-your-key-here"
    .\install.ps1
#>

param(
    [string]$ApiKey = $env:OPENROUTER_API_KEY
)

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ScriptDir "installation.log"
$ApiKey = if ($ApiKey) { $ApiKey } else { "sk-or-v1-placeholder-key" }

# Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
    Write-Log $Message "SUCCESS"
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
    Write-Log $Message "ERROR"
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "[⚠] $Message" -ForegroundColor Yellow
    Write-Log $Message "WARNING"
}

function Check-Docker {
    try {
        $null = docker --version 2>$null
        Write-Success "Docker is installed"
        return $true
    }
    catch {
        Write-Error-Custom "Docker is not installed"
        return $false
    }
}

function Check-DockerCompose {
    try {
        $null = docker-compose --version 2>$null
        Write-Success "Docker Compose is installed"
        return $true
    }
    catch {
        Write-Error-Custom "Docker Compose is not installed"
        return $false
    }
}

function Start-Services {
    Write-Log "Starting PostgreSQL and Redis containers..."
    
    Push-Location (Split-Path $ScriptDir)
    try {
        $output = docker-compose up -d 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Services started"
        }
        else {
            Write-Error-Custom "Failed to start services: $output"
            return $false
        }
    }
    finally {
        Pop-Location
    }
    
    # Wait for PostgreSQL
    Write-Log "Waiting for PostgreSQL to be ready..."
    $maxAttempts = 30
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $null = docker exec raverse-postgres pg_isready -U raverse -d raverse 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "PostgreSQL is ready"
                break
            }
        }
        catch { }
        
        if ($i -eq $maxAttempts) {
            Write-Error-Custom "PostgreSQL failed to start"
            return $false
        }
        Start-Sleep -Seconds 2
    }
    
    # Wait for Redis
    Write-Log "Waiting for Redis to be ready..."
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $null = docker exec raverse-redis redis-cli ping 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Redis is ready"
                break
            }
        }
        catch { }
        
        if ($i -eq $maxAttempts) {
            Write-Error-Custom "Redis failed to start"
            return $false
        }
        Start-Sleep -Seconds 2
    }
    
    return $true
}

function Run-SetupWizard {
    Write-Log "Running setup wizard in non-interactive mode..."
    
    Push-Location $ScriptDir
    try {
        $output = python -m jaegis_raverse_mcp_server.setup_wizard `
            --non-interactive `
            --db-url "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse" `
            --redis-url "redis://localhost:6379/0" `
            --api-key $ApiKey 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Setup wizard completed"
            return $true
        }
        else {
            Write-Error-Custom "Setup wizard failed: $output"
            return $false
        }
    }
    finally {
        Pop-Location
    }
}

function Verify-Installation {
    Write-Log "Verifying installation..."
    
    # Check if .env file exists
    $envFile = Join-Path $ScriptDir ".env"
    if (Test-Path $envFile) {
        Write-Success ".env file created"
    }
    else {
        Write-Error-Custom ".env file not found"
        return $false
    }
    
    # Check database connection
    Write-Log "Checking database connection..."
    try {
        $null = docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Database connection verified"
        }
        else {
            Write-Warning-Custom "Database connection check failed"
        }
    }
    catch {
        Write-Warning-Custom "Database connection check failed"
    }
    
    # Check Redis connection
    Write-Log "Checking Redis connection..."
    try {
        $null = docker exec raverse-redis redis-cli ping 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Redis connection verified"
        }
        else {
            Write-Warning-Custom "Redis connection check failed"
        }
    }
    catch {
        Write-Warning-Custom "Redis connection check failed"
    }
    
    return $true
}

function Main {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  RAVERSE MCP Server - Automated Installation                  ║" -ForegroundColor Cyan
    Write-Host "║  Version 1.0.5                                                ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "Starting automated installation..."
    Write-Log "Log file: $LogFile"
    
    # Check prerequisites
    if (-not (Check-Docker)) {
        Write-Error-Custom "Docker is required for automated installation"
        exit 1
    }
    
    if (-not (Check-DockerCompose)) {
        Write-Error-Custom "Docker Compose is required for automated installation"
        exit 1
    }
    
    # Start services
    if (-not (Start-Services)) {
        Write-Error-Custom "Failed to start services"
        exit 1
    }
    
    # Run setup wizard
    if (-not (Run-SetupWizard)) {
        Write-Error-Custom "Setup wizard failed"
        exit 1
    }
    
    # Verify installation
    if (-not (Verify-Installation)) {
        Write-Warning-Custom "Installation verification had issues"
    }
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  ✓ Installation completed successfully!                       ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    Write-Success "Installation completed"
    Write-Log "Next steps:"
    Write-Log "  1. Start the server: python -m jaegis_raverse_mcp_server.server"
    Write-Log "  2. Or use NPM: npx raverse-mcp-server"
    Write-Log "  3. Check logs: Get-Content $LogFile -Tail 50"
    
    exit 0
}

# Run main function
Main

