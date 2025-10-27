"""First-time setup guide for RAVERSE MCP Server"""

import os
import sys
from pathlib import Path
from typing import Optional


def detect_error_type(error_message: str) -> str:
    """Detect the type of database error"""
    error_lower = error_message.lower()
    
    if "password authentication failed" in error_lower:
        return "AUTH_FAILED"
    elif "connection refused" in error_lower or "could not connect" in error_lower:
        return "CONNECTION_REFUSED"
    elif "database" in error_lower and "does not exist" in error_lower:
        return "DATABASE_NOT_FOUND"
    elif "role" in error_lower and "does not exist" in error_lower:
        return "ROLE_NOT_FOUND"
    else:
        return "UNKNOWN"


def is_first_time_setup() -> bool:
    """Check if this appears to be first-time setup"""
    # Check if .env file exists in the package directory
    package_dir = Path(__file__).parent.parent
    env_file = package_dir / ".env"
    return not env_file.exists()


def get_setup_guide(error_message: str, error_type: str) -> str:
    """Generate a comprehensive setup guide"""
    
    package_dir = Path(__file__).parent.parent
    env_example = package_dir / ".env.example"
    
    guide = "\n"
    guide += "=" * 80 + "\n"
    guide += "⚠️  RAVERSE MCP SERVER - FIRST-TIME SETUP REQUIRED\n"
    guide += "=" * 80 + "\n\n"
    
    # Problem identification
    guide += "DATABASE CONNECTION FAILED\n"
    guide += "-" * 80 + "\n"
    
    if error_type == "AUTH_FAILED":
        guide += "Issue: PostgreSQL authentication failed\n"
        guide += "Reason: Database credentials are incorrect or not configured\n\n"
    elif error_type == "CONNECTION_REFUSED":
        guide += "Issue: Cannot connect to PostgreSQL server\n"
        guide += "Reason: PostgreSQL is not running or not accessible at localhost:5432\n\n"
    elif error_type == "DATABASE_NOT_FOUND":
        guide += "Issue: Database 'raverse' does not exist\n"
        guide += "Reason: PostgreSQL database needs to be created\n\n"
    elif error_type == "ROLE_NOT_FOUND":
        guide += "Issue: PostgreSQL user 'raverse' does not exist\n"
        guide += "Reason: Database user needs to be created\n\n"
    else:
        guide += "Issue: Database connection error\n"
        guide += f"Details: {error_message}\n\n"
    
    # Quick fix section
    guide += "QUICK FIX (3 STEPS):\n"
    guide += "-" * 80 + "\n"
    guide += "1. Copy .env.example to .env:\n"
    guide += f"   Copy-Item '{env_example}' -Destination '{package_dir}\\.env'\n\n"
    guide += "2. Edit .env with your database credentials:\n"
    guide += f"   notepad '{package_dir}\\.env'\n\n"
    guide += "3. Start PostgreSQL and Redis, then run the server again\n\n"
    
    # Detailed setup options
    guide += "DETAILED SETUP OPTIONS:\n"
    guide += "-" * 80 + "\n\n"
    
    guide += "OPTION 1: Docker (Recommended - Fastest)\n"
    guide += "  Prerequisites: Docker and Docker Compose installed\n"
    guide += "  Commands:\n"
    guide += "    # Create docker-compose.yml with PostgreSQL and Redis\n"
    guide += "    docker-compose up -d\n"
    guide += "    # Then run the server\n"
    guide += "    npx raverse-mcp-server@latest\n\n"
    
    guide += "OPTION 2: Local PostgreSQL + Redis (Windows)\n"
    guide += "  Step 1: Install PostgreSQL\n"
    guide += "    - Download from: https://www.postgresql.org/download/windows/\n"
    guide += "    - During installation, set password for 'postgres' user\n"
    guide += "    - Remember the password for later\n\n"
    guide += "  Step 2: Create database and user\n"
    guide += "    # Open PowerShell and connect to PostgreSQL\n"
    guide += "    psql -U postgres\n"
    guide += "    # In psql prompt, run:\n"
    guide += "    CREATE USER raverse WITH PASSWORD 'raverse_secure_password_2025';\n"
    guide += "    CREATE DATABASE raverse OWNER raverse;\n"
    guide += "    \\q\n\n"
    guide += "  Step 3: Install Redis\n"
    guide += "    - Download from: https://github.com/microsoftarchive/redis/releases\n"
    guide += "    - Or use Windows Subsystem for Linux (WSL)\n"
    guide += "    - Or use Docker: docker run -d -p 6379:6379 redis:latest\n\n"
    guide += "  Step 4: Update .env file\n"
    guide += f"    - Edit: {package_dir}\\.env\n"
    guide += "    - Set DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse\n"
    guide += "    - Set REDIS_URL=redis://localhost:6379/0\n\n"
    
    guide += "OPTION 3: Cloud Database (Managed Services)\n"
    guide += "  - PostgreSQL: AWS RDS, Azure Database, Google Cloud SQL, Heroku\n"
    guide += "  - Redis: AWS ElastiCache, Azure Cache, Heroku Redis\n"
    guide += "  - Update DATABASE_URL and REDIS_URL in .env with cloud credentials\n\n"
    
    # Environment variables
    guide += "ENVIRONMENT VARIABLES REFERENCE:\n"
    guide += "-" * 80 + "\n"
    guide += "DATABASE_URL\n"
    guide += "  Purpose: PostgreSQL connection string\n"
    guide += "  Format: postgresql://username:password@host:port/database\n"
    guide += "  Example: postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse\n\n"
    guide += "REDIS_URL\n"
    guide += "  Purpose: Redis connection string\n"
    guide += "  Format: redis://host:port/database\n"
    guide += "  Example: redis://localhost:6379/0\n\n"
    guide += "LLM_API_KEY\n"
    guide += "  Purpose: API key for LLM provider (OpenRouter)\n"
    guide += "  Get from: https://openrouter.ai/keys\n"
    guide += "  Example: sk-or-v1-...\n\n"
    
    # Verification
    guide += "VERIFICATION & TROUBLESHOOTING:\n"
    guide += "-" * 80 + "\n"
    guide += "Verify PostgreSQL is running:\n"
    guide += "  psql -U raverse -d raverse -c 'SELECT 1;'\n\n"
    guide += "Verify Redis is running:\n"
    guide += "  redis-cli ping\n"
    guide += "  (Should return: PONG)\n\n"
    guide += "Common Issues:\n"
    guide += "  - Port 5432 already in use: Change port in DATABASE_URL\n"
    guide += "  - Redis not installed: Use Docker or install from https://redis.io\n"
    guide += "  - Wrong password: Update .env and restart PostgreSQL\n"
    guide += "  - Database doesn't exist: Run CREATE DATABASE command above\n\n"
    
    # Documentation links
    guide += "DOCUMENTATION & RESOURCES:\n"
    guide += "-" * 80 + "\n"
    guide += f"  - .env.example: {env_example}\n"
    guide += f"  - Installation Guide: {package_dir}/INSTALLATION.md\n"
    guide += f"  - Quick Start: {package_dir}/QUICKSTART.md\n"
    guide += f"  - Integration Guide: {package_dir}/INTEGRATION_GUIDE.md\n"
    guide += "  - PostgreSQL Docs: https://www.postgresql.org/docs/\n"
    guide += "  - Redis Docs: https://redis.io/documentation\n\n"
    
    guide += "=" * 80 + "\n"
    guide += "After completing setup, run: npx raverse-mcp-server@latest\n"
    guide += "=" * 80 + "\n"
    
    return guide


def print_setup_guide(error_message: str) -> None:
    """Print setup guide to console"""
    error_type = detect_error_type(error_message)
    guide = get_setup_guide(error_message, error_type)
    print(guide, file=sys.stderr)

