#!/bin/bash

################################################################################
# RAVERSE MCP Server - Automated Installation Script
# 
# This script automates the complete setup process:
# - Checks for Docker
# - Starts PostgreSQL and Redis containers
# - Creates .env configuration
# - Verifies database connections
# - Starts the server
#
# Usage: ./install.sh [--api-key YOUR_KEY]
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/installation.log"
API_KEY="${1:-${OPENROUTER_API_KEY:-sk-or-v1-placeholder-key}}"

# Functions
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$LOG_FILE"
}

check_docker() {
    if command -v docker &> /dev/null; then
        log_success "Docker is installed"
        return 0
    else
        log_error "Docker is not installed"
        return 1
    fi
}

check_docker_compose() {
    if command -v docker-compose &> /dev/null; then
        log_success "Docker Compose is installed"
        return 0
    else
        log_error "Docker Compose is not installed"
        return 1
    fi
}

start_services() {
    log_info "Starting PostgreSQL and Redis containers..."
    cd "$SCRIPT_DIR/.."
    
    if docker-compose up -d >> "$LOG_FILE" 2>&1; then
        log_success "Services started"
    else
        log_error "Failed to start services"
        return 1
    fi
    
    # Wait for services
    log_info "Waiting for PostgreSQL to be ready..."
    for i in {1..30}; do
        if docker exec raverse-postgres pg_isready -U raverse -d raverse &> /dev/null; then
            log_success "PostgreSQL is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL failed to start"
            return 1
        fi
        sleep 2
    done
    
    log_info "Waiting for Redis to be ready..."
    for i in {1..30}; do
        if docker exec raverse-redis redis-cli ping &> /dev/null; then
            log_success "Redis is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "Redis failed to start"
            return 1
        fi
        sleep 2
    done
}

run_setup_wizard() {
    log_info "Running setup wizard in non-interactive mode..."
    cd "$SCRIPT_DIR"
    
    if python -m jaegis_raverse_mcp_server.setup_wizard \
        --non-interactive \
        --db-url "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse" \
        --redis-url "redis://localhost:6379/0" \
        --api-key "$API_KEY" >> "$LOG_FILE" 2>&1; then
        log_success "Setup wizard completed"
        return 0
    else
        log_error "Setup wizard failed"
        return 1
    fi
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check if .env file exists
    if [ -f "$SCRIPT_DIR/.env" ]; then
        log_success ".env file created"
    else
        log_error ".env file not found"
        return 1
    fi
    
    # Check database connection
    log_info "Checking database connection..."
    if docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;" &> /dev/null; then
        log_success "Database connection verified"
    else
        log_warning "Database connection check failed"
    fi
    
    # Check Redis connection
    log_info "Checking Redis connection..."
    if docker exec raverse-redis redis-cli ping &> /dev/null; then
        log_success "Redis connection verified"
    else
        log_warning "Redis connection check failed"
    fi
}

main() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  RAVERSE MCP Server - Automated Installation                  ║"
    echo "║  Version 1.0.5                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log_info "Starting automated installation..."
    log_info "Log file: $LOG_FILE"
    
    # Check prerequisites
    if ! check_docker; then
        log_error "Docker is required for automated installation"
        exit 1
    fi
    
    if ! check_docker_compose; then
        log_error "Docker Compose is required for automated installation"
        exit 1
    fi
    
    # Start services
    if ! start_services; then
        log_error "Failed to start services"
        exit 1
    fi
    
    # Run setup wizard
    if ! run_setup_wizard; then
        log_error "Setup wizard failed"
        exit 1
    fi
    
    # Verify installation
    if ! verify_installation; then
        log_warning "Installation verification had issues"
    fi
    
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  ✓ Installation completed successfully!                       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log_success "Installation completed"
    log_info "Next steps:"
    log_info "  1. Start the server: python -m jaegis_raverse_mcp_server.server"
    log_info "  2. Or use NPM: npx raverse-mcp-server"
    log_info "  3. Check logs: tail -f $LOG_FILE"
    
    exit 0
}

# Run main function
main "$@"

