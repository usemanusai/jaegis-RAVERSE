#!/bin/bash
# RAVERSE Docker Quick Start Script
# Date: October 25, 2025
# Purpose: Quick setup and deployment using Docker Compose

set -e

echo "=========================================="
echo "RAVERSE Docker Quick Start"
echo "=========================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    echo "Please install Docker from https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Error: Docker Compose is not installed"
    echo "Please install Docker Compose from https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "Please edit .env and set your OPENROUTER_API_KEY"
    echo "Then run this script again"
    exit 1
fi

# Check if OPENROUTER_API_KEY is set
source .env
if [ -z "$OPENROUTER_API_KEY" ] || [ "$OPENROUTER_API_KEY" = "sk-or-v1-your-api-key-here" ]; then
    echo "Error: OPENROUTER_API_KEY not set in .env file"
    echo "Please edit .env and set your OpenRouter API key"
    exit 1
fi

echo "Starting RAVERSE services..."
echo ""

# Build and start services
docker-compose up -d --build

echo ""
echo "Waiting for services to be healthy..."
sleep 10

# Check service status
docker-compose ps

echo ""
echo "=========================================="
echo "RAVERSE Services Started Successfully!"
echo "=========================================="
echo ""
echo "Services:"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis: localhost:6379"
echo "  - RAVERSE App: Running"
echo ""
echo "Optional Development Tools:"
echo "  - pgAdmin: http://localhost:5050"
echo "  - RedisInsight: http://localhost:5540"
echo ""
echo "To start dev tools:"
echo "  docker-compose --profile dev up -d"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f raverse-app"
echo ""
echo "To stop services:"
echo "  docker-compose down"
echo ""
echo "To stop and remove volumes:"
echo "  docker-compose down -v"
echo ""
echo "=========================================="

