#!/usr/bin/env node

/**
 * RAVERSE MCP Server CLI Entry Point
 * 
 * This script provides a Node.js wrapper for the Python MCP server,
 * allowing it to be installed and run via npm.
 * 
 * Usage:
 *   raverse-mcp-server              # Start the server
 *   raverse-mcp-server --dev        # Start in development mode
 *   raverse-mcp-server --help       # Show help
 *   raverse-mcp-server --version    # Show version
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const VERSION = '1.0.2';
const PACKAGE_NAME = 'raverse-mcp-server';

// Parse command line arguments
const args = process.argv.slice(2);
const isDev = args.includes('--dev');
const showHelp = args.includes('--help') || args.includes('-h');
const showVersion = args.includes('--version') || args.includes('-v');

// Display help
if (showHelp) {
  console.log(`
${PACKAGE_NAME} v${VERSION}

MCP Server for RAVERSE - AI Multi-Agent Binary Patching System

USAGE:
  raverse-mcp-server [OPTIONS]

OPTIONS:
  --dev              Start in development mode with debug logging
  --help, -h         Show this help message
  --version, -v      Show version information

ENVIRONMENT VARIABLES:
  DATABASE_URL       PostgreSQL connection string (default: postgresql://localhost/raverse)
  REDIS_URL          Redis connection string (default: redis://localhost:6379)
  OPENROUTER_API_KEY OpenRouter API key for LLM features
  LOG_LEVEL          Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO)
  SERVER_PORT        Server port (default: 8000)
  SERVER_HOST        Server host (default: 127.0.0.1)

EXAMPLES:
  # Start the server with default configuration
  raverse-mcp-server

  # Start in development mode with debug logging
  raverse-mcp-server --dev

  # Start with custom database URL
  DATABASE_URL=postgresql://user:pass@host/db raverse-mcp-server

DOCUMENTATION:
  - Installation: https://github.com/usemanusai/jaegis-RAVERSE/blob/main/jaegis-RAVERSE-mcp-server/INSTALLATION.md
  - MCP Clients: https://github.com/usemanusai/jaegis-RAVERSE/blob/main/jaegis-RAVERSE-mcp-server/MCP_CLIENT_SETUP.md
  - Quick Start: https://github.com/usemanusai/jaegis-RAVERSE/blob/main/jaegis-RAVERSE-mcp-server/QUICKSTART.md

SUPPORT:
  GitHub: https://github.com/usemanusai/jaegis-RAVERSE
  Issues: https://github.com/usemanusai/jaegis-RAVERSE/issues
  `);
  process.exit(0);
}

// Display version
if (showVersion) {
  console.log(`${PACKAGE_NAME} v${VERSION}`);
  process.exit(0);
}

// Determine Python executable
function getPythonExecutable() {
  const pythonCandidates = ['python3', 'python'];
  
  for (const python of pythonCandidates) {
    try {
      const { execSync } = require('child_process');
      execSync(`${python} --version`, { stdio: 'ignore' });
      return python;
    } catch (e) {
      // Try next candidate
    }
  }
  
  return 'python3'; // Default fallback
}

// Check if Python is available
function checkPythonAvailable() {
  try {
    const { execSync } = require('child_process');
    const python = getPythonExecutable();
    execSync(`${python} --version`, { stdio: 'pipe' });
    return true;
  } catch (e) {
    return false;
  }
}

// Check if package is installed
function checkPackageInstalled() {
  try {
    const { execSync } = require('child_process');
    const python = getPythonExecutable();
    execSync(`${python} -c "import jaegis_raverse_mcp_server"`, { stdio: 'pipe' });
    return true;
  } catch (e) {
    return false;
  }
}

// Main function
function main() {
  // Check Python availability
  if (!checkPythonAvailable()) {
    console.error('ERROR: Python 3.13+ is required but not found in PATH');
    console.error('Please install Python 3.13 or higher from https://www.python.org/');
    process.exit(1);
  }

  // Check if package is installed
  if (!checkPackageInstalled()) {
    console.error('ERROR: RAVERSE MCP Server package is not installed');
    console.error('Please run: npm run setup');
    process.exit(1);
  }

  // Set up environment
  const env = Object.assign({}, process.env);
  
  if (isDev) {
    env.LOG_LEVEL = 'DEBUG';
    console.log('Starting RAVERSE MCP Server in development mode...');
  } else {
    console.log('Starting RAVERSE MCP Server...');
  }

  // Get Python executable
  const python = getPythonExecutable();

  // Spawn Python process
  const pythonProcess = spawn(python, ['-m', 'jaegis_raverse_mcp_server.server'], {
    env: env,
    stdio: 'inherit',
    cwd: __dirname
  });

  // Handle process exit
  pythonProcess.on('exit', (code) => {
    if (code !== 0) {
      console.error(`RAVERSE MCP Server exited with code ${code}`);
    }
    process.exit(code);
  });

  // Handle errors
  pythonProcess.on('error', (err) => {
    console.error('Failed to start RAVERSE MCP Server:', err.message);
    process.exit(1);
  });

  // Handle signals
  process.on('SIGINT', () => {
    console.log('\nShutting down RAVERSE MCP Server...');
    pythonProcess.kill('SIGINT');
  });

  process.on('SIGTERM', () => {
    console.log('\nShutting down RAVERSE MCP Server...');
    pythonProcess.kill('SIGTERM');
  });
}

// Run main function
main();

