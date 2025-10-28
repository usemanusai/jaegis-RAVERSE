# RAVERSE MCP Server - Interactive Setup Wizard Guide

## Overview

The RAVERSE MCP Server includes an interactive setup wizard that automatically runs when the server detects missing configuration (no `.env` file exists). This guide explains both setup modes and how to use them.

## Quick Start

### First Time Running the Server

When you run the RAVERSE MCP Server for the first time without a `.env` file:

```bash
# Via NPM
npx raverse-mcp-server@latest

# Via Python
python -m jaegis_raverse_mcp_server.server
```

The setup wizard will automatically launch and guide you through configuration.

## Setup Modes

### Mode 1: Secure Automatic Setup (Recommended for Beginners)

**Best for**: First-time users who want a fully automated setup

**What it does**:
- ✓ Generates cryptographically secure credentials using Python's `secrets` module
- ✓ Automatically detects available ports (5432 for PostgreSQL, 6379 for Redis)
- ✓ Creates a complete `.env` configuration file
- ✓ Validates OpenRouter API key format
- ✓ Sets secure file permissions on `.env`

**Time required**: 5-10 minutes

**Requirements**:
- OpenRouter API key (get one at https://openrouter.ai/keys)
- Internet connection (for API key validation)

**What you need to do**:
1. Select option `1` when prompted
2. Provide your OpenRouter API key
3. Wait for setup to complete
4. Start the server

**Generated credentials**:
- PostgreSQL username: `raverse_user_<random>`
- PostgreSQL password: 43-character cryptographically secure string
- Redis password: 43-character cryptographically secure string
- Database: `raverse`
- Ports: Auto-detected (default 5432 for PostgreSQL, 6379 for Redis)

### Mode 2: Manual Setup (Advanced Users)

**Best for**: Users with existing PostgreSQL/Redis instances or custom configurations

**What it does**:
- ✓ Prompts for your existing database connection string
- ✓ Prompts for your existing Redis connection string
- ✓ Validates all connection strings before saving
- ✓ Creates `.env` file with your custom settings

**Time required**: 10-15 minutes

**Requirements**:
- Running PostgreSQL instance
- Running Redis instance
- Connection strings for both services
- OpenRouter API key (optional)

**What you need to do**:
1. Select option `2` when prompted
2. Provide PostgreSQL connection string (format: `postgresql://user:password@host:port/database`)
3. Provide Redis connection string (format: `redis://:password@host:port/database`)
4. Provide OpenRouter API key (or skip to add later)
5. Start the server

## Connection String Formats

### PostgreSQL

```
postgresql://username:password@localhost:5432/raverse
```

**Components**:
- `username`: PostgreSQL user
- `password`: PostgreSQL password
- `localhost`: Database host (or IP address)
- `5432`: Database port
- `raverse`: Database name

### Redis

```
redis://:password@localhost:6379/0
```

**Components**:
- `password`: Redis password (optional, use `:` if no password)
- `localhost`: Redis host (or IP address)
- `6379`: Redis port
- `0`: Database number (0-15)

## OpenRouter API Key

### Getting Your API Key

1. Visit https://openrouter.ai/keys
2. Sign up or log in to your account
3. Create a new API key
4. Copy the key (format: `sk-or-v1-...`)

### API Key Format

- **Prefix**: `sk-or-v1-`
- **Minimum length**: 40 characters
- **Example**: `sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

## Configuration File (.env)

After setup completes, a `.env` file is created with the following structure:

```env
# Server Settings
SERVER_NAME=jaegis-raverse-mcp-server
SERVER_VERSION=1.0.4
LOG_LEVEL=INFO

# Database Settings
DATABASE_URL=postgresql://...
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis Settings
REDIS_URL=redis://...
REDIS_TIMEOUT=5

# LLM Settings
LLM_API_KEY=sk-or-v1-...
LLM_PROVIDER=openrouter
LLM_MODEL=meta-llama/llama-3.1-70b-instruct
LLM_TIMEOUT=30

# Embeddings Settings
EMBEDDINGS_MODEL=all-MiniLM-L6-v2
EMBEDDINGS_DIMENSION=384

# Feature Flags
ENABLE_BINARY_ANALYSIS=true
ENABLE_WEB_ANALYSIS=true
ENABLE_KNOWLEDGE_BASE=true
ENABLE_INFRASTRUCTURE=true

# Performance Settings
MAX_CONCURRENT_TASKS=10
CACHE_TTL_SECONDS=3600
REQUEST_TIMEOUT_SECONDS=60
```

## Troubleshooting

### Port Already in Use

If ports 5432 or 6379 are already in use:
- **Automatic Setup**: The wizard will automatically find the next available port
- **Manual Setup**: Specify a different port in your connection string

### Invalid API Key

If your OpenRouter API key is rejected:
- Verify the format starts with `sk-or-v1-`
- Ensure it's at least 40 characters long
- Check that you copied it correctly from https://openrouter.ai/keys
- You can skip this step and add it later to `.env`

### Connection String Validation Failed

**PostgreSQL**:
- Ensure format is: `postgresql://user:password@host:port/database`
- Verify the database exists and is accessible
- Check username and password are correct

**Redis**:
- Ensure format is: `redis://:password@host:port/database`
- Verify Redis is running and accessible
- Check password is correct (or use empty password with just `:`)

### Setup Interrupted (Ctrl+C)

If you press Ctrl+C during setup:
- Any partial `.env` file will be automatically removed
- You can run the setup wizard again
- No cleanup of database or Redis is performed

## Setup Logging

All setup wizard actions are logged to `setup_wizard.log` in the package directory:

```
[2025-10-28T10:30:45.123456] [INFO] Starting automatic setup mode
[2025-10-28T10:30:46.234567] [INFO] Generated credentials for PostgreSQL user: raverse_user_abc123
[2025-10-28T10:30:47.345678] [INFO] PostgreSQL port available: 5432
[2025-10-28T10:30:48.456789] [INFO] Redis port available: 6379
[2025-10-28T10:30:49.567890] [INFO] OpenRouter API key validated
[2025-10-28T10:30:50.678901] [INFO] .env file created successfully
```

## Security Considerations

### Credential Generation

- Credentials are generated using Python's `secrets` module (cryptographically secure)
- Passwords are 43 characters long with high entropy
- Credentials are displayed only once in the summary

### File Permissions

- `.env` file is created with secure permissions (600 on Unix systems)
- On Windows, file permissions are set to read-only for the current user
- Never commit `.env` to version control

### API Key Storage

- OpenRouter API key is stored in `.env` file
- Keep this file secure and never share it
- Rotate API keys periodically

## Next Steps

After setup completes:

1. **Verify Configuration**: Check that `.env` file was created
2. **Start the Server**: Run the server command again
3. **Check Logs**: Monitor `setup_wizard.log` for any issues
4. **Test Connection**: Verify database and Redis are accessible

## Support

For issues or questions:
- Check the troubleshooting section above
- Review `setup_wizard.log` for detailed error messages
- Visit https://github.com/usemanusai/jaegis-RAVERSE/issues
- Join our Discord community for support

## Version Information

- **Setup Wizard Version**: 1.0.4
- **Supported Platforms**: Windows 10/11, Ubuntu 22.04+, macOS 13+
- **Python Version**: 3.8+
- **Last Updated**: 2025-10-28

