# PyPI Publishing Guide

**Status**: Ready for Publishing
**Package**: jaegis-raverse-mcp-server
**Version**: 1.0.0
**Registry**: https://pypi.org/

---

## Prerequisites

### 1. PyPI Account
- Account: usemanusai
- Email: use.manus.ai@gmail.com
- Status: ✅ Account exists

### 2. API Token
- Generate at: https://pypi.org/manage/account/token/
- Scope: Entire account
- Status: ⏳ Need to generate or use existing

### 3. Build Tools
- ✅ build 1.3.0 - Installed
- ✅ twine 6.2.0 - Installed
- ✅ wheel 0.45.1 - Installed

### 4. Distribution Files
- ✅ jaegis_raverse_mcp_server-1.0.0-py3-none-any.whl
- ✅ jaegis_raverse_mcp_server-1.0.0.tar.gz
- ✅ Both verified with twine

---

## Publishing Methods

### Method 1: Using PyPI Token (Recommended)

```bash
# Set environment variable with token
$env:TWINE_PASSWORD = "pypi-AgEIcHlwaS5vcmc..."

# Upload packages
python -m twine upload dist/* \
  --repository pypi \
  --username __token__ \
  --password $env:TWINE_PASSWORD
```

### Method 2: Interactive Login

```bash
# Upload with interactive login
python -m twine upload dist/* --repository pypi

# When prompted:
# Username: usemanusai
# Password: [your-pypi-password]
```

### Method 3: Using .pypirc Configuration

```bash
# Create ~/.pypirc file
cat > ~/.pypirc << 'EOF'
[distutils]
index-servers =
    pypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = usemanusai
password = [your-pypi-token]
EOF

# Upload
python -m twine upload dist/*
```

---

## Step-by-Step Publishing

### Step 1: Verify Packages
```bash
cd jaegis-RAVERSE-mcp-server
python -m twine check dist/*
```

**Expected Output**:
```
Checking dist/jaegis_raverse_mcp_server-1.0.0-py3-none-any.whl: PASSED
Checking dist/jaegis_raverse_mcp_server-1.0.0.tar.gz: PASSED
```

### Step 2: Upload to PyPI
```bash
python -m twine upload dist/*
```

**Expected Output**:
```
Uploading jaegis_raverse_mcp_server-1.0.0-py3-none-any.whl
Uploading jaegis_raverse_mcp_server-1.0.0.tar.gz
```

### Step 3: Verify Publication
```bash
# Check PyPI
curl https://pypi.org/pypi/jaegis-raverse-mcp-server/json

# Or visit
https://pypi.org/project/jaegis-raverse-mcp-server/
```

---

## Post-Publishing Verification

### 1. Check PyPI Package Page
- URL: https://pypi.org/project/jaegis-raverse-mcp-server/
- Verify version 1.0.0 is listed
- Verify description is correct
- Verify all files are present

### 2. Test Installation
```bash
# Create test environment
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate

# Install package
pip install jaegis-raverse-mcp-server

# Verify installation
raverse-mcp-server --version
raverse-mcp-server --help

# Cleanup
deactivate
rm -rf test_env
```

### 3. Check Package Metadata
```bash
pip show jaegis-raverse-mcp-server
```

**Expected Output**:
```
Name: jaegis-raverse-mcp-server
Version: 1.0.0
Summary: MCP Server for RAVERSE - AI Multi-Agent Binary Patching System with 35 tools
Home-page: https://github.com/usemanusai/jaegis-RAVERSE
Author: RAVERSE Team
Author-email: team@raverse.ai
License: MIT
Location: /path/to/site-packages
Requires: mcp, pydantic, pydantic-settings, python-dotenv, requests, psycopg2-binary, redis, pgvector, sentence-transformers, structlog, prometheus-client
```

---

## Troubleshooting

### Issue: "Invalid distribution"
**Solution**: Run `twine check dist/*` to verify packages

### Issue: "Unauthorized"
**Solution**: 
- Verify PyPI credentials
- Check API token is valid
- Ensure token has upload permissions

### Issue: "File already exists"
**Solution**: 
- Version already published
- Use new version number
- Or delete old version from PyPI

### Issue: "Invalid metadata"
**Solution**:
- Check pyproject.toml syntax
- Verify all required fields
- Run `python -m build` again

---

## Package Information

### Name
- PyPI: jaegis-raverse-mcp-server
- Import: jaegis_raverse_mcp_server

### Version
- Current: 1.0.0
- Semantic Versioning: MAJOR.MINOR.PATCH

### Description
MCP Server for RAVERSE - AI Multi-Agent Binary Patching System with 35 tools

### Keywords
- mcp
- model-context-protocol
- raverse
- binary-analysis
- reverse-engineering
- ai-agents
- multi-agent
- binary-patching
- security-analysis

### Dependencies
- mcp>=0.1.0
- pydantic>=2.5.0
- pydantic-settings>=2.1.0
- python-dotenv>=1.0.0
- requests>=2.31.0
- psycopg2-binary>=2.9.9
- redis>=5.0.0
- pgvector>=0.2.4
- sentence-transformers>=2.2.2
- structlog>=24.1.0
- prometheus-client>=0.19.0

### Entry Points
- raverse-mcp-server = jaegis_raverse_mcp_server.server:main

### License
- MIT

### Python Version
- Requires: >=3.13

---

## Success Criteria

✅ Package uploaded to PyPI
✅ Version 1.0.0 visible on PyPI
✅ Package metadata correct
✅ Installation works with pip
✅ CLI command accessible
✅ All dependencies resolved
✅ No errors during installation

---

**Status**: Ready for Publishing
**Next Step**: Execute publishing commands

