# Publishing Guide - RAVERSE MCP Server

Step-by-step guide for publishing RAVERSE MCP Server to npm and PyPI.

## Prerequisites

### NPM Publishing
- npm account at https://www.npmjs.com/
- npm CLI installed (`npm --version`)
- Credentials: usemanusai / use.manus.ai@gmail.com

### PyPI Publishing
- PyPI account at https://pypi.org/
- twine installed (`pip install twine`)
- Credentials: usemanusai / use.manus.ai@gmail.com

### Both
- Git installed and configured
- Repository access
- Version bumped in all files

---

## Step 1: Prepare for Publishing

### 1.1 Update Version

Update version in all files:

**package.json**:
```json
{
  "version": "1.0.0"
}
```

**pyproject.toml**:
```toml
[project]
version = "1.0.0"
```

**Dockerfile** (if applicable):
```dockerfile
LABEL version="1.0.0"
```

### 1.2 Update CHANGELOG

Create `CHANGELOG.md`:
```markdown
# Changelog

## [1.0.0] - 2025-10-27

### Added
- Initial release with all 35 MCP tools
- NPM package distribution
- PyPI package distribution
- Docker image distribution
- Comprehensive documentation
- MCP client setup guides for 20+ clients

### Features
- Binary Analysis (4 tools)
- Knowledge Base & RAG (4 tools)
- Web Analysis (5 tools)
- Infrastructure (5 tools)
- Advanced Analysis (5 tools)
- Management (4 tools)
- Utilities (5 tools)
- System (4 tools)
- NLP & Validation (2 tools)

### Documentation
- Installation guide
- Quick start guide
- MCP client setup for 20+ clients
- Integration guide
- Deployment guide
- Tools registry

### License
MIT License
```

### 1.3 Commit Changes

```bash
# Stage changes
git add package.json pyproject.toml CHANGELOG.md

# Commit
git commit -m "Release v1.0.0: Initial release with all 35 tools"

# Create tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push to GitHub
git push origin main
git push origin v1.0.0
```

---

## Step 2: Publish to NPM

### 2.1 Login to NPM

```bash
# Login to npm
npm login

# Enter credentials when prompted:
# Username: usemanusai
# Password: [your npm password]
# Email: use.manus.ai@gmail.com
# OTP (if 2FA enabled): [your 2FA code]
```

### 2.2 Verify Login

```bash
# Check who you're logged in as
npm whoami

# Should output: usemanusai
```

### 2.3 Build Package

```bash
# Clean previous builds
npm run clean

# Build Python package
npm run build

# Verify package contents
npm pack --dry-run

# Should show all files to be included
```

### 2.4 Publish Package

```bash
# Publish to npm (scoped package)
npm publish --access public

# Output should show:
# npm notice Publishing to https://registry.npmjs.org/
# npm notice Publishing @raverse/mcp-server@1.0.0
```

### 2.5 Verify Publication

```bash
# Check package on npm
npm view @raverse/mcp-server

# Should show version 1.0.0

# Test installation
npm install -g @raverse/mcp-server

# Verify installation
raverse-mcp-server --version

# Should output: @raverse/mcp-server v1.0.0
```

### 2.6 Verify on npmjs.com

1. Visit https://www.npmjs.com/package/@raverse/mcp-server
2. Verify version 1.0.0 is listed
3. Check package details are correct
4. Verify all files are included

---

## Step 3: Publish to PyPI

### 3.1 Install Build Tools

```bash
# Install build and twine
pip install build twine

# Verify installation
python -m build --version
twine --version
```

### 3.2 Build Distribution

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build distribution
python -m build

# Verify build
ls -la dist/

# Should contain:
# - jaegis_raverse_mcp_server-1.0.0-py3-none-any.whl
# - jaegis_raverse_mcp_server-1.0.0.tar.gz
```

### 3.3 Check Distribution

```bash
# Check package metadata
twine check dist/*

# Should output: Checking distribution...
# All checks passed
```

### 3.4 Configure PyPI Credentials

```bash
# Create ~/.pypirc
cat > ~/.pypirc << 'EOF'
[distutils]
index-servers =
    pypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = usemanusai
EOF

# Set permissions
chmod 600 ~/.pypirc
```

### 3.5 Publish to PyPI

```bash
# Upload to PyPI
python -m twine upload dist/*

# When prompted, enter your PyPI password
# Or use API token: __token__ / pypi-...

# Output should show:
# Uploading jaegis_raverse_mcp_server-1.0.0-py3-none-any.whl
# Uploading jaegis_raverse_mcp_server-1.0.0.tar.gz
```

### 3.6 Verify Publication

```bash
# Check package on PyPI
pip search jaegis-raverse-mcp-server

# Or visit: https://pypi.org/project/jaegis-raverse-mcp-server/

# Test installation
pip install jaegis-raverse-mcp-server

# Verify installation
raverse-mcp-server --version

# Should output: jaegis-raverse-mcp-server v1.0.0
```

### 3.7 Verify on pypi.org

1. Visit https://pypi.org/project/jaegis-raverse-mcp-server/
2. Verify version 1.0.0 is listed
3. Check package details are correct
4. Verify download links work

---

## Step 4: Create GitHub Release

### 4.1 Create Release on GitHub

```bash
# Using GitHub CLI (if installed)
gh release create v1.0.0 \
  --title "Release v1.0.0" \
  --notes "Initial release with all 35 MCP tools"

# Or manually on GitHub:
# 1. Go to https://github.com/usemanusai/jaegis-RAVERSE/releases
# 2. Click "Draft a new release"
# 3. Select tag v1.0.0
# 4. Add release title and notes
# 5. Click "Publish release"
```

### 4.2 Release Notes Template

```markdown
# Release v1.0.0 - Initial Release

## Overview
RAVERSE MCP Server v1.0.0 is now available on npm and PyPI!

## Installation

### NPM
```bash
npm install -g @raverse/mcp-server
```

### PyPI
```bash
pip install jaegis-raverse-mcp-server
```

### Docker
```bash
docker pull raverse/mcp-server:1.0.0
```

## Features
- ✅ All 35 MCP tools fully implemented
- ✅ Support for 20+ MCP clients
- ✅ Comprehensive documentation
- ✅ Production-ready code
- ✅ MIT License

## Tools Included
- Binary Analysis (4 tools)
- Knowledge Base & RAG (4 tools)
- Web Analysis (5 tools)
- Infrastructure (5 tools)
- Advanced Analysis (5 tools)
- Management (4 tools)
- Utilities (5 tools)
- System (4 tools)
- NLP & Validation (2 tools)

## Documentation
- [Installation Guide](INSTALLATION.md)
- [Quick Start](QUICKSTART.md)
- [MCP Client Setup](MCP_CLIENT_SETUP.md)
- [Integration Guide](INTEGRATION_GUIDE.md)
- [Tools Registry](TOOLS_REGISTRY_COMPLETE.md)

## Downloads
- [npm Package](https://www.npmjs.com/package/@raverse/mcp-server)
- [PyPI Package](https://pypi.org/project/jaegis-raverse-mcp-server/)
- [Docker Image](https://hub.docker.com/r/raverse/mcp-server)

## Support
- GitHub Issues: https://github.com/usemanusai/jaegis-RAVERSE/issues
- Documentation: https://github.com/usemanusai/jaegis-RAVERSE/tree/main/jaegis-RAVERSE-mcp-server
```

---

## Step 5: Verify All Distributions

### 5.1 Verify NPM Package

```bash
# Install from npm
npm install -g @raverse/mcp-server

# Test
raverse-mcp-server --version
raverse-mcp-server --help

# Uninstall
npm uninstall -g @raverse/mcp-server
```

### 5.2 Verify PyPI Package

```bash
# Create test environment
python -m venv test_env
source test_env/bin/activate

# Install from PyPI
pip install jaegis-raverse-mcp-server

# Test
raverse-mcp-server --version
raverse-mcp-server --help

# Cleanup
deactivate
rm -rf test_env
```

### 5.3 Verify Docker Image

```bash
# Pull image
docker pull raverse/mcp-server:1.0.0

# Test
docker run raverse/mcp-server:1.0.0 --version

# Cleanup
docker rmi raverse/mcp-server:1.0.0
```

---

## Step 6: Announce Release

### 6.1 Update Repository README

Update main `README.md` at repository root:

```markdown
## Installation

### NPM
```bash
npm install -g @raverse/mcp-server
```

### PyPI
```bash
pip install jaegis-raverse-mcp-server
```

### Docker
```bash
docker pull raverse/mcp-server:latest
```

See [Installation Guide](jaegis-RAVERSE-mcp-server/INSTALLATION.md) for details.
```

### 6.2 Update Repository Topics

On GitHub repository settings:
- Add topics: `mcp-server`, `npm-package`, `pypi-package`, `binary-analysis`, `reverse-engineering`

### 6.3 Announce on Social Media

- Tweet about release
- Post on relevant forums
- Update documentation sites

---

## Troubleshooting

### NPM Publishing Issues

**Error: "You must be logged in"**
```bash
npm login
npm whoami
```

**Error: "Package name already exists"**
- Check if package already published
- Use different scoped name

**Error: "Permission denied"**
- Verify npm account has publish permissions
- Check 2FA settings

### PyPI Publishing Issues

**Error: "Invalid distribution"**
```bash
twine check dist/*
```

**Error: "Invalid credentials"**
```bash
# Use API token instead
# Username: __token__
# Password: pypi-AgEIcHlwaS5vcmc...
```

**Error: "File already exists"**
- Version already published
- Bump version and rebuild

### General Issues

**Package not appearing**
- Wait 5-10 minutes for indexing
- Clear package manager cache
- Verify on registry website

**Installation fails**
- Check Python/Node version
- Verify dependencies installed
- Check network connectivity

---

## Post-Publishing

### 6.1 Monitor Downloads

- npm: https://www.npmjs.com/package/@raverse/mcp-server
- PyPI: https://pypi.org/project/jaegis-raverse-mcp-server/

### 6.2 Respond to Issues

- Monitor GitHub issues
- Respond to user feedback
- Fix bugs promptly

### 6.3 Plan Next Release

- Gather feedback
- Plan features
- Schedule next release

---

**Last Updated**: October 27, 2025
**Version**: 1.0.0

