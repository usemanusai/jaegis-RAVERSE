# NPM Publishing Guide

**Status**: Ready for Publishing
**Package**: @raverse/mcp-server
**Version**: 1.0.0
**Registry**: https://registry.npmjs.org/

---

## Prerequisites

### 1. NPM Account
- Account: usemanusai
- Email: use.manus.ai@gmail.com
- Status: ✅ Account exists

### 2. NPM CLI
- Version: Latest
- Status: ✅ Installed

### 3. Package Configuration
- ✅ package.json created
- ✅ .npmignore created
- ✅ bin/raverse-mcp-server.js created
- ✅ All metadata configured

### 4. Scoped Package
- Scope: @raverse
- Package: mcp-server
- Full name: @raverse/mcp-server
- Access: public

---

## Publishing Steps

### Step 1: Verify Package Configuration

```bash
cd jaegis-RAVERSE-mcp-server

# Check package.json
cat package.json

# Verify bin entry point
cat bin/raverse-mcp-server.js

# Check .npmignore
cat .npmignore
```

### Step 2: Login to NPM

```bash
npm login

# When prompted:
# Username: usemanusai
# Password: [your-npm-password]
# Email: use.manus.ai@gmail.com
# Authenticator app code: [if 2FA enabled]
```

### Step 3: Verify Login

```bash
npm whoami
# Expected output: usemanusai
```

### Step 4: Publish Package

```bash
npm publish --access public

# For scoped packages, --access public is required
```

**Expected Output**:
```
npm notice Publishing to https://registry.npmjs.org/
npm notice Publishing @raverse/mcp-server@1.0.0
npm notice Packaged files:
npm notice - package.json
npm notice - README.md
npm notice - bin/raverse-mcp-server.js
npm notice - jaegis_raverse_mcp_server/...
npm notice - ...
+ @raverse/mcp-server@1.0.0
```

---

## Post-Publishing Verification

### 1. Check NPM Package Page
- URL: https://www.npmjs.com/package/@raverse/mcp-server
- Verify version 1.0.0 is listed
- Verify description is correct
- Verify all files are present
- Verify download count

### 2. Test Installation (Global)
```bash
npm install -g @raverse/mcp-server

# Verify
raverse-mcp-server --version
raverse-mcp-server --help

# Uninstall
npm uninstall -g @raverse/mcp-server
```

### 3. Test Installation (Local)
```bash
# Create test directory
mkdir test-raverse
cd test-raverse

# Initialize npm project
npm init -y

# Install package
npm install @raverse/mcp-server

# Verify
npx raverse-mcp-server --version

# Cleanup
cd ..
rm -rf test-raverse
```

### 4. Check Package Info
```bash
npm view @raverse/mcp-server

# Or specific version
npm view @raverse/mcp-server@1.0.0
```

**Expected Output**:
```
@raverse/mcp-server@1.0.0 | MIT | deps: 0 | versions: 1

RAVERSE MCP Server with 35 tools for binary analysis, web analysis, and more

bin: raverse-mcp-server

dist
.tarball: https://registry.npmjs.org/@raverse/mcp-server/-/mcp-server-1.0.0.tgz
.shasum: [hash]
.integrity: [hash]
.unpackedSize: [size]

maintainers:
- usemanusai <use.manus.ai@gmail.com>

dist-tags:
latest: 1.0.0
```

---

## Package Contents

### Files Included
- package.json
- README.md
- LICENSE
- bin/raverse-mcp-server.js
- jaegis_raverse_mcp_server/ (all Python modules)
- pyproject.toml
- requirements.txt
- .env.example

### Files Excluded (.npmignore)
- .git/
- .gitignore
- .env
- .venv/
- __pycache__/
- *.pyc
- .pytest_cache/
- .coverage
- dist/
- build/
- *.egg-info/
- tests/
- docs/
- .github/
- .editorconfig
- .pre-commit-config.yaml

---

## Troubleshooting

### Issue: "You must be logged in"
**Solution**: Run `npm login` and verify with `npm whoami`

### Issue: "Package name already exists"
**Solution**: 
- Check if package already published
- Use different scope or name
- Or update existing package with new version

### Issue: "Permission denied"
**Solution**:
- Verify npm account has publish permissions
- Check if scoped package access is set to public
- Verify 2FA if enabled

### Issue: "Invalid package.json"
**Solution**:
- Validate JSON syntax
- Check required fields (name, version, description)
- Run `npm publish --dry-run` to test

### Issue: "Bin entry point not found"
**Solution**:
- Verify bin/raverse-mcp-server.js exists
- Check file permissions
- Verify shebang line: `#!/usr/bin/env node`

---

## Package Information

### Name
- Scoped: @raverse/mcp-server
- Scope: @raverse
- Package: mcp-server

### Version
- Current: 1.0.0
- Semantic Versioning: MAJOR.MINOR.PATCH

### Description
RAVERSE MCP Server with 35 tools for binary analysis, web analysis, infrastructure, and more

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

### Bin Entry Point
- Command: raverse-mcp-server
- Script: bin/raverse-mcp-server.js
- Function: Spawns Python MCP server

### License
- MIT

### Repository
- URL: https://github.com/usemanusai/jaegis-RAVERSE.git
- Type: git

### Homepage
- https://github.com/usemanusai/jaegis-RAVERSE

### Bugs
- URL: https://github.com/usemanusai/jaegis-RAVERSE/issues

---

## NPM Scripts

```json
{
  "scripts": {
    "setup": "npm install && pip install -r requirements.txt",
    "test": "pytest tests/",
    "dev": "raverse-mcp-server --dev",
    "build": "python -m build",
    "publish": "npm publish --access public"
  }
}
```

---

## Success Criteria

✅ Package published to npm
✅ Version 1.0.0 visible on npm
✅ Package metadata correct
✅ Installation works with npm
✅ CLI command accessible globally
✅ Bin entry point works
✅ No errors during installation

---

**Status**: Ready for Publishing
**Next Step**: Execute publishing commands

