# NPX Package Issues - Diagnosis and Fixes

**Date**: 2025-10-30  
**Status**: 🔴 **CRITICAL - REQUIRES ACTION**

---

## Issue Summary

Two critical errors prevent MCP servers from running via NPX:

1. **Error 1 (EBUSY)**: `raverse-mcp-server` - File lock in NPM cache
2. **Error 2 (E404)**: `raverse-mcp-proxy` - Package not found on NPM registry

---

## Error 1: raverse-mcp-server - EBUSY (File Lock)

### Problem
```
npm error code EBUSY
npm error syscall rename
npm error errno -4082
npm error EBUSY: resource busy or locked, rename 'C:\Users\...\node_modules\raverse-mcp-server\bin'
```

### Root Cause
- Windows file locking issue in NPM cache
- File `raverse-mcp-server/bin` is locked by another process
- NPM cannot rename the file during extraction

### Package Status
- ✅ **Published on NPM**: raverse-mcp-server@1.0.10
- ✅ **Available**: https://www.npmjs.com/package/raverse-mcp-server
- ❌ **Executable via NPX**: Blocked by cache lock

### Solutions (In Order of Preference)

#### Solution 1A: Clear NPM Cache (Recommended)
```bash
# Step 1: Clear NPM cache
npm cache clean --force

# Step 2: Verify cache
npm cache verify

# Step 3: Try again
npx -y raverse-mcp-server@latest --version
```

#### Solution 1B: Delete Specific Cache Directory
```bash
# Windows PowerShell (as Administrator)
Remove-Item -Path "$env:APPDATA\npm-cache\_npx" -Recurse -Force

# Or Git Bash
rm -rf "C:\Users\[USERNAME]\AppData\Local\npm-cache\_npx"

# Then try again
npx -y raverse-mcp-server@latest --version
```

#### Solution 1C: Use Local Installation (Workaround)
```bash
# Install locally in project
npm install raverse-mcp-server@latest

# Run from node_modules
npx raverse-mcp-server --version
```

#### Solution 1D: Use Specific Version
```bash
# Try a different version
npx -y raverse-mcp-server@1.0.9 --version
```

#### Solution 1E: Restart Terminal and System
```bash
# Close all terminal windows
# Restart your computer
# Try again
npx -y raverse-mcp-server@latest --version
```

---

## Error 2: raverse-mcp-proxy - E404 (Not Found)

### Problem
```
npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/raverse-mcp-proxy
npm error 404  'raverse-mcp-proxy@latest' is not in this registry.
```

### Root Cause
- `raverse-mcp-proxy` package is NOT published to NPM registry
- Package exists locally but only as a Cloudflare Worker
- MCP configurations reference it via NPX, but it's not available

### Package Status
- ❌ **Not Published**: raverse-mcp-proxy not on NPM
- ✅ **Deployed**: https://raverse-mcp-proxy.use-manus-ai.workers.dev (Cloudflare Worker)
- ❌ **Installable via NPM**: Not available

### Solutions (In Order of Preference)

#### Solution 2A: Publish to NPM (Requires OTP)
```bash
# Navigate to package directory
cd raverse-mcp-proxy

# Publish with OTP (requires authenticator)
npm publish --access public --otp=<6-digit-code>

# After publishing, update MCP configs to use:
# "args": ["-y", "raverse-mcp-proxy@latest"]
```

**Note**: Requires one-time password from NPM authenticator.

#### Solution 2B: Remove from MCP Configurations (Recommended)
Since `raverse-mcp-proxy` is a Cloudflare Worker (not meant to be installed locally), remove it from all 21 MCP configuration files:

```json
// REMOVE THIS ENTIRE BLOCK from all 21 files:
"raverse-mcp-proxy": {
  "command": "npx",
  "args": ["-y", "raverse-mcp-proxy@latest"],
  "env": {
    "PROXY_URL": "https://raverse-mcp-proxy.use-manus-ai.workers.dev",
    "BACKEND_URL": "https://jaegis-raverse.onrender.com"
  }
}
```

**Rationale**: 
- raverse-mcp-proxy is a Cloudflare Worker, not a Node.js package
- It's already deployed at https://raverse-mcp-proxy.use-manus-ai.workers.dev
- The raverse-mcp-server already uses PROXY_URL to connect to it
- No need to install it locally via NPX

#### Solution 2C: Create Wrapper Package
Create a minimal NPM package that wraps the Cloudflare Worker:

```bash
# Create wrapper package
mkdir raverse-mcp-proxy-wrapper
cd raverse-mcp-proxy-wrapper
npm init -y

# Add to package.json:
# "bin": { "raverse-mcp-proxy": "bin/proxy.js" }

# Create bin/proxy.js that redirects to Cloudflare Worker
```

---

## Recommended Action Plan

### Immediate (Next 5 minutes)
1. **For Error 1**: Run `npm cache clean --force` and try again
2. **For Error 2**: Remove `raverse-mcp-proxy` from all 21 MCP config files

### Short-term (Next 30 minutes)
1. Test raverse-mcp-server after cache clear
2. Update all 21 MCP config files to remove raverse-mcp-proxy
3. Commit changes to GitHub

### Long-term (Optional)
1. If needed, publish raverse-mcp-proxy to NPM with OTP
2. Update MCP configs to include it again

---

## Testing After Fixes

### Test raverse-mcp-server
```bash
# Test version
npx -y raverse-mcp-server@latest --version

# Test help
npx -y raverse-mcp-server@latest --help

# Test with Augment Code config
npx -y raverse-mcp-server@latest
```

### Test MCP Configuration
```bash
# Test one configuration file
cat mcp-configs/other/augment-code.json

# Should only contain "raverse" server (no raverse-mcp-proxy)
```

---

## Files Affected

### 21 MCP Configuration Files to Update
- mcp-configs/anthropic/claude-desktop.json
- mcp-configs/cursor/cursor.json
- mcp-configs/jetbrains/jetbrains-ai.json
- mcp-configs/vscode/vscode-cline.json
- mcp-configs/vscode/vscode-roo-code.json
- mcp-configs/zed/zed-editor.json
- mcp-configs/other/aider.json
- mcp-configs/other/amazon-codewhisperer.json
- mcp-configs/other/augment-code.json
- mcp-configs/other/bolt-new.json
- mcp-configs/other/claude-web.json
- mcp-configs/other/continue-dev.json
- mcp-configs/other/devin-ai.json
- mcp-configs/other/github-copilot.json
- mcp-configs/other/gpt-4-web.json
- mcp-configs/other/lovable-dev.json
- mcp-configs/other/manus-ai.json
- mcp-configs/other/perplexity.json
- mcp-configs/other/replit.json
- mcp-configs/other/sourcegraph-cody.json
- mcp-configs/other/tabnine.json
- mcp-configs/other/v0-dev.json
- mcp-configs/other/windsurf.json

---

## Next Steps

1. ✅ Clear NPM cache for raverse-mcp-server
2. ⏳ Remove raverse-mcp-proxy from all 21 MCP config files
3. ⏳ Test raverse-mcp-server with Augment Code
4. ⏳ Commit and push changes to GitHub
5. ⏳ Verify all 21 configs work correctly

---

**Status**: Awaiting user action to proceed with fixes.

