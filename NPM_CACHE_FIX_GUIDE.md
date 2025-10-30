# 🔧 NPM Cache EBUSY Error - Fix Guide

## Problem
When running `npx -y raverse-mcp-server@latest`, you get:
```
npm error code EBUSY
npm error syscall rename
npm error EBUSY: resource busy or locked, rename '...\node_modules\raverse-mcp-server\bin'
```

This is a **Windows file locking issue** where the npm cache becomes corrupted and locked.

---

## ✅ Solution: Clear NPM Cache

### Option 1: Quick Fix (Recommended)
```bash
# Kill any running node/npm processes
taskkill /F /IM node.exe 2>&1 || true
taskkill /F /IM npm.exe 2>&1 || true

# Wait a moment
timeout /t 3

# Delete the entire npm cache
rmdir /s /q "%APPDATA%\npm-cache"

# Try again
npx -y raverse-mcp-server@latest
```

### Option 2: PowerShell (Most Reliable)
```powershell
# Stop all node and npm processes
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process npm -ErrorAction SilentlyContinue | Stop-Process -Force

# Wait
Start-Sleep -Seconds 3

# Remove cache
Remove-Item -Path "$env:APPDATA\npm-cache" -Recurse -Force -ErrorAction SilentlyContinue

# Try again
npx -y raverse-mcp-server@latest
```

### Option 3: Bash/Git Bash
```bash
# Kill processes
taskkill /F /IM node.exe 2>&1 || true
taskkill /F /IM npm.exe 2>&1 || true

# Wait
sleep 3

# Remove cache
rm -rf "C:/Users/$(whoami)/AppData/Local/npm-cache"

# Try again
npx -y raverse-mcp-server@latest
```

---

## Alternative: Use Python Instead

If NPX continues to have issues, use the Python package directly:

```bash
# Install via pip
pip install jaegis-raverse-mcp-server

# Run the server
python -m jaegis_raverse_mcp_server.server
```

---

## Prevention

To prevent this issue in the future:

1. **Regularly clean npm cache:**
   ```bash
   npm cache clean --force
   ```

2. **Use npm ci instead of npm install:**
   ```bash
   npm ci
   ```

3. **Update npm to latest:**
   ```bash
   npm install -g npm@latest
   ```

4. **Use a different package manager:**
   - **Yarn:** `yarn global add raverse-mcp-server`
   - **PNPM:** `pnpm add -g raverse-mcp-server`

---

## Verification

After applying the fix, verify it works:

```bash
# Check version
npx -y raverse-mcp-server@latest --version

# Should output:
# raverse-mcp-server v1.0.11
```

---

## Still Having Issues?

If the problem persists:

1. **Restart your computer** - This clears all file locks
2. **Use Python package** - More reliable on Windows
3. **Use WSL2** - Windows Subsystem for Linux 2
4. **Use Docker** - Containerized solution

---

## Root Cause

This issue occurs because:
- Windows file locking is more aggressive than Unix
- npm cache can become corrupted during interrupted downloads
- Multiple npm processes can lock the same files
- Antivirus software sometimes interferes with file operations

The fix works by:
1. Stopping all npm/node processes
2. Deleting the corrupted cache
3. Forcing npm to re-download fresh packages

---

**Status:** ✅ **FIXED**

The RAVERSE MCP Server now works correctly with `npx -y raverse-mcp-server@latest`


