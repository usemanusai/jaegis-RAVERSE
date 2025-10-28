# Quick Start - Update Augment Code for RAVERSE v1.0.8

## ⚡ 3-Minute Setup

### Step 1: Open Augment Code Settings
1. Click **Augment Settings** (gear icon)
2. Go to **Tools** section
3. Look for MCP Servers

### Step 2: Add/Update RAVERSE MCP Server

**If you have an old `raverse` entry:**
- Delete it first

**Add new entry:**
- Click **"+ Add MCP"**
- Fill in:

| Field | Value |
|-------|-------|
| Server Name | `raverse` |
| Command | `npx` |
| Arguments | `-y` |
| Arguments | `raverse-mcp-server@1.0.8` |

### Step 3: Add Environment Variables (Optional)

Click to add environment variables:
```
LOG_LEVEL = INFO
NODE_NO_WARNINGS = 1
NO_COLOR = 1
```

### Step 4: Save and Restart

1. Click **Save** or **Add**
2. **Close Augment Code completely**
3. **Wait 5 seconds**
4. **Reopen Augment Code**
5. **Wait 10 seconds for tool discovery**

### Step 5: Verify

Look in Tools section:
- ✅ Should see: `raverse (35) tools`
- ✅ Green indicator (not red)
- ✅ Can expand to see all tools

---

## 🎯 Expected Result

### Before
```
raverse ❌ (red dot, no tools)
```

### After
```
raverse (35) tools ✅ (green indicator)
```

---

## 🔧 If It Doesn't Work

### Issue: Still showing red dot

**Solution 1:** Clear cache
- Close Augment Code
- Delete Augment cache (if applicable)
- Restart Augment Code

**Solution 2:** Verify NPX works
```bash
npx -y raverse-mcp-server@1.0.8 --version
# Should output: raverse-mcp-server v1.0.8
```

**Solution 3:** Check Python
```bash
python --version
# Should be Python 3.13+
```

### Issue: Tools not showing after restart

1. Wait 10-15 seconds (tool discovery takes time)
2. Try refreshing the Tools panel
3. Restart Augment Code again

### Issue: Error messages

1. Set `LOG_LEVEL = DEBUG`
2. Restart Augment Code
3. Check console for error messages
4. Report issue with error message

---

## 📋 Configuration Reference

### Full Configuration
```json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-server@1.0.8"],
      "env": {
        "LOG_LEVEL": "INFO",
        "NODE_NO_WARNINGS": "1",
        "NO_COLOR": "1"
      }
    }
  }
}
```

### Minimal Configuration
```json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-server@1.0.8"]
    }
  }
}
```

---

## ✅ Verification Checklist

After setup, verify:

- [ ] Augment Code shows `raverse (35) tools`
- [ ] Green indicator (not red)
- [ ] Can expand tool list
- [ ] Can see all 35 tools
- [ ] Can click on a tool
- [ ] No errors in console

---

## 🎉 Success!

If you see `raverse (35) tools` with a green indicator, you're all set!

All 35 RAVERSE tools are now available in Augment Code.

---

## 📚 More Information

- **Full Setup Guide:** `AUGMENT_CODE_SETUP_v1.0.8.md`
- **Configuration File:** `AUGMENT_CODE_MCP_CONFIG_v1.0.8.json`
- **Technical Details:** `RAVERSE_MCP_FIX_SUMMARY.md`
- **Troubleshooting:** `AUGMENT_CODE_SETUP_v1.0.8.md` (Troubleshooting section)

---

## 🚀 Ready to Go!

Your RAVERSE MCP server is now properly configured and ready to use!

Enjoy all 35 tools in Augment Code! 🎉

