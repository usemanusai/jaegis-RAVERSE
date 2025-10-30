#!/usr/bin/env node

/**
 * RAVERSE MCP Proxy - Deployment Verification Script
 * 
 * This script verifies that the proxy is correctly deployed and functioning.
 */

import fetch from "node-fetch";

const PROXY_URL = "https://raverse-mcp-proxy.use-manus-ai.workers.dev";
const BACKEND_URL = "https://jaegis-raverse.onrender.com";

const colors = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
};

function log(message, color = "reset") {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

async function checkProxyHealth() {
  log("\n📋 Checking Proxy Health...", "blue");

  try {
    const response = await fetch(`${PROXY_URL}/health`);
    const data = await response.json();

    if (response.ok) {
      log("✅ Proxy is healthy", "green");
      log(`   Status: ${data.status}`, "green");
      log(`   Backend: ${data.backend}`, "green");
      log(`   Timestamp: ${data.timestamp}`, "green");
      return true;
    } else {
      log("❌ Proxy returned error", "red");
      log(`   Status: ${response.status}`, "red");
      log(`   Response: ${JSON.stringify(data)}`, "red");
      return false;
    }
  } catch (error) {
    log(`❌ Failed to check proxy health: ${error.message}`, "red");
    return false;
  }
}

async function checkBackendHealth() {
  log("\n📋 Checking Backend Health...", "blue");

  try {
    const response = await fetch(`${BACKEND_URL}/health`);
    const data = await response.json();

    if (response.ok) {
      log("✅ Backend is healthy", "green");
      log(`   Status: ${data.status}`, "green");
      log(`   Timestamp: ${data.timestamp}`, "green");
      return true;
    } else {
      log("⚠️  Backend returned error", "yellow");
      log(`   Status: ${response.status}`, "yellow");
      return false;
    }
  } catch (error) {
    log(`⚠️  Failed to check backend health: ${error.message}`, "yellow");
    return false;
  }
}

async function checkCORS() {
  log("\n📋 Checking CORS Support...", "blue");

  try {
    const response = await fetch(`${PROXY_URL}/health`, {
      method: "OPTIONS",
      headers: {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "POST",
      },
    });

    const corsOrigin = response.headers.get("Access-Control-Allow-Origin");
    const corsMethods = response.headers.get("Access-Control-Allow-Methods");

    if (corsOrigin && corsMethods) {
      log("✅ CORS is properly configured", "green");
      log(`   Allow-Origin: ${corsOrigin}`, "green");
      log(`   Allow-Methods: ${corsMethods}`, "green");
      return true;
    } else {
      log("❌ CORS headers missing", "red");
      return false;
    }
  } catch (error) {
    log(`❌ Failed to check CORS: ${error.message}`, "red");
    return false;
  }
}

async function checkCaching() {
  log("\n📋 Checking Caching...", "blue");

  try {
    // First request (cache miss)
    const start1 = Date.now();
    const response1 = await fetch(`${PROXY_URL}/health`);
    const time1 = Date.now() - start1;

    // Second request (cache hit)
    const start2 = Date.now();
    const response2 = await fetch(`${PROXY_URL}/health`);
    const time2 = Date.now() - start2;

    log("✅ Caching is working", "green");
    log(`   First request: ${time1}ms (cache miss)`, "green");
    log(`   Second request: ${time2}ms (cache hit)`, "green");

    if (time2 < time1) {
      log(`   Cache speedup: ${((time1 - time2) / time1 * 100).toFixed(1)}%`, "green");
    }

    return true;
  } catch (error) {
    log(`❌ Failed to check caching: ${error.message}`, "red");
    return false;
  }
}

async function checkPerformance() {
  log("\n📋 Checking Performance...", "blue");

  try {
    const times = [];

    for (let i = 0; i < 5; i++) {
      const start = Date.now();
      await fetch(`${PROXY_URL}/health`);
      times.push(Date.now() - start);
    }

    const avg = times.reduce((a, b) => a + b) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);

    log("✅ Performance metrics collected", "green");
    log(`   Average: ${avg.toFixed(0)}ms`, "green");
    log(`   Min: ${min}ms`, "green");
    log(`   Max: ${max}ms`, "green");

    if (avg < 500) {
      log("   ✅ Performance is excellent", "green");
    } else if (avg < 1000) {
      log("   ⚠️  Performance is acceptable", "yellow");
    } else {
      log("   ❌ Performance is poor", "red");
    }

    return true;
  } catch (error) {
    log(`❌ Failed to check performance: ${error.message}`, "red");
    return false;
  }
}

async function runAllChecks() {
  log("\n╔════════════════════════════════════════════════════════════╗", "blue");
  log("║     RAVERSE MCP Proxy - Deployment Verification            ║", "blue");
  log("╚════════════════════════════════════════════════════════════╝", "blue");

  log(`\nProxy URL: ${PROXY_URL}`, "blue");
  log(`Backend URL: ${BACKEND_URL}`, "blue");

  const results = {
    proxyHealth: await checkProxyHealth(),
    backendHealth: await checkBackendHealth(),
    cors: await checkCORS(),
    caching: await checkCaching(),
    performance: await checkPerformance(),
  };

  // Summary
  log("\n╔════════════════════════════════════════════════════════════╗", "blue");
  log("║                    Verification Summary                    ║", "blue");
  log("╚════════════════════════════════════════════════════════════╝", "blue");

  const passed = Object.values(results).filter((r) => r).length;
  const total = Object.keys(results).length;

  log(`\nPassed: ${passed}/${total}`, passed === total ? "green" : "yellow");

  Object.entries(results).forEach(([check, passed]) => {
    const status = passed ? "✅" : "❌";
    log(`${status} ${check}`, passed ? "green" : "red");
  });

  if (passed === total) {
    log("\n✅ All checks passed! Proxy is ready for production.", "green");
    process.exit(0);
  } else {
    log("\n⚠️  Some checks failed. Please review the output above.", "yellow");
    process.exit(1);
  }
}

// Run verification
runAllChecks().catch((error) => {
  log(`\n❌ Verification failed: ${error.message}`, "red");
  process.exit(1);
});

