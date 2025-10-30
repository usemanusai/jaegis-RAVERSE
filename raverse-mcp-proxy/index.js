/**
 * RAVERSE MCP Proxy - Cloudflare Worker
 * 
 * This worker proxies requests to the RAVERSE MCP server running on Render.
 * It provides edge caching, request routing, and performance optimization.
 * 
 * Deployment: https://raverse-mcp-proxy.use-manus-ai.workers.dev
 * Backend: https://jaegis-raverse.onrender.com
 */

const BACKEND_URL = "https://jaegis-raverse.onrender.com";
const CACHE_TTL = 3600; // 1 hour
const HEALTH_CHECK_INTERVAL = 300; // 5 minutes

/**
 * Main fetch handler for incoming requests
 */
export default {
  async fetch(request, env, ctx) {
    try {
      // Log incoming request
      console.error(`[RAVERSE-MCP-PROXY] ${request.method} ${request.url}`);

      // Handle CORS preflight
      if (request.method === "OPTIONS") {
        return handleCORS(request);
      }

      // Parse URL
      const url = new URL(request.url);
      const pathname = url.pathname;

      // Health check endpoint
      if (pathname === "/health" || pathname === "/health/") {
        return await handleHealthCheck(env);
      }

      // Proxy to backend
      return await proxyToBackend(request, env, ctx);
    } catch (error) {
      console.error(`[RAVERSE-MCP-PROXY] Error: ${error.message}`);
      return new Response(
        JSON.stringify({
          error: "Internal Server Error",
          message: error.message,
          timestamp: new Date().toISOString(),
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    }
  },

  /**
   * Scheduled handler for periodic health checks
   */
  async scheduled(event, env, ctx) {
    console.error("[RAVERSE-MCP-PROXY] Running scheduled health check");
    await checkBackendHealth(env);
  },
};

/**
 * Handle CORS preflight requests
 */
function handleCORS(request) {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      "Access-Control-Max-Age": "86400",
    },
  });
}

/**
 * Handle health check requests
 */
async function handleHealthCheck(env) {
  try {
    const response = await fetch(`${BACKEND_URL}/health`, {
      method: "GET",
      headers: {
        "User-Agent": "RAVERSE-MCP-Proxy/1.0",
      },
    });

    const data = await response.json();

    return new Response(
      JSON.stringify({
        status: "healthy",
        proxy: "operational",
        backend: data.status || "unknown",
        timestamp: new Date().toISOString(),
        uptime: data.uptime || "unknown",
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-cache",
        },
      }
    );
  } catch (error) {
    console.error(`[RAVERSE-MCP-PROXY] Health check failed: ${error.message}`);
    return new Response(
      JSON.stringify({
        status: "unhealthy",
        proxy: "operational",
        backend: "unreachable",
        error: error.message,
        timestamp: new Date().toISOString(),
      }),
      {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      }
    );
  }
}

/**
 * Proxy request to backend with caching and retry logic
 */
async function proxyToBackend(request, env, ctx) {
  const url = new URL(request.url);
  const cacheKey = new Request(url.toString(), { method: request.method });
  const cache = caches.default;

  // Check cache for GET requests
  if (request.method === "GET") {
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      console.error(`[RAVERSE-MCP-PROXY] Cache hit for ${url.pathname}`);
      return addCORSHeaders(cachedResponse.clone());
    }
  }

  // Build backend URL
  const backendUrl = new URL(url.pathname + url.search, BACKEND_URL);

  // Create forwarded request
  const forwardedRequest = new Request(backendUrl, {
    method: request.method,
    headers: buildForwardedHeaders(request),
    body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
  });

  // Proxy with retry logic
  let response;
  let lastError;

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      response = await fetch(forwardedRequest.clone());

      // Cache successful GET responses
      if (request.method === "GET" && response.status === 200) {
        const cacheResponse = response.clone();
        ctx.waitUntil(
          cache.put(
            cacheKey,
            new Response(cacheResponse.body, {
              status: cacheResponse.status,
              headers: {
                ...Object.fromEntries(cacheResponse.headers),
                "Cache-Control": `public, max-age=${CACHE_TTL}`,
              },
            })
          )
        );
      }

      return addCORSHeaders(response);
    } catch (error) {
      lastError = error;
      console.error(
        `[RAVERSE-MCP-PROXY] Attempt ${attempt + 1} failed: ${error.message}`
      );

      // Exponential backoff
      if (attempt < 2) {
        await new Promise((resolve) =>
          setTimeout(resolve, Math.pow(2, attempt) * 1000)
        );
      }
    }
  }

  // All retries failed
  console.error(
    `[RAVERSE-MCP-PROXY] All retry attempts failed: ${lastError.message}`
  );
  return new Response(
    JSON.stringify({
      error: "Backend Service Unavailable",
      message: lastError.message,
      timestamp: new Date().toISOString(),
    }),
    {
      status: 503,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    }
  );
}

/**
 * Build forwarded headers for backend request
 */
function buildForwardedHeaders(request) {
  const headers = new Headers(request.headers);

  // Add proxy headers
  headers.set("X-Forwarded-By", "Cloudflare-Worker");
  headers.set("X-Forwarded-Proto", "https");
  headers.set("X-Forwarded-Host", new URL(request.url).hostname);
  headers.set("X-Real-IP", request.headers.get("CF-Connecting-IP") || "unknown");

  // Remove hop-by-hop headers
  headers.delete("Connection");
  headers.delete("Keep-Alive");
  headers.delete("Transfer-Encoding");
  headers.delete("Upgrade");

  return headers;
}

/**
 * Add CORS headers to response
 */
function addCORSHeaders(response) {
  const newResponse = new Response(response.body, response);
  newResponse.headers.set("Access-Control-Allow-Origin", "*");
  newResponse.headers.set(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS, PATCH"
  );
  newResponse.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With"
  );
  return newResponse;
}

/**
 * Check backend health (for scheduled events)
 */
async function checkBackendHealth(env) {
  try {
    const response = await fetch(`${BACKEND_URL}/health`);
    const data = await response.json();
    console.error(
      `[RAVERSE-MCP-PROXY] Backend health: ${data.status || "unknown"}`
    );
  } catch (error) {
    console.error(
      `[RAVERSE-MCP-PROXY] Backend health check failed: ${error.message}`
    );
  }
}

