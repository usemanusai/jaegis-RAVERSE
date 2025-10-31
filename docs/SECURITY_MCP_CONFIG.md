## Augment Code MCP Configuration (Production Security)

This guide shows how to configure Augment Code to run the RAVERSE MCP Server with production‑grade security, proper tool exposure, and TLS verification against Aiven PostgreSQL.

Key guarantees:
- Tools are correctly exposed via MCP (you should see a tool count like "raverse (35)")
- STDIO safety: all logs go to stderr; stdout carries only JSON‑RPC
- Aiven PostgreSQL connections are encrypted and can be verified with CA (verify‑full)
- Secrets live only in local JSON files ignored by Git

---

### 1) Create a local MCP config with real credentials

Create mcp-configs/other/augment-code.local.json (this file is gitignored) with your real endpoints and credentials.

Replace the values marked <REDACTED> with yours:

````json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-server@latest"],
      "env": {
        "PROXY_URL": "https://raverse-mcp-proxy.use-manus-ai.workers.dev",
        "BACKEND_URL": "https://jaegis-raverse.onrender.com",
        "LOG_LEVEL": "INFO",
        "SERVER_VERSION": "1.0.11",

        "REDIS_URL": "rediss://default:<REDACTED>@<your-valkey-host>:23056",

        "DATABASE_URL": "postgres://avnadmin:<REDACTED>@<your-pg-host>:23055/defaultdb?sslmode=require",

        "POSTGRES_CA_CERT": "-----BEGIN CERTIFICATE-----\n...your Aiven CA pem lines...\n-----END CERTIFICATE-----"
      }
    }
  }
}
````

Notes:
- The CA PEM can be embedded as a JSON string with \n escapes. The server automatically unescapes and writes it to a secure temp file, then upgrades sslmode=require → verify-full.
- Only raverse must be configured. The raverse-mcp-proxy entry is not needed as a local server and is disabled in the public config.


### 2) Public repo config stays sanitized

mcp-configs/other/augment-code.json (committed to Git) remains sanitized and contains placeholders. Never commit real secrets.

````json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-server@latest"],
      "env": {
        "PROXY_URL": "https://raverse-mcp-proxy.use-manus-ai.workers.dev",
        "BACKEND_URL": "https://jaegis-raverse.onrender.com",
        "LOG_LEVEL": "INFO",
        "SERVER_VERSION": "1.0.11",
        "REDIS_URL": "rediss://default:REDACTED@<host>:23056",
        "DATABASE_URL": "postgres://avnadmin:REDACTED@<host>:23055/defaultdb?sslmode=require",
        "POSTGRES_CA_CERT": ""
      }
    }
  }
}
````

Git ignore rules:
- .gitignore includes: `mcp-configs/**/*.local.json`


### 3) Start the server and verify tool exposure

- On Windows PowerShell:

````powershell
$env:REDIS_URL="rediss://default:<REDACTED>@<host>:23056";
$env:DATABASE_URL="postgres://avnadmin:<REDACTED>@<host>:23055/defaultdb?sslmode=require";
$env:POSTGRES_CA_CERT="-----BEGIN CERTIFICATE-----`n...`n-----END CERTIFICATE-----";
$env:PROXY_URL="https://raverse-mcp-proxy.use-manus-ai.workers.dev";
$env:BACKEND_URL="https://jaegis-raverse.onrender.com";
$env:LOG_LEVEL="INFO"; $env:SERVER_VERSION="1.0.11";

npx -y raverse-mcp-server@latest
````

- In Augment Code, select the "raverse" MCP server.
- You should see a tool count (e.g., "raverse (35)").
- If you see a red dot with no tool count, check client logs; ensure STDIO isn’t polluted by stdout logs. This server uses stderr for logs by default.


### 4) Security and TLS behavior

- If POSTGRES_CA_CERT is provided, the server:
  - Writes the CA to a temp file
  - Appends `sslrootcert=<temp>` to the DSN if missing
  - Forces `sslmode=verify-full` (replaces any existing sslmode)
- If POSTGRES_CA_CERT is not provided, the server honors the sslmode in DATABASE_URL as-is (default examples use `require`).


### 5) Troubleshooting

- Redis AUTH errors: ensure REDIS_URL includes `rediss://user:password@host:port`
- DB pool errors: verify DATABASE_URL host/port, and that your workstation can resolve and reach Aiven endpoints
- Tool list missing: client must send tools/list after initialize; this server implements initialize and tools/list per MCP
- STDIO corruption: do not print to stdout in client or wrapper; this server routes Node wrapper messages to stderr


### 6) Change log (security-relevant)

- Added POSTGRES_CA_CERT support with JSON-escaped newline handling
- Enforced verify-full when CA is supplied
- Routed Node wrapper logs to stderr to protect MCP stdio
- Sanitized public MCP config; introduced gitignore for all `*.local.json`

