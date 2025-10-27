## RAVERSE — Offline Edition
### AI Multi‑Agent Binary Patching System for Local Analysis

**Version 2.0.0 (Offline Edition)** | **Date: October 25, 2025**

⚠️ **IMPORTANT CLARIFICATION** ⚠️

This is the **OFFLINE EDITION** of RAVERSE:
- ✅ **Runs LOCALLY** on your desktop/workstation
- ✅ **Analyzes LOCAL targets** (local binaries, local files, local applications)
- ✅ **No remote/online target analysis** (see README-Online.md for remote target analysis)

Automates bypassing simple password checks in **LOCAL binaries** using AI‑assisted analysis and patching with production-ready PostgreSQL and Redis integration. Intended strictly for educational and authorized testing purposes.

### 🚀 Highlights

- **Production-Ready Infrastructure:** Docker Compose with PostgreSQL 17 (pgvector) and Redis 8.2
- **Vector Search:** Semantic similarity search for disassembly patterns using HNSW indexes
- **Intelligent Caching:** Multi-layer caching (Redis + PostgreSQL) for LLM responses and analysis results
- **Modular Agents:** Comprehensive test coverage with Testcontainers integration
- **Environment‑Based Config:** Centralized settings with `.env` support
- **Structured Logging:** Console and file logging with token usage tracking
- **Safer Patching:** Automatic backups, VA→file offset conversion, comprehensive validation
- **Free‑Tier LLM Optimization:** JSON-focused prompts, connection pooling, retry strategy
- **MCP-Guided Development:** Built with Context7 (library docs) and Hyperbrowser (best practices research)
- **CPU-Optimized:** No GPU required, runs efficiently on 16-32GB RAM systems

### 🐳 Quick Start (Docker - Recommended)

**Prerequisites:** Docker Engine 28.5.1+, Docker Compose v2.40.2+

#### Windows (PowerShell)
```powershell
# 1. Clone and navigate
git clone https://github.com/your-org/raverse.git
cd raverse

# 2. Configure environment
Copy-Item .env.example .env
# Edit .env and set OPENROUTER_API_KEY

# 3. Start services
.\examples\docker_quickstart.ps1

# 4. Analyze a binary
docker-compose exec raverse-app python main.py /app/binaries/your_binary.exe
```

#### Linux/macOS (Bash)
```bash
# 1. Clone and navigate
git clone https://github.com/your-org/raverse.git
cd raverse

# 2. Configure environment
cp .env.example .env
# Edit .env and set OPENROUTER_API_KEY

# 3. Start services
chmod +x examples/docker_quickstart.sh
./examples/docker_quickstart.sh

# 4. Analyze a binary
docker-compose exec raverse-app python main.py /app/binaries/your_binary.exe
```

**Services Started:**
- PostgreSQL 17 with pgvector: `localhost:5432`
- Redis 8.2: `localhost:6379`
- RAVERSE Application: Running in container

**Optional Development Tools:**
```bash
# Start pgAdmin and RedisInsight
docker-compose --profile dev up -d

# Access tools
# pgAdmin: http://localhost:5050
# RedisInsight: http://localhost:5540
```

---

### 🐍 Quick Start (Standalone Python)

**Prerequisites:** Python 3.13+

#### Windows (PowerShell)
```powershell
# 1. Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
Copy-Item .env.example .env
# Edit .env and set OPENROUTER_API_KEY

# 4. Run analysis (standalone mode, no database)
python main.py your_binary.exe --no-database
```

#### Linux/macOS (Bash)
```bash
# 1. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and set OPENROUTER_API_KEY

# 4. Run analysis (standalone mode, no database)
python main.py your_binary.exe --no-database
```

---

### 🧪 Tests

#### Unit Tests (Standalone)
```bash
# Activate virtual environment first
pytest -v --cov=agents --cov=utils
```

#### Integration Tests (with Testcontainers)
```bash
# Requires Docker running
pytest -v --cov=agents --cov=utils tests/test_database.py tests/test_cache.py
```

#### Full Test Suite
```bash
pytest -v --cov=agents --cov=utils --cov-report=html
# View coverage report: htmlcov/index.html
```

---

### 🏗️ Architecture

#### System Overview
```
┌─────────────────────────────────────────────────────────┐
│                  RAVERSE Application                    │
│  ┌──────────────────────────────────────────────────┐   │
│  │         OrchestratingAgent (Main Controller)     │   │
│  │  - OpenRouter API integration                    │   │
│  │  - Session-based connection pooling              │   │
│  │  - Multi-layer caching (Redis + PostgreSQL)      │   │
│  │  - Binary metadata extraction                    │   │
│  └────┬─────────────────────────────────────────────┘   │
│       │                                                  │
│  ┌────▼──────────────────────────────────────────────┐  │
│  │  Agent Pipeline (Sequential Execution)           │  │
│  │  1. DisassemblyAnalysisAgent (DAA)               │  │
│  │  2. LogicIdentificationMappingAgent (LIMA)       │  │
│  │  3. PatchingExecutionAgent (PEA)                 │  │
│  │  4. VerificationAgent (VA)                       │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────┬───────────────────────────────────────────┘
              │
    ┌─────────┴─────────┐
    │                   │
┌───▼────────────┐  ┌──▼──────────┐
│  PostgreSQL 17 │  │  Redis 8.2  │
│  + pgvector    │  │  RDB + AOF  │
│                │  │             │
│  - Binaries    │  │  - Sessions │
│  - Analysis    │  │  - LLM Cache│
│  - Patches     │  │  - Analysis │
│  - LLM Cache   │  │  - Metadata │
│  - Vectors     │  │             │
└────────────────┘  └─────────────┘
```

#### Agent Responsibilities

**OrchestratingAgent**
- Coordinates all agents in sequential pipeline
- Manages OpenRouter API calls with retry logic
- Implements multi-layer caching (Redis → PostgreSQL → API)
- Tracks binary metadata and analysis history
- Session-based connection pooling for performance

**DisassemblyAnalysisAgent (DAA)**
- Requests disassembly from OpenRouter
- PE/ELF-aware prompts with format-specific guidance
- JSON-focused output for structured parsing
- Caches disassembly results in Redis/PostgreSQL

**LogicIdentificationMappingAgent (LIMA)**
- Extracts password check logic from disassembly
- Identifies `compare_addr`, `jump_addr`, `opcode`
- x86 opcode reference for accurate identification
- JSON parsing with regex fallback

**PatchingExecutionAgent (PEA)**
- Validates patch parameters
- Creates automatic backup before modification
- Writes opcode bytes to binary
- VA→file offset conversion for PE/ELF
- Records patch history in database

**VerificationAgent (VA)**
- Executes patched binary with test input
- 10-second timeout for safety
- Validates patch success
- Stores verification results

#### Database Schema

**PostgreSQL Tables:**
- `binaries`: Binary file metadata and status
- `disassembly_cache`: Cached disassembly with vector embeddings
- `analysis_results`: AI agent analysis outputs
- `patch_history`: All patching operations
- `llm_cache`: Cached LLM responses
- `vector_search_index`: Semantic search index

**Redis Keys:**
- `session:*`: User sessions
- `analysis:*`: Analysis results
- `disasm:*`: Disassembly cache
- `llm:*`: LLM response cache
- `ratelimit:*`: Rate limiting counters
- `binary:*`: Binary metadata

---

### 📚 Documentation

- **[DOCKER_DEPLOYMENT.md](docs/DOCKER_DEPLOYMENT.md)** — Complete Docker deployment guide with production best practices
- **[ONBOARDING.md](docs/ONBOARDING.md)** — Comprehensive guide for AI agents and developers
- **[BINARY_PATCHING_BEST_PRACTICES.md](docs/BINARY_PATCHING_BEST_PRACTICES.md)** — PE/ELF formats, VA-to-offset conversion, x86 opcodes, safety checklist
- **[OPENROUTER_OPTIMIZATION.md](docs/OPENROUTER_OPTIMIZATION.md)** — Rate limits, token optimization, connection pooling, timeout configuration
- **[MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md)** — How Context7 and Hyperbrowser MCP servers were used during development
- **[AI_RESPONSE_FORMAT.md](docs/AI_RESPONSE_FORMAT.md)** — Expected JSON formats for agent responses

---

### 🔧 Configuration

All settings can be configured via environment variables in `.env`:

```bash
# OpenRouter API
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=raverse
POSTGRES_PASSWORD=raverse_secure_password_2025
POSTGRES_DB=raverse

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=raverse_redis_password_2025

# Application
LOG_LEVEL=INFO
CACHE_TTL_LLM=604800  # 7 days
CACHE_TTL_ANALYSIS=86400  # 24 hours
```

See `.env.example` for all available options.

---

### 🔒 Legal & Ethics

**IMPORTANT:** Use only on binaries you own or are authorized to analyze.

- Reverse engineering may violate software licenses
- Unauthorized modification of software is illegal in many jurisdictions
- This tool is for educational and authorized security research only
- See [BINARY_PATCHING_BEST_PRACTICES.md](docs/BINARY_PATCHING_BEST_PRACTICES.md) Section 7 for legal considerations

---

### 📊 Performance

**Benchmarks (16GB RAM, 4-core CPU):**
- Binary analysis: 5-15 seconds (with caching: <1 second)
- LLM API calls: 2-5 seconds (with caching: <100ms)
- Database queries: <10ms (with indexes)
- Redis cache: <1ms

**Optimization Features:**
- Connection pooling (PostgreSQL: 10 connections, Redis: 50 connections)
- Multi-layer caching (Redis → PostgreSQL → API)
- HNSW vector indexes for fast similarity search
- Automatic retry with exponential backoff
- Token usage optimization (500 tokens for JSON, 2000 for analysis)

---

### 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

### 📊 RAVERSE Editions Comparison

| Feature | Offline Edition | Online Edition |
|---------|-----------------|----------------|
| **Target Location** | LOCAL (your machine) | REMOTE/ONLINE (internet targets) |
| **Deployment** | Local desktop/workstation | Local desktop/workstation |
| **Target Types** | Local binaries, files, applications | Web apps, APIs, cloud services, online resources |
| **Network Required** | No (optional for LLM APIs) | Yes (to reach remote targets) |
| **Primary Use Cases** | Binary analysis, local patching, malware analysis | Web app testing, API analysis, cloud security |
| **Tools Focus** | Ghidra, IDA, binary analysis tools | Proxies, browser automation, web scanners |
| **Data Privacy** | All analysis stays local | Network traffic to remote targets |
| **Documentation** | README-Offline.md (this file) | README-Online.md |

**Key Distinction:** Both editions are LOCAL applications. The difference is WHERE the analysis targets are located.

---

### 📝 License

[Your License Here]

---

### 🙏 Acknowledgments

- Built with [OpenRouter](https://openrouter.ai/) for LLM access
- PostgreSQL [pgvector](https://github.com/pgvector/pgvector) for vector search
- Redis for high-performance caching
- MCP servers (Context7, Hyperbrowser) for development research
- Testcontainers for integration testing

---

**Version:** 2.0.0
**Last Updated:** October 25, 2025
**Status:** Production-Ready

