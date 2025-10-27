## RAVERSE — AI Multi‑Agent Binary Patching System (Onboarding)

This document is a concise, structured guide for AI agents and developers to quickly understand and contribute to the RAVERSE codebase.

---

## 1) Project Overview
- Purpose: Automate bypassing simple password checks in binaries using AI‑assisted analysis and patching.
- Method: Coordinate multiple agents to (a) obtain disassembly context, (b) locate authentication logic, (c) patch conditional jumps, and (d) validate the bypass.
- Status: Modular package (agents/*), tests/, and structured logging (see README for migration notes).
- Legal: Use ONLY on binaries you own or are authorized to analyze.

---

## 2) Architecture Guide (Agents)
- **OrchestratingAgent (OA)**
  - Role: Main controller; wires agent calls and provides OpenRouter access with connection pooling.
  - Input: binary_path
  - Output: Final verification result string
  - Notes:
    - Uses `requests.Session` for connection reuse (MCP-guided: Context7 /psf/requests)
    - Automatic retry with exponential backoff via `HTTPAdapter` and `urllib3.Retry`
    - SHA-256 response caching to avoid redundant API calls
    - Configurable `max_tokens` parameter (default 500 for JSON responses)
    - Separate connect/read timeouts (10s, 30s) to avoid hanging

- **DisassemblyAnalysisAgent (DAA)**
  - Role: Requests an AI‑generated “disassembly”/analysis context for the binary.
  - Input: binary_path
  - Output: disassembly_output (string)
  - Notes:
    - Enhanced prompt with PE/ELF format awareness (MCP-guided: Hyperbrowser research)
    - Emphasizes instruction boundaries and specific x86 patterns (CMP, TEST, strcmp)
    - Requests structured JSON output with validation requirements
    - Input validation: checks file existence and read permissions

- **LogicIdentificationMappingAgent (LIMA)**
  - Role: Extracts key locations (compare, jump) and opcode from the AI output.
  - Input: disassembly_output
  - Output: { compare_addr, jump_addr, opcode }
  - Notes:
    - Enhanced prompt with x86 opcode reference table (JE=0x74, JNE=0x75, etc.)
    - Emphasizes instruction boundary awareness and short vs near jump distinction
    - JSON parsing with regex fallback for robustness
    - Hex address and opcode validation with safe defaults

- **PatchingExecutionAgent (PEA)**
  - Role: Modifies a byte at the computed file offset (jump_addr) to force success path.
  - Input: LIMA output, binary_path
  - Output: Path to patched binary (currently same path)
  - Notes:
    - Creates backup file (`<binary>.backup`) before patching
    - Validates hex address and opcode formats
    - TODO: Implement VA→file offset conversion for PE/ELF formats

- **VerificationAgent (VA)**
  - Role: Executes the patched binary and checks output for success signal.
  - Input: patched_binary_path, original_binary_path
  - Output: "CRACK SUCCESSFUL" | "CRACK FAILURE" | "VERIFICATION_TIMEOUT" | None
  - Notes:
    - Sends a wrong password via stdin; searches stdout for substring "success"
    - 10-second timeout to prevent hanging on infinite loops

Small code excerpts (reference):

<augment_code_snippet path="main.py" mode="EXCERPT">
````python
class OrchestratingAgent:
    def __init__(self, openrouter_api_key, model="meta-llama/llama-3.3-70b-instruct:free"):
        self.openrouter_api_key = openrouter_api_key
        self.model = model
        self.agents = {
            'DAA': DisassemblyAnalysisAgent(self),
            'LIMA': LogicIdentificationMappingAgent(self),
````
</augment_code_snippet>

<augment_code_snippet path="main.py" mode="EXCERPT">
````python
class LogicIdentificationMappingAgent:
    def parse_response(self, content):
        compare_addr = re.search(r'compare_addr: (0x[0-9a-fA-F]+)', content)
        jump_addr    = re.search(r'jump_addr: (0x[0-9a-fA-F]+)', content)
        opcode       = re.search(r'opcode: ([0-9a-fA-F]+)', content)
        return (compare_addr.group(1) if compare_addr else "0x0000",
                jump_addr.group(1)    if jump_addr    else "0x0000",
````
</augment_code_snippet>

---

## 3) Codebase Structure
- Repository root
  - agents/ — Modular agents package (orchestrator, disassembly_analysis, logic_identification, patching_execution, verification)
  - main.py — Entry point (reads OPENROUTER_API_KEY from env; sets up logging)
  - tests/ — Unit tests for agents
  - docs/ — Documentation (this file, AI_RESPONSE_FORMAT.md)
  - .env.example — Template env file
  - requirements.txt — Dependencies

---

## 4) Technical Stack
- Language: Python 3.9+
- Libraries: requests (HTTP client)
- AI Provider: OpenRouter API (Chat Completions)
  - Default model: meta-llama/llama-3.3-70b-instruct:free
  - Endpoint: https://openrouter.ai/api/v1/chat/completions
- System tools: subprocess for execution of binaries; direct file I/O for patching
- OS: Cross‑platform in principle; verification runs depend on the target binary’s platform

---

## 5) Workflow Documentation (End‑to‑End)
1. Disassemble/Analyze (DAA)
   - Builds a prompt with the binary path and requests AI to provide a disassembly/analysis context.
   - Output: text blob with addresses/opcodes (expected by LIMA parsing).

2. Identify Logic (LIMA)
   - Regex‑extracts `compare_addr`, `jump_addr`, `opcode` from model output.
   - Output example: { compare_addr: 0x40123A, jump_addr: 0x401245, opcode: 74 }

3. Patch (PEA)
   - Interprets `jump_addr` as a file offset (hex string) and seeks to that position.
   - Writes the chosen opcode (e.g., 0x74) at that offset.

4. Verify (VA)
   - Runs the patched binary; writes a wrong password to stdin.
   - Checks stdout for the substring "success" to declare a bypass.

Notes and caveats:
- AI output format is not guaranteed; adjust parsing to the model’s actual response.
- Mapping from virtual addresses to file offsets is non‑trivial in real binaries; current approach assumes direct file offset usage.
- Real disassembly typically requires external tools (e.g., objdump, radare2, Ghidra headless) — not currently integrated.

---

## 6) Development Guidelines
- Agent boundaries
  - Keep each agent single‑purpose (analysis, mapping, patching, verification).
  - Surface clear input/output contracts and avoid implicit coupling.

- OpenRouter usage
  - Centralize calls via OrchestratingAgent.call_openrouter (retries, token limits).
  - Prefer structured outputs (ask the model to return JSON with fields) to avoid brittle regex.

- Robust parsing
  - Validate fields (hex format, ranges); fail fast with actionable errors.
  - Add schema checks and default fallbacks; emit logs when using defaults.

- Patching safety
  - Never patch in‑place without a backup; prefer writing to a new file path.
  - Confirm address/offset mapping; do not assume VA/FO conversions.

- Verification reliability
  - Capture exit codes and stderr; allow configurable success patterns.
  - Add timeouts; handle non‑interactive binaries.

- Testing
  - Unit tests: mock OpenRouter responses; test LIMA.parse_response with varied content.
  - Integration tests: use a temp binary file; verify PEA writes expected bytes at offset.
  - E2E (optional): target a known sample with a trivial check; gate behind an opt‑in flag.

- Extensibility
  - Consider moving agents into a package structure: `agents/{orchestrator,daa,lima,pea,va}.py`.
  - Add pluggable disassemblers and verifiers; support multiple strategies via interfaces.

- Logging & observability
  - Add structured logs per agent; record prompts (redact secrets) and key decisions.

- Security & legal
  - Never embed API keys in code; restrict usage to authorized binaries only.

---

## 7) Quick Start Guide
Prerequisites
- Python 3.9+ installed

Setup (PowerShell)
- Create venv and install dependency:
  - `python -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; pip install requests`

Configure (Environment Variables)
- Copy `.env.example` to `.env` and set values:
  - `OPENROUTER_API_KEY=sk-or-...`
  - `OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free` (optional)
- Or set in PowerShell for the current session:
  - `$env:OPENROUTER_API_KEY = "sk-or-..."`

Run (PowerShell)
- `python .\main.py`

Notes
- API key is read from environment by default (no code edits needed).
- Logging writes to `raverse.log` and console.
- MCP servers (Context7, Hyperbrowser) were used during development for research and library documentation.
  - See [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for details on how to leverage these tools for future development.

<augment_code_snippet path="main.py" mode="EXCERPT">
````python
import logging
from agents import OrchestratingAgent

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    oa = OrchestratingAgent()  # Reads OPENROUTER_API_KEY from env
    print(oa.run("path/to/your/binary"))
````
</augment_code_snippet>

Troubleshooting
- Missing dependency: `pip install requests`
- API errors: verify key, network, model name; retries are built‑in.
- No success detected: check stdout pattern; binary may not be interactive; or address mapping incorrect.

---

## Appendix — OpenRouter API Call (Current Shape)
- POST https://openrouter.ai/api/v1/chat/completions
- Headers: `Authorization: Bearer <API_KEY>`, `Content-Type: application/json`
- Body: `{ model, messages: [{role: "user", content: prompt}], max_tokens }`
- Response: expect `choices[0].message.content` to contain parseable fields

