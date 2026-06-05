# AI Security Demo Platform

A locally-hosted AI security demonstration platform built for Palo Alto Networks.
Demonstrates AI runtime threats, MLOps pipeline security, and how Prisma AIRS detects and blocks threats at every layer.

---

## Architecture

```
Remote browser → Cloudflare WAF (IP allowlist) → Cloudflare Tunnel
                                                      └─ FastAPI :8000
                                                           ├─ React frontend (built dist/)
                                                           ├─ /api/* routes
                                                           ├─ Prisma AIRS (runtime scan)
                                                           ├─ Portkey Gateway → Ollama / Groq
                                                           └─ MCP Server (CVE / MITRE ATT&CK)

GitHub push / PR / schedule → GitHub Actions
  └─ Prisma AIRS Model Security Scan
       ├─ BLOCKED → pipeline fails
       └─ ALLOWED → model tagged as airs-approved on HuggingFace
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Attack Vector Panel** | 6 categories, 12 preset prompts for live demos |
| **Prisma AIRS Runtime** | Toggle threat detection on/off mid-demo |
| **Portkey Gateway** | Route traffic through Portkey with AIRS guardrails |
| **Multi-model switching** | Local Ollama or Groq (llama-4-scout, qwen3) |
| **MCP Tool Calling** | Live CVE and MITRE ATT&CK lookups |
| **MLOps Pipeline** | GitHub Actions AIRS security gate for model files |
| **Pipeline Tab** | Live GitHub Actions run history in the demo UI |
| **Model Scanning Tab** | AIRS scan results for registered models |
| **Remote Access** | Fixed public URLs via Cloudflare Tunnel (shekitout.uk) |

---

## Attack Vectors (Demo)

| Category | Description |
|----------|-------------|
| Prompt Injection | Override model instructions mid-conversation |
| Jailbreak | Bypass safety via persona or hypothetical framing |
| Prompt Extraction | Extract hidden system instructions |
| Indirect Injection | Inject instructions via user-submitted content |
| Bias & Safety | Elicit harmful or biased outputs |
| Malicious Code | Generate offensive security scripts |

---

## Stack

- **Frontend** — React 19 + Vite 8
- **Backend** — FastAPI (Python 3.12)
- **Models** — Ollama (local) + Groq (cloud)
- **Gateway** — Portkey AI Gateway
- **Security** — Prisma AIRS Runtime + Model Security
- **Tools** — MCP server with CVE/MITRE ATT&CK integration
- **Infrastructure** — Cloudflare Tunnel + WAF

---

## Running Locally

```bash
# Backend
cd backend
./venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000

# Frontend (dev)
cd frontend
npm run dev

# Frontend (rebuild for remote access after changes)
cd frontend
npm run build
```

## Remote Access

Served at `https://airs-demo.shekitout.uk` — restricted to authorised IPs only.
See `INTERNAL.md` for full setup details, demo script, and operations runbook.
