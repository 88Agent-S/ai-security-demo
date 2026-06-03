# AI Security Demo Platform

A locally-hosted AI security demonstration platform built for Palo Alto Networks.
Demonstrates common AI attack vectors and how Prisma AIRS detects and blocks them at runtime.

---

## Architecture Overview

```
Browser → React Frontend → FastAPI Backend → Ollama (local models)
                                          → Portkey Gateway → Ollama (via ngrok)
                                          → Prisma AIRS (threat scanning)
                                          → MCP Server (CVE / MITRE ATT&CK tools)
```

---

## Features

- **Attack Vector Panel** — 6 categories with preset prompts for live demos
- **Prisma AIRS Toggle** — enable/disable runtime threat detection mid-demo
- **Portkey Gateway Toggle** — route traffic through Portkey with AIRS guardrails
- **MCP Tool Calling** — live CVE and MITRE ATT&CK lookups via cybersecurity assistant mode
- **Per-message Stats** — token count, timing, and speed

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

- **Frontend** — React + Vite
- **Backend** — FastAPI (Python)
- **Models** — Ollama (local inference)
- **Gateway** — Portkey AI Gateway
- **Security** — Prisma AIRS Runtime Security
- **Tools** — MCP server with CVE/MITRE ATT&CK integration

---

## Prerequisites

- Mac with Homebrew installed
- Ollama running with required models pulled
- API keys configured in `backend/.env` (see `.env.example`)

---

## Running Locally

```bash
# Backend
cd backend
./venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000

# Frontend
cd frontend
npm run dev
```
