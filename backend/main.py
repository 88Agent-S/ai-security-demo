import asyncio
import json
import logging
import os
import subprocess
import sys
import uuid
from contextlib import asynccontextmanager

import httpx
import secure
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from portkey_ai import Portkey, createHeaders, PORTKEY_GATEWAY_URL
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

# Map MODEL_SECURITY_TSG_ID → TSG_ID expected by the model security SDK
_tsg = os.getenv("MODEL_SECURITY_TSG_ID")
if _tsg:
    os.environ.setdefault("TSG_ID", _tsg)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from model_security_client.api import ModelSecurityAPIClient
    _model_security_available = bool(os.getenv("MODEL_SECURITY_CLIENT_ID"))
except ImportError:
    ModelSecurityAPIClient = None
    _model_security_available = False

limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

secure_headers = secure.Secure(
    server=secure.Server().set(""),
    csp=secure.ContentSecurityPolicy()
        .default_src("'self'")
        .connect_src("'self'")
        .script_src("'self'"),
    xfo=secure.XFrameOptions().deny(),
    referrer=secure.ReferrerPolicy().no_referrer(),
    cache=secure.CacheControl().no_store(),
)

OLLAMA_BASE_URL = "http://127.0.0.1:11434"
ATTACK_MODEL = "dolphin-llama3:8b"
TOOL_MODEL = "llama3.1:8b"
MAX_INPUT_LENGTH = 4000
MCP_SERVER_URL = "http://127.0.0.1:3001/mcp"

SYSTEM_PROMPT = (
    "You are a helpful AI assistant used in a security demonstration platform. "
    "Respond clearly and concisely."
)

SYSTEM_PROMPT_TOOLS = (
    "You are an expert cybersecurity analyst with access to live security databases. "
    "When asked about vulnerabilities, CVEs, or attack techniques, use your tools to retrieve "
    "accurate, up-to-date information. Always use lookup_cve for specific CVE IDs, "
    "search_cves for general vulnerability searches, and lookup_attack_technique for MITRE ATT&CK. "
    "Be precise, thorough, and cite the data you retrieve."
)

PRISMA_AIRS_API_KEY = os.getenv("PRISMA_AIRS_API_KEY")
PRISMA_AIRS_PROFILE = os.getenv("PRISMA_AIRS_PROFILE", "mac-mini-apisec")
PRISMA_AIRS_ENDPOINT = os.getenv(
    "PRISMA_AIRS_ENDPOINT",
    "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request",
)

MODEL_SECURITY_API_ENDPOINT = os.getenv("MODEL_SECURITY_API_ENDPOINT", "https://api.sase.paloaltonetworks.com/aims")
MODEL_SECURITY_GROUP_UUID = os.getenv("MODEL_SECURITY_GROUP_UUID")

PORTKEY_API_KEY = os.getenv("PORTKEY_API_KEY")
PORTKEY_AIRS_CONFIG_ID = os.getenv("PORTKEY_AIRS_CONFIG_ID")
OLLAMA_PUBLIC_URL = os.getenv("OLLAMA_PUBLIC_URL")
GROQ_VIRTUAL_KEY = os.getenv("GROQ_VIRTUAL_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

PROVIDER_MODELS = {
    "ollama": ATTACK_MODEL,
    "groq": "llama-3.1-8b-instant",
}

GROQ_MODELS = [
    "llama-3.1-8b-instant",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "qwen/qwen3-32b",
]

def _groq_available() -> bool:
    return bool(GROQ_VIRTUAL_KEY or GROQ_API_KEY)

mcp_tool_definitions: list = []
_mcp_process: subprocess.Popen | None = None


# ── MCP helpers ────────────────────────────────────────────────────────────────

async def load_mcp_tools() -> bool:
    global mcp_tool_definitions
    for attempt in range(6):
        try:
            async with streamablehttp_client(MCP_SERVER_URL) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    mcp_tool_definitions = [
                        {
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "description": t.description,
                                "parameters": t.inputSchema,
                            },
                        }
                        for t in result.tools
                    ]
                    names = [t["function"]["name"] for t in mcp_tool_definitions]
                    logger.info("MCP ready — %d tools: %s", len(names), names)
                    return True
        except Exception as e:
            if attempt < 5:
                logger.info("MCP server starting, retrying... (%d/6)", attempt + 1)
                await asyncio.sleep(1.5)
            else:
                logger.warning("MCP server unavailable: %s", e)
    return False


async def call_mcp_tool(name: str, arguments: dict) -> str:
    try:
        async with streamablehttp_client(MCP_SERVER_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)
                return result.content[0].text if result.content else "No result returned."
    except Exception as e:
        logger.warning("MCP tool '%s' failed: %s", name, e)
        return f"Tool error: {e}"


async def run_tool_chat(messages: list) -> tuple[str, list, dict]:
    """Agentic loop: run llama3.1 with MCP tools until a final text response."""
    tool_calls_log: list = []
    loop_messages = [{"role": "system", "content": SYSTEM_PROMPT_TOOLS}] + messages
    last_data: dict = {}

    for _ in range(8):
        payload = {
            "model": TOOL_MODEL,
            "messages": loop_messages,
            "tools": mcp_tool_definitions,
            "stream": False,
            "options": {"num_predict": 2048},
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=120.0
            )
            r.raise_for_status()

        last_data = r.json()
        msg = last_data["message"]
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            return msg.get("content", ""), tool_calls_log, last_data

        loop_messages.append(
            {"role": "assistant", "content": msg.get("content", ""), "tool_calls": tool_calls}
        )

        for tc in tool_calls:
            fn = tc["function"]
            tool_name = fn["name"]
            arguments = fn.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except Exception:
                    arguments = {}

            logger.info("Tool → %s(%s)", tool_name, arguments)
            result = await call_mcp_tool(tool_name, arguments)

            tool_calls_log.append({
                "tool": tool_name,
                "args": arguments,
                "preview": result[:200] + ("..." if len(result) > 200 else ""),
            })
            loop_messages.append({"role": "tool", "content": result})

    return "Maximum tool iterations reached.", tool_calls_log, last_data


# ── Portkey gateway ────────────────────────────────────────────────────────────

async def chat_via_portkey(messages: list, mode: str, airs_enabled: bool, provider: str = "ollama", model_override: str | None = None) -> tuple[str, list | None, dict]:
    """Route chat through Portkey gateway. AIRS guardrail applied when airs_enabled."""
    config = PORTKEY_AIRS_CONFIG_ID if airs_enabled else None
    use_tools = mode == "assistant" and bool(mcp_tool_definitions) and provider == "ollama"

    if provider == "groq" and GROQ_VIRTUAL_KEY:
        client = Portkey(
            api_key=PORTKEY_API_KEY,
            virtual_key=GROQ_VIRTUAL_KEY,
            config=config,
        )
    elif provider == "groq" and GROQ_API_KEY:
        client = Portkey(
            api_key=PORTKEY_API_KEY,
            provider="groq",
            Authorization=f"Bearer {GROQ_API_KEY}",
            config=config,
        )
    else:
        client = Portkey(
            api_key=PORTKEY_API_KEY,
            provider="ollama",
            custom_host=OLLAMA_PUBLIC_URL,
            config=config,
        )

    default_model = PROVIDER_MODELS.get(provider, ATTACK_MODEL)
    model = TOOL_MODEL if use_tools else (model_override or default_model)
    system_prompt = SYSTEM_PROMPT_TOOLS if use_tools else SYSTEM_PROMPT

    loop_messages = [{"role": "system", "content": system_prompt}] + messages
    tool_calls_log: list = []

    for _ in range(8 if use_tools else 1):
        kwargs = {
            "model": model,
            "messages": loop_messages,
            "max_tokens": 2048 if use_tools else 1024,
        }
        if use_tools:
            kwargs["tools"] = mcp_tool_definitions

        response = await asyncio.get_event_loop().run_in_executor(
            None, lambda: client.chat.completions.create(**kwargs)
        )

        msg = response.choices[0].message
        tool_calls = getattr(msg, "tool_calls", None) or []

        if not tool_calls or not use_tools:
            return msg.content or "", tool_calls_log or None, {}

        loop_messages.append(msg.model_dump())

        for tc in tool_calls:
            fn = tc.function
            try:
                args = json.loads(fn.arguments) if isinstance(fn.arguments, str) else fn.arguments
            except Exception:
                args = {}
            logger.info("Portkey tool → %s(%s)", fn.name, args)
            result = await call_mcp_tool(fn.name, args)
            tool_calls_log.append({
                "tool": fn.name,
                "args": args,
                "preview": result[:200] + ("..." if len(result) > 200 else ""),
            })
            loop_messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

    return "Maximum tool iterations reached.", tool_calls_log, {}


# ── AIRS helpers ───────────────────────────────────────────────────────────────

async def scan_with_airs(prompt: str, response: str = "") -> dict:
    if not PRISMA_AIRS_API_KEY:
        return {"error": "AIRS not configured"}
    payload = {
        "tr_id": str(uuid.uuid4()),
        "ai_profile": {"profile_name": PRISMA_AIRS_PROFILE},
        "contents": [{"prompt": prompt, "response": response}],
    }
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                PRISMA_AIRS_ENDPOINT,
                json=payload,
                headers={"x-pan-token": PRISMA_AIRS_API_KEY, "Content-Type": "application/json"},
                timeout=10.0,
            )
            r.raise_for_status()
            return r.json()
    except httpx.TimeoutException:
        logger.warning("AIRS scan timed out")
        return {"error": "AIRS timeout"}
    except Exception as e:
        logger.warning("AIRS scan failed: %s", e)
        return {"error": str(e)}


def parse_airs_result(result: dict) -> dict:
    if result.get("error"):
        return {"status": "error", "message": result["error"]}
    action = result.get("action", "allow")
    category = result.get("category", "")
    prompt_det = result.get("prompt_detected", {})
    resp_det = result.get("response_detected", {})
    threat_map = {
        "injection": "Prompt Injection",
        "url_cats": "Malicious URL",
        "dlp": "Sensitive Data",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
    }
    threats = [label for key, label in threat_map.items() if prompt_det.get(key) or resp_det.get(key)]
    return {"status": "block" if action == "block" else "allow", "action": action, "category": category, "threats": threats}


# ── App lifecycle ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _mcp_process

    _mcp_process = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "mcp_server.py")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    logger.info("MCP server starting (pid %d)...", _mcp_process.pid)

    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3.0)
            if r.status_code == 200:
                logger.info("Ollama reachable — attack: %s  tools: %s", ATTACK_MODEL, TOOL_MODEL)
        except Exception:
            logger.warning("Ollama not reachable at startup")

    await load_mcp_tools()

    if PRISMA_AIRS_API_KEY:
        logger.info("Prisma AIRS configured — profile: %s", PRISMA_AIRS_PROFILE)
    else:
        logger.warning("Prisma AIRS not configured — toggle will be disabled")

    yield

    if _mcp_process and _mcp_process.poll() is None:
        _mcp_process.terminate()
        logger.info("MCP server stopped")


# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(title="AI Security Demo Platform", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    secure_headers.set_headers(response)
    return response


# ── Models ─────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ("user", "assistant"):
            raise ValueError("role must be 'user' or 'assistant'")
        return v

    @field_validator("content")
    @classmethod
    def validate_content(cls, v):
        if not v or not v.strip():
            raise ValueError("content cannot be empty")
        if len(v) > MAX_INPUT_LENGTH:
            raise ValueError(f"content exceeds {MAX_INPUT_LENGTH} character limit")
        return v.strip()


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    airs_enabled: bool = False
    mode: str = "attack"
    gateway_enabled: bool = False
    provider: str = "ollama"
    model_override: str | None = None

    @field_validator("messages")
    @classmethod
    def validate_messages(cls, v):
        if not v:
            raise ValueError("messages cannot be empty")
        if len(v) > 50:
            raise ValueError("conversation history too long")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v):
        if v not in ("attack", "assistant"):
            raise ValueError("mode must be 'attack' or 'assistant'")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v):
        if v not in ("ollama", "groq"):
            raise ValueError("provider must be 'ollama' or 'groq'")
        return v


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3.0)
            ollama_ok = r.status_code == 200
        except Exception:
            ollama_ok = False
    return {
        "status": "ok",
        "attack_model": ATTACK_MODEL,
        "tool_model": TOOL_MODEL,
        "ollama": ollama_ok,
        "airs": bool(PRISMA_AIRS_API_KEY),
        "mcp": bool(mcp_tool_definitions),
        "mcp_tools": [t["function"]["name"] for t in mcp_tool_definitions],
        "gateway": bool(PORTKEY_API_KEY and OLLAMA_PUBLIC_URL),
        "groq": _groq_available(),
    }


@app.get("/api/scan/models")
@limiter.limit("10/minute")
async def get_model_scans(request: Request):
    if not _model_security_available:
        return JSONResponse(status_code=503, content={"error": "Model security not configured"})
    try:
        client = ModelSecurityAPIClient(base_url=MODEL_SECURITY_API_ENDPOINT)
        raw = dict(client.list_scans())
        scans = raw.get("scans", [])

        seen: dict = {}
        for s in scans:
            labels = {lbl.key: lbl.value for lbl in (s.labels or [])}
            if labels.get("platform") not in ("macmini", "macmini-hf"):
                continue
            name = labels.get("demo", s.model_uri.split("/")[-1] if s.model_uri else "unknown")
            if name not in seen or s.created_at > seen[name].created_at:
                seen[name] = s

        results = []
        for name, s in seen.items():
            labels = {lbl.key: lbl.value for lbl in (s.labels or [])}
            outcome = str(s.eval_outcome).replace("EvalOutcome.", "")
            results.append({
                "name": name,
                "outcome": outcome,
                "rules_failed": s.eval_summary.rules_failed,
                "rules_total": s.eval_summary.total_rules,
                "formats": s.model_formats or [],
                "files_scanned": s.total_files_scanned,
                "scanned_at": s.created_at.isoformat(),
                "source": labels.get("source", "local"),
                "model_uri": s.model_uri,
                "labels": labels,
            })
        return {"models": results}
    except Exception as e:
        logger.error("Model scan fetch error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/chat")
@limiter.limit("20/minute")
async def chat(request: Request, body: ChatRequest):
    prompt = body.messages[-1].content
    airs_prompt_result = None
    airs_response_result = None
    tool_calls = None

    messages = [{"role": m.role, "content": m.content} for m in body.messages]

    # Gateway path — traffic flows through Portkey; AIRS guardrail runs inside Portkey
    groq_ok = body.provider == "groq" and _groq_available()
    if body.gateway_enabled and PORTKEY_API_KEY and (OLLAMA_PUBLIC_URL or groq_ok):
        try:
            ai_response, tool_calls, data = await chat_via_portkey(messages, body.mode, body.airs_enabled, body.provider, body.model_override)
        except Exception as e:
            logger.error("Portkey error: %s", e)
            err_str = str(e)
            is_airs_block = body.airs_enabled and (
                getattr(e, "status_code", None) == 446 or "446" in err_str
            )
            if is_airs_block:
                threats = []
                try:
                    import ast
                    body_data = getattr(e, "body", None)
                    if not isinstance(body_data, dict):
                        start = err_str.find("{")
                        if start != -1:
                            body_data = ast.literal_eval(err_str[start:])
                    hooks = body_data.get("hook_results", {}).get("before_request_hooks", [])
                    if hooks:
                        pd = hooks[0].get("checks", [{}])[0].get("data", {}).get("prompt_detected", {})
                        threat_map = {
                            "injection": "Prompt Injection",
                            "url_cats": "Malicious URL",
                            "dlp": "Sensitive Data",
                            "toxic_content": "Toxic Content",
                            "malicious_code": "Malicious Code",
                        }
                        threats = [label for key, label in threat_map.items() if pd.get(key)]
                except Exception:
                    pass
                return JSONResponse(status_code=200, content={
                    "role": "assistant",
                    "content": (
                        "[PRISMA AIRS BLOCKED] This prompt was blocked by Prisma AIRS.\n"
                        f"Threat detected: {', '.join(threats) if threats else 'Policy violation'}"
                    ),
                    "airs": {"prompt": {"status": "block", "threats": threats}, "response": None},
                    "tool_calls": None,
                    "gateway": True,
                    "provider": body.provider,
                    "model": body.model_override or PROVIDER_MODELS.get(body.provider, ATTACK_MODEL),
                    "stats": None,
                })
            return JSONResponse(status_code=502, content={"error": f"Gateway error: {e}"})

        return {
            "role": "assistant",
            "content": ai_response,
            "tool_calls": tool_calls,
            "airs": {"prompt": {"status": "allow", "threats": []}, "response": None} if body.airs_enabled else None,
            "gateway": True,
            "provider": body.provider,
            "model": body.model_override or PROVIDER_MODELS.get(body.provider, ATTACK_MODEL),
            "stats": None,
        }

    try:
        if body.mode == "assistant" and mcp_tool_definitions:
            ai_response, tool_calls, data = await run_tool_chat(messages)
        else:
            payload = {
                "model": ATTACK_MODEL,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                "stream": False,
                "options": {"num_predict": 1024},
            }
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=60.0
                )
                r.raise_for_status()
            data = r.json()
            ai_response = data["message"]["content"]

    except httpx.ConnectError:
        return JSONResponse(status_code=503, content={"error": "Ollama is not running"})
    except httpx.TimeoutException:
        return JSONResponse(status_code=504, content={"error": "Model response timed out"})
    except httpx.HTTPStatusError as e:
        logger.error("Ollama error: %s", e.response.text)
        return JSONResponse(status_code=502, content={"error": "Model error"})

    # AIRS response scan (direct path only)
    if body.airs_enabled and PRISMA_AIRS_API_KEY:
        raw = await scan_with_airs(prompt=prompt, response=ai_response)
        airs_response_result = parse_airs_result(raw)

    stats = None
    if data:
        eval_duration = data.get("eval_duration") or 1
        stats = {
            "total_ms": round(data.get("total_duration", 0) / 1_000_000),
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "tokens_per_sec": round(data.get("eval_count", 0) / (eval_duration / 1_000_000_000), 1),
        }

    return {
        "role": "assistant",
        "content": ai_response,
        "tool_calls": tool_calls,
        "airs": {"prompt": airs_prompt_result, "response": airs_response_result} if body.airs_enabled else None,
        "stats": stats,
    }


# ── SSE streaming endpoint ─────────────────────────────────────────────────────

def _sse(event_type: str, **data) -> str:
    return f"data: {json.dumps({'type': event_type, **data})}\n\n"


@app.post("/api/chat/stream")
@limiter.limit("20/minute")
async def chat_stream(request: Request, body: ChatRequest):
    prompt = body.messages[-1].content
    messages = [{"role": m.role, "content": m.content} for m in body.messages]

    async def event_stream():
        # ── Gateway path (non-streaming, emit as single token) ─────────────────
        groq_ok = body.provider == "groq" and _groq_available()
        if body.gateway_enabled and PORTKEY_API_KEY and (OLLAMA_PUBLIC_URL or groq_ok):
            try:
                ai_response, tool_calls, _ = await chat_via_portkey(
                    messages, body.mode, body.airs_enabled, body.provider, body.model_override
                )
                yield _sse("token", content=ai_response)
                yield _sse(
                    "done",
                    tool_calls=tool_calls,
                    airs={"prompt": {"status": "allow", "threats": []}, "response": None} if body.airs_enabled else None,
                    stats=None,
                    gateway=True,
                    provider=body.provider,
                    model=body.model_override or PROVIDER_MODELS.get(body.provider, ATTACK_MODEL),
                )
            except Exception as e:
                err_str = str(e)
                is_airs_block = body.airs_enabled and (
                    getattr(e, "status_code", None) == 446 or "446" in err_str
                )
                if is_airs_block:
                    threats = []
                    try:
                        import ast
                        body_data = getattr(e, "body", None)
                        if not isinstance(body_data, dict):
                            start = err_str.find("{")
                            if start != -1:
                                body_data = ast.literal_eval(err_str[start:])
                        hooks = body_data.get("hook_results", {}).get("before_request_hooks", [])
                        if hooks:
                            pd = hooks[0].get("checks", [{}])[0].get("data", {}).get("prompt_detected", {})
                            threat_map = {
                                "injection": "Prompt Injection",
                                "url_cats": "Malicious URL",
                                "dlp": "Sensitive Data",
                                "toxic_content": "Toxic Content",
                                "malicious_code": "Malicious Code",
                            }
                            threats = [label for key, label in threat_map.items() if pd.get(key)]
                    except Exception:
                        pass
                    block_msg = (
                        "[PRISMA AIRS BLOCKED] This prompt was blocked by Prisma AIRS.\n"
                        f"Threat detected: {', '.join(threats) if threats else 'Policy violation'}"
                    )
                    yield _sse("token", content=block_msg)
                    yield _sse(
                        "done",
                        tool_calls=None,
                        airs={"prompt": {"status": "block", "threats": threats}, "response": None},
                        stats=None,
                        gateway=True,
                        provider=body.provider,
                        model=body.model_override or PROVIDER_MODELS.get(body.provider, ATTACK_MODEL),
                    )
                else:
                    yield _sse("error", message=f"Gateway error: {e}")
            return

        # ── Assistant / tool mode (emit tool_call events, then stream final text) ─
        if body.mode == "assistant" and mcp_tool_definitions:
            tool_calls_log: list = []
            loop_messages = [{"role": "system", "content": SYSTEM_PROMPT_TOOLS}] + messages
            last_data: dict = {}
            final_response = ""

            for _ in range(8):
                payload = {
                    "model": TOOL_MODEL,
                    "messages": loop_messages,
                    "tools": mcp_tool_definitions,
                    "stream": False,
                    "options": {"num_predict": 2048},
                }
                try:
                    async with httpx.AsyncClient() as client:
                        r = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=120.0)
                        r.raise_for_status()
                except httpx.ConnectError:
                    yield _sse("error", message="Ollama is not running")
                    return
                except httpx.TimeoutException:
                    yield _sse("error", message="Model response timed out")
                    return

                last_data = r.json()
                msg = last_data["message"]
                tool_calls = msg.get("tool_calls") or []

                if not tool_calls:
                    final_response = msg.get("content", "")
                    break

                loop_messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": tool_calls})

                for tc in tool_calls:
                    fn = tc["function"]
                    tool_name = fn["name"]
                    arguments = fn.get("arguments", {})
                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except Exception:
                            arguments = {}
                    logger.info("Tool → %s(%s)", tool_name, arguments)
                    result = await call_mcp_tool(tool_name, arguments)
                    preview = result[:200] + ("..." if len(result) > 200 else "")
                    tool_calls_log.append({"tool": tool_name, "args": arguments, "preview": preview})
                    yield _sse("tool_call", tool=tool_name, args=arguments, preview=preview)
                    loop_messages.append({"role": "tool", "content": result})
            else:
                final_response = "Maximum tool iterations reached."

            for word in final_response.split(" "):
                yield _sse("token", content=word + " ")

            airs_result = None
            if body.airs_enabled and PRISMA_AIRS_API_KEY:
                raw = await scan_with_airs(prompt=prompt, response=final_response)
                airs_result = parse_airs_result(raw)

            eval_duration = last_data.get("eval_duration") or 1
            stats = {
                "total_ms": round(last_data.get("total_duration", 0) / 1_000_000),
                "prompt_tokens": last_data.get("prompt_eval_count", 0),
                "completion_tokens": last_data.get("eval_count", 0),
                "tokens_per_sec": round(last_data.get("eval_count", 0) / (eval_duration / 1_000_000_000), 1),
            }
            yield _sse(
                "done",
                tool_calls=tool_calls_log,
                airs={"prompt": None, "response": airs_result} if body.airs_enabled else None,
                stats=stats,
            )
            return

        # ── Direct attack path: pre-scan prompt, then stream from Ollama ─────────
        airs_prompt_result = None
        airs_response_result = None

        if body.airs_enabled and PRISMA_AIRS_API_KEY:
            raw = await scan_with_airs(prompt=prompt, response="")
            airs_prompt_result = parse_airs_result(raw)
            if airs_prompt_result.get("status") == "block":
                threats = airs_prompt_result.get("threats", [])
                block_msg = (
                    "[PRISMA AIRS BLOCKED] This prompt was blocked before reaching the model.\n"
                    f"Threat detected: {', '.join(threats) if threats else 'Policy violation'}"
                )
                yield _sse("token", content=block_msg)
                yield _sse(
                    "done",
                    tool_calls=None,
                    airs={"prompt": airs_prompt_result, "response": None},
                    stats=None,
                )
                return

        payload = {
            "model": ATTACK_MODEL,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
            "stream": True,
            "options": {"num_predict": 1024},
        }
        full_response = ""
        final_data: dict = {}

        try:
            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST", f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=60.0
                ) as r:
                    r.raise_for_status()
                    async for line in r.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except Exception:
                            continue
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            full_response += token
                            yield _sse("token", content=token)
                        if chunk.get("done"):
                            final_data = chunk
        except httpx.ConnectError:
            yield _sse("error", message="Ollama is not running")
            return
        except httpx.TimeoutException:
            yield _sse("error", message="Model response timed out")
            return
        except httpx.HTTPStatusError:
            yield _sse("error", message="Model error")
            return

        if body.airs_enabled and PRISMA_AIRS_API_KEY:
            raw = await scan_with_airs(prompt="", response=full_response)
            airs_response_result = parse_airs_result(raw)

        stats = None
        if final_data:
            eval_duration = final_data.get("eval_duration") or 1
            stats = {
                "total_ms": round(final_data.get("total_duration", 0) / 1_000_000),
                "prompt_tokens": final_data.get("prompt_eval_count", 0),
                "completion_tokens": final_data.get("eval_count", 0),
                "tokens_per_sec": round(final_data.get("eval_count", 0) / (eval_duration / 1_000_000_000), 1),
            }

        yield _sse(
            "done",
            tool_calls=None,
            airs={"prompt": airs_prompt_result, "response": airs_response_result} if body.airs_enabled else None,
            stats=stats,
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
