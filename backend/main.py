import logging
import os
import uuid
from contextlib import asynccontextmanager

import httpx
import secure
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
MODEL = "dolphin-llama3:8b"
MAX_INPUT_LENGTH = 4000
SYSTEM_PROMPT = (
    "You are a helpful AI assistant used in a security demonstration platform. "
    "Respond clearly and concisely."
)

PRISMA_AIRS_API_KEY = os.getenv("PRISMA_AIRS_API_KEY")
PRISMA_AIRS_PROFILE = os.getenv("PRISMA_AIRS_PROFILE", "mac-mini-apisec")
PRISMA_AIRS_ENDPOINT = os.getenv("PRISMA_AIRS_ENDPOINT", "https://service.api.aisecurity.paloaltonetworks.com")


async def scan_with_airs(prompt: str, response: str = "") -> dict:
    """Scan prompt and/or response with Prisma AIRS. Returns scan result dict."""
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
                f"{PRISMA_AIRS_ENDPOINT}/v1/scan",
                json=payload,
                headers={
                    "x-pan-token": PRISMA_AIRS_API_KEY,
                    "Content-Type": "application/json",
                },
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
    """Normalise AIRS response into a simple threat summary."""
    if "error" in result:
        return {"status": "error", "message": result["error"]}

    action = result.get("action", "allow")
    category = result.get("category", "")

    # Collect detected threat types
    threats = []
    prompt_det = result.get("prompt_detected", {})
    resp_det = result.get("response_detected", {})

    threat_map = {
        "injection": "Prompt Injection",
        "url_cats": "Malicious URL",
        "dlp": "Sensitive Data",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
    }

    for key, label in threat_map.items():
        if prompt_det.get(key) or resp_det.get(key):
            threats.append(label)

    return {
        "status": "block" if action == "block" else "allow",
        "action": action,
        "category": category,
        "threats": threats,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3.0)
            if r.status_code == 200:
                logger.info("Ollama is reachable — model: %s", MODEL)
            else:
                logger.warning("Ollama responded with status %s", r.status_code)
        except Exception:
            logger.warning("Ollama not reachable at startup — is it running?")
    if PRISMA_AIRS_API_KEY:
        logger.info("Prisma AIRS configured — profile: %s", PRISMA_AIRS_PROFILE)
    else:
        logger.warning("Prisma AIRS not configured — AIRS toggle will be disabled")
    yield


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
    secure_headers.framework.fastapi(response)
    return response


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

    @field_validator("messages")
    @classmethod
    def validate_messages(cls, v):
        if not v:
            raise ValueError("messages cannot be empty")
        if len(v) > 50:
            raise ValueError("conversation history too long")
        return v


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
        "model": MODEL,
        "ollama": ollama_ok,
        "airs": bool(PRISMA_AIRS_API_KEY),
    }


@app.post("/api/chat")
@limiter.limit("20/minute")
async def chat(request: Request, body: ChatRequest):
    prompt = body.messages[-1].content
    airs_prompt_result = None
    airs_response_result = None

    # Scan incoming prompt with AIRS if enabled
    if body.airs_enabled and PRISMA_AIRS_API_KEY:
        raw = await scan_with_airs(prompt=prompt)
        airs_prompt_result = parse_airs_result(raw)
        if airs_prompt_result["status"] == "block":
            return JSONResponse(status_code=200, content={
                "role": "assistant",
                "content": f"[PRISMA AIRS BLOCKED] This prompt was blocked by Prisma AIRS.\nThreat detected: {', '.join(airs_prompt_result['threats']) or airs_prompt_result['category']}",
                "airs": {"prompt": airs_prompt_result, "response": None},
                "stats": None,
            })

    messages = [{"role": m.role, "content": m.content} for m in body.messages]
    payload = {
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
        "stream": False,
        "options": {"num_predict": 1024},
    }

    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json=payload,
                timeout=60.0,
            )
            r.raise_for_status()
    except httpx.ConnectError:
        return JSONResponse(status_code=503, content={"error": "Ollama is not running"})
    except httpx.TimeoutException:
        return JSONResponse(status_code=504, content={"error": "Model response timed out"})
    except httpx.HTTPStatusError as e:
        logger.error("Ollama error: %s", e.response.text)
        return JSONResponse(status_code=502, content={"error": "Model error"})

    data = r.json()
    ai_response = data["message"]["content"]

    # Scan model response with AIRS if enabled
    if body.airs_enabled and PRISMA_AIRS_API_KEY:
        raw = await scan_with_airs(prompt=prompt, response=ai_response)
        airs_response_result = parse_airs_result(raw)

    return {
        "role": "assistant",
        "content": ai_response,
        "airs": {
            "prompt": airs_prompt_result,
            "response": airs_response_result,
        } if body.airs_enabled else None,
        "stats": {
            "total_ms": round(data.get("total_duration", 0) / 1_000_000),
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "tokens_per_sec": round(
                data.get("eval_count", 0) / (data.get("eval_duration", 1) / 1_000_000_000), 1
            ),
        },
    }
