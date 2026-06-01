import logging
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
    return {"status": "ok", "model": MODEL, "ollama": ollama_ok}


@app.post("/api/chat")
@limiter.limit("20/minute")
async def chat(request: Request, body: ChatRequest):
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
    return {
        "role": "assistant",
        "content": data["message"]["content"],
        "stats": {
            "total_ms": round(data.get("total_duration", 0) / 1_000_000),
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "tokens_per_sec": round(
                data.get("eval_count", 0) / (data.get("eval_duration", 1) / 1_000_000_000), 1
            ),
        },
    }
