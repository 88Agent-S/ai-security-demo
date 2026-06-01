import os
import logging
from contextlib import asynccontextmanager

import anthropic
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

# Rate limiter — keyed by IP
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

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = "claude-haiku-4-5"
MAX_INPUT_LENGTH = 4000


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ANTHROPIC_API_KEY:
        logger.warning("ANTHROPIC_API_KEY not set — chat endpoint will be unavailable")
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
def health():
    return {"status": "ok", "model": MODEL}


@app.post("/api/chat")
@limiter.limit("20/minute")
async def chat(request: Request, body: ChatRequest):
    if not ANTHROPIC_API_KEY:
        return JSONResponse(status_code=503, content={"error": "API key not configured"})

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    messages = [{"role": m.role, "content": m.content} for m in body.messages]

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=(
            "You are a helpful AI assistant used in a security demonstration platform. "
            "Respond clearly and concisely."
        ),
        messages=messages,
    )

    return {"role": "assistant", "content": response.content[0].text}
