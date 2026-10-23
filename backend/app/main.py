import time
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.config import settings
from backend.app.database import init_db, SessionLocal
from backend.models.db_models import DocumentModel
from backend.seed import seed_database
from backend.app.routers import (
    agent_router,
    stats_router,
    policy_router,
    approvals_router,
    audit_router,
    scenarios_router,
    demo_router
)

# In-memory sliding window rate limiter
RATE_LIMIT_STORE = defaultdict(list)
MAX_BODY_SIZE = 65536  # 64 KB limit


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables exist and seed initial data if empty
    init_db()
    with SessionLocal() as db:
        if db.query(DocumentModel).count() == 0:
            seed_database(db=db, clear_existing=False)
    yield


app = FastAPI(
    title="AI Agent Security Guard API",
    description="Explainable Security Gateway for Enterprise AI Agents",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request Size Limit & Rate Limiter Middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # 1. Payload size check
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"error": "PayloadTooLarge", "detail": f"Request body exceeds {MAX_BODY_SIZE} bytes limit."}
        )

    # 2. Per-client / per-principal rate limiting
    client_ip = request.client.host if request.client else "127.0.0.1"
    auth_header = request.headers.get("authorization", "")
    rate_key = auth_header if auth_header else client_ip

    now = time.time()
    RATE_LIMIT_STORE[rate_key] = [t for t in RATE_LIMIT_STORE[rate_key] if now - t < 60]
    if len(RATE_LIMIT_STORE[rate_key]) >= settings.RATE_LIMIT_PER_MINUTE:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": "RateLimitExceeded", "detail": "Rate limit of 60 requests per minute exceeded."}
        )
    RATE_LIMIT_STORE[rate_key].append(now)

    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        # Prevent stack trace leakage in accordance with security requirements
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "detail": "An internal error occurred. Detailed stack traces are suppressed for security."
            }
        )


# Global Exception Handler for 400s & Validation errors
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": "UnhandledServerError",
            "detail": "A safe error response without stack trace."
        }
    )


# Include Routers
app.include_router(agent_router)
app.include_router(stats_router)
app.include_router(policy_router)
app.include_router(approvals_router)
app.include_router(audit_router)
app.include_router(scenarios_router)
app.include_router(demo_router)


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "AI Agent Security Guard",
        "demo_mode": settings.DEMO_MODE
    }
