"""
QuantumTrust Backend — FastAPI application entry point
"""
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config.settings import settings
from app.db.database import init_db
from app.api import upload, verification, reports

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("quantumtrust")


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("QuantumTrust API starting up — initializing database…")
    await init_db()
    logger.info("Database initialized. API ready.")
    yield
    logger.info("QuantumTrust API shutting down.")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="QuantumTrust API",
    description=(
        "Quantum-Inspired Digital Signature Security — "
        "PDF signature verification and document integrity analysis."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|10\..*|192\.168\..*)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global error handler ───────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again."},
    )


# ── Routes ─────────────────────────────────────────────────────────────────────
app.include_router(upload.router,       prefix="/api", tags=["Analysis"])
app.include_router(verification.router, prefix="/api", tags=["Analysis"])
app.include_router(reports.router,      prefix="/api", tags=["Reports"])


@app.get("/api/health", tags=["System"])
async def health_check() -> dict:
    return {"status": "ok", "service": "QuantumTrust API"}


# ── Dev entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level="info",
    )
