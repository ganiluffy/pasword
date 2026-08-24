from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.analyzer import analyze_password
from backend.generator import generate_password
from backend.schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    GeneratedPasswordResponse,
    GenerateRequest,
    HealthResponse,
)

logger = logging.getLogger("password_security_analyzer")
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "null",
]

app = FastAPI(
    title="Password Security Analyzer",
    description="Fully local password strength analysis and secure generation.",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    safe_errors = [
        {key: value for key, value in error.items() if key not in ("input", "ctx", "url")}
        for error in exc.errors()
    ]
    logger.warning("Rejected request: %d validation error(s)", len(safe_errors))
    return JSONResponse(status_code=422, content={"detail": safe_errors})


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "Unhandled %s while handling %s %s",
        type(exc).__name__,
        request.method,
        request.url.path,
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(payload: AnalyzeRequest) -> AnalysisResponse:
    result = analyze_password(payload.password)
    logger.info(
        "Analyzed a password (length=%d, verdict=%s)",
        result["stats"]["length"],
        result["strength"]["label"],
    )
    return AnalysisResponse.model_validate(result)


@app.post("/api/generate", response_model=GeneratedPasswordResponse)
def generate(payload: GenerateRequest) -> GeneratedPasswordResponse:
    password = generate_password(
        length=payload.length,
        uppercase=payload.uppercase,
        lowercase=payload.lowercase,
        numbers=payload.numbers,
        special=payload.special,
    )
    logger.info("Generated a password (length=%d)", payload.length)
    return GeneratedPasswordResponse(password=password, length=payload.length)


_FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"
app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
