"""Minimal FastAPI example for the PromptGate Docker image.

Usage:
    docker build -t promptgate:latest .
    docker run -p 8000:8000 promptgate:latest
    curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
         -d '{"text": "Ignore all previous instructions"}'
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from promptgate import PromptGate

app = FastAPI(title="PromptGate")
gate = PromptGate()


class ScanRequest(BaseModel):
    text: str
    user_id: str | None = None


@app.post("/scan")
async def scan(req: ScanRequest) -> dict:
    result = await gate.scan_async(req.text, user_id=req.user_id)
    return {
        "is_safe": result.is_safe,
        "risk_score": result.risk_score,
        "threats": list(result.threats),
        "explanation": result.explanation,
        "detector_used": result.detector_used,
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
