"""
QuantumTrust — POST /api/analyze
Accepts a PDF upload, runs full analysis pipeline, stores result, returns JSON.
"""
from __future__ import annotations
import asyncio
import logging
import os
import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.db.database import get_db
from app.models.analysis import Analysis
from app.schemas.analysis import AnalysisResult
from app.services import (
    pdf_parser,
    signature_verifier,
    certificate_analyzer,
    duplicate_detector,
    threat_engine,
    quantum_analysis,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_MAX_BYTES = settings.max_file_size_mb * 1024 * 1024
_SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._\-]")


def _sanitize_filename(name: str) -> str:
    """Strip path traversal, keep only safe characters."""
    name = os.path.basename(name)
    name = _SAFE_FILENAME.sub("_", name)
    return name[:256] or "document.pdf"


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_pdf(
    file: UploadFile = File(..., description="Digitally signed PDF to analyze"),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Full PDF digital signature analysis pipeline.

    1. Validate upload (type, size)
    2. Parse PDF structure (pypdf)
    3. Verify digital signature (pyHanko)
    4. Analyze certificate
    5. Compute document fingerprint
    6. Check for duplicates
    7. Run threat engine
    8. Run quantum-inspired analysis
    9. Determine final verdict
    10. Store result
    11. Return structured JSON
    """
    # ── 1. Validate file type ──────────────────────────────────────────────────
    filename = _sanitize_filename(file.filename or "upload.pdf")
    content_type = file.content_type or ""

    if not filename.lower().endswith(".pdf") and "pdf" not in content_type.lower():
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only PDF files are accepted. Please upload a valid PDF document.",
        )

    # ── 2. Read and validate size ──────────────────────────────────────────────
    pdf_bytes = await file.read()
    file_size = len(pdf_bytes)

    if file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty.",
        )

    if file_size > _MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size {file_size / 1024 / 1024:.1f} MB exceeds the {settings.max_file_size_mb} MB limit.",
        )

    # Validate PDF magic bytes
    if not pdf_bytes.startswith(b"%PDF"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file does not appear to be a valid PDF (missing PDF header).",
        )

    # ── 3. Generate analysis ID ────────────────────────────────────────────────
    analysis_id = secrets.token_hex(16)

    logger.info("Starting analysis %s for file '%s' (%d bytes)", analysis_id, filename, file_size)

    # ── 4. Parse PDF structure ─────────────────────────────────────────────────
    try:
        pdf_structure = pdf_parser.parse_pdf_structure(pdf_bytes)
    except Exception as exc:
        logger.error("PDF parse failed: %s", exc)
        pdf_structure = {"pdf_version": None, "suspicious_signals": [], "parse_error": str(exc)}

    # ── 5. Verify digital signature ────────────────────────────────────────────
    try:
        sig_result = await asyncio.to_thread(signature_verifier.verify_pdf_signatures, pdf_bytes)
    except Exception as exc:
        logger.error("Signature verification failed: %s", exc)
        sig_result = {"present": False, "overall_status": "UNKNOWN", "error": str(exc)}

    # ── 6. Analyze certificate ─────────────────────────────────────────────────
    cert_info: dict[str, Any] = {
        "subject": None, "issuer": None, "serial_number": None,
        "valid_from": None, "valid_until": None, "trust_status": "UNAVAILABLE",
        "is_expired": None, "is_self_signed": None,
    }
    if sig_result.get("signatures"):
        primary_sig = sig_result["signatures"][0]
        cert_raw = primary_sig.get("_cert_object")
        if cert_raw is not None:
            cert_info = certificate_analyzer.analyze_certificate(cert_raw)
        else:
            # Reconstruct from already-extracted cert fields
            cert_info.update({
                "subject":       primary_sig.get("cert_subject"),
                "issuer":        primary_sig.get("cert_issuer"),
                "serial_number": primary_sig.get("cert_serial"),
                "valid_from":    primary_sig.get("cert_valid_from"),
                "valid_until":   primary_sig.get("cert_valid_until"),
                "trust_status":  primary_sig.get("trust_status") or "UNAVAILABLE",
            })

    # ── 7. Build integrity result ──────────────────────────────────────────────
    integrity_result: dict[str, Any] = {
        "integrity_status":       sig_result.get("integrity_status", "UNKNOWN"),
        "modification_status":    sig_result.get("integrity_modification_status", "UNKNOWN"),
        "byte_range":             sig_result.get("byte_range"),
    }

    # ── 8. Fingerprint + duplicate detection ───────────────────────────────────
    fingerprint = duplicate_detector.generate_fingerprint(pdf_bytes)
    dup_result  = await duplicate_detector.check_duplicate(fingerprint, analysis_id, db)

    # ── 9. Quantum-inspired analysis ──────────────────────────────────────────
    q_result = quantum_analysis.run_quantum_analysis(
        sig_result, cert_info, integrity_result,
        pdf_structure, dup_result
    )

    # ── 10. Threat analysis (combines crypto, cert, structure, duplicate & quantum signals)
    threat_result = threat_engine.calculate_threat(
        sig_result, cert_info, integrity_result, pdf_structure, dup_result, q_result
    )

    # ── 11. Verdict (cryptographic verification retains highest authority) ─────
    verdict = threat_engine.determine_verdict(
        sig_result, cert_info, integrity_result, threat_result
    )

    # ── 12. Assemble result ────────────────────────────────────────────────────
    now = datetime.now(timezone.utc)

    full_result: dict[str, Any] = {
        "analysis_id": analysis_id,
        "document": {
            "filename":    filename,
            "file_size":   file_size,
            "pdf_version": pdf_structure.get("pdf_version"),
            "fingerprint": fingerprint,
        },
        "signature": {
            "present":              sig_result.get("present", False),
            "count":                sig_result.get("count", 0),
            "status":               sig_result.get("overall_status"),
            "signature_type":       sig_result.get("signature_type"),
            "digest_algorithm":     sig_result.get("digest_algorithm"),
            "signature_algorithm":  sig_result.get("signature_algorithm"),
            "public_key_algorithm": sig_result.get("public_key_algorithm"),
            "key_size":             sig_result.get("key_size"),
        },
        "certificate": {
            "subject":        cert_info.get("subject"),
            "issuer":         cert_info.get("issuer"),
            "serial_number":  cert_info.get("serial_number"),
            "valid_from":     cert_info.get("valid_from"),
            "valid_until":    cert_info.get("valid_until"),
            "trust_status":   cert_info.get("trust_status"),
        },
        "integrity": {
            "status":               integrity_result.get("integrity_status"),
            "byte_range":           integrity_result.get("byte_range"),
            "modification_status":  integrity_result.get("modification_status"),
        },
        "duplicate": {
            "is_duplicate":           dup_result.get("is_duplicate", False),
            "match_type":             dup_result.get("match_type", "NONE"),
            "matching_analysis_id":   dup_result.get("matching_analysis_id"),
        },
        "security": {
            "threat_score":    threat_result.get("threat_score", 0),
            "threat_level":    threat_result.get("threat_level", "LOW"),
            "detected_threats": threat_result.get("detected_threats", []),
        },
        "quantum_analysis": {
            "state_dimension":   q_result.get("state_dimension", 14),
            "state_similarity":  q_result.get("state_similarity"),
            "correlation_score": q_result.get("correlation_score"),
            "disturbance_score": q_result.get("disturbance_score"),
            "anomaly_distance":  q_result.get("anomaly_distance"),
            "entropy":           q_result.get("entropy"),
            "reference_type":    q_result.get("reference_type", "deterministic_baseline"),
            "simulation_note":   q_result.get("simulation_note"),
        },
        "verdict": verdict,
        "created_at": now.isoformat(),
    }

    # ── 13. Persist ────────────────────────────────────────────────────────────
    try:
        analysis_record = Analysis(
            analysis_id=analysis_id,
            filename=filename,
            file_size=file_size,
            pdf_version=pdf_structure.get("pdf_version"),
            fingerprint=fingerprint,
            signature_present=sig_result.get("present", False),
            signature_status=sig_result.get("overall_status"),
            signature_count=sig_result.get("count", 0),
            threat_score=float(threat_result.get("threat_score", 0)),
            threat_level=threat_result.get("threat_level"),
            verdict=verdict,
        )
        analysis_record.set_full_result(full_result)
        db.add(analysis_record)

        await duplicate_detector.store_fingerprint(fingerprint, analysis_id, filename, db)
        await db.commit()
    except Exception as exc:
        logger.error("Persistence error: %s", exc)
        await db.rollback()
        # Return result even if DB fails

    logger.info("Analysis %s complete. Verdict: %s, Threat: %s/%s",
                analysis_id, verdict, threat_result.get("threat_level"), threat_result.get("threat_score"))

    return full_result
