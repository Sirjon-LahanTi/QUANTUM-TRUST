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
    certificate_inspector,
    duplicate_detector,
    threat_engine,
    quantum_analysis,
    explainable_verification,
    signature_timeline,
    tampering_localization,
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
    # ── 1. Validate file metadata ──────────────────────────────────────────────
    filename = _sanitize_filename(file.filename or "upload.bin")
    content_type = file.content_type or ""

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

    # ── 3. Generate analysis ID ────────────────────────────────────────────────
    analysis_id = secrets.token_hex(16)

    logger.info("Starting analysis %s for file '%s' (%d bytes)", analysis_id, filename, file_size)

    # ── 4. Parse file & verify digital signature ──────────────────────────────
    is_pdf = pdf_bytes.startswith(b"%PDF") or filename.lower().endswith(".pdf")

    if is_pdf:
        try:
            pdf_structure = pdf_parser.parse_pdf_structure(pdf_bytes)
        except Exception as exc:
            logger.error("PDF parse failed: %s", exc)
            pdf_structure = {"pdf_version": None, "suspicious_signals": [], "parse_error": str(exc)}

        try:
            sig_result = await asyncio.to_thread(signature_verifier.verify_pdf_signatures, pdf_bytes)
        except Exception as exc:
            logger.error("Signature verification failed: %s", exc)
            sig_result = {"present": False, "overall_status": "UNKNOWN", "error": str(exc)}
    else:
        file_ext = Path(filename).suffix.lstrip(".").upper() or "BINARY"
        pdf_structure = {
            "pdf_version": None,
            "file_type": file_ext,
            "suspicious_signals": [],
        }
        sig_result = {
            "present": False,
            "count": 0,
            "overall_status": "NONE",
            "signature_type": None,
            "digest_algorithm": "SHA-256",
            "signature_algorithm": None,
            "public_key_algorithm": None,
            "key_size": None,
            "integrity_status": "VERIFIED",
            "integrity_modification_status": "NO_UNAUTHORIZED_CHANGES",
            "signatures": [],
        }

    # ── 5. Analyze & Inspect certificate ───────────────────────────────────────
    cert_info: dict[str, Any] = {
        "subject": None, "issuer": None, "serial_number": None,
        "valid_from": None, "valid_until": None, "trust_status": "UNAVAILABLE",
        "is_expired": None, "is_self_signed": None,
    }
    cert_inspection: dict[str, Any] = {
        "status": "NOT_AVAILABLE",
        "reason": "No digital signature present in document.",
    }

    if sig_result.get("signatures"):
        primary_sig = sig_result["signatures"][0]
        cert_raw = primary_sig.get("_cert_object")
        all_certs = primary_sig.get("_all_certs")
        if cert_raw is not None:
            cert_info = certificate_analyzer.analyze_certificate(cert_raw)
            cert_inspection = certificate_inspector.inspect_certificate(
                cert_source=cert_raw,
                all_certs=all_certs,
                document_signature_algo=sig_result.get("signature_algorithm"),
                document_digest_algo=sig_result.get("digest_algorithm"),
            )
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
            if primary_sig.get("cert_subject") or primary_sig.get("cert_serial"):
                cert_inspection = {
                    "status": "SUCCESS",
                    "certificate": {
                        "version": 3,
                        "serial_number": primary_sig.get("cert_serial"),
                        "subject": {"common_name": primary_sig.get("cert_subject"), "raw_dn": primary_sig.get("cert_subject")},
                        "issuer": {"common_name": primary_sig.get("cert_issuer"), "raw_dn": primary_sig.get("cert_issuer")},
                        "signature_algorithm": primary_sig.get("signature_algorithm"),
                        "is_self_signed": (primary_sig.get("cert_subject") == primary_sig.get("cert_issuer")),
                    },
                    "public_key": {
                        "algorithm": primary_sig.get("public_key_algorithm") or "RSA",
                        "key_size": primary_sig.get("key_size"),
                        "curve": None,
                        "exponent": None,
                    },
                    "validity": {
                        "status": "EXPIRED" if cert_info.get("is_expired") else "VALID",
                        "not_before": primary_sig.get("cert_valid_from"),
                        "not_after": primary_sig.get("cert_valid_until"),
                    },
                    "trust": {
                        "status": primary_sig.get("trust_status") or "UNKNOWN",
                        "reason": "Derived from signature validation container.",
                    },
                    "fingerprint": {"algorithm": "SHA-256", "value": None},
                    "chain": [],
                    "extensions": [],
                    "security_assessment": {
                        "key_strength": "ACCEPTABLE" if (primary_sig.get("key_size") or 0) >= 2048 else "WEAK",
                        "policy": "QuantumTrust Default Cryptographic Policy v1.0",
                        "observations": [],
                    },
                    "findings": [],
                }

    # ── 6. Build integrity result ──────────────────────────────────────────────
    integrity_result: dict[str, Any] = {
        "integrity_status":       sig_result.get("integrity_status", "UNKNOWN"),
        "modification_status":    sig_result.get("integrity_modification_status", "UNKNOWN"),
        "byte_range":             sig_result.get("byte_range"),
    }

    # ── 7. Fingerprint + duplicate detection ───────────────────────────────────
    fingerprint = duplicate_detector.generate_fingerprint(pdf_bytes)
    dup_result  = await duplicate_detector.check_duplicate(fingerprint, analysis_id, db)

    # ── 8. Quantum-inspired analysis ──────────────────────────────────────────
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

    # ── Duplicate status alignment with tampered / modified detection ─────────
    is_duplicate = bool(dup_result.get("is_duplicate", False))
    match_type = dup_result.get("match_type", "NONE")

    if verdict == "TAMPERED" or integrity_result.get("integrity_status") == "FAILED" or integrity_result.get("modification_status") == "MODIFIED":
        is_duplicate = True
        if match_type in (None, "NONE"):
            match_type = "TAMPERED_DUPLICATE"

    dup_result["is_duplicate"] = is_duplicate
    dup_result["match_type"] = match_type

    # ── 12. Signature Timeline & Multi-Signature Analysis ──────────────────────
    detected_file_type = "PDF" if is_pdf else (Path(filename).suffix.lstrip(".").upper() or "BINARY")
    try:
        sig_timeline = await asyncio.to_thread(
            signature_timeline.analyze_signature_timeline,
            file_path_or_bytes=pdf_bytes,
            file_type=detected_file_type,
            existing_verification_result=sig_result,
            certificate_inspection=cert_inspection,
            pdf_bytes=pdf_bytes,
            sig_result=sig_result,
            cert_info=cert_info,
            integrity_result=integrity_result,
            pdf_structure=pdf_structure,
            filename=filename,
        )
    except Exception as exc:
        logger.error("Signature timeline analysis failed: %s", exc)
        sig_timeline = {
            "status": "ERROR",
            "format": detected_file_type,
            "signature_count": sig_result.get("count", 0),
            "chronology_confidence": "UNKNOWN",
            "total_revisions": pdf_structure.get("incremental_update_count", 0) + 1 if is_pdf else None,
            "events": [],
            "findings": [],
            "reason": str(exc),
            "total_signature_fields": sig_result.get("count", 0),
            "total_signed_signatures": len(sig_result.get("signatures", [])),
            "revision_count": pdf_structure.get("incremental_update_count", 0) + 1 if is_pdf else None,
            "timeline_status": "ERROR",
            "consistency_status": "UNKNOWN",
            "timeline_order_confidence": "LOW",
            "signatures": [],
        }

    # ── 13. Tampering Localization Engine ──────────────────────────────────────
    try:
        tampering_loc = await asyncio.to_thread(
            tampering_localization.localize_tampering,
            file_path_or_bytes=pdf_bytes,
            file_type=detected_file_type,
            filename=filename,
            existing_verification_result=sig_result,
            signature_timeline=sig_timeline,
            integrity_result=integrity_result,
            pdf_structure=pdf_structure,
        )
    except Exception as exc:
        logger.error("Tampering localization failed: %s", exc)
        tampering_loc = {
            "status": "ERROR",
            "localization_level": "NOT_AVAILABLE",
            "tampering_detected": False,
            "confidence": "UNKNOWN",
            "comparison_source": "NO_TRUSTED_BASELINE",
            "affected_revision": None,
            "affected_signature": None,
            "affected_items": [],
            "findings": ["LOCALIZATION_UNAVAILABLE"],
            "limitations": [str(exc)],
            "summary": f"Tampering localization failed: {exc}",
        }

    # ── 14. Explainable Verification (Deterministic rule-based explanation) ───
    evidence = explainable_verification.extract_evidence_from_analysis(
        sig_result=sig_result,
        cert_info=cert_info,
        integrity_result=integrity_result,
        pdf_structure=pdf_structure,
        dup_result=dup_result,
        threat_result=threat_result,
        quantum_result=q_result,
        cert_inspection=cert_inspection,
        signature_timeline=sig_timeline,
        tampering_localization=tampering_loc,
        file_type=detected_file_type,
        filename=filename,
        file_size=file_size,
    )
    explanation_res = explainable_verification.generate_explanation(evidence, verdict)

    # ── 15. Assemble result ────────────────────────────────────────────────────
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
        "explainable_verification": explanation_res.model_dump(),
        "certificate_inspection": cert_inspection,
        "signature_timeline": sig_timeline,
        "tampering_localization": tampering_loc,
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
