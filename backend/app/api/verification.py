"""
QuantumTrust — GET /api/analysis/{id} and GET /api/analyses
"""
from __future__ import annotations
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.analysis import Analysis

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/analysis/{analysis_id}")
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return the complete analysis result for a given ID."""
    stmt = select(Analysis).where(Analysis.analysis_id == analysis_id)
    record = await db.scalar(stmt)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found.",
        )

    res = record.get_full_result()
    if res:
        if "certificate_inspection" not in res:
            sig_data = res.get("signature", {})
            cert_data = res.get("certificate", {})
            if sig_data.get("present"):
                res["certificate_inspection"] = {
                    "status": "SUCCESS",
                    "certificate": {
                        "version": 3,
                        "serial_number": cert_data.get("serial_number"),
                        "subject": {"common_name": cert_data.get("subject"), "raw_dn": cert_data.get("subject")},
                        "issuer": {"common_name": cert_data.get("issuer"), "raw_dn": cert_data.get("issuer")},
                        "signature_algorithm": sig_data.get("signature_algorithm"),
                        "is_self_signed": (cert_data.get("subject") == cert_data.get("issuer")),
                    },
                    "public_key": {
                        "algorithm": sig_data.get("public_key_algorithm") or "RSA",
                        "key_size": sig_data.get("key_size"),
                        "curve": None,
                        "exponent": None,
                    },
                    "validity": {
                        "status": "EXPIRED" if cert_data.get("is_expired") else "VALID",
                        "not_before": cert_data.get("valid_from"),
                        "not_after": cert_data.get("valid_until"),
                    },
                    "trust": {
                        "status": cert_data.get("trust_status") or "UNKNOWN",
                        "reason": "Retrieved from analysis record.",
                    },
                    "fingerprint": {"algorithm": "SHA-256", "value": None},
                    "chain": [],
                    "extensions": [],
                    "security_assessment": {
                        "key_strength": "ACCEPTABLE" if (sig_data.get("key_size") or 0) >= 2048 else "WEAK",
                        "policy": "QuantumTrust Default Cryptographic Policy v1.0",
                        "observations": [],
                    },
                    "findings": [],
                }
            else:
                res["certificate_inspection"] = {
                    "status": "NOT_AVAILABLE",
                    "reason": "No digital signature present in document.",
                }

        if "explainable_verification" not in res:
            from app.services import explainable_verification
            sig_data = res.get("signature", {})
            cert_data = res.get("certificate", {})
            intg_data = res.get("integrity", {})
            doc_data = res.get("document", {})
            dup_data = res.get("duplicate", {})
            sec_data = res.get("security", {})
            q_data = res.get("quantum_analysis", {})
            verdict = res.get("verdict", "SUSPICIOUS")

            evidence = explainable_verification.extract_evidence_from_analysis(
                sig_result=sig_data,
                cert_info=cert_data,
                integrity_result=intg_data,
                pdf_structure={"pdf_version": doc_data.get("pdf_version"), "suspicious_signals": []},
                dup_result=dup_data,
                threat_result=sec_data,
                quantum_result=q_data,
                cert_inspection=res.get("certificate_inspection"),
            )
            explanation_res = explainable_verification.generate_explanation(evidence, verdict)
            res["explainable_verification"] = explanation_res.model_dump()

    return res



@router.get("/analyses")
async def list_analyses(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return a list of recent analyses (summary view) for the dashboard."""
    limit = max(1, min(limit, 200))
    stmt = select(Analysis).order_by(desc(Analysis.created_at)).limit(limit)
    rows = (await db.scalars(stmt)).all()

    results = []
    for row in rows:
        results.append({
            "analysis_id": row.analysis_id,
            "document": {
                "filename":    row.filename,
                "file_size":   row.file_size,
                "pdf_version": row.pdf_version,
                "fingerprint": row.fingerprint,
            },
            "signature": {
                "present": row.signature_present,
                "count":   row.signature_count,
                "status":  row.signature_status,
            },
            "security": {
                "threat_score": row.threat_score,
                "threat_level": row.threat_level,
                "detected_threats": [],
            },
            "verdict":    row.verdict,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        })

    return results


@router.delete("/analysis/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Delete a single analysis record and its associated fingerprint."""
    stmt = select(Analysis).where(Analysis.analysis_id == analysis_id)
    record = await db.scalar(stmt)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found.",
        )

    await db.delete(record)
    # Also delete associated fingerprint if exists
    from app.models.analysis import Fingerprint
    from sqlalchemy import delete
    await db.execute(delete(Fingerprint).where(Fingerprint.analysis_id == analysis_id))
    await db.commit()

    return {"message": f"Analysis '{analysis_id}' deleted successfully.", "analysis_id": analysis_id}


@router.delete("/analyses")
async def clear_all_analyses(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Delete all analysis history and fingerprints."""
    from app.models.analysis import Fingerprint
    from sqlalchemy import delete
    await db.execute(delete(Analysis))
    await db.execute(delete(Fingerprint))
    await db.commit()

    return {"message": "All analysis history cleared successfully."}

