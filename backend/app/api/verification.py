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

    return record.get_full_result()


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

