"""
QuantumTrust — Duplicate detection service

Generates a cryptographic document fingerprint (SHA-256) for content comparison.
Duplicate detection is SEPARATE from signature authenticity.

A duplicate document can have:
- Valid or invalid signature
- Same or different signer

Matching fingerprints only indicate exact content identity, not authenticity.
"""
from __future__ import annotations
import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


def generate_fingerprint(pdf_bytes: bytes) -> str:
    """
    Generate a SHA-256 fingerprint of the PDF content.
    Uses the full file bytes for content identity comparison.
    """
    return hashlib.sha256(pdf_bytes).hexdigest()


async def check_duplicate(
    fingerprint: str,
    current_analysis_id: str,
    db_session: Any,
) -> dict[str, Any]:
    """
    Check if a document with the same fingerprint has been analyzed before.

    Returns:
        {is_duplicate, match_type, matching_analysis_id}
    """
    result: dict[str, Any] = {
        "is_duplicate": False,
        "match_type": "NONE",
        "matching_analysis_id": None,
    }

    try:
        from sqlalchemy import select
        from app.models.analysis import Fingerprint

        stmt = select(Fingerprint).where(
            Fingerprint.fingerprint == fingerprint,
            Fingerprint.analysis_id != current_analysis_id,
        ).limit(1)

        row = await db_session.scalar(stmt)
        if row is not None:
            result["is_duplicate"] = True
            result["match_type"] = "EXACT_CONTENT"
            result["matching_analysis_id"] = row.analysis_id

    except Exception as exc:
        logger.warning("Duplicate check error: %s", exc)

    return result


async def store_fingerprint(
    fingerprint: str,
    analysis_id: str,
    filename: str,
    db_session: Any,
) -> None:
    """Store a fingerprint record for future duplicate detection."""
    try:
        from app.models.analysis import Fingerprint
        from sqlalchemy import select

        existing = await db_session.scalar(
            select(Fingerprint).where(Fingerprint.fingerprint == fingerprint)
        )
        if existing is None:
            fp_record = Fingerprint(
                fingerprint=fingerprint,
                analysis_id=analysis_id,
                filename=filename,
            )
            db_session.add(fp_record)
            # Commit happens in the calling context
    except Exception as exc:
        logger.warning("Fingerprint store error: %s", exc)
