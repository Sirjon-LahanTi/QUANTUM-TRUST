"""
QuantumTrust Backend — Pydantic response schemas
"""
from __future__ import annotations
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DocumentInfo(BaseModel):
    filename: str
    file_size: int
    pdf_version: str | None = None
    fingerprint: str | None = None


class SignatureInfo(BaseModel):
    present: bool = False
    count: int = 0
    status: str | None = None        # VALID, INVALID, UNKNOWN, UNSUPPORTED, NONE
    signature_type: str | None = None
    digest_algorithm: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    key_size: int | None = None


class CertificateInfo(BaseModel):
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_status: str | None = None  # TRUSTED, UNTRUSTED, EXPIRED, SELF_SIGNED, UNAVAILABLE


class IntegrityInfo(BaseModel):
    status: str | None = None        # VERIFIED, FAILED, PERMITTED_CHANGES, UNKNOWN
    byte_range: list[int] | None = None
    modification_status: str | None = None  # NO_UNAUTHORIZED_CHANGES, MODIFIED, UNKNOWN


class DuplicateInfo(BaseModel):
    is_duplicate: bool = False
    match_type: str | None = None    # EXACT_CONTENT, NONE
    matching_analysis_id: str | None = None


class SecurityInfo(BaseModel):
    threat_score: float = 0
    threat_level: str = "LOW"        # LOW, MEDIUM, HIGH, CRITICAL
    detected_threats: list[str] = Field(default_factory=list)


class QuantumAnalysis(BaseModel):
    state_dimension: int | None = 14
    state_similarity: float | None = None
    correlation_score: float | None = None
    disturbance_score: float | None = None
    anomaly_distance: float | None = None
    entropy: float | None = None
    reference_type: str | None = "deterministic_baseline"
    simulation_note: str | None = None


class AnalysisResult(BaseModel):
    analysis_id: str
    document: DocumentInfo
    signature: SignatureInfo
    certificate: CertificateInfo
    integrity: IntegrityInfo
    duplicate: DuplicateInfo
    security: SecurityInfo
    quantum_analysis: QuantumAnalysis
    verdict: str                     # AUTHENTIC, TAMPERED, SUSPICIOUS
    created_at: str | None = None


class AnalysisSummary(BaseModel):
    """Lightweight summary for the dashboard list."""
    analysis_id: str
    document: DocumentInfo
    signature: SignatureInfo
    security: SecurityInfo
    verdict: str | None = None
    created_at: datetime | None = None


class ReportData(BaseModel):
    """Full report payload."""
    analysis_id: str
    generated_at: datetime
    result: AnalysisResult


class ErrorResponse(BaseModel):
    detail: str
