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


class VerificationStep(BaseModel):
    id: str
    order: int
    check: str
    status: str  # PASS, FAIL, WARNING, NOT_CHECKED
    observed_value: str | None = None
    expected_condition: str | None = None
    explanation: str
    technical_detail: str | None = None


class EvidenceItem(BaseModel):
    code: str
    category: str
    status: str  # PASS, FAIL, WARNING, INFO
    title: str
    value: str | None = None
    reason: str


class ExplanationResult(BaseModel):
    summary: str
    verification_steps: list[VerificationStep] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    failed_checks: list[EvidenceItem] = Field(default_factory=list)
    warnings: list[EvidenceItem] = Field(default_factory=list)
    passed_checks: list[EvidenceItem] = Field(default_factory=list)
    final_reason: str
    confidence: str  # HIGH, MEDIUM, LOW, NOT_AVAILABLE
    methodology: str = (
        "Deterministic rule-based explanation derived from cryptographic verification evidence."
    )


class PublicKeyInfo(BaseModel):
    algorithm: str | None = None
    key_size: int | None = None
    curve: str | None = None
    exponent: int | None = None


class CertificateSubject(BaseModel):
    common_name: str | None = None
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    raw_dn: str | None = None


class CertificateIssuer(BaseModel):
    common_name: str | None = None
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None
    raw_dn: str | None = None


class CertificateDetail(BaseModel):
    version: int | None = 3
    serial_number: str | None = None
    subject: CertificateSubject | dict[str, Any] | None = None
    issuer: CertificateIssuer | dict[str, Any] | None = None
    signature_algorithm: str | None = None
    is_self_signed: bool | None = None


class ValidityInfo(BaseModel):
    status: str = "NOT_CHECKED"  # VALID, EXPIRED, NOT_YET_VALID, NOT_CHECKED, UNKNOWN
    not_before: str | None = None
    not_after: str | None = None


class TrustInfo(BaseModel):
    status: str = "NOT_CHECKED"  # TRUSTED, UNTRUSTED, SELF_SIGNED, UNKNOWN, NOT_CHECKED
    reason: str | None = None
    is_trusted: bool = False


class FingerprintInfo(BaseModel):
    algorithm: str = "SHA-256"
    value: str | None = None


class ChainItem(BaseModel):
    role: str = "SIGNER"  # SIGNER, INTERMEDIATE_CA, ROOT_CA, UNKNOWN
    chain_position: int = 0
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    validity: str | None = None
    is_self_signed: bool = False


class ExtensionItem(BaseModel):
    name: str
    critical: bool = False
    value: str | None = None


class SecurityAssessment(BaseModel):
    key_strength: str = "UNKNOWN"  # ACCEPTABLE, WEAK, UNSUPPORTED, UNKNOWN
    policy: str | None = None
    observations: list[str] = Field(default_factory=list)


class FindingItem(BaseModel):
    code: str
    severity: str  # HIGH, MEDIUM, LOW, INFO
    title: str
    description: str


class CertificateInspectionResult(BaseModel):
    status: str = "SUCCESS"  # SUCCESS, NOT_AVAILABLE, EXTRACTION_FAILED, UNSUPPORTED
    reason: str | None = None
    certificate: CertificateDetail | dict[str, Any] | None = None
    public_key: PublicKeyInfo | dict[str, Any] | None = None
    validity: ValidityInfo | dict[str, Any] | None = None
    trust: TrustInfo | dict[str, Any] | None = None
    fingerprint: FingerprintInfo | dict[str, Any] | None = None
    chain: list[ChainItem | dict[str, Any]] = Field(default_factory=list)
    extensions: list[ExtensionItem | dict[str, Any]] = Field(default_factory=list)
    security_assessment: SecurityAssessment | dict[str, Any] | None = None
    findings: list[FindingItem | dict[str, Any]] = Field(default_factory=list)


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
    explainable_verification: ExplanationResult | None = None
    certificate_inspection: CertificateInspectionResult | None = None


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


