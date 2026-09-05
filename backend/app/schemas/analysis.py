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


class TimelineFinding(BaseModel):
    code: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    title: str
    description: str
    signature_id: str | None = None
    evidence: dict[str, Any] | None = None


class SignerInfo(BaseModel):
    common_name: str | None = None
    organization: str | None = None
    email: str | None = None
    raw_dn: str | None = None


class SigningTimeInfo(BaseModel):
    value: str | None = None
    source: str | None = None  # CMS_SIGNING_TIME, PDF_SIGNATURE_DATE, TRUSTED_TIMESTAMP, UNKNOWN
    consistency: str | None = "CONSISTENT"  # CONSISTENT, CONFLICT, UNKNOWN


class ByteRangeInfo(BaseModel):
    ranges: list[int] | None = None
    covered_length: int | None = None
    coverage_status: str = "UNKNOWN"  # VALID, INVALID, UNKNOWN
    excludes_contents_placeholder: bool | None = None


class RevisionInfo(BaseModel):
    revision_number: int | None = None
    total_revisions: int | None = None
    covers_revision: int | None = None
    is_latest_revision: bool | None = None


class VerificationSummary(BaseModel):
    signature_valid: bool | None = None
    integrity_verified: bool | None = None
    certificate_valid: bool | None = None
    certificate_trusted: bool | None = None


class SignatureEvent(BaseModel):
    signature_id: str
    sequence: int = 1
    sequence_number: int | None = None
    field_name: str | None = None
    signer_name: str | None = None
    signer_certificate_subject: str | None = None
    certificate_fingerprint: str | None = None
    signing_time: str | None = None
    signing_time_source: str | None = None  # CMS_SIGNING_TIME, PDF_SIGNATURE_DATE, TRUSTED_TIMESTAMP, XAdES_SIGNING_TIME, UNKNOWN
    signature_algorithm: str | None = None
    digest_algorithm: str | None = None
    signature_format: str | None = None     # CMS, XMLDSig, JWS, PKCS#7
    revision_id: str | None = None
    version_id: str | None = None
    covered_content: str | None = None
    coverage_status: str | None = "VALID"   # VALID, INVALID, UNKNOWN, FULL_REVISION
    cryptographic_status: str = "NOT_CHECKED"  # VALID, INVALID, UNKNOWN, NOT_CHECKED
    certificate_status: str | None = "UNKNOWN"
    trust_status: str | None = "UNKNOWN"
    timestamp_status: str | None = "UNAVAILABLE"
    chronology_confidence: str | None = "HIGH" # HIGH, MEDIUM, LOW, UNKNOWN
    post_signature_change: str | None = None
    findings: list[TimelineFinding | dict[str, Any]] = Field(default_factory=list)


class SignatureTimelineEntry(BaseModel):
    signature_id: str
    field_name: str
    sequence_number: int
    sequence: int | None = None
    signer: SignerInfo | dict[str, Any] | None = None
    signer_name: str | None = None
    signer_certificate_subject: str | None = None
    signing_time: SigningTimeInfo | dict[str, Any] | str | None = None
    signing_time_source: str | None = None
    signature_algorithm: str | None = None
    digest_algorithm: str | None = None
    signature_format: str | None = None
    certificate_fingerprint: str | None = None
    byte_range: ByteRangeInfo | dict[str, Any] | None = None
    revision: RevisionInfo | dict[str, Any] | None = None
    revision_id: str | None = None
    version_id: str | None = None
    covered_content: str | None = None
    coverage_status: str | None = None
    cryptographic_status: str | None = None
    certificate_status: str | None = None
    trust_status: str | None = None
    timestamp_status: str | None = None
    chronology_confidence: str | None = None
    verification: VerificationSummary | dict[str, Any] | None = None
    status: str = "NOT_CHECKED"  # VALID, INVALID, SUSPICIOUS, NOT_CHECKED, UNSUPPORTED
    post_signature_change: str | None = None
    findings: list[TimelineFinding | dict[str, Any]] = Field(default_factory=list)


class SignatureTimelineResult(BaseModel):
    status: str = "AVAILABLE"                # AVAILABLE, NOT_AVAILABLE, NO_SIGNATURES, PARTIAL, ERROR
    format: str = "PDF"                      # PDF, CMS/PKCS#7, XMLDSig, DOCX, BINARY, etc.
    signature_count: int = 0
    chronology_confidence: str = "HIGH"      # HIGH, MEDIUM, LOW, UNKNOWN
    total_revisions: int | None = None
    events: list[SignatureEvent | dict[str, Any]] = Field(default_factory=list)
    findings: list[TimelineFinding | dict[str, Any]] = Field(default_factory=list)
    reason: str | None = None

    # Backward-compatibility aliases
    total_signature_fields: int = 0
    total_signed_signatures: int = 0
    revision_count: int | None = None
    timeline_status: str = "NOT_AVAILABLE"  # ANALYZED, NOT_AVAILABLE, NO_SIGNATURES, ERROR
    consistency_status: str = "UNKNOWN"      # CONSISTENT, INCONSISTENT, PARTIAL, UNKNOWN
    timeline_order_confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    signatures: list[SignatureTimelineEntry | dict[str, Any]] = Field(default_factory=list)


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
    signature_timeline: SignatureTimelineResult | None = None


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


