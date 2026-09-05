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


class DecisionFactor(BaseModel):
    factor: str
    impact: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status: str = "PASS"    # PASS, FAIL, WARNING, LOCALIZED, SUSPICIOUS, NOT_AVAILABLE
    explanation: str


class VerificationStep(BaseModel):
    step_id: str | None = None
    id: str | None = None
    order: int = 1
    category: str = "SIGNATURE_VERIFICATION"  # FILE_FORMAT, SIGNATURE_VERIFICATION, CERTIFICATE, PUBLIC_KEY, DOCUMENT_INTEGRITY, SIGNATURE_TIMELINE, TAMPERING_LOCALIZATION, THREAT_ANALYSIS, QUANTUM_INSPIRED_ANALYSIS, FINAL_VERDICT
    check: str | None = None
    title: str | None = None
    status: str = "PASS"  # PASS, FAIL, WARNING, NOT_CHECKED, NOT_AVAILABLE
    observed_value: str | None = None
    expected_condition: str | None = None
    explanation: str = ""
    evidence: list[str] = Field(default_factory=list)
    technical_detail: str | None = None
    technical_details: str | None = None
    severity: str | None = None  # CRITICAL, HIGH, MEDIUM, LOW, INFO

    def model_post_init(self, __context: Any) -> None:
        if self.step_id is None and self.id is not None:
            self.step_id = self.id
        elif self.id is None and self.step_id is not None:
            self.id = self.step_id

        if self.title is None and self.check is not None:
            self.title = self.check
        elif self.check is None and self.title is not None:
            self.check = self.title

        if self.technical_details is None and self.technical_detail is not None:
            self.technical_details = self.technical_detail
        elif self.technical_detail is None and self.technical_details is not None:
            self.technical_detail = self.technical_details


class EvidenceItem(BaseModel):
    evidence_id: str | None = None
    code: str | None = None
    category: str = "SIGNATURE"
    source: str = "VERIFICATION_ENGINE"
    field: str | None = None
    status: str = "PASS"  # PASS, FAIL, WARNING, INFO
    title: str = ""
    value: str | None = None
    description: str | None = None
    reason: str | None = None
    importance: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO

    def model_post_init(self, __context: Any) -> None:
        if self.evidence_id is None and self.code is not None:
            self.evidence_id = self.code
        elif self.code is None and self.evidence_id is not None:
            self.code = self.evidence_id

        if self.description is None and self.reason is not None:
            self.description = self.reason
        elif self.reason is None and self.description is not None:
            self.reason = self.description


class ExplanationResult(BaseModel):
    verdict: str = "SUSPICIOUS"
    summary: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW, UNKNOWN, NOT_AVAILABLE
    decision_factors: list[DecisionFactor] = Field(default_factory=list)
    verification_steps: list[VerificationStep] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    why_not_authentic: list[str] = Field(default_factory=list)
    what_would_change_verdict: str | None = None
    warnings: list[Any] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    failed_checks: list[EvidenceItem] = Field(default_factory=list)
    passed_checks: list[EvidenceItem] = Field(default_factory=list)
    final_reason: str = ""
    methodology: str = (
        "Deterministic rule-based explanation derived from cryptographic verification evidence. "
        "Classical quantum-inspired metrics serve as secondary mathematical anomaly signals."
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


class AffectedItem(BaseModel):
    location_type: str = "UNKNOWN"        # PAGE, OBJECT, JSON_PATH, XML_XPATH, XML_ELEMENT, DOCUMENT_PART, PARAGRAPH, TABLE_CELL, BYTE_RANGE, SIGNATURE_CONTAINER, METADATA
    location: str                         # Human-readable location description
    structural_path: str | None = None
    page: int | None = None
    object_id: str | int | None = None
    element_name: str | None = None
    json_path: str | None = None
    xml_xpath: str | None = None
    document_part: str | None = None
    paragraph: int | str | None = None
    table: str | None = None
    cell: str | None = None
    range: str | None = None
    byte_range: list[int] | None = None
    before_value: Any | None = None
    after_value: Any | None = None
    change_type: str = "UNKNOWN_CHANGE"   # VALUE_CHANGED, ELEMENT_CHANGED, FIELD_CHANGED, OBJECT_CHANGED, CONTENT_CHANGED, TEXT_CHANGED, INSERTED, DELETED, MOVED, FORMULA_CHANGED, ANNOTATION_CHANGED, METADATA_CHANGED, STRUCTURE_CHANGED, BYTES_MODIFIED, SIGNATURE_CONTAINER_CHANGED, BYTE_RANGE_CHANGED, REFERENCE_DIGEST_MISMATCH, UNKNOWN_CHANGE
    evidence: list[str] = Field(default_factory=list)
    localization_confidence: str = "UNKNOWN"  # HIGH, MEDIUM, LOW, UNKNOWN


class TamperingLocalizationResult(BaseModel):
    status: str = "NOT_AVAILABLE"            # LOCALIZED, NOT_LOCALIZED, NOT_AVAILABLE, NO_TAMPERING_DETECTED, ERROR
    localization_level: str = "NOT_AVAILABLE" # NONE, FILE_LEVEL, BYTE_LEVEL, STRUCTURAL, PAGE_LEVEL, OBJECT_LEVEL, ELEMENT_LEVEL, FIELD_LEVEL, REGION_LEVEL, UNKNOWN, NOT_AVAILABLE
    tampering_detected: bool = False
    confidence: str = "UNKNOWN"              # HIGH, MEDIUM, LOW, UNKNOWN
    comparison_source: str = "NO_TRUSTED_BASELINE" # EARLIER_SIGNED_REVISION, SIGNED_PAYLOAD_REFERENCE, DIGEST_REFERENCE, INCREMENTAL_REVISION_DIFF, PACKAGE_PARTS, USER_PROVIDED_REFERENCE, NO_TRUSTED_BASELINE
    affected_revision: str | None = None
    affected_signature: str | None = None
    affected_items: list[AffectedItem] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    summary: str | None = None


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
    tampering_localization: TamperingLocalizationResult | None = None



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


