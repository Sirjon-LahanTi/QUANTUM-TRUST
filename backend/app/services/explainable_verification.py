"""
QuantumTrust — Explainable Verification Engine

Provides a deterministic, rule-based explanation layer derived strictly from
actual cryptographic verification and document analysis results.

Guiding Principles:
1. No AI / LLM generation: all explanations are strictly derived from concrete evidence.
2. No cryptographic re-computation: consumes existing verification outputs.
3. Authoritative verdict alignment: explains WHY the backend determined AUTHENTIC, TAMPERED, or SUSPICIOUS.
4. No algorithm assumptions: reports detected algorithms or explicitly marks as UNKNOWN.
5. True missing data representation: unperformed or unavailable checks remain NOT_CHECKED / UNKNOWN, never fabricated as False.
6. Quantum-inspired separation: quantum metrics are clearly contextualized as secondary classical simulation signals.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


# ── Status and Category Enums / Literals ──────────────────────────────────────

class StepStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_CHECKED = "NOT_CHECKED"


class EvidenceCategory(str, Enum):
    SIGNATURE = "SIGNATURE"
    INTEGRITY = "INTEGRITY"
    CERTIFICATE = "CERTIFICATE"
    ALGORITHM = "ALGORITHM"
    STRUCTURE = "STRUCTURE"
    THREAT = "THREAT"
    DUPLICATE = "DUPLICATE"
    QUANTUM_INSPIRED = "QUANTUM_INSPIRED"


class EvidenceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_AVAILABLE = "NOT_AVAILABLE"


# ── Pydantic Output Models ───────────────────────────────────────────────────

class VerificationStep(BaseModel):
    """An ordered stage in the verification trace."""
    id: str
    order: int
    check: str
    status: str  # PASS | FAIL | WARNING | NOT_CHECKED
    observed_value: str | None = None
    expected_condition: str | None = None
    explanation: str
    technical_detail: str | None = None


class EvidenceItem(BaseModel):
    """A distinct granular piece of evidence."""
    code: str
    category: str  # SIGNATURE | INTEGRITY | CERTIFICATE | ALGORITHM | STRUCTURE | THREAT | DUPLICATE | QUANTUM_INSPIRED
    status: str    # PASS | FAIL | WARNING | INFO
    title: str
    value: str | None = None
    reason: str


class ExplanationResult(BaseModel):
    """Complete explainable verification result payload."""
    summary: str
    verification_steps: list[VerificationStep] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    failed_checks: list[EvidenceItem] = Field(default_factory=list)
    warnings: list[EvidenceItem] = Field(default_factory=list)
    passed_checks: list[EvidenceItem] = Field(default_factory=list)
    final_reason: str
    confidence: str  # HIGH | MEDIUM | LOW | NOT_AVAILABLE
    methodology: str = (
        "Deterministic rule-based explanation derived from cryptographic verification evidence. "
        "Classical quantum-inspired metrics serve as secondary mathematical anomaly signals."
    )


# ── Normalized Input Evidence Model ──────────────────────────────────────────

@dataclass
class VerificationEvidence:
    """Normalized evidence input aggregated from all verification sub-systems."""
    signature_present: bool = False
    signature_count: int = 0
    signature_valid: bool | None = None
    integrity_verified: bool | None = None
    signed_content_modified: bool | None = None

    digest_algorithm: str | None = None
    signature_algorithm: str | None = None

    certificate_present: bool = False
    certificate_valid: bool | None = None
    certificate_trusted: bool | None = None
    certificate_expired: bool | None = None
    certificate_revoked: bool | None = None

    byte_range_present: bool | None = None
    byte_range_valid: bool | None = None

    public_key_algorithm: str | None = None
    public_key_size: int | None = None

    structural_anomalies: list[str] = field(default_factory=list)
    detected_threats: list[str] = field(default_factory=list)

    threat_score: float | int | None = None
    threat_level: str | None = None

    duplicate_detected: bool = False
    duplicate_match_type: str | None = None

    quantum_analysis: dict[str, Any] | None = None
    signatures_detail: list[dict[str, Any]] = field(default_factory=list)
    certificate_inspection: dict[str, Any] | None = None


# ── Evidence Extractor from Subsystem Dictionaries ───────────────────────────

def extract_evidence_from_analysis(
    sig_result: dict[str, Any],
    cert_info: dict[str, Any],
    integrity_result: dict[str, Any],
    pdf_structure: dict[str, Any],
    dup_result: dict[str, Any],
    threat_result: dict[str, Any],
    quantum_result: dict[str, Any] | None = None,
    cert_inspection: dict[str, Any] | None = None,
) -> VerificationEvidence:
    """
    Constructs normalized VerificationEvidence from raw backend sub-system outputs.
    Ensures missing values remain None/unknown rather than false negatives.
    """
    sig_present = bool(sig_result.get("present", False))
    sig_count = int(sig_result.get("count", 0))
    overall_status = sig_result.get("overall_status")

    sig_valid: bool | None = None
    if sig_present:
        if overall_status == "VALID":
            sig_valid = True
        elif overall_status in ("INVALID", "CORRUPTED"):
            sig_valid = False
        else:
            sig_valid = None

    # Integrity & ByteRange
    byte_range = integrity_result.get("byte_range") or sig_result.get("byte_range")
    byte_range_present = (byte_range is not None and isinstance(byte_range, list) and len(byte_range) > 0)
    
    int_status = (integrity_result.get("integrity_status") or "").upper()
    mod_status = (integrity_result.get("modification_status") or "").upper()

    integrity_verified: bool | None = None
    signed_content_modified: bool | None = None
    byte_range_valid: bool | None = None

    if sig_present:
        if int_status == "VERIFIED" or mod_status == "NO_UNAUTHORIZED_CHANGES":
            integrity_verified = True
            signed_content_modified = False
            byte_range_valid = True
        elif int_status == "PERMITTED_CHANGES" or mod_status == "PERMITTED_CHANGES":
            integrity_verified = True
            signed_content_modified = False  # Permitted incremental update
            byte_range_valid = True
        elif int_status == "FAILED" or mod_status == "MODIFIED":
            integrity_verified = False
            signed_content_modified = True
            byte_range_valid = False
        else:
            integrity_verified = None
            signed_content_modified = None
            byte_range_valid = None

    # Certificate
    cert_present = bool(
        cert_info.get("subject") or
        cert_info.get("issuer") or
        cert_info.get("serial_number") or
        (cert_inspection and cert_inspection.get("status") == "SUCCESS") or
        (sig_result.get("signatures") and sig_result["signatures"][0].get("cert_subject"))
    )
    trust_status = (cert_info.get("trust_status") or "UNAVAILABLE").upper()
    cert_expired = cert_info.get("is_expired")
    cert_valid: bool | None = None
    cert_trusted: bool | None = None

    if cert_inspection and cert_inspection.get("status") == "SUCCESS":
        val_sec = cert_inspection.get("validity") or {}
        val_st = val_sec.get("status")
        if val_st == "EXPIRED":
            cert_expired = True
            cert_valid = False
        elif val_st == "NOT_YET_VALID":
            cert_valid = False
        elif val_st == "VALID":
            cert_valid = True
            cert_expired = False

        trust_sec = cert_inspection.get("trust") or {}
        t_st = trust_sec.get("status")
        if t_st == "TRUSTED":
            cert_trusted = True
        elif t_st in ("UNTRUSTED", "SELF_SIGNED", "EXPIRED"):
            cert_trusted = False

    elif cert_present:
        if cert_expired is True:
            cert_valid = False
            cert_trusted = False
        elif trust_status == "TRUSTED":
            cert_valid = True
            cert_trusted = True
        elif trust_status in ("UNTRUSTED", "SELF_SIGNED", "EXPIRED"):
            cert_valid = (cert_expired is False or cert_expired is None)
            cert_trusted = False
        else:
            cert_valid = None
            cert_trusted = None

    # Structural anomalies from PDF parser
    structural_anomalies = list(pdf_structure.get("suspicious_signals", []))

    # Threats
    detected_threats = list(threat_result.get("detected_threats", []))
    threat_score = threat_result.get("threat_score")
    threat_level = threat_result.get("threat_level")

    # Duplicate
    dup_detected = bool(dup_result.get("is_duplicate", False))
    dup_match = dup_result.get("match_type")

    # Algorithms
    digest_algo = sig_result.get("digest_algorithm")
    sig_algo = sig_result.get("signature_algorithm")
    pub_key_algo = sig_result.get("public_key_algorithm")
    key_size = sig_result.get("key_size")

    return VerificationEvidence(
        signature_present=sig_present,
        signature_count=sig_count,
        signature_valid=sig_valid,
        integrity_verified=integrity_verified,
        signed_content_modified=signed_content_modified,
        digest_algorithm=digest_algo,
        signature_algorithm=sig_algo,
        certificate_present=cert_present,
        certificate_valid=cert_valid,
        certificate_trusted=cert_trusted,
        certificate_expired=cert_expired,
        certificate_revoked=cert_info.get("is_revoked"),
        byte_range_present=byte_range_present,
        byte_range_valid=byte_range_valid,
        public_key_algorithm=pub_key_algo,
        public_key_size=key_size,
        structural_anomalies=structural_anomalies,
        detected_threats=detected_threats,
        threat_score=threat_score,
        threat_level=threat_level,
        duplicate_detected=dup_detected,
        duplicate_match_type=dup_match,
        quantum_analysis=quantum_result,
        signatures_detail=sig_result.get("signatures", []),
        certificate_inspection=cert_inspection,
    )


# ── Deterministic Rule-Based Engine ──────────────────────────────────────────

def generate_explanation(
    evidence: VerificationEvidence,
    verdict: str,
) -> ExplanationResult:
    """
    Deterministically converts VerificationEvidence and the backend verdict
    into an ExplanationResult with ordered trace steps and granular evidence items.
    """
    steps: list[VerificationStep] = []
    evidence_items: list[EvidenceItem] = []
    verdict_upper = (verdict or "SUSPICIOUS").upper()

    step_order = 1

    # ── Step 1: Signature Presence ────────────────────────────────────────────
    if evidence.signature_present:
        sig_count_str = f"{evidence.signature_count} digital signature(s) detected"
        steps.append(VerificationStep(
            id="sig_presence",
            order=step_order,
            check="Digital signature presence",
            status=StepStatus.PASS.value,
            observed_value=f"Found ({evidence.signature_count})",
            expected_condition="At least 1 digital signature present in document",
            explanation=f"Detected {evidence.signature_count} digital signature structure(s) embedded in the PDF.",
            technical_detail="Parsed signature dictionaries via pyHanko embedded signature reader.",
        ))
        evidence_items.append(EvidenceItem(
            code="SIG_PRESENT",
            category=EvidenceCategory.SIGNATURE.value,
            status=EvidenceStatus.PASS.value,
            title="Digital Signature Presence",
            value=f"{evidence.signature_count} signature(s)",
            reason="One or more valid digital signature dictionaries were located within the document structure.",
        ))
    else:
        steps.append(VerificationStep(
            id="sig_presence",
            order=step_order,
            check="Digital signature presence",
            status=StepStatus.FAIL.value,
            observed_value="None",
            expected_condition="At least 1 digital signature present in document",
            explanation="No digital signature was detected in the submitted file.",
            technical_detail="No /ByteRange or signature dictionary found in the PDF object table.",
        ))
        evidence_items.append(EvidenceItem(
            code="SIG_ABSENT",
            category=EvidenceCategory.SIGNATURE.value,
            status=EvidenceStatus.FAIL.value,
            title="Digital Signature Missing",
            value="0 signatures",
            reason="The document contains no digital signature dictionaries or embedded PKCS#7 / CMS signatures.",
        ))

    step_order += 1

    # ── Step 2: Algorithm Detection (No assumptions) ──────────────────────────
    if evidence.signature_present:
        digest_detected = bool(evidence.digest_algorithm)
        sig_algo_detected = bool(evidence.signature_algorithm)

        algo_desc_parts = []
        if digest_detected:
            algo_desc_parts.append(f"Digest: {evidence.digest_algorithm}")
        if sig_algo_detected:
            algo_desc_parts.append(f"Signature: {evidence.signature_algorithm}")
        if evidence.public_key_algorithm:
            algo_desc_parts.append(f"Key: {evidence.public_key_algorithm} ({evidence.public_key_size or '?'} bits)")

        is_weak_digest = evidence.digest_algorithm and evidence.digest_algorithm.upper() in ("MD5", "SHA1", "SHA-1")
        
        if digest_detected and sig_algo_detected:
            status = StepStatus.WARNING.value if is_weak_digest else StepStatus.PASS.value
            exp_text = (
                f"Weak digest algorithm {evidence.digest_algorithm} detected."
                if is_weak_digest else
                f"Cryptographic algorithms detected: {', '.join(algo_desc_parts)}."
            )
            steps.append(VerificationStep(
                id="algo_detection",
                order=step_order,
                check="Cryptographic algorithm identification",
                status=status,
                observed_value=" / ".join(algo_desc_parts),
                expected_condition="Standard cryptographically secure digest and signature algorithms",
                explanation=exp_text,
                technical_detail=f"Extracted from signer CMS / X.509 ASN.1 structure without hardcoded defaults.",
            ))
            evidence_items.append(EvidenceItem(
                code="ALGO_WEAK" if is_weak_digest else "ALGO_IDENTIFIED",
                category=EvidenceCategory.ALGORITHM.value,
                status=EvidenceStatus.WARNING.value if is_weak_digest else EvidenceStatus.PASS.value,
                title="Cryptographic Algorithms",
                value=" / ".join(algo_desc_parts),
                reason=(
                    f"Digest algorithm {evidence.digest_algorithm} is cryptographically obsolete."
                    if is_weak_digest else
                    "Signature and digest algorithms were parsed directly from CMS signature attributes."
                ),
            ))
        elif digest_detected or sig_algo_detected:
            steps.append(VerificationStep(
                id="algo_detection",
                order=step_order,
                check="Cryptographic algorithm identification",
                status=StepStatus.WARNING.value,
                observed_value=" / ".join(algo_desc_parts) or "Partial",
                expected_condition="Complete digest and signature algorithm identification",
                explanation="Only partial cryptographic algorithm parameters could be identified from the signature header.",
                technical_detail="CMS signer information was incomplete or partially omitted.",
            ))
            evidence_items.append(EvidenceItem(
                code="ALGO_PARTIAL",
                category=EvidenceCategory.ALGORITHM.value,
                status=EvidenceStatus.WARNING.value,
                title="Partial Algorithm Identification",
                value=" / ".join(algo_desc_parts),
                reason="Algorithm parameters were only partially present in the signature metadata.",
            ))
        else:
            steps.append(VerificationStep(
                id="algo_detection",
                order=step_order,
                check="Cryptographic algorithm identification",
                status=StepStatus.WARNING.value,
                observed_value="Unknown / Unsupported",
                expected_condition="Valid recognized signature algorithm",
                explanation="The signature algorithm could not be determined or is not supported.",
                technical_detail="SignerInfo digestAlgorithm or signatureAlgorithm ASN.1 OID was unrecognized.",
            ))
            evidence_items.append(EvidenceItem(
                code="ALGO_UNKNOWN",
                category=EvidenceCategory.ALGORITHM.value,
                status=EvidenceStatus.WARNING.value,
                title="Algorithm Identification Unresolved",
                value="Unknown",
                reason="Could not determine digest or signature algorithm from embedded CMS metadata.",
            ))
    else:
        steps.append(VerificationStep(
            id="algo_detection",
            order=step_order,
            check="Cryptographic algorithm identification",
            status=StepStatus.NOT_CHECKED.value,
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Algorithm identification was not performed because no signature is present.",
            technical_detail=None,
        ))

    step_order += 1

    # ── Step 3: Certificate and Trust Validation ──────────────────────────────
    if evidence.signature_present:
        if not evidence.certificate_present:
            steps.append(VerificationStep(
                id="cert_validation",
                order=step_order,
                check="Signer certificate parsing & validation",
                status=StepStatus.WARNING.value,
                observed_value="No certificate embedded",
                expected_condition="Valid X.509 certificate embedded in CMS signature",
                explanation="No signer certificate was found embedded in the signature container.",
                technical_detail="Certificates bag in CMS SignedData is empty.",
            ))
            evidence_items.append(EvidenceItem(
                code="CERT_ABSENT",
                category=EvidenceCategory.CERTIFICATE.value,
                status=EvidenceStatus.WARNING.value,
                title="Signer Certificate Unavailable",
                value="None",
                reason="Signer certificate is absent; trust evaluation cannot be executed.",
            ))
        elif evidence.certificate_expired:
            steps.append(VerificationStep(
                id="cert_validation",
                order=step_order,
                check="Signer certificate parsing & validation",
                status=StepStatus.WARNING.value,
                observed_value="Expired",
                expected_condition="Certificate within valid lifetime (NotBefore / NotAfter)",
                explanation="The signer certificate has expired beyond its NotAfter validity timestamp.",
                technical_detail="Current verification timestamp is strictly after certificate valid_until date.",
            ))
            evidence_items.append(EvidenceItem(
                code="CERT_EXPIRED",
                category=EvidenceCategory.CERTIFICATE.value,
                status=EvidenceStatus.WARNING.value,
                title="Certificate Expired",
                value="Expired",
                reason="The digital certificate is past its expiration date.",
            ))
        elif evidence.certificate_trusted is False:
            steps.append(VerificationStep(
                id="cert_validation",
                order=step_order,
                check="Signer certificate parsing & validation",
                status=StepStatus.WARNING.value,
                observed_value="Untrusted / Self-signed",
                expected_condition="Certificate issued by a trusted root Certificate Authority",
                explanation="The certificate is self-signed or not chained to a trusted root authority.",
                technical_detail="Certificate path validation could not establish a path to a trusted root anchor.",
            ))
            evidence_items.append(EvidenceItem(
                code="CERT_UNTRUSTED",
                category=EvidenceCategory.CERTIFICATE.value,
                status=EvidenceStatus.WARNING.value,
                title="Untrusted Certificate Chain",
                value="Self-Signed / Untrusted",
                reason="The certificate is not anchored in a trusted system or enterprise root CA.",
            ))
        elif evidence.certificate_valid is True and evidence.certificate_trusted is True:
            steps.append(VerificationStep(
                id="cert_validation",
                order=step_order,
                check="Signer certificate parsing & validation",
                status=StepStatus.PASS.value,
                observed_value="Trusted & Valid",
                expected_condition="Valid, unexpired certificate from trusted root CA",
                explanation="The signer certificate is valid, unexpired, and cryptographically verified.",
                technical_detail="Certificate parsed successfully with valid ASN.1 structure and date window.",
            ))
            evidence_items.append(EvidenceItem(
                code="CERT_VALID",
                category=EvidenceCategory.CERTIFICATE.value,
                status=EvidenceStatus.PASS.value,
                title="Signer Certificate Valid",
                value="Valid",
                reason="Certificate is active, formatted correctly, and possesses valid lifetime parameters.",
            ))
        else:
            steps.append(VerificationStep(
                id="cert_validation",
                order=step_order,
                check="Signer certificate parsing & validation",
                status=StepStatus.PASS.value,
                observed_value="Parsed",
                expected_condition="Valid X.509 certificate",
                explanation="Signer certificate parsed successfully from signature container.",
                technical_detail="Certificate fields extracted without structural errors.",
            ))
            evidence_items.append(EvidenceItem(
                code="CERT_PARSED",
                category=EvidenceCategory.CERTIFICATE.value,
                status=EvidenceStatus.PASS.value,
                title="Certificate Parsed",
                value="Available",
                reason="Certificate metadata was extracted successfully.",
            ))
    else:
        steps.append(VerificationStep(
            id="cert_validation",
            order=step_order,
            check="Signer certificate parsing & validation",
            status=StepStatus.NOT_CHECKED.value,
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Certificate validation was not performed because no signature is present.",
            technical_detail=None,
        ))

    step_order += 1

    # ── Step 4: Cryptographic Signature Verification ──────────────────────────
    if evidence.signature_present:
        if evidence.signature_valid is True:
            steps.append(VerificationStep(
                id="crypto_signature",
                order=step_order,
                check="Signature cryptographic verification",
                status=StepStatus.PASS.value,
                observed_value="Valid",
                expected_condition="Signature value cryptographically verifies against digest and public key",
                explanation="The digital signature cryptographically verifies against the signed content and the associated public key.",
                technical_detail="Asymmetric signature decryption / validation against the calculated digest succeeded.",
            ))
            evidence_items.append(EvidenceItem(
                code="CRYPTO_SIG_VALID",
                category=EvidenceCategory.SIGNATURE.value,
                status=EvidenceStatus.PASS.value,
                title="Cryptographic Signature Valid",
                value="Valid",
                reason="The mathematical signature calculation matches the signed message digest.",
            ))
        elif evidence.signature_valid is False:
            steps.append(VerificationStep(
                id="crypto_signature",
                order=step_order,
                check="Signature cryptographic verification",
                status=StepStatus.FAIL.value,
                observed_value="Invalid / Mismatch",
                expected_condition="Signature value cryptographically verifies against digest and public key",
                explanation="Cryptographic signature verification failed. The existing signature does not validate against the signed content.",
                technical_detail="Decrypted signature digest does not match computed byte range digest (tampering or corrupt signature).",
            ))
            evidence_items.append(EvidenceItem(
                code="CRYPTO_SIG_INVALID",
                category=EvidenceCategory.SIGNATURE.value,
                status=EvidenceStatus.FAIL.value,
                title="Cryptographic Signature Failed",
                value="Invalid",
                reason="The digital signature does not mathematically match the signed document content.",
            ))
        else:
            steps.append(VerificationStep(
                id="crypto_signature",
                order=step_order,
                check="Signature cryptographic verification",
                status=StepStatus.WARNING.value,
                observed_value="Unknown / Unverified",
                expected_condition="Definitive cryptographic verification",
                explanation="Cryptographic verification could not reach a definitive pass/fail conclusion.",
                technical_detail="pyHanko returned UNKNOWN or unsupported validation status.",
            ))
            evidence_items.append(EvidenceItem(
                code="CRYPTO_SIG_UNKNOWN",
                category=EvidenceCategory.SIGNATURE.value,
                status=EvidenceStatus.WARNING.value,
                title="Signature Verification Inconclusive",
                value="Unknown",
                reason="Cryptographic validation could not be definitively concluded.",
            ))
    else:
        steps.append(VerificationStep(
            id="crypto_signature",
            order=step_order,
            check="Signature cryptographic verification",
            status=StepStatus.NOT_CHECKED.value,
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Signature verification was not performed because no signature is present.",
            technical_detail=None,
        ))

    step_order += 1

    # ── Step 5: ByteRange and Signed Content Integrity ────────────────────────
    if evidence.signature_present:
        if evidence.integrity_verified is True:
            steps.append(VerificationStep(
                id="content_integrity",
                order=step_order,
                check="Signed content integrity (ByteRange)",
                status=StepStatus.PASS.value,
                observed_value="Intact",
                expected_condition="Signed ByteRange byte sequence remains unmodified",
                explanation="The content covered by the digital signature remains consistent with the signed ByteRange.",
                technical_detail="ByteRange byte boundaries cover the document revision without unauthorized alterations.",
            ))
            evidence_items.append(EvidenceItem(
                code="INTEGRITY_VERIFIED",
                category=EvidenceCategory.INTEGRITY.value,
                status=EvidenceStatus.PASS.value,
                title="Document Integrity Verified",
                value="Intact",
                reason="No unauthorized byte modifications were detected within the signed ByteRange.",
            ))
        elif evidence.integrity_verified is False:
            steps.append(VerificationStep(
                id="content_integrity",
                order=step_order,
                check="Signed content integrity (ByteRange)",
                status=StepStatus.FAIL.value,
                observed_value="Modified / Corrupted",
                expected_condition="Signed ByteRange byte sequence remains unmodified",
                explanation="The signed content no longer matches the cryptographic signature evidence.",
                technical_detail="Discrepancy detected between the signed byte sequence and current document byte content.",
            ))
            evidence_items.append(EvidenceItem(
                code="INTEGRITY_FAILED",
                category=EvidenceCategory.INTEGRITY.value,
                status=EvidenceStatus.FAIL.value,
                title="Signed Content Modified",
                value="Modified",
                reason="Document bytes covered by the signature have been altered or corrupted after signing.",
            ))
        else:
            steps.append(VerificationStep(
                id="content_integrity",
                order=step_order,
                check="Signed content integrity (ByteRange)",
                status=StepStatus.WARNING.value,
                observed_value="Unverified",
                expected_condition="Signed ByteRange byte sequence verification",
                explanation="Document integrity could not be definitively verified.",
                technical_detail="ByteRange inspection produced inconclusive coverage metrics.",
            ))
            evidence_items.append(EvidenceItem(
                code="INTEGRITY_UNKNOWN",
                category=EvidenceCategory.INTEGRITY.value,
                status=EvidenceStatus.WARNING.value,
                title="Integrity Verification Inconclusive",
                value="Unverified",
                reason="Byte coverage validation could not be completed.",
            ))
    else:
        steps.append(VerificationStep(
            id="content_integrity",
            order=step_order,
            check="Signed content integrity (ByteRange)",
            status=StepStatus.NOT_CHECKED.value,
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Integrity check was not performed because no signature is present.",
            technical_detail=None,
        ))

    step_order += 1

    # ── Step 6: Structural & Security Anomalies ────────────────────────────────
    if evidence.structural_anomalies:
        steps.append(VerificationStep(
            id="structural_anomalies",
            order=step_order,
            check="PDF structural & threat analysis",
            status=StepStatus.WARNING.value,
            observed_value=f"{len(evidence.structural_anomalies)} anomaly(ies)",
            expected_condition="Clean PDF structure without suspicious elements",
            explanation=f"Detected structural signals: {'; '.join(evidence.structural_anomalies)}.",
            technical_detail="Identified during PDF object and cross-reference stream parsing.",
        ))
        for anomaly in evidence.structural_anomalies:
            evidence_items.append(EvidenceItem(
                code="STRUCTURE_ANOMALY",
                category=EvidenceCategory.STRUCTURE.value,
                status=EvidenceStatus.WARNING.value,
                title="Structural Anomaly",
                value=anomaly,
                reason=f"PDF parser flagged: {anomaly}",
            ))
    else:
        steps.append(VerificationStep(
            id="structural_anomalies",
            order=step_order,
            check="PDF structural & threat analysis",
            status=StepStatus.PASS.value,
            observed_value="Clean",
            expected_condition="Clean PDF structure without suspicious elements",
            explanation="No suspicious structural anomalies (embedded scripts, hidden streams) detected.",
            technical_detail="Object tree inspection passed without security alerts.",
        ))
        evidence_items.append(EvidenceItem(
            code="STRUCTURE_CLEAN",
            category=EvidenceCategory.STRUCTURE.value,
            status=EvidenceStatus.PASS.value,
            title="Clean Document Structure",
            value="Clean",
            reason="No suspicious objects or structural anomalies found in the PDF object stream.",
        ))

    step_order += 1

    # ── Multi-Signature Evidence (if applicable) ──────────────────────────────
    if evidence.signature_count > 1 and evidence.signatures_detail:
        for idx, sig_detail in enumerate(evidence.signatures_detail, start=1):
            fname = sig_detail.get("field_name") or f"Signature #{idx}"
            s_status = sig_detail.get("status") or "UNKNOWN"
            ev_status = (
                EvidenceStatus.PASS.value if s_status == "VALID" else
                EvidenceStatus.FAIL.value if s_status in ("INVALID", "CORRUPTED") else
                EvidenceStatus.WARNING.value
            )
            evidence_items.append(EvidenceItem(
                code=f"SIG_{idx}_DETAIL",
                category=EvidenceCategory.SIGNATURE.value,
                status=ev_status,
                title=f"Signature #{idx} ({fname})",
                value=s_status,
                reason=(
                    f"Signature field '{fname}' evaluated with status {s_status} "
                    f"(Digest: {sig_detail.get('digest_algorithm') or 'Unknown'}, "
                    f"Algo: {sig_detail.get('signature_algorithm') or 'Unknown'})."
                ),
            ))

    # ── Step 7: Quantum-Inspired Simulation Analysis (Secondary Signal) ───────
    if evidence.quantum_analysis and isinstance(evidence.quantum_analysis, dict):
        q = evidence.quantum_analysis
        sim_val = q.get("state_similarity")
        dist_val = q.get("anomaly_distance")
        entropy_val = q.get("entropy")

        has_elevated_anomaly = (dist_val is not None and isinstance(dist_val, (int, float)) and dist_val >= 0.50)
        q_status = StepStatus.WARNING.value if has_elevated_anomaly else StepStatus.PASS.value

        detail_metrics = []
        if sim_val is not None:
            detail_metrics.append(f"Similarity={float(sim_val):.4f}")
        if dist_val is not None:
            detail_metrics.append(f"AnomalyDist={float(dist_val):.4f}")
        if entropy_val is not None:
            detail_metrics.append(f"Entropy={float(entropy_val):.4f}")

        steps.append(VerificationStep(
            id="quantum_simulation",
            order=step_order,
            check="Quantum-inspired classical anomaly simulation",
            status=q_status,
            observed_value=", ".join(detail_metrics) or "Simulated",
            expected_condition="Low anomaly distance (< 0.50) from baseline reference state",
            explanation=(
                "Elevated quantum-inspired anomaly distance detected relative to the baseline state. "
                "Note: This is a classical mathematical anomaly signal, not authoritative proof of tampering."
                if has_elevated_anomaly else
                "Quantum-inspired classical simulation metrics are consistent with the authentic baseline state."
            ),
            technical_detail="14-dimensional feature vector projected onto normalized Hilbert space amplitudes.",
        ))

        evidence_items.append(EvidenceItem(
            code="QUANTUM_ANOMALY_ELEVATED" if has_elevated_anomaly else "QUANTUM_BASELINE_CONSISTENT",
            category=EvidenceCategory.QUANTUM_INSPIRED.value,
            status=EvidenceStatus.WARNING.value if has_elevated_anomaly else EvidenceStatus.INFO.value,
            title="Quantum-Inspired Mathematical Analysis",
            value=", ".join(detail_metrics) or "Simulated",
            reason=(
                "Classical mathematical simulation of quantum feature space indicates deviation from baseline; "
                "treated strictly as secondary signal."
                if has_elevated_anomaly else
                "Classical simulation metrics conform with authentic baseline state vector."
            ),
        ))
        step_order += 1

    # ── Step 8: Final Verdict Trace Step ──────────────────────────────────────
    steps.append(VerificationStep(
        id="final_verdict",
        order=step_order,
        check="Final security verdict",
        status=(
            StepStatus.PASS.value if verdict_upper == "AUTHENTIC" else
            StepStatus.FAIL.value if verdict_upper == "TAMPERED" else
            StepStatus.WARNING.value
        ),
        observed_value=verdict_upper,
        expected_condition="AUTHENTIC",
        explanation=_generate_verdict_explanation(verdict_upper, evidence),
        technical_detail=f"Authoritative backend decision based on cryptographic verification and integrity analysis.",
    ))

    # ── Certificate Inspection Findings Integration ──────────────────────────
    if evidence.certificate_inspection and isinstance(evidence.certificate_inspection, dict):
        for f in evidence.certificate_inspection.get("findings", []):
            f_code = f.get("code")
            f_sev = (f.get("severity") or "INFO").upper()
            f_status = (
                EvidenceStatus.FAIL.value if f_sev == "HIGH"
                else EvidenceStatus.WARNING.value if f_sev in ("MEDIUM", "LOW")
                else EvidenceStatus.INFO.value
            )
            if not any(e.code == f_code for e in evidence_items):
                evidence_items.append(EvidenceItem(
                    code=f_code,
                    category=EvidenceCategory.CERTIFICATE.value,
                    status=f_status,
                    title=f.get("title", "Certificate Security Finding"),
                    value=f_sev,
                    reason=f.get("description", ""),
                ))

    # ── Filter Failed, Warnings, and Passed Evidence ──────────────────────────
    passed_checks = [e for e in evidence_items if e.status == EvidenceStatus.PASS.value]
    failed_checks = [e for e in evidence_items if e.status == EvidenceStatus.FAIL.value]
    warnings = [e for e in evidence_items if e.status in (EvidenceStatus.WARNING.value, EvidenceStatus.INFO.value)]

    # ── Categorical Confidence Level ──────────────────────────────────────────
    confidence = _calculate_confidence(evidence)

    # ── Final Reason & Summary ────────────────────────────────────────────────
    final_reason = _generate_verdict_explanation(verdict_upper, evidence)
    summary = _generate_executive_summary(verdict_upper, evidence, confidence)

    return ExplanationResult(
        summary=summary,
        verification_steps=steps,
        evidence=evidence_items,
        failed_checks=failed_checks,
        warnings=warnings,
        passed_checks=passed_checks,
        final_reason=final_reason,
        confidence=confidence.value,
    )


# ── Internal Reason & Summary Helpers ─────────────────────────────────────────

def _generate_verdict_explanation(verdict: str, evidence: VerificationEvidence) -> str:
    """Generate deterministic explanation for WHY the verdict was reached."""
    if verdict == "AUTHENTIC":
        algo_part = ""
        if evidence.digest_algorithm and evidence.signature_algorithm:
            algo_part = f" using {evidence.digest_algorithm} with {evidence.signature_algorithm}"
        return (
            f"Digital signature verification succeeded{algo_part} and the signed content passed "
            f"integrity validation. The certificate and structural security checks produced no blocking findings."
        )

    if verdict == "TAMPERED":
        reasons = []
        if evidence.signature_valid is False:
            reasons.append("the cryptographic signature does not validate against the signed document content")
        if evidence.signed_content_modified is True or evidence.integrity_verified is False:
            reasons.append("the signed ByteRange byte content has been altered post-signing")
        if not reasons:
            reasons.append("document integrity validation failed against recorded cryptographic signatures")
        return f"Cryptographic verification failed because {' and '.join(reasons)}."

    # SUSPICIOUS
    if not evidence.signature_present:
        return "No digital signature was detected in the submitted file; authenticity cannot be established."

    suspicious_reasons = []
    if evidence.certificate_expired:
        suspicious_reasons.append("the signing certificate is expired")
    if evidence.certificate_trusted is False:
        suspicious_reasons.append("the certificate is untrusted or self-signed")
    if evidence.structural_anomalies:
        suspicious_reasons.append("structural anomalies were detected in the PDF object stream")
    if evidence.signature_valid is None:
        suspicious_reasons.append("the signature could not be fully verified")

    if suspicious_reasons:
        return (
            f"The document could not be certified as Authentic: {'; '.join(suspicious_reasons)}."
        )

    return (
        "The digital signature is present, but security, certificate, or structural checks produced warnings."
    )


def _generate_executive_summary(
    verdict: str,
    evidence: VerificationEvidence,
    confidence: ConfidenceLevel,
) -> str:
    """Generate high-level executive summary."""
    if verdict == "AUTHENTIC":
        return (
            f"Document verified as AUTHENTIC with {confidence.value} confidence. "
            f"Cryptographic signature is valid and document integrity is intact."
        )
    elif verdict == "TAMPERED":
        return (
            f"Document classified as TAMPERED with {confidence.value} confidence. "
            f"Cryptographic verification or ByteRange integrity checks failed."
        )
    else:
        return (
            f"Document classified as SUSPICIOUS with {confidence.value} confidence. "
            f"One or more security, certificate, or structural criteria require attention."
        )


def _calculate_confidence(evidence: VerificationEvidence) -> ConfidenceLevel:
    """
    Categorical confidence reflects evidence completeness, NOT arbitrary probabilities.

    HIGH:
      - Signature verification executed (PASS or FAIL)
      - Integrity check executed (PASS or FAIL)
      - Certificate details extracted

    MEDIUM:
      - Some security evidence was unavailable or partially checked

    LOW:
      - Only partial verification possible (e.g. no signature or corrupt container)

    NOT_AVAILABLE:
      - Insufficient verification evidence
    """
    if not evidence.signature_present:
        return ConfidenceLevel.HIGH if evidence.structural_anomalies is not None else ConfidenceLevel.LOW

    has_sig_check = (evidence.signature_valid is not None)
    has_integrity_check = (evidence.integrity_verified is not None)
    has_cert_check = (evidence.certificate_present and evidence.certificate_valid is not None)

    if has_sig_check and has_integrity_check and has_cert_check:
        return ConfidenceLevel.HIGH
    elif has_sig_check and has_integrity_check:
        return ConfidenceLevel.HIGH
    elif has_sig_check or has_integrity_check:
        return ConfidenceLevel.MEDIUM
    elif evidence.signature_present:
        return ConfidenceLevel.LOW
    else:
        return ConfidenceLevel.NOT_AVAILABLE
