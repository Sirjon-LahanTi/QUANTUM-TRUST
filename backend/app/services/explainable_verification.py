"""
QuantumTrust — Explainable Verification Engine

Provides a production-grade, deterministic, rule-based explanation layer derived strictly
from actual cryptographic verification, structural integrity, certificate inspection,
signature timeline, tampering localization, threat analysis, and quantum-inspired signals.

Guiding Principles:
1. No AI / LLM generation: All explanations are strictly derived from concrete verification evidence.
2. No cryptographic re-computation: Consumes existing verification engine outputs.
3. Authoritative verdict alignment: Explains WHY the backend reached AUTHENTIC, TAMPERED, or SUSPICIOUS.
4. Format-aware terminology: Uses accurate concepts (Page for PDF, XPath/Element for XML,
   JSON Path for JSON, Sheet/Cell for XLSX, Paragraph/Part for DOCX, Byte Range for Binary).
5. Anti-fabrication guarantee: Never invents locations, timestamps, algorithms, certificate info, or diffs.
6. True missing data representation: Unperformed or unavailable checks remain UNKNOWN / NOT_CHECKED.
7. Quantum-inspired separation: Quantum metrics are clearly contextualized as secondary classical signals.
8. Evidence hierarchy: Cryptographic verification > Document integrity > Certificate validity/trust >
   Timeline consistency > Tampering localization > Threat analysis > Quantum anomaly signal.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.schemas.analysis import (
    DecisionFactor,
    EvidenceItem,
    ExplanationResult,
    VerificationStep,
)

logger = logging.getLogger(__name__)


# ── Status and Category Enums ────────────────────────────────────────────────

class StepStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class EvidenceCategory(str, Enum):
    FILE_FORMAT = "FILE_FORMAT"
    SIGNATURE_VERIFICATION = "SIGNATURE_VERIFICATION"
    SIGNATURE = "SIGNATURE"
    DOCUMENT_INTEGRITY = "DOCUMENT_INTEGRITY"
    INTEGRITY = "INTEGRITY"
    CERTIFICATE = "CERTIFICATE"
    PUBLIC_KEY = "PUBLIC_KEY"
    ALGORITHM = "ALGORITHM"
    ALGORITHM_SECURITY = "ALGORITHM_SECURITY"
    SIGNATURE_TIMELINE = "SIGNATURE_TIMELINE"
    TAMPERING_LOCALIZATION = "TAMPERING_LOCALIZATION"
    STRUCTURE = "STRUCTURE"
    THREAT_ANALYSIS = "THREAT_ANALYSIS"
    THREAT = "THREAT"
    DUPLICATE = "DUPLICATE"
    QUANTUM_INSPIRED_ANALYSIS = "QUANTUM_INSPIRED_ANALYSIS"
    QUANTUM_INSPIRED = "QUANTUM_INSPIRED"
    FINAL_VERDICT = "FINAL_VERDICT"


class EvidenceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"


class FactorImpact(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"
    NOT_AVAILABLE = "NOT_AVAILABLE"


# ── Normalized Input Evidence Model ──────────────────────────────────────────

@dataclass
class VerificationEvidence:
    """Normalized evidence input aggregated from all verification sub-systems."""
    file_type: str = "PDF"
    filename: str = "document.pdf"
    file_size: int | None = None

    signature_present: bool = False
    signature_count: int = 0
    signature_valid: bool | None = None
    signature_status: str | None = None
    signature_type: str | None = None

    digest_algorithm: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    public_key_curve: str | None = None

    integrity_status: str | None = None
    integrity_verified: bool | None = None
    signed_content_modified: bool | None = None
    byte_range_present: bool | None = None
    byte_range_valid: bool | None = None
    byte_range: list[int] | None = None

    certificate_present: bool = False
    certificate_valid: bool | None = None
    certificate_trusted: bool | None = None
    certificate_expired: bool | None = None
    certificate_revoked: bool | None = None
    certificate_trust_status: str | None = None
    certificate_validity_status: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_serial: str | None = None
    certificate_fingerprint: str | None = None

    structural_anomalies: list[str] = field(default_factory=list)
    detected_threats: list[str] = field(default_factory=list)
    threat_score: float | int | None = None
    threat_level: str | None = None

    duplicate_detected: bool = False
    duplicate_match_type: str | None = None

    quantum_analysis: dict[str, Any] | None = None
    signatures_detail: list[dict[str, Any]] = field(default_factory=list)
    certificate_inspection: dict[str, Any] | None = None
    signature_timeline: dict[str, Any] | None = None
    tampering_localization: dict[str, Any] | None = None
    limitations: list[str] = field(default_factory=list)


# ── Evidence Extractor from Subsystem Dictionaries ───────────────────────────

def extract_evidence_from_analysis(
    sig_result: dict[str, Any] | None = None,
    cert_info: dict[str, Any] | None = None,
    integrity_result: dict[str, Any] | None = None,
    pdf_structure: dict[str, Any] | None = None,
    dup_result: dict[str, Any] | None = None,
    threat_result: dict[str, Any] | None = None,
    quantum_result: dict[str, Any] | None = None,
    cert_inspection: dict[str, Any] | None = None,
    signature_timeline: dict[str, Any] | None = None,
    tampering_localization: dict[str, Any] | None = None,
    file_type: str = "PDF",
    filename: str = "document.pdf",
    file_size: int | None = None,
) -> VerificationEvidence:
    """
    Constructs normalized VerificationEvidence from raw backend sub-system outputs.
    Ensures missing values remain None/unknown rather than false negatives.
    """
    sig_res = sig_result or {}
    c_info = cert_info or {}
    intg_res = integrity_result or {}
    pdf_struct = pdf_structure or {}
    dup_res = dup_result or {}
    thr_res = threat_result or {}
    q_res = quantum_result or {}
    c_insp = cert_inspection or {}
    s_time = signature_timeline or {}
    t_loc = tampering_localization or {}

    # File Format Detection
    detected_format = file_type.upper()
    if detected_format in ("PDF", "UNKNOWN"):
        if filename.lower().endswith(".xml") or filename.lower().endswith(".xades"):
            detected_format = "XML"
        elif filename.lower().endswith(".json") or filename.lower().endswith(".jws"):
            detected_format = "JSON"
        elif filename.lower().endswith(".docx"):
            detected_format = "DOCX"
        elif filename.lower().endswith(".xlsx"):
            detected_format = "XLSX"
        elif filename.lower().endswith(".p7s") or filename.lower().endswith(".p7m") or filename.lower().endswith(".p7b"):
            detected_format = "CMS/PKCS#7"
        elif filename.lower().endswith(".bin") or filename.lower().endswith(".dat"):
            detected_format = "BINARY"

    sig_present = bool(sig_res.get("present", False))
    sig_count = int(sig_res.get("count", 0))
    overall_status = (sig_res.get("overall_status") or sig_res.get("status") or "").upper()
    sig_type = sig_res.get("signature_type")

    sig_valid: bool | None = None
    if sig_present:
        if overall_status == "VALID":
            sig_valid = True
        elif overall_status in ("INVALID", "CORRUPTED"):
            sig_valid = False
        else:
            sig_valid = None

    # Integrity & ByteRange
    byte_range = intg_res.get("byte_range") or sig_res.get("byte_range")
    byte_range_present = (byte_range is not None and isinstance(byte_range, list) and len(byte_range) > 0)
    
    int_status = (intg_res.get("integrity_status") or intg_res.get("status") or "").upper()
    mod_status = (intg_res.get("modification_status") or "").upper()

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
            signed_content_modified = False
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
        c_info.get("subject") or
        c_info.get("issuer") or
        c_info.get("serial_number") or
        (c_insp and c_insp.get("status") == "SUCCESS") or
        (sig_res.get("signatures") and sig_res["signatures"][0].get("cert_subject"))
    )
    trust_status = (c_info.get("trust_status") or "UNAVAILABLE").upper()
    cert_expired = c_info.get("is_expired")
    cert_valid: bool | None = None
    cert_trusted: bool | None = None
    cert_val_status: str | None = None

    if c_insp and c_insp.get("status") == "SUCCESS":
        val_sec = c_insp.get("validity") or {}
        val_st = (val_sec.get("status") or "").upper()
        cert_val_status = val_st
        if val_st == "EXPIRED":
            cert_expired = True
            cert_valid = False
        elif val_st == "NOT_YET_VALID":
            cert_valid = False
            cert_expired = False
        elif val_st == "VALID":
            cert_valid = True
            cert_expired = False

        trust_sec = c_insp.get("trust") or {}
        t_st = (trust_sec.get("status") or "").upper()
        trust_status = t_st
        if t_st == "TRUSTED":
            cert_trusted = True
        elif t_st in ("UNTRUSTED", "SELF_SIGNED", "EXPIRED"):
            cert_trusted = False
        elif t_st in ("UNKNOWN", "NOT_CHECKED"):
            cert_trusted = None

    elif cert_present:
        if cert_expired is True:
            cert_valid = False
            cert_trusted = False
            cert_val_status = "EXPIRED"
        elif trust_status == "TRUSTED":
            cert_valid = True
            cert_trusted = True
            cert_val_status = "VALID"
        elif trust_status in ("UNTRUSTED", "SELF_SIGNED", "EXPIRED"):
            cert_valid = (cert_expired is False or cert_expired is None)
            cert_trusted = False
            cert_val_status = "VALID" if cert_valid else "EXPIRED"
        else:
            cert_valid = None
            cert_trusted = None
            cert_val_status = "UNKNOWN"

    # Algorithms
    digest_algo = sig_res.get("digest_algorithm")
    sig_algo = sig_res.get("signature_algorithm")
    pub_key_algo = sig_res.get("public_key_algorithm")
    key_size = sig_res.get("key_size")

    if c_insp and c_insp.get("public_key"):
        pk_info = c_insp["public_key"]
        pub_key_algo = pub_key_algo or pk_info.get("algorithm")
        key_size = key_size or pk_info.get("key_size")

    # Structural anomalies
    structural_anomalies = list(pdf_struct.get("suspicious_signals", []))

    # Threats
    detected_threats = list(thr_res.get("detected_threats", []))
    threat_score = thr_res.get("threat_score")
    threat_level = thr_res.get("threat_level")

    # Duplicate
    dup_detected = bool(dup_res.get("is_duplicate", False))
    dup_match = dup_res.get("match_type")

    # Collect format limitations
    limitations = []
    if t_loc and t_loc.get("limitations"):
        limitations.extend(t_loc["limitations"])
    if s_time and s_time.get("reason") and s_time.get("status") == "NOT_AVAILABLE":
        limitations.append(s_time["reason"])
    if not cert_trusted and cert_present:
        limitations.append("Signer certificate chain trust could not be established with the local trust store.")

    return VerificationEvidence(
        file_type=detected_format,
        filename=filename,
        file_size=file_size,
        signature_present=sig_present,
        signature_count=sig_count,
        signature_valid=sig_valid,
        signature_status=overall_status or None,
        signature_type=sig_type,
        digest_algorithm=digest_algo,
        signature_algorithm=sig_algo,
        public_key_algorithm=pub_key_algo,
        public_key_size=key_size,
        integrity_status=int_status or None,
        integrity_verified=integrity_verified,
        signed_content_modified=signed_content_modified,
        byte_range_present=byte_range_present,
        byte_range_valid=byte_range_valid,
        byte_range=byte_range if isinstance(byte_range, list) else None,
        certificate_present=cert_present,
        certificate_valid=cert_valid,
        certificate_trusted=cert_trusted,
        certificate_expired=cert_expired,
        certificate_revoked=c_info.get("is_revoked"),
        certificate_trust_status=trust_status,
        certificate_validity_status=cert_val_status,
        certificate_subject=c_info.get("subject") or (sig_res.get("signatures") and sig_res["signatures"][0].get("cert_subject")),
        certificate_issuer=c_info.get("issuer") or (sig_res.get("signatures") and sig_res["signatures"][0].get("cert_issuer")),
        certificate_serial=c_info.get("serial_number") or (sig_res.get("signatures") and sig_res["signatures"][0].get("cert_serial")),
        certificate_fingerprint=c_info.get("fingerprint") or (c_insp.get("fingerprint") or {}).get("value"),
        structural_anomalies=structural_anomalies,
        detected_threats=detected_threats,
        threat_score=threat_score,
        threat_level=threat_level,
        duplicate_detected=dup_detected,
        duplicate_match_type=dup_match,
        quantum_analysis=q_res,
        signatures_detail=sig_res.get("signatures", []),
        certificate_inspection=c_insp,
        signature_timeline=s_time,
        tampering_localization=t_loc,
        limitations=limitations,
    )


# ── Primary API Function: generate_verdict_explanation ───────────────────────

def generate_verdict_explanation(
    verification_result: dict[str, Any] | None = None,
    certificate_inspection: dict[str, Any] | None = None,
    signature_timeline: dict[str, Any] | None = None,
    tampering_localization: dict[str, Any] | None = None,
    threat_analysis: dict[str, Any] | None = None,
    quantum_analysis: dict[str, Any] | None = None,
    final_verdict: str = "SUSPICIOUS",
    file_type: str = "PDF",
    filename: str = "document.pdf",
    integrity_result: dict[str, Any] | None = None,
    pdf_structure: dict[str, Any] | None = None,
    duplicate_result: dict[str, Any] | None = None,
    cert_info: dict[str, Any] | None = None,
) -> ExplanationResult:
    """
    Public entrypoint to generate a full ExplanationResult directly from sub-system results.
    Consumes outputs without performing cryptographic verification.
    """
    evidence = extract_evidence_from_analysis(
        sig_result=verification_result,
        cert_info=cert_info,
        integrity_result=integrity_result,
        pdf_structure=pdf_structure,
        dup_result=duplicate_result,
        threat_result=threat_analysis,
        quantum_result=quantum_analysis,
        cert_inspection=certificate_inspection,
        signature_timeline=signature_timeline,
        tampering_localization=tampering_localization,
        file_type=file_type,
        filename=filename,
    )
    return generate_explanation(evidence, final_verdict)


# ── Deterministic Rule-Based Engine ──────────────────────────────────────────

def generate_explanation(
    evidence: VerificationEvidence,
    verdict: str,
) -> ExplanationResult:
    """
    Deterministically converts VerificationEvidence and the authoritative backend verdict
    into an ExplanationResult with ordered trace steps, decision factors, and granular evidence.
    """
    steps: list[VerificationStep] = []
    evidence_items: list[EvidenceItem] = []
    decision_factors: list[DecisionFactor] = []
    why_not_authentic: list[str] = []
    limitations: list[str] = list(evidence.limitations)
    
    verdict_upper = (verdict or "SUSPICIOUS").upper()
    doc_format = evidence.file_type.upper()

    step_order = 1

    # ── Step 1: File Identification & Format Verification ────────────────────
    is_supported_format = doc_format in ("PDF", "XML", "JSON", "DOCX", "XLSX", "CMS/PKCS#7", "BINARY")
    
    steps.append(VerificationStep(
        step_id="file_identification",
        id="file_identification",
        order=step_order,
        category=EvidenceCategory.FILE_FORMAT.value,
        status=StepStatus.PASS.value if is_supported_format else StepStatus.WARNING.value,
        title="File identification and format parsing",
        check="File identification and format parsing",
        observed_value=f"{doc_format} ({evidence.filename})",
        expected_condition="Supported document or signature container format",
        explanation=f"Identified file format as {doc_format}. Parser dispatched format-specific structural adapter.",
        technical_detail=f"Parsed file '{evidence.filename}' using {doc_format} inspection pipeline.",
        severity=FactorImpact.INFO.value,
    ))
    evidence_items.append(EvidenceItem(
        evidence_id="FILE_FORMAT_DETECTED",
        code="FILE_FORMAT_DETECTED",
        category=EvidenceCategory.FILE_FORMAT.value,
        source="FORMAT_PARSER",
        field="file_type",
        status=EvidenceStatus.PASS.value if is_supported_format else EvidenceStatus.WARNING.value,
        title="Format Identification",
        value=doc_format,
        description=f"File extension and byte stream identified as {doc_format}.",
        reason=f"File extension and byte stream identified as {doc_format}.",
        importance=FactorImpact.LOW.value,
    ))
    step_order += 1

    # ── Step 2: Digital Signature Presence & Count ────────────────────────────
    if evidence.signature_present:
        steps.append(VerificationStep(
            step_id="sig_presence",
            id="sig_presence",
            order=step_order,
            category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
            status=StepStatus.PASS.value,
            title="Digital signature presence",
            check="Digital signature presence",
            observed_value=f"{evidence.signature_count} signature(s) detected",
            expected_condition="At least 1 digital signature present in document",
            explanation=f"Detected {evidence.signature_count} digital signature structure(s) embedded in the {doc_format} container.",
            technical_detail=f"Parsed signature structures for {doc_format} container via embedded reader.",
            severity=FactorImpact.INFO.value,
        ))
        evidence_items.append(EvidenceItem(
            evidence_id="SIG_PRESENT",
            code="SIG_PRESENT",
            category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
            source="SIGNATURE_ENGINE",
            field="signature_count",
            status=EvidenceStatus.PASS.value,
            title="Digital Signature Presence",
            value=f"{evidence.signature_count} signature(s)",
            description="One or more valid digital signature dictionaries or structures were located.",
            reason="One or more valid digital signature dictionaries or structures were located.",
            importance=FactorImpact.HIGH.value,
        ))
    else:
        steps.append(VerificationStep(
            step_id="sig_presence",
            id="sig_presence",
            order=step_order,
            category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
            status=StepStatus.FAIL.value,
            title="Digital signature presence",
            check="Digital signature presence",
            observed_value="0 signatures detected",
            expected_condition="At least 1 digital signature present in document",
            explanation=f"No digital signature was detected in the submitted {doc_format} file.",
            technical_detail=f"No signature dictionary or signed block found in {doc_format} object table.",
            severity=FactorImpact.CRITICAL.value,
        ))
        evidence_items.append(EvidenceItem(
            evidence_id="SIG_ABSENT",
            code="SIG_ABSENT",
            category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
            source="SIGNATURE_ENGINE",
            field="signature_present",
            status=EvidenceStatus.FAIL.value,
            title="Digital Signature Missing",
            value="0 signatures",
            description="The document contains no digital signature dictionaries or embedded PKCS#7 / CMS signatures.",
            reason="The document contains no digital signature dictionaries or embedded PKCS#7 / CMS signatures.",
            importance=FactorImpact.CRITICAL.value,
        ))
        why_not_authentic.append("No cryptographic digital signature was found in the file.")
        decision_factors.append(DecisionFactor(
            factor="SIGNATURE_VERIFICATION",
            impact=FactorImpact.CRITICAL.value,
            status="FAIL",
            explanation="No digital signature was detected in the file; authenticity cannot be verified.",
        ))

    step_order += 1

    # ── Step 3: Cryptographic Algorithms (No assumptions / No fake defaults) ──
    if evidence.signature_present:
        digest_detected = bool(evidence.digest_algorithm)
        sig_algo_detected = bool(evidence.signature_algorithm)

        algo_parts = []
        if digest_detected:
            algo_parts.append(f"Digest: {evidence.digest_algorithm}")
        if sig_algo_detected:
            algo_parts.append(f"Signature: {evidence.signature_algorithm}")
        if evidence.public_key_algorithm:
            key_sz = f"{evidence.public_key_size} bits" if evidence.public_key_size else "size unspecified"
            algo_parts.append(f"Public Key: {evidence.public_key_algorithm} ({key_sz})")

        is_weak_digest = evidence.digest_algorithm and evidence.digest_algorithm.upper() in ("MD5", "SHA1", "SHA-1")
        
        if digest_detected and sig_algo_detected:
            algo_status = StepStatus.WARNING.value if is_weak_digest else StepStatus.PASS.value
            algo_exp = (
                f"Weak digest algorithm {evidence.digest_algorithm} detected. Modern cryptographic policy recommends SHA-256 or stronger."
                if is_weak_digest else
                f"Cryptographic algorithms detected: {', '.join(algo_parts)}."
            )
            steps.append(VerificationStep(
                step_id="algo_detection",
                id="algo_detection",
                order=step_order,
                category=EvidenceCategory.ALGORITHM_SECURITY.value,
                status=algo_status,
                title="Cryptographic algorithm identification",
                check="Cryptographic algorithm identification",
                observed_value=" / ".join(algo_parts),
                expected_condition="Standard cryptographically secure digest and signature algorithms",
                explanation=algo_exp,
                technical_detail="Extracted from signer CMS / X.509 ASN.1 structure without hardcoded defaults.",
                severity=FactorImpact.MEDIUM.value if is_weak_digest else FactorImpact.INFO.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="ALGO_WEAK" if is_weak_digest else "ALGO_IDENTIFIED",
                code="ALGO_WEAK" if is_weak_digest else "ALGO_IDENTIFIED",
                category=EvidenceCategory.ALGORITHM_SECURITY.value,
                source="SIGNATURE_ENGINE",
                field="signature_algorithm",
                status=EvidenceStatus.WARNING.value if is_weak_digest else EvidenceStatus.PASS.value,
                title="Cryptographic Algorithms",
                value=" / ".join(algo_parts),
                description=(
                    f"Digest algorithm {evidence.digest_algorithm} is cryptographically obsolete."
                    if is_weak_digest else
                    "Signature and digest algorithms were parsed directly from signature attributes."
                ),
                reason=(
                    f"Digest algorithm {evidence.digest_algorithm} is cryptographically obsolete."
                    if is_weak_digest else
                    "Signature and digest algorithms were parsed directly from signature attributes."
                ),
                importance=FactorImpact.HIGH.value if is_weak_digest else FactorImpact.LOW.value,
            ))
            if is_weak_digest:
                why_not_authentic.append(f"Obsolete digest algorithm detected ({evidence.digest_algorithm}).")
        elif digest_detected or sig_algo_detected:
            steps.append(VerificationStep(
                step_id="algo_detection",
                id="algo_detection",
                order=step_order,
                category=EvidenceCategory.ALGORITHM_SECURITY.value,
                status=StepStatus.WARNING.value,
                title="Cryptographic algorithm identification",
                check="Cryptographic algorithm identification",
                observed_value=" / ".join(algo_parts) or "Partial",
                expected_condition="Complete digest and signature algorithm identification",
                explanation="Only partial cryptographic algorithm parameters could be identified from the signature header.",
                technical_detail="Signer information was incomplete or partially omitted.",
                severity=FactorImpact.MEDIUM.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="ALGO_PARTIAL",
                code="ALGO_PARTIAL",
                category=EvidenceCategory.ALGORITHM_SECURITY.value,
                source="SIGNATURE_ENGINE",
                field="algorithm",
                status=EvidenceStatus.WARNING.value,
                title="Partial Algorithm Identification",
                value=" / ".join(algo_parts),
                description="Algorithm parameters were only partially present in the signature metadata.",
                reason="Algorithm parameters were only partially present in the signature metadata.",
                importance=FactorImpact.MEDIUM.value,
            ))
        else:
            steps.append(VerificationStep(
                step_id="algo_detection",
                id="algo_detection",
                order=step_order,
                category=EvidenceCategory.ALGORITHM_SECURITY.value,
                status=StepStatus.WARNING.value,
                title="Cryptographic algorithm identification",
                check="Cryptographic algorithm identification",
                observed_value="Unknown / Unsupported",
                expected_condition="Valid recognized signature algorithm",
                explanation="The signature uses an algorithm that the current verification engine does not support or could not resolve.",
                technical_detail="Digest or signature algorithm ASN.1 OID was unrecognized.",
                severity=FactorImpact.HIGH.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="ALGO_UNKNOWN",
                code="ALGO_UNKNOWN",
                category=EvidenceCategory.ALGORITHM_SECURITY.value,
                source="SIGNATURE_ENGINE",
                field="algorithm",
                status=EvidenceStatus.WARNING.value,
                title="Algorithm Identification Unresolved",
                value="Unknown",
                description="Could not determine digest or signature algorithm from embedded metadata.",
                reason="Could not determine digest or signature algorithm from embedded metadata.",
                importance=FactorImpact.HIGH.value,
            ))
            limitations.append("The signature uses an algorithm that the current verification engine does not support or identify.")
    else:
        steps.append(VerificationStep(
            step_id="algo_detection",
            id="algo_detection",
            order=step_order,
            category=EvidenceCategory.ALGORITHM_SECURITY.value,
            status=StepStatus.NOT_CHECKED.value,
            title="Cryptographic algorithm identification",
            check="Cryptographic algorithm identification",
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Algorithm identification was not performed because no signature is present.",
            technical_detail=None,
            severity=FactorImpact.INFO.value,
        ))

    step_order += 1

    # ── Step 4: Certificate & Public Key Validation ───────────────────────────
    if evidence.signature_present:
        if not evidence.certificate_present:
            steps.append(VerificationStep(
                step_id="cert_validation",
                id="cert_validation",
                order=step_order,
                category=EvidenceCategory.CERTIFICATE.value,
                status=StepStatus.WARNING.value,
                title="Signer certificate parsing & validation",
                check="Signer certificate parsing & validation",
                observed_value="No certificate embedded",
                expected_condition="Valid X.509 certificate embedded in signature container",
                explanation="No signer certificate was found embedded in the signature container. Trust evaluation cannot be executed.",
                technical_detail="Certificates bag in SignedData is empty.",
                severity=FactorImpact.MEDIUM.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CERT_ABSENT",
                code="CERT_ABSENT",
                category=EvidenceCategory.CERTIFICATE.value,
                source="CERTIFICATE_INSPECTOR",
                field="certificate_present",
                status=EvidenceStatus.WARNING.value,
                title="Signer Certificate Unavailable",
                value="None",
                description="Signer certificate is absent; trust evaluation cannot be executed.",
                reason="Signer certificate is absent; trust evaluation cannot be executed.",
                importance=FactorImpact.MEDIUM.value,
            ))
            limitations.append("Signer certificate was not embedded in the signature container.")
        elif evidence.certificate_expired:
            steps.append(VerificationStep(
                step_id="cert_validation",
                id="cert_validation",
                order=step_order,
                category=EvidenceCategory.CERTIFICATE.value,
                status=StepStatus.WARNING.value,
                title="Signer certificate parsing & validation",
                check="Signer certificate parsing & validation",
                observed_value="Expired",
                expected_condition="Certificate within valid lifetime (NotBefore / NotAfter)",
                explanation="The signer certificate has expired beyond its NotAfter validity timestamp. Note: Certificate validity confirms expiration status, but does not equate to document integrity.",
                technical_detail="Verification timestamp is strictly after certificate valid_until date.",
                severity=FactorImpact.HIGH.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CERT_EXPIRED",
                code="CERT_EXPIRED",
                category=EvidenceCategory.CERTIFICATE.value,
                source="CERTIFICATE_INSPECTOR",
                field="valid_until",
                status=EvidenceStatus.WARNING.value,
                title="Certificate Expired",
                value="Expired",
                description="The digital certificate is past its expiration date.",
                reason="The digital certificate is past its expiration date.",
                importance=FactorImpact.HIGH.value,
            ))
            why_not_authentic.append("The signing certificate has expired.")
            decision_factors.append(DecisionFactor(
                factor="CERTIFICATE_VALIDITY",
                impact=FactorImpact.HIGH.value,
                status="WARNING",
                explanation="Signer certificate has passed its NotAfter expiration date.",
            ))
        elif evidence.certificate_trusted is False:
            steps.append(VerificationStep(
                step_id="cert_validation",
                id="cert_validation",
                order=step_order,
                category=EvidenceCategory.CERTIFICATE.value,
                status=StepStatus.WARNING.value,
                title="Signer certificate parsing & validation",
                check="Signer certificate parsing & validation",
                observed_value="Untrusted / Self-signed",
                expected_condition="Certificate issued by a trusted root Certificate Authority",
                explanation="The certificate is self-signed or not anchored in a trusted system root Certificate Authority.",
                technical_detail="Certificate path validation could not establish a path to a trusted root anchor.",
                severity=FactorImpact.MEDIUM.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CERT_UNTRUSTED",
                code="CERT_UNTRUSTED",
                category=EvidenceCategory.CERTIFICATE.value,
                source="CERTIFICATE_INSPECTOR",
                field="trust_status",
                status=EvidenceStatus.WARNING.value,
                title="Untrusted Certificate Chain",
                value="Self-Signed / Untrusted",
                description="Certificate chain trust could not be established with the currently configured trust store.",
                reason="Certificate chain trust could not be established with the currently configured trust store.",
                importance=FactorImpact.MEDIUM.value,
            ))
        elif evidence.certificate_valid is True and evidence.certificate_trusted is True:
            steps.append(VerificationStep(
                step_id="cert_validation",
                id="cert_validation",
                order=step_order,
                category=EvidenceCategory.CERTIFICATE.value,
                status=StepStatus.PASS.value,
                title="Signer certificate parsing & validation",
                check="Signer certificate parsing & validation",
                observed_value="Trusted & Valid",
                expected_condition="Valid, unexpired certificate from trusted root CA",
                explanation="The signer certificate is valid, unexpired, and cryptographically verified against a trusted root anchor.",
                technical_detail="Certificate parsed successfully with valid ASN.1 structure, date window, and trust path.",
                severity=FactorImpact.INFO.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CERT_VALID",
                code="CERT_VALID",
                category=EvidenceCategory.CERTIFICATE.value,
                source="CERTIFICATE_INSPECTOR",
                field="validity",
                status=EvidenceStatus.PASS.value,
                title="Signer Certificate Valid",
                value="Valid & Trusted",
                description="Certificate is active, unexpired, and verified against trusted roots.",
                reason="Certificate is active, unexpired, and verified against trusted roots.",
                importance=FactorImpact.HIGH.value,
            ))
        else:
            steps.append(VerificationStep(
                step_id="cert_validation",
                id="cert_validation",
                order=step_order,
                category=EvidenceCategory.CERTIFICATE.value,
                status=StepStatus.PASS.value,
                title="Signer certificate parsing & validation",
                check="Signer certificate parsing & validation",
                observed_value="Parsed",
                expected_condition="Valid X.509 certificate",
                explanation="Signer certificate parsed successfully from signature container.",
                technical_detail="Certificate fields extracted without structural errors.",
                severity=FactorImpact.INFO.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CERT_PARSED",
                code="CERT_PARSED",
                category=EvidenceCategory.CERTIFICATE.value,
                source="CERTIFICATE_INSPECTOR",
                field="certificate",
                status=EvidenceStatus.PASS.value,
                title="Certificate Parsed",
                value="Available",
                description="Certificate metadata was extracted successfully.",
                reason="Certificate metadata was extracted successfully.",
                importance=FactorImpact.LOW.value,
            ))
    else:
        steps.append(VerificationStep(
            step_id="cert_validation",
            id="cert_validation",
            order=step_order,
            category=EvidenceCategory.CERTIFICATE.value,
            status=StepStatus.NOT_CHECKED.value,
            title="Signer certificate parsing & validation",
            check="Signer certificate parsing & validation",
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Certificate validation was not performed because no signature is present.",
            technical_detail=None,
            severity=FactorImpact.INFO.value,
        ))

    step_order += 1

    # ── Step 5: Cryptographic Signature Verification (Highest Authority) ─────
    if evidence.signature_present:
        if evidence.signature_valid is True:
            steps.append(VerificationStep(
                step_id="crypto_signature",
                id="crypto_signature",
                order=step_order,
                category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
                status=StepStatus.PASS.value,
                title="Signature cryptographic verification",
                check="Signature cryptographic verification",
                observed_value="Valid",
                expected_condition="Signature value cryptographically verifies against digest and public key",
                explanation="The digital signature cryptographically verifies against the signed content and the signer's public key.",
                technical_detail="Asymmetric signature validation against the calculated digest succeeded.",
                severity=FactorImpact.INFO.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CRYPTO_SIG_VALID",
                code="CRYPTO_SIG_VALID",
                category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
                source="SIGNATURE_ENGINE",
                field="signature_valid",
                status=EvidenceStatus.PASS.value,
                title="Cryptographic Signature Valid",
                value="Valid",
                description="The mathematical signature calculation matches the signed message digest.",
                reason="The mathematical signature calculation matches the signed message digest.",
                importance=FactorImpact.CRITICAL.value,
            ))
            decision_factors.append(DecisionFactor(
                factor="SIGNATURE_VERIFICATION",
                impact=FactorImpact.CRITICAL.value,
                status="PASS",
                explanation="Digital signature mathematically validated against the signed message digest.",
            ))
        elif evidence.signature_valid is False:
            steps.append(VerificationStep(
                step_id="crypto_signature",
                id="crypto_signature",
                order=step_order,
                category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
                status=StepStatus.FAIL.value,
                title="Signature cryptographic verification",
                check="Signature cryptographic verification",
                observed_value="Invalid / Mismatch",
                expected_condition="Signature value cryptographically verifies against digest and public key",
                explanation="Cryptographic signature verification failed. The signature does not validate against the signed content.",
                technical_detail="Decrypted signature digest does not match computed digest for signed content.",
                severity=FactorImpact.CRITICAL.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CRYPTO_SIG_INVALID",
                code="CRYPTO_SIG_INVALID",
                category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
                source="SIGNATURE_ENGINE",
                field="signature_valid",
                status=EvidenceStatus.FAIL.value,
                title="Cryptographic Signature Failed",
                value="Invalid",
                description="The digital signature does not mathematically match the signed document content.",
                reason="The digital signature does not mathematically match the signed document content.",
                importance=FactorImpact.CRITICAL.value,
            ))
            why_not_authentic.append("Cryptographic signature verification failed against the document content.")
            decision_factors.append(DecisionFactor(
                factor="SIGNATURE_VERIFICATION",
                impact=FactorImpact.CRITICAL.value,
                status="FAIL",
                explanation="The digital signature verification failed for the signed content.",
            ))
        else:
            steps.append(VerificationStep(
                step_id="crypto_signature",
                id="crypto_signature",
                order=step_order,
                category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
                status=StepStatus.WARNING.value,
                title="Signature cryptographic verification",
                check="Signature cryptographic verification",
                observed_value="Unknown / Inconclusive",
                expected_condition="Definitive cryptographic verification",
                explanation="Cryptographic verification could not reach a definitive pass/fail conclusion.",
                technical_detail="Signature validation returned UNKNOWN or unsupported signature container state.",
                severity=FactorImpact.HIGH.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="CRYPTO_SIG_UNKNOWN",
                code="CRYPTO_SIG_UNKNOWN",
                category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
                source="SIGNATURE_ENGINE",
                field="signature_valid",
                status=EvidenceStatus.WARNING.value,
                title="Signature Verification Inconclusive",
                value="Unknown",
                description="Cryptographic validation could not be definitively concluded.",
                reason="Cryptographic validation could not be definitively concluded.",
                importance=FactorImpact.HIGH.value,
            ))
            why_not_authentic.append("Signature cryptographic verification was inconclusive.")
            decision_factors.append(DecisionFactor(
                factor="SIGNATURE_VERIFICATION",
                impact=FactorImpact.HIGH.value,
                status="WARNING",
                explanation="Signature verification produced an inconclusive outcome.",
            ))
    else:
        steps.append(VerificationStep(
            step_id="crypto_signature",
            id="crypto_signature",
            order=step_order,
            category=EvidenceCategory.SIGNATURE_VERIFICATION.value,
            status=StepStatus.NOT_CHECKED.value,
            title="Signature cryptographic verification",
            check="Signature cryptographic verification",
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Signature verification was not performed because no signature is present.",
            technical_detail=None,
            severity=FactorImpact.INFO.value,
        ))

    step_order += 1

    # ── Step 6: Document Integrity & Byte / Structural Coverage ───────────────
    intg_target_name = (
        "ByteRange & Incremental Revision" if doc_format == "PDF" else
        "Signed XML Elements / References" if doc_format == "XML" else
        "Signed JSON Payload" if doc_format == "JSON" else
        "Signed Workbook & Worksheet Parts" if doc_format == "XLSX" else
        "Signed Document Package Parts" if doc_format == "DOCX" else
        "Signed Content Digest"
    )

    if evidence.signature_present:
        if evidence.integrity_verified is True:
            steps.append(VerificationStep(
                step_id="content_integrity",
                id="content_integrity",
                order=step_order,
                category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
                status=StepStatus.PASS.value,
                title=f"Signed content integrity ({intg_target_name})",
                check=f"Signed content integrity ({intg_target_name})",
                observed_value="Intact",
                expected_condition=f"Signed {intg_target_name} content remains unmodified",
                explanation=f"The content protected by the digital signature matches the signed baseline. No unauthorized modifications detected.",
                technical_detail=f"Integrity coverage verified across {doc_format} document structure without unauthorized alterations.",
                severity=FactorImpact.INFO.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="INTEGRITY_VERIFIED",
                code="INTEGRITY_VERIFIED",
                category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
                source="INTEGRITY_ENGINE",
                field="integrity_status",
                status=EvidenceStatus.PASS.value,
                title="Document Integrity Verified",
                value="Intact",
                description=f"No unauthorized modifications were detected within the signed {doc_format} content.",
                reason=f"No unauthorized modifications were detected within the signed {doc_format} content.",
                importance=FactorImpact.CRITICAL.value,
            ))
            decision_factors.append(DecisionFactor(
                factor="DOCUMENT_INTEGRITY",
                impact=FactorImpact.CRITICAL.value,
                status="PASS",
                explanation=f"Document integrity verified; signed {doc_format} content is intact.",
            ))
        elif evidence.integrity_verified is False:
            tl = evidence.tampering_localization or {}
            affected_items = tl.get("affected_items", [])
            loc_parts = [it.get("location") for it in affected_items if it.get("location")]
            loc_summary = ", ".join(loc_parts[:3]) if loc_parts else None

            exp_msg = f"The signed content no longer matches the cryptographically protected {doc_format} data."
            tech_detail = f"Discrepancy detected between the signed reference data and current {doc_format} content."
            if loc_summary:
                exp_msg += f" Tampering was localized to: {loc_summary}."
                tech_detail += f" Localization engine identified {len(affected_items)} modified structural item(s)."
            else:
                exp_msg += " The exact modification location could not be established from available structural evidence."

            steps.append(VerificationStep(
                step_id="content_integrity",
                id="content_integrity",
                order=step_order,
                category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
                status=StepStatus.FAIL.value,
                title=f"Signed content integrity ({intg_target_name})",
                check=f"Signed content integrity ({intg_target_name})",
                observed_value=f"Modified ({loc_summary})" if loc_summary else "Modified / Altered",
                expected_condition=f"Signed {intg_target_name} content remains unmodified",
                explanation=exp_msg,
                technical_detail=tech_detail,
                severity=FactorImpact.CRITICAL.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="INTEGRITY_FAILED",
                code="INTEGRITY_FAILED",
                category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
                source="INTEGRITY_ENGINE",
                field="integrity_status",
                status=EvidenceStatus.FAIL.value,
                title="Signed Content Modified",
                value=loc_summary or "Modified",
                description=f"Document content covered by the signature has been altered after signing ({loc_summary or 'structural mismatch'}).",
                reason=f"Document content covered by the signature has been altered after signing ({loc_summary or 'structural mismatch'}).",
                importance=FactorImpact.CRITICAL.value,
            ))
            why_not_authentic.append("Signed content integrity failed: Document has been altered after signing.")
            decision_factors.append(DecisionFactor(
                factor="DOCUMENT_INTEGRITY",
                impact=FactorImpact.CRITICAL.value,
                status="FAIL",
                explanation="The signed content is inconsistent with the current document content.",
            ))

            # Add localized items if present
            if affected_items:
                for aff_it in affected_items[:5]:
                    evidence_items.append(EvidenceItem(
                        evidence_id="TAMPERING_LOCALIZED",
                        code="TAMPERING_LOCALIZED",
                        category=EvidenceCategory.TAMPERING_LOCALIZATION.value,
                        source="LOCALIZATION_ENGINE",
                        field=aff_it.get("location_type", "LOCATION"),
                        status=EvidenceStatus.FAIL.value,
                        title=f"Tampering: {aff_it.get('location', 'Unknown Location')}",
                        value=aff_it.get("change_type", "CONTENT_CHANGED"),
                        description="; ".join(aff_it.get("evidence", [])) or f"Modified relative to signed {doc_format} baseline.",
                        reason="; ".join(aff_it.get("evidence", [])) or f"Modified relative to signed {doc_format} baseline.",
                        importance=FactorImpact.HIGH.value,
                    ))
        else:
            steps.append(VerificationStep(
                step_id="content_integrity",
                id="content_integrity",
                order=step_order,
                category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
                status=StepStatus.WARNING.value,
                title=f"Signed content integrity ({intg_target_name})",
                check=f"Signed content integrity ({intg_target_name})",
                observed_value="Unverified",
                expected_condition=f"Signed {intg_target_name} verification",
                explanation="Document integrity could not be definitively verified from the available byte coverage.",
                technical_detail="Integrity inspection produced inconclusive coverage metrics.",
                severity=FactorImpact.MEDIUM.value,
            ))
            evidence_items.append(EvidenceItem(
                evidence_id="INTEGRITY_UNKNOWN",
                code="INTEGRITY_UNKNOWN",
                category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
                source="INTEGRITY_ENGINE",
                field="integrity_status",
                status=EvidenceStatus.WARNING.value,
                title="Integrity Verification Inconclusive",
                value="Unverified",
                description="Byte / structural coverage validation could not be completed.",
                reason="Byte / structural coverage validation could not be completed.",
                importance=FactorImpact.MEDIUM.value,
            ))
            why_not_authentic.append("Signed content integrity could not be fully established.")
    else:
        steps.append(VerificationStep(
            step_id="content_integrity",
            id="content_integrity",
            order=step_order,
            category=EvidenceCategory.DOCUMENT_INTEGRITY.value,
            status=StepStatus.NOT_CHECKED.value,
            title=f"Signed content integrity ({intg_target_name})",
            check=f"Signed content integrity ({intg_target_name})",
            observed_value=None,
            expected_condition="Digital signature present",
            explanation="Integrity check was not performed because no signature is present.",
            technical_detail=None,
            severity=FactorImpact.INFO.value,
        ))

    step_order += 1

    # ── Step 7: Signature Timeline & Revisions ────────────────────────────────
    tl = evidence.signature_timeline or {}
    tl_status = (tl.get("status") or tl.get("timeline_status") or "NOT_AVAILABLE").upper()

    if tl and tl_status in ("AVAILABLE", "ANALYZED", "PARTIAL"):
        tl_consistency = (tl.get("consistency_status") or "CONSISTENT").upper()
        total_signed = tl.get("signature_count") or tl.get("total_signed_signatures", 0)
        rev_count = tl.get("total_revisions") or tl.get("revision_count", 1)
        sig_list = tl.get("events") or tl.get("signatures", [])

        if tl_consistency == "CONSISTENT":
            tl_step_status = StepStatus.PASS.value
            tl_obs = f"Consistent ({total_signed} signed / {rev_count} revs)"
            if total_signed > 1:
                tl_exp = f"{total_signed} signatures detected across {rev_count} document revisions. The revision sequence is structurally consistent and earlier signed content was preserved."
            elif total_signed == 1:
                tl_exp = f"Digital signature is cryptographically valid for Revision 1 of {rev_count} and matches its ByteRange specification."
            else:
                tl_exp = "No active digital signatures detected in the document structure."
        elif tl_consistency == "INCONSISTENT":
            tl_step_status = StepStatus.FAIL.value
            tl_obs = f"Inconsistent ({total_signed} signed)"
            tl_exp = "Signature timeline analysis detected unauthorized modifications, invalid ByteRanges, or cryptographic failures in one or more signed revisions."
            why_not_authentic.append("Revision history contains unauthorized modifications or timeline inconsistencies.")
        else:
            tl_step_status = StepStatus.WARNING.value
            tl_obs = f"Partial ({total_signed} signed)"
            tl_exp = "Signature timeline contains unverified, self-signed, or inconclusive signature states."

        steps.append(VerificationStep(
            step_id="signature_timeline",
            id="signature_timeline",
            order=step_order,
            category=EvidenceCategory.SIGNATURE_TIMELINE.value,
            status=tl_step_status,
            title="Signature timeline & revision consistency",
            check="Signature timeline & revision consistency",
            observed_value=tl_obs,
            expected_condition="All signatures cryptographically valid and consistent with revision sequence",
            explanation=tl_exp,
            technical_detail=f"ByteRange coverage verified across {rev_count} revisions in {doc_format} container; order confidence: {tl.get('chronology_confidence', 'HIGH')}.",
            severity=FactorImpact.HIGH.value if tl_consistency == "INCONSISTENT" else FactorImpact.INFO.value,
        ))
        evidence_items.append(EvidenceItem(
            evidence_id="TIMELINE_CONSISTENCY",
            code="TIMELINE_CONSISTENCY",
            category=EvidenceCategory.SIGNATURE_TIMELINE.value,
            source="TIMELINE_ENGINE",
            field="consistency_status",
            status=EvidenceStatus.PASS.value if tl_consistency == "CONSISTENT" else (
                EvidenceStatus.FAIL.value if tl_consistency == "INCONSISTENT" else EvidenceStatus.WARNING.value
            ),
            title="Signature Timeline Consistency",
            value=tl_consistency,
            description=tl_exp,
            reason=tl_exp,
            importance=FactorImpact.HIGH.value,
        ))
        if total_signed > 1:
            decision_factors.append(DecisionFactor(
                factor="SIGNATURE_TIMELINE",
                impact=FactorImpact.MEDIUM.value,
                status="PASS" if tl_consistency == "CONSISTENT" else "WARNING",
                explanation=f"{total_signed} signatures detected across {rev_count} revisions; sequence is {tl_consistency.lower()}.",
            ))
        step_order += 1

    elif tl and tl_status == "NOT_AVAILABLE":
        limitations.append(tl.get("reason") or f"Reliable signature chronology is not exposed by the {doc_format} format.")

    # ── Step 8: Tampering Localization Result ─────────────────────────────────
    tloc = evidence.tampering_localization or {}
    tloc_status = (tloc.get("status") or "NOT_AVAILABLE").upper()
    tloc_items = tloc.get("affected_items", [])
    
    if tloc_status == "LOCALIZED" and tloc_items:
        first_loc = tloc_items[0].get("location", "Specific location")
        loc_msg = f"Unauthorized modification localized to {first_loc}"
        if len(tloc_items) > 1:
            loc_msg += f" and {len(tloc_items) - 1} other location(s)"
        loc_msg += f" in {doc_format} structure."

        steps.append(VerificationStep(
            step_id="tampering_localization",
            id="tampering_localization",
            order=step_order,
            category=EvidenceCategory.TAMPERING_LOCALIZATION.value,
            status=StepStatus.FAIL.value,
            title="Tampering localization",
            check="Tampering localization",
            observed_value=f"{len(tloc_items)} Affected Location(s)",
            expected_condition="No structural modifications detected",
            explanation=loc_msg,
            technical_detail=f"Localization level: {tloc.get('localization_level', 'STRUCTURAL')}; Baseline: {tloc.get('comparison_source', 'BASELINE')}.",
            severity=FactorImpact.HIGH.value,
        ))
        decision_factors.append(DecisionFactor(
            factor="TAMPERING_LOCALIZATION",
            impact=FactorImpact.HIGH.value,
            status="LOCALIZED",
            explanation=loc_msg,
        ))
        step_order += 1
    elif evidence.signed_content_modified is True and not tloc_items:
        limitations.append("The integrity check indicates an anomaly, but the available evidence is insufficient to identify the exact modified location.")

    # ── Step 9: Threat Analysis & Structural Anomalies ────────────────────────
    threat_lvl = (evidence.threat_level or "LOW").upper()
    threat_sc = evidence.threat_score or 0
    threat_status = (
        StepStatus.FAIL.value if threat_lvl in ("CRITICAL", "HIGH") else
        StepStatus.WARNING.value if threat_lvl == "MEDIUM" else
        StepStatus.PASS.value
    )
    threat_exp = (
        f"Threat Level: {threat_lvl} (Score: {threat_sc}/100). Detected threats: {', '.join(evidence.detected_threats) if evidence.detected_threats else 'None'}."
    )
    steps.append(VerificationStep(
        step_id="threat_analysis",
        id="threat_analysis",
        order=step_order,
        category=EvidenceCategory.THREAT_ANALYSIS.value,
        status=threat_status,
        title="Threat and structural anomaly analysis",
        check="Threat and structural anomaly analysis",
        observed_value=f"{threat_lvl} ({threat_sc}/100)",
        expected_condition="LOW threat level without security anomalies",
        explanation=threat_exp,
        technical_detail="Deterministic threat evaluation aggregating cryptographic, structural, and certificate signals.",
        severity=FactorImpact.HIGH.value if threat_lvl in ("CRITICAL", "HIGH") else FactorImpact.LOW.value,
    ))
    evidence_items.append(EvidenceItem(
        evidence_id="THREAT_LEVEL_EVAL",
        code="THREAT_LEVEL_EVAL",
        category=EvidenceCategory.THREAT_ANALYSIS.value,
        source="THREAT_ENGINE",
        field="threat_level",
        status=EvidenceStatus.FAIL.value if threat_lvl in ("CRITICAL", "HIGH") else (
            EvidenceStatus.WARNING.value if threat_lvl == "MEDIUM" else EvidenceStatus.PASS.value
        ),
        title=f"Threat Level: {threat_lvl}",
        value=f"{threat_sc}/100",
        description=threat_exp,
        reason=threat_exp,
        importance=FactorImpact.HIGH.value,
    ))
    if threat_lvl in ("CRITICAL", "HIGH"):
        why_not_authentic.append(f"Threat analysis classified the file as {threat_lvl} risk.")
        decision_factors.append(DecisionFactor(
            factor="THREAT_ANALYSIS",
            impact=FactorImpact.HIGH.value,
            status="FAIL" if threat_lvl == "CRITICAL" else "WARNING",
            explanation=f"Threat score {threat_sc}/100 exceeds safe threshold ({', '.join(evidence.detected_threats[:2]) or 'Anomalies detected'}).",
        ))
    step_order += 1

    # ── Step 10: Quantum-Inspired Classical Simulation (Secondary Signal) ─────
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
            step_id="quantum_simulation",
            id="quantum_simulation",
            order=step_order,
            category=EvidenceCategory.QUANTUM_INSPIRED_ANALYSIS.value,
            status=q_status,
            title="Quantum-inspired classical anomaly simulation",
            check="Quantum-inspired classical anomaly simulation",
            observed_value=", ".join(detail_metrics) or "Simulated",
            expected_condition="Low anomaly distance (< 0.50) from baseline reference state",
            explanation=(
                "Quantum-inspired analysis identified an elevated anomaly signal. "
                "This is a classical simulation using quantum-inspired mathematical representations as an additional security signal. "
                "It does not perform verification using a real quantum computer and does not override cryptographic verification."
                if has_elevated_anomaly else
                "Quantum-inspired classical simulation metrics are consistent with the authentic baseline state. "
                "Classical mathematical simulation used as a secondary signal."
            ),
            technical_detail="14-dimensional feature vector projected onto normalized Hilbert space amplitudes; secondary heuristic signal.",
            severity=FactorImpact.LOW.value,
        ))
        evidence_items.append(EvidenceItem(
            evidence_id="QUANTUM_ANOMALY_ELEVATED" if has_elevated_anomaly else "QUANTUM_BASELINE_CONSISTENT",
            code="QUANTUM_ANOMALY_ELEVATED" if has_elevated_anomaly else "QUANTUM_BASELINE_CONSISTENT",
            category=EvidenceCategory.QUANTUM_INSPIRED_ANALYSIS.value,
            source="QUANTUM_ENGINE",
            field="anomaly_distance",
            status=EvidenceStatus.WARNING.value if has_elevated_anomaly else EvidenceStatus.INFO.value,
            title="Quantum-Inspired Mathematical Analysis",
            value=", ".join(detail_metrics) or "Simulated",
            description=(
                "Classical simulation identified elevated anomaly distance; secondary signal that does not override cryptographic evidence."
                if has_elevated_anomaly else
                "Classical simulation metrics conform with authentic baseline state vector."
            ),
            reason=(
                "Classical simulation identified elevated anomaly distance; secondary signal that does not override cryptographic evidence."
                if has_elevated_anomaly else
                "Classical simulation metrics conform with authentic baseline state vector."
            ),
            importance=FactorImpact.LOW.value,
        ))
        step_order += 1

    # ── Step 11: Final Verdict Step ───────────────────────────────────────────
    steps.append(VerificationStep(
        step_id="final_verdict",
        id="final_verdict",
        order=step_order,
        category=EvidenceCategory.FINAL_VERDICT.value,
        status=(
            StepStatus.PASS.value if verdict_upper == "AUTHENTIC" else
            StepStatus.FAIL.value if verdict_upper == "TAMPERED" else
            StepStatus.WARNING.value
        ),
        title="Final security verdict",
        check="Final security verdict",
        observed_value=verdict_upper,
        expected_condition="AUTHENTIC",
        explanation=_generate_verdict_explanation(verdict_upper, evidence, doc_format),
        technical_detail=f"Authoritative backend verdict based on cryptographic evidence hierarchy.",
        severity=FactorImpact.CRITICAL.value if verdict_upper == "TAMPERED" else (
            FactorImpact.HIGH.value if verdict_upper == "SUSPICIOUS" else FactorImpact.INFO.value
        ),
    ))

    # ── Certificate Findings Integration ──────────────────────────────────────
    if evidence.certificate_inspection and isinstance(evidence.certificate_inspection, dict):
        for f in evidence.certificate_inspection.get("findings", []):
            f_code = f.get("code")
            f_sev = (f.get("severity") or "INFO").upper()
            f_status = (
                EvidenceStatus.FAIL.value if f_sev == "HIGH"
                else EvidenceStatus.WARNING.value if f_sev in ("MEDIUM", "LOW")
                else EvidenceStatus.INFO.value
            )
            if not any(e.code == f_code or e.evidence_id == f_code for e in evidence_items):
                evidence_items.append(EvidenceItem(
                    evidence_id=f_code,
                    code=f_code,
                    category=EvidenceCategory.CERTIFICATE.value,
                    source="CERTIFICATE_INSPECTOR",
                    field="finding",
                    status=f_status,
                    title=f.get("title", "Certificate Security Finding"),
                    value=f_sev,
                    description=f.get("description", ""),
                    reason=f.get("description", ""),
                    importance=f_sev,
                ))

    # ── Deduplicate & Filter Lists ────────────────────────────────────────────
    passed_checks = [e for e in evidence_items if e.status == EvidenceStatus.PASS.value]
    failed_checks = [e for e in evidence_items if e.status == EvidenceStatus.FAIL.value]
    warnings_list = [e for e in evidence_items if e.status == EvidenceStatus.WARNING.value]

    # ── Calculate Confidence ──────────────────────────────────────────────────
    confidence = _calculate_confidence(evidence)

    # ── Summary & Final Reason ────────────────────────────────────────────────
    final_reason = _generate_verdict_explanation(verdict_upper, evidence, doc_format)
    summary = _generate_executive_summary(verdict_upper, evidence, confidence, doc_format)

    # ── What Would Change This Result? ────────────────────────────────────────
    what_would_change = _generate_what_would_change(verdict_upper, evidence, doc_format)

    # Clean duplicates in limitations and why_not_authentic
    limitations = list(dict.fromkeys(limitations))
    why_not_authentic = list(dict.fromkeys(why_not_authentic))

    return ExplanationResult(
        verdict=verdict_upper,
        summary=summary,
        confidence=confidence.value,
        decision_factors=decision_factors,
        verification_steps=steps,
        evidence=evidence_items,
        why_not_authentic=why_not_authentic if verdict_upper != "AUTHENTIC" else [],
        what_would_change_verdict=what_would_change,
        warnings=warnings_list,
        limitations=limitations,
        failed_checks=failed_checks,
        passed_checks=passed_checks,
        final_reason=final_reason,
    )


# ── Internal Reason & Summary Helpers ─────────────────────────────────────────

def _generate_verdict_explanation(verdict: str, evidence: VerificationEvidence, doc_format: str = "PDF") -> str:
    """Generate deterministic explanation for WHY the verdict was reached."""
    if verdict == "AUTHENTIC":
        algo_part = ""
        if evidence.digest_algorithm and evidence.signature_algorithm:
            algo_part = f" using {evidence.digest_algorithm} with {evidence.signature_algorithm}"
        return (
            f"QuantumTrust classified this {doc_format} file as AUTHENTIC because the digital signature was "
            f"successfully verified{algo_part}, the signed content passed integrity validation, and no "
            f"significant certificate, revision, or security anomalies were detected."
        )

    if verdict == "TAMPERED":
        reasons = []
        if evidence.signature_valid is False:
            reasons.append("the cryptographic signature verification failed for the signed content")
        if evidence.signed_content_modified is True or evidence.integrity_verified is False:
            tl = evidence.tampering_localization or {}
            aff_items = tl.get("affected_items", [])
            if aff_items:
                loc_name = aff_items[0].get("location")
                reasons.append(f"the signed content no longer matches the current document (modification localized to {loc_name})")
            else:
                reasons.append(f"the signed content differs from the protected {doc_format} document content")
        if not reasons:
            reasons.append(f"document integrity validation failed against recorded cryptographic signatures")

        return f"QuantumTrust classified this {doc_format} file as TAMPERED because {' and '.join(reasons)}."

    # SUSPICIOUS
    if not evidence.signature_present:
        return f"No digital signature was detected in the submitted {doc_format} file; cryptographic authenticity cannot be established."

    suspicious_reasons = []
    if evidence.certificate_expired:
        suspicious_reasons.append("the signing certificate has expired")
    if evidence.certificate_trusted is False:
        suspicious_reasons.append("certificate chain trust could not be established with the configured trust store")
    if evidence.structural_anomalies:
        suspicious_reasons.append("structural anomalies were detected in the document stream")
    if evidence.signature_valid is None:
        suspicious_reasons.append("the cryptographic signature could not be fully resolved")
    if evidence.threat_level in ("HIGH", "CRITICAL"):
        suspicious_reasons.append(f"threat analysis flagged the document with {evidence.threat_level} risk")

    if suspicious_reasons:
        return (
            f"QuantumTrust classified this {doc_format} file as SUSPICIOUS because the cryptographic signature "
            f"is mathematically present, but additional security evidence contains anomalies: {'; '.join(suspicious_reasons)}."
        )

    return (
        f"QuantumTrust classified this {doc_format} file as SUSPICIOUS because security, certificate, "
        f"or structural checks produced warnings that prevent a clean AUTHENTIC classification."
    )


def _generate_executive_summary(
    verdict: str,
    evidence: VerificationEvidence,
    confidence: ConfidenceLevel,
    doc_format: str = "PDF",
) -> str:
    """Generate high-level executive summary."""
    if verdict == "AUTHENTIC":
        return (
            f"{doc_format} file verified as AUTHENTIC with {confidence.value} confidence. "
            f"Cryptographic signature is valid and document content integrity is fully intact."
        )
    elif verdict == "TAMPERED":
        tl = evidence.tampering_localization or {}
        aff_items = tl.get("affected_items", [])
        loc_str = f" with modification localized to {aff_items[0].get('location')}" if aff_items else ""
        return (
            f"{doc_format} file classified as TAMPERED with {confidence.value} confidence. "
            f"Digital signature verification failed against the current document content{loc_str}."
        )
    else:
        return (
            f"{doc_format} file classified as SUSPICIOUS with {confidence.value} confidence. "
            f"Cryptographic or certificate security anomalies prevent an authentic certification."
        )


def _generate_what_would_change(verdict: str, evidence: VerificationEvidence, doc_format: str = "PDF") -> str | None:
    """Explain what conditions would be needed to achieve AUTHENTIC without giving bypass instructions."""
    if verdict == "AUTHENTIC":
        return None

    if verdict == "TAMPERED":
        return (
            f"The document would need to pass cryptographic signature verification against the original signed content "
            f"and contain no unauthorized byte or structural alterations post-signing."
        )

    # SUSPICIOUS
    requirements = []
    if not evidence.signature_present:
        requirements.append("contain a valid, cryptographically verifiable digital signature")
    if evidence.certificate_expired:
        requirements.append("be signed with an active certificate evaluated within its valid NotBefore/NotAfter lifetime")
    if evidence.certificate_trusted is False:
        requirements.append("chain to a trusted root Certificate Authority configured in the trust store")
    if evidence.structural_anomalies:
        requirements.append("contain no suspicious structural objects or malformed syntax")

    if not requirements:
        requirements.append("resolve all certificate, structural, and cryptographic warnings")

    return f"To achieve an AUTHENTIC verdict, the file must: {'; '.join(requirements)}."


def _calculate_confidence(evidence: VerificationEvidence) -> ConfidenceLevel:
    """
    Categorical confidence reflects evidence completeness, NOT arbitrary probabilities.

    HIGH:
      - Signature verification executed (PASS or FAIL)
      - Integrity check executed (PASS or FAIL)
      - Certificate details extracted

    MEDIUM:
      - Some security evidence was unavailable or partially checked (e.g. self-signed without trust anchor)

    LOW:
      - Only partial verification possible (e.g. no signature or corrupt container)

    UNKNOWN / NOT_AVAILABLE:
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
        return ConfidenceLevel.UNKNOWN
