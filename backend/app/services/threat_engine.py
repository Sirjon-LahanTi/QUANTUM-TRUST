"""
QuantumTrust — Deterministic rule-based threat engine

Calculates a threat score (0–100) and threat level based on security signals.
All decisions are deterministic — no ML/AI.

Scoring table:
  Signal                              Score Impact
  ──────────────────────────────────────────────
  Signature invalid/corrupted         +50
  Signed content modified (FAILED)    +45
  Certificate expired                 +25
  Certificate untrusted               +20
  Certificate self-signed             +15
  Weak algorithm (SHA-1/MD5)          +15
  Suspicious PDF structure            +10
  Malformed/corrupted signature       +30
  Duplicate replay indicators         +10
  Multiple conflicting signatures     +10
  JavaScript in PDF                   +15
  Embedded files                      +10
  Excessive incremental updates       +10
  Signature algorithm unknown         +5
  Certificate unavailable             +5
  Integrity unknown                   +5

Levels:
  0–29:   LOW
  30–59:  MEDIUM
  60–79:  HIGH
  80–100: CRITICAL
"""
from __future__ import annotations
from typing import Any

# ── Scoring weights ────────────────────────────────────────────────────────────

_THREAT_RULES: list[tuple[str, int, str]] = [
    # (condition_key, score, label)
    ("sig_invalid",            50, "Cryptographic signature verification failed"),
    ("sig_corrupted",          30, "Malformed or corrupted signature structure"),
    ("content_modified",       45, "Signed document content has been modified"),
    ("cert_expired",           25, "Certificate has expired"),
    ("cert_untrusted",         20, "Certificate is not trusted"),
    ("cert_self_signed",       15, "Certificate is self-signed"),
    ("weak_digest",            15, "Weak digest algorithm detected (SHA-1 or MD5)"),
    ("duplicate_replay",       10, "Document is an exact duplicate of a previously analyzed document"),
    ("multiple_sigs_conflict", 10, "Multiple conflicting signatures detected"),
    ("has_javascript",         15, "JavaScript content detected in PDF"),
    ("has_embedded_files",     10, "Embedded files detected in PDF"),
    ("excessive_updates",      10, "Excessive incremental updates in PDF structure"),
    ("sig_algo_unknown",        5, "Signature algorithm could not be determined"),
    ("cert_unavailable",        5, "Certificate information unavailable"),
    ("integrity_unknown",       5, "Document integrity could not be fully verified"),
    ("quantum_anomaly",         5, "Elevated quantum-inspired anomaly distance from baseline"),
    ("no_signature",            0, "No digital signature present"),
]

_SCORE_KEY_MAP = {rule[0]: rule for rule in _THREAT_RULES}


def calculate_threat(
    sig_result: dict[str, Any],
    cert_info: dict[str, Any],
    integrity_result: dict[str, Any],
    pdf_structure: dict[str, Any],
    duplicate_result: dict[str, Any],
    quantum_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Calculate the overall threat score and level.

    Returns:
        {threat_score, threat_level, detected_threats}
    """
    conditions: dict[str, bool] = _evaluate_conditions(
        sig_result, cert_info, integrity_result, pdf_structure, duplicate_result, quantum_result
    )

    score = 0
    detected: list[str] = []

    for key, points, label in _THREAT_RULES:
        if conditions.get(key, False) and points > 0:
            score += points
            detected.append(label)

    score = min(score, 100)
    level = _score_to_level(score)

    return {
        "threat_score": score,
        "threat_level": level,
        "detected_threats": detected,
    }


def _evaluate_conditions(
    sig: dict[str, Any],
    cert: dict[str, Any],
    integ: dict[str, Any],
    pdf: dict[str, Any],
    dup: dict[str, Any],
    quantum: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Evaluate all threat condition flags."""
    sig_status  = (sig.get("overall_status") or "NONE").upper()
    integ_status = (integ.get("integrity_status") or "UNKNOWN").upper()
    integ_mod    = (integ.get("modification_status") or "UNKNOWN").upper()
    cert_trust   = (cert.get("trust_status") or "UNAVAILABLE").upper()
    digest_algo  = (sig.get("digest_algorithm") or "").upper()

    has_quantum_anomaly = False
    if quantum and isinstance(quantum, dict):
        anomaly_dist = quantum.get("anomaly_distance")
        if anomaly_dist is not None and isinstance(anomaly_dist, (int, float)) and anomaly_dist >= 0.50:
            has_quantum_anomaly = True

    return {
        "sig_invalid":   sig_status in ("INVALID",),
        "sig_corrupted": sig_status in ("CORRUPTED",),
        "content_modified": (
            integ_status == "FAILED" or
            integ_mod == "MODIFIED"
        ),
        "cert_expired":      cert_trust == "EXPIRED",
        "cert_untrusted":    cert_trust in ("UNTRUSTED",),
        "cert_self_signed":  cert_trust == "SELF_SIGNED",
        "weak_digest":       digest_algo in ("SHA1", "SHA-1", "MD5", "MD2"),
        "duplicate_replay":  bool(dup.get("is_duplicate", False)),
        "multiple_sigs_conflict": (
            sig.get("count", 0) > 1 and sig_status not in ("VALID",)
        ),
        "has_javascript":       bool(pdf.get("has_js", False)),
        "has_embedded_files":   bool(pdf.get("has_embedded_files", False)),
        "excessive_updates":    int(pdf.get("incremental_update_count", 0)) > 2,
        "sig_algo_unknown":     sig_status not in ("NONE",) and not sig.get("signature_algorithm"),
        "cert_unavailable":     cert_trust == "UNAVAILABLE",
        "integrity_unknown":    integ_status == "UNKNOWN",
        "quantum_anomaly":      has_quantum_anomaly,
        "no_signature":         sig_status == "NONE",
    }


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def determine_verdict(
    sig_result: dict[str, Any],
    cert_info: dict[str, Any],
    integrity_result: dict[str, Any],
    threat_result: dict[str, Any],
) -> str:
    """
    Determine final verdict: AUTHENTIC, TAMPERED, or SUSPICIOUS.

    Rules (in priority order):
    1. If content was modified or signature is invalid → TAMPERED
    2. If no signature → SUSPICIOUS (cannot authenticate)
    3. If signature valid + integrity verified + no critical cert issues → AUTHENTIC
    4. Otherwise → SUSPICIOUS
    """
    sig_status   = (sig_result.get("overall_status") or "NONE").upper()
    integ_status = (integrity_result.get("integrity_status") or "UNKNOWN").upper()
    integ_mod    = (integrity_result.get("modification_status") or "UNKNOWN").upper()
    cert_trust   = (cert_info.get("trust_status") or "UNAVAILABLE").upper()
    threat_level = (threat_result.get("threat_level") or "LOW").upper()

    # TAMPERED: clear evidence of modification or failed crypto
    if sig_status == "INVALID" or integ_mod == "MODIFIED" or integ_status == "FAILED":
        return "TAMPERED"

    # SUSPICIOUS: no signature
    if sig_status == "NONE":
        return "SUSPICIOUS"

    # AUTHENTIC: valid signature, verified integrity, acceptable trust
    if (
        sig_status == "VALID"
        and integ_status == "VERIFIED"
        and integ_mod in ("NO_UNAUTHORIZED_CHANGES", "PERMITTED_CHANGES")
        and cert_trust not in ("UNTRUSTED", "EXPIRED")
        and threat_level not in ("CRITICAL",)
    ):
        return "AUTHENTIC"

    # SUSPICIOUS: everything else
    return "SUSPICIOUS"
