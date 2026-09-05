"""
QuantumTrust — Certificate analyzer (compatibility bridge)

Delegates to certificate_inspector for core X.509 parsing and inspection
while maintaining backward-compatible interface.
"""
from __future__ import annotations
import logging
from typing import Any

from app.services import certificate_inspector

logger = logging.getLogger(__name__)


def analyze_certificate(cert_data: Any) -> dict[str, Any]:
    """
    Analyze a certificate object and return legacy summary dictionary.
    Delegates to certificate_inspector to eliminate parsing duplication.
    """
    result: dict[str, Any] = {
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "valid_from": None,
        "valid_until": None,
        "trust_status": "UNAVAILABLE",
        "is_expired": None,
        "is_self_signed": None,
    }

    if cert_data is None:
        return result

    try:
        insp = certificate_inspector.inspect_certificate(cert_data)
        if insp.get("status") != "SUCCESS":
            return result

        cert = insp.get("certificate") or {}
        val = insp.get("validity") or {}
        trust = insp.get("trust") or {}
        subj = cert.get("subject") or {}
        issu = cert.get("issuer") or {}

        subj_str = subj.get("raw_dn") or subj.get("common_name")
        issu_str = issu.get("raw_dn") or issu.get("common_name")
        val_status = val.get("status")
        is_exp = (val_status == "EXPIRED")

        trust_st = trust.get("status", "UNKNOWN")
        if is_exp:
            trust_st = "EXPIRED"

        result.update({
            "subject": subj_str,
            "issuer": issu_str,
            "serial_number": cert.get("serial_number"),
            "valid_from": val.get("not_before"),
            "valid_until": val.get("not_after"),
            "trust_status": trust_st,
            "is_expired": is_exp,
            "is_self_signed": cert.get("is_self_signed"),
        })
    except Exception as exc:
        logger.error("analyze_certificate error: %s", exc)

    return result
