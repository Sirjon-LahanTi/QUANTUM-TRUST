"""
QuantumTrust — Certificate analyzer (cryptography library layer)

Parses X.509 certificates for:
- Subject / Issuer details
- Serial number
- Validity dates
- Public key algorithm and key size
- Trust status determination

Separate from cryptographic signature validity.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def analyze_certificate(cert_data: Any) -> dict[str, Any]:
    """
    Analyze a certificate object.

    cert_data can be:
    - asn1crypto.x509.Certificate (from pyHanko)
    - cryptography.x509.Certificate
    - bytes (DER-encoded)
    - None

    Returns a normalized certificate info dict.
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

    # Try asn1crypto certificate (from pyHanko)
    try:
        result.update(_parse_asn1crypto_cert(cert_data))
        return result
    except Exception:
        pass

    # Try cryptography library certificate
    try:
        result.update(_parse_cryptography_cert(cert_data))
        return result
    except Exception:
        pass

    # Try DER bytes
    if isinstance(cert_data, (bytes, bytearray)):
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(cert_data)
            result.update(_parse_cryptography_cert(cert))
            return result
        except Exception:
            pass

    return result


def _parse_asn1crypto_cert(cert: Any) -> dict[str, Any]:
    """Parse asn1crypto Certificate object."""
    result: dict[str, Any] = {}

    # Subject
    try:
        result["subject"] = _asn1_dn_to_str(cert.subject)
    except Exception:
        pass

    # Issuer
    try:
        result["issuer"] = _asn1_dn_to_str(cert.issuer)
    except Exception:
        pass

    # Serial
    try:
        result["serial_number"] = format(cert.serial_number, 'X')
    except Exception:
        try:
            result["serial_number"] = str(cert["tbs_certificate"]["serial_number"].native)
        except Exception:
            pass

    # Validity
    try:
        tbs = cert["tbs_certificate"]
        validity = tbs["validity"]

        not_before = validity["not_before"].native
        not_after  = validity["not_after"].native

        result["valid_from"]  = _format_datetime(not_before)
        result["valid_until"] = _format_datetime(not_after)

        now = datetime.now(timezone.utc)
        if hasattr(not_after, "utcoffset"):
            expired = not_after < now
        else:
            expired = not_after.replace(tzinfo=timezone.utc) < now
        result["is_expired"] = expired

        if expired:
            result["trust_status"] = "EXPIRED"
        else:
            result["trust_status"] = "UNKNOWN"

    except Exception as e:
        logger.debug("asn1crypto validity parse error: %s", e)

    # Self-signed detection
    try:
        subj = cert.subject.hashable
        issu = cert.issuer.hashable
        result["is_self_signed"] = (subj == issu)
        if result.get("is_self_signed") and result.get("trust_status") not in ("EXPIRED",):
            result["trust_status"] = "SELF_SIGNED"
    except Exception:
        pass

    return result


def _parse_cryptography_cert(cert: Any) -> dict[str, Any]:
    """Parse cryptography.x509.Certificate object."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    result: dict[str, Any] = {}

    # Subject
    try:
        result["subject"] = cert.subject.rfc4514_string()
    except Exception:
        try:
            result["subject"] = _cryptography_dn_to_str(cert.subject)
        except Exception:
            pass

    # Issuer
    try:
        result["issuer"] = cert.issuer.rfc4514_string()
    except Exception:
        try:
            result["issuer"] = _cryptography_dn_to_str(cert.issuer)
        except Exception:
            pass

    # Serial
    try:
        result["serial_number"] = format(cert.serial_number, 'X')
    except Exception:
        pass

    # Validity
    try:
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc
    except AttributeError:
        # Older cryptography versions
        try:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)
        except Exception:
            not_before = None
            not_after  = None

    if not_before:
        result["valid_from"] = _format_datetime(not_before)
    if not_after:
        result["valid_until"] = _format_datetime(not_after)
        now = datetime.now(timezone.utc)
        expired = not_after < now
        result["is_expired"] = expired
        result["trust_status"] = "EXPIRED" if expired else "UNKNOWN"

    # Self-signed
    try:
        result["is_self_signed"] = (cert.subject == cert.issuer)
        if result.get("is_self_signed") and result.get("trust_status") != "EXPIRED":
            result["trust_status"] = "SELF_SIGNED"
    except Exception:
        pass

    return result


def _asn1_dn_to_str(dn: Any) -> str | None:
    """Convert asn1crypto Distinguished Name to a readable string."""
    try:
        parts = []
        for rdn in dn.chosen:
            for attr in rdn:
                try:
                    parts.append(f"{attr['type'].human_friendly}={attr['value'].native}")
                except Exception:
                    try:
                        parts.append(f"{attr['type'].native}={attr['value'].native}")
                    except Exception:
                        pass
        return ", ".join(parts) if parts else None
    except Exception:
        try:
            return str(dn.human_friendly)
        except Exception:
            try:
                return str(dn)
            except Exception:
                return None


def _cryptography_dn_to_str(name: Any) -> str:
    """Convert cryptography Name to a readable string."""
    parts = []
    for attr in name:
        try:
            parts.append(f"{attr.oid.dotted_string}={attr.value}")
        except Exception:
            pass
    return ", ".join(parts)


def _format_datetime(dt: Any) -> str | None:
    """Format a datetime to ISO8601 string."""
    if dt is None:
        return None
    try:
        if hasattr(dt, "isoformat"):
            return dt.isoformat()
        return str(dt)
    except Exception:
        return None
