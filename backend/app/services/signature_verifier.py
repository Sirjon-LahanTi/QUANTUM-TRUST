"""
QuantumTrust — PDF digital signature verifier (pyHanko primary layer)

Performs proper PDF digital signature verification:
- Inspects PDF signature structure (ByteRange, CMS/PKCS#7)
- Auto-detects actual digest algorithm and signature algorithm
- Verifies signature cryptographically
- Checks signed content integrity via ByteRange
- Does NOT assume SHA-256 or RSA — reads actual algorithm from CMS structure
- Does NOT expose, request, or require the private key
"""
from __future__ import annotations
import io
import logging
from typing import Any

logger = logging.getLogger(__name__)


def verify_pdf_signatures(pdf_bytes: bytes) -> dict[str, Any]:
    """
    Verify all digital signatures in a PDF using pyHanko.

    Returns:
        {
            present, count, signatures: [...], overall_status,
            digest_algorithm, signature_algorithm, public_key_algorithm,
            key_size, signature_type, byte_range, error
        }
    """
    result: dict[str, Any] = {
        "present": False,
        "count": 0,
        "signatures": [],
        "overall_status": "NONE",  # NONE, VALID, INVALID, UNKNOWN, UNSUPPORTED, CORRUPTED
        "digest_algorithm": None,
        "signature_algorithm": None,
        "public_key_algorithm": None,
        "key_size": None,
        "signature_type": None,
        "byte_range": None,
        "integrity_status": "UNKNOWN",
        "integrity_modification_status": "UNKNOWN",
        "error": None,
    }

    try:
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko.sign.fields import enumerate_sig_fields
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation.status import SignatureCoverageLevel

        reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)

        # Retrieve embedded signatures (pyHanko primary mechanism)
        embedded_sigs = list(reader.embedded_signatures)
        sig_fields = list(enumerate_sig_fields(reader, filled_status=True))

        if not embedded_sigs and not sig_fields:
            result["overall_status"] = "NONE"
            return result

        sig_count = max(len(embedded_sigs), len(sig_fields))
        result["present"] = True
        result["count"] = sig_count

        sig_results = []
        overall_valid = True
        any_invalid = False
        any_unknown = False

        if embedded_sigs:
            for emb_sig in embedded_sigs:
                field_name = getattr(emb_sig, "field_name", None)
                if not field_name and hasattr(emb_sig, "sig_field"):
                    try:
                        field_name = str(emb_sig.sig_field.get("/T", "Signature"))
                    except Exception:
                        field_name = "Signature"

                sig_detail: dict[str, Any] = {
                    "field_name": field_name or "Signature",
                    "status": "UNKNOWN",
                    "digest_algorithm": None,
                    "signature_algorithm": None,
                    "public_key_algorithm": None,
                    "key_size": None,
                    "byte_range": None,
                    "integrity_ok": None,
                    "modification_ok": None,
                    "cert_subject": None,
                    "cert_issuer": None,
                    "cert_serial": None,
                    "cert_valid_from": None,
                    "cert_valid_until": None,
                    "trust_status": None,
                    "error": None,
                    "_cert_object": None,
                    "_all_certs": [],
                }

                try:
                    # Validate embedded signature cryptographically
                    val_result = validate_pdf_signature(emb_sig)

                    # Extract all certificates in the CMS container
                    all_certs: list[Any] = []
                    try:
                        if hasattr(emb_sig, "signed_data") and emb_sig.signed_data is not None:
                            certs_container = emb_sig.signed_data.get("certificates")
                            if certs_container:
                                for c in certs_container:
                                    if hasattr(c, "chosen"):
                                        all_certs.append(c.chosen)
                                    else:
                                        all_certs.append(c)
                    except Exception as ce:
                        logger.debug("Error retrieving CMS certificates: %s", ce)

                    # --- Digest algorithm ---
                    try:
                        md_algo = getattr(val_result, "md_algorithm", None)
                        if md_algo:
                            sig_detail["digest_algorithm"] = str(md_algo).upper()
                    except Exception:
                        pass

                    # --- ByteRange ---
                    try:
                        if hasattr(emb_sig, "byte_range") and emb_sig.byte_range:
                            sig_detail["byte_range"] = list(emb_sig.byte_range)
                        elif hasattr(val_result, "sig_object") and "/ByteRange" in val_result.sig_object:
                            sig_detail["byte_range"] = list(val_result.sig_object["/ByteRange"])
                    except Exception:
                        pass

                    # --- Certificate & Public Key Details ---
                    try:
                        cert = getattr(val_result, "signing_cert", None)
                        if cert is not None:
                            sig_detail["_cert_object"] = cert
                            if cert not in all_certs:
                                all_certs.insert(0, cert)
                            sig_detail["_all_certs"] = all_certs

                            pub_key = getattr(cert, "public_key", None)
                            if pub_key is not None:
                                sig_detail["public_key_algorithm"] = _detect_public_key_algorithm(pub_key)
                                sig_detail["key_size"] = _get_key_size(pub_key)

                            # Signature algorithm from cert or val_result
                            sig_algo = getattr(cert, "signature_algo", None)
                            if sig_algo:
                                sig_detail["signature_algorithm"] = _format_sig_algo(sig_algo)
                            elif hasattr(val_result, "signature_algorithm"):
                                sig_detail["signature_algorithm"] = _format_sig_algo(val_result.signature_algorithm)

                            # Certificate details
                            sig_detail["cert_subject"] = _dn_to_str(getattr(cert, "subject", None))
                            sig_detail["cert_issuer"]  = _dn_to_str(getattr(cert, "issuer", None))
                            try:
                                sig_detail["cert_serial"] = format(cert.serial_number, "X") if hasattr(cert, "serial_number") else str(cert["tbs_certificate"]["serial_number"].native)
                            except Exception:
                                pass
                            try:
                                sig_detail["cert_valid_from"]  = str(cert["tbs_certificate"]["validity"]["not_before"].native)
                            except Exception:
                                pass
                            try:
                                sig_detail["cert_valid_until"] = str(cert["tbs_certificate"]["validity"]["not_after"].native)
                            except Exception:
                                pass
                        else:
                            sig_detail["_all_certs"] = all_certs
                    except Exception as ce:
                        logger.debug("Cert detail extraction error: %s", ce)

                    # --- Cryptographic validity ---
                    try:
                        intact = getattr(val_result, "intact", None)
                        valid = getattr(val_result, "valid", None)

                        if intact is True and valid is True:
                            sig_detail["status"] = "VALID"
                        elif intact is False or valid is False:
                            sig_detail["status"] = "INVALID"
                            any_invalid = True
                            overall_valid = False
                        else:
                            # Fallback to bottom_line
                            if getattr(val_result, "bottom_line", False):
                                sig_detail["status"] = "VALID"
                            else:
                                sig_detail["status"] = "UNKNOWN"
                                any_unknown = True
                    except Exception:
                        sig_detail["status"] = "UNKNOWN"
                        any_unknown = True

                    # --- Integrity / coverage ---
                    try:
                        coverage = getattr(val_result, "coverage", None)
                        if coverage is not None:
                            if coverage >= SignatureCoverageLevel.ENTIRE_REVISION:
                                sig_detail["integrity_ok"] = True
                                sig_detail["modification_ok"] = "NO_UNAUTHORIZED_CHANGES"
                            else:
                                sig_detail["integrity_ok"] = True
                                sig_detail["modification_ok"] = "PERMITTED_CHANGES"
                        else:
                            sig_detail["integrity_ok"] = (sig_detail["status"] == "VALID")
                            sig_detail["modification_ok"] = "NO_UNAUTHORIZED_CHANGES" if sig_detail["status"] == "VALID" else "UNKNOWN"
                    except Exception:
                        pass

                    # --- Trust status ---
                    try:
                        if cert is not None:
                            subj = getattr(cert, "subject", None)
                            issu = getattr(cert, "issuer", None)
                            if subj and issu and _dn_to_str(subj) == _dn_to_str(issu):
                                sig_detail["trust_status"] = "SELF_SIGNED"
                            else:
                                trust = getattr(val_result, "trust_problem_indic", None)
                                if trust is None:
                                    sig_detail["trust_status"] = "TRUSTED"
                                else:
                                    sig_detail["trust_status"] = "SELF_SIGNED" if getattr(val_result, "intact", False) else "UNTRUSTED"
                        else:
                            sig_detail["trust_status"] = "UNAVAILABLE"
                    except Exception:
                        sig_detail["trust_status"] = "SELF_SIGNED" if sig_detail["status"] == "VALID" else "UNAVAILABLE"

                except Exception as field_exc:
                    logger.warning("Error validating embedded sig '%s': %s", field_name, field_exc)
                    sig_detail["status"] = "CORRUPTED"
                    sig_detail["error"] = str(field_exc)
                    any_invalid = True
                    overall_valid = False

                sig_results.append(sig_detail)

        result["signatures"] = sig_results

        # --- Aggregate to first/primary signature ---
        if sig_results:
            primary = sig_results[0]
            result["digest_algorithm"]     = primary.get("digest_algorithm")
            result["signature_algorithm"]  = primary.get("signature_algorithm")
            result["public_key_algorithm"] = primary.get("public_key_algorithm")
            result["key_size"]             = primary.get("key_size")
            result["byte_range"]           = primary.get("byte_range")

            integrity_ok = primary.get("integrity_ok")
            if integrity_ok is True:
                result["integrity_status"] = "VERIFIED"
                result["integrity_modification_status"] = primary.get("modification_ok", "NO_UNAUTHORIZED_CHANGES")
            elif integrity_ok is False:
                result["integrity_status"] = "FAILED"
                result["integrity_modification_status"] = "MODIFIED"
            else:
                if primary.get("status") == "VALID":
                    result["integrity_status"] = "VERIFIED"
                    result["integrity_modification_status"] = "NO_UNAUTHORIZED_CHANGES"
                else:
                    result["integrity_status"] = "UNKNOWN"
                    result["integrity_modification_status"] = "UNKNOWN"

            sig_status = primary.get("status", "UNKNOWN")
            if sig_status == "INVALID" or sig_status == "CORRUPTED":
                result["integrity_status"] = "FAILED"
                result["integrity_modification_status"] = "MODIFIED"

        # Overall status
        if any_invalid:
            result["overall_status"] = "INVALID"
        elif any_unknown:
            result["overall_status"] = "UNKNOWN"
        elif overall_valid and sig_results:
            result["overall_status"] = "VALID"
        else:
            result["overall_status"] = "UNKNOWN"

        # Signature type
        result["signature_type"] = "CMS/PKCS#7"

    except ImportError as imp_err:
        logger.error("pyHanko not installed: %s", imp_err)
        result["overall_status"] = "UNSUPPORTED"
        result["error"] = f"Signature verification library unavailable: {imp_err}"
    except Exception as exc:
        logger.error("Signature verification error: %s", exc)
        result["overall_status"] = "UNKNOWN"
        result["error"] = str(exc)

    return result


# ── Helper functions ──────────────────────────────────────────────────────────

def _format_sig_algo(algo_obj: Any) -> str | None:
    """Format signature algorithm nicely."""
    if algo_obj is None:
        return None
    raw = str(algo_obj).lower()
    if "rsassa_pkcs1v15" in raw or "rsa_pkcs1" in raw or raw == "rsa":
        return "RSA-PKCS#1 v1.5"
    if "rsassa_pss" in raw or "pss" in raw:
        return "RSA-PSS"
    if "ecdsa" in raw:
        return "ECDSA"
    if "ed25519" in raw:
        return "Ed25519"
    if "ed448" in raw:
        return "Ed448"
    if "dsa" in raw:
        return "DSA"
    return str(algo_obj).upper()


def _detect_public_key_algorithm(pub_key: Any) -> str | None:
    """Detect public key algorithm from asn1crypto public key object."""
    if pub_key is None:
        return None
    try:
        algo = getattr(pub_key, "algorithm", None)
        if algo == "rsa":
            return "RSA"
        elif algo == "ec":
            return "ECDSA"
        elif algo == "dsa":
            return "DSA"
        elif algo == "ed25519":
            return "Ed25519"
        elif algo == "ed448":
            return "Ed448"
        elif algo:
            return str(algo).upper()
    except Exception:
        pass

    try:
        t = type(pub_key).__name__.upper()
        if "RSA" in t:
            return "RSA"
        if "EC" in t:
            return "ECDSA"
    except Exception:
        pass
    return None


def _get_key_size(pub_key: Any) -> int | None:
    """Extract key size in bits."""
    if pub_key is None:
        return None
    try:
        if hasattr(pub_key, "bit_size"):
            return pub_key.bit_size
        if hasattr(pub_key, "key_size"):
            return pub_key.key_size
    except Exception:
        pass
    return None


def _dn_to_str(dn: Any) -> str | None:
    """Convert an asn1crypto DistinguishedName to a readable string."""
    if dn is None:
        return None
    try:
        if hasattr(dn, "human_friendly"):
            return dn.human_friendly
    except Exception:
        pass

    try:
        parts = []
        for rdn in dn.chosen:
            for attr in rdn:
                try:
                    parts.append(f"{attr['type'].native}={attr['value'].native}")
                except Exception:
                    pass
        return ", ".join(parts) if parts else str(dn)
    except Exception:
        try:
            return str(dn)
        except Exception:
            return None
