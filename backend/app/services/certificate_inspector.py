"""
QuantumTrust — Certificate & Public-Key Inspector Service

A production-grade inspection, validation, normalization, and explanation module
for X.509 digital certificates and public keys embedded in digitally signed documents.

Key Principles:
1. Read actual digital signatures and embedded certificates without assuming RSA or SHA-256.
2. Never request, generate, access, or expose private keys or secret material.
3. Distinguish clearly between:
   - Certificate signature algorithm vs Document digital signature algorithm vs Digest algorithm
   - Certificate validity (time-based) vs Certificate trust (PKI-based) vs Document integrity
4. Provide structured, frontend-safe normalization with evidence-based findings.
5. Apply configurable cryptographic security policies for public-key evaluation.
"""
from __future__ import annotations

import binascii
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Configuration / Cryptographic Security Policy ──────────────────────────────

class KeySecurityPolicy:
    """Configurable cryptographic security evaluation policy."""
    POLICY_NAME = "QuantumTrust Default Cryptographic Policy v1.0"
    MIN_RSA_BITS = 2048
    RECOMMENDED_RSA_BITS = 3072
    MIN_EC_BITS = 256
    ALLOWED_EC_CURVES = {
        "secp256r1", "p-256", "prime256v1",
        "secp384r1", "p-384",
        "secp521r1", "p-521",
        "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1",
    }
    APPROVED_ED_ALGORITHMS = {"ED25519", "ED448"}
    WEAK_DIGESTS_IN_CERT = {"MD2", "MD5", "SHA1", "SHA-1"}


def evaluate_key_security(
    algorithm: str | None,
    key_size: int | None,
    curve: str | None = None,
    exponent: int | None = None,
) -> dict[str, Any]:
    """
    Evaluate key strength against deterministic security policy.
    Returns { "key_strength": "ACCEPTABLE" | "WEAK" | "UNSUPPORTED" | "UNKNOWN", "policy": "...", "observations": [...] }
    """
    if not algorithm:
        return {
            "key_strength": "UNKNOWN",
            "policy": KeySecurityPolicy.POLICY_NAME,
            "observations": ["Public key algorithm could not be determined."],
        }

    algo_upper = algorithm.upper()
    observations: list[str] = []

    if algo_upper == "RSA":
        if key_size is None:
            return {
                "key_strength": "UNKNOWN",
                "policy": KeySecurityPolicy.POLICY_NAME,
                "observations": ["RSA key size could not be determined."],
            }
        if key_size < KeySecurityPolicy.MIN_RSA_BITS:
            observations.append(
                f"RSA key size of {key_size} bits is below the minimum recommended standard ({KeySecurityPolicy.MIN_RSA_BITS} bits)."
            )
            return {
                "key_strength": "WEAK",
                "policy": KeySecurityPolicy.POLICY_NAME,
                "observations": observations,
            }
        elif key_size < KeySecurityPolicy.RECOMMENDED_RSA_BITS:
            observations.append(
                f"RSA {key_size}-bit key meets standard legacy security threshold (>= {KeySecurityPolicy.MIN_RSA_BITS} bits)."
            )
        else:
            observations.append(
                f"RSA {key_size}-bit key provides strong classical cryptographic security (>= {KeySecurityPolicy.RECOMMENDED_RSA_BITS} bits)."
            )
        if exponent and exponent < 65537:
            observations.append(f"RSA public exponent {exponent} is lower than standard F4 (65537).")
        return {
            "key_strength": "ACCEPTABLE",
            "policy": KeySecurityPolicy.POLICY_NAME,
            "observations": observations,
        }

    elif algo_upper in ("EC", "ECDSA"):
        curve_norm = (curve or "").lower().replace("-", "").replace("_", "")
        if key_size and key_size < KeySecurityPolicy.MIN_EC_BITS:
            observations.append(f"Elliptic curve key size ({key_size} bits) is below minimum recommended standard (256 bits).")
            return {
                "key_strength": "WEAK",
                "policy": KeySecurityPolicy.POLICY_NAME,
                "observations": observations,
            }
        observations.append(f"Elliptic Curve key using curve '{curve or 'unknown'}' ({key_size or '?'} bits) meets modern cryptographic standards.")
        return {
            "key_strength": "ACCEPTABLE",
            "policy": KeySecurityPolicy.POLICY_NAME,
            "observations": observations,
        }

    elif algo_upper in KeySecurityPolicy.APPROVED_ED_ALGORITHMS:
        observations.append(f"Edwards-curve algorithm ({algo_upper}) provides state-of-the-art classical security and side-channel resilience.")
        return {
            "key_strength": "ACCEPTABLE",
            "policy": KeySecurityPolicy.POLICY_NAME,
            "observations": observations,
        }

    elif algo_upper == "DSA":
        observations.append("Legacy Digital Signature Algorithm (DSA) is deprecated under current cryptographic security standards.")
        return {
            "key_strength": "WEAK",
            "policy": KeySecurityPolicy.POLICY_NAME,
            "observations": observations,
        }

    else:
        observations.append(f"Algorithm '{algorithm}' is not recognized under current security evaluation policy.")
        return {
            "key_strength": "UNSUPPORTED",
            "policy": KeySecurityPolicy.POLICY_NAME,
            "observations": observations,
        }


# ── Inspection Entry Point ───────────────────────────────────────────────────

def inspect_certificate(
    cert_source: Any,
    all_certs: list[Any] | None = None,
    document_signature_algo: str | None = None,
    document_digest_algo: str | None = None,
) -> dict[str, Any]:
    """
    Comprehensive X.509 Certificate and Public-Key inspection.

    cert_source can be:
      - pyHanko / asn1crypto.x509.Certificate
      - cryptography.x509.Certificate
      - bytes (DER-encoded X.509 certificate)
      - None

    all_certs: optional list of additional embedded certificates (for chain analysis)
    document_signature_algo: document digital signature algorithm (distinct from cert sig algo)
    document_digest_algo: document digest algorithm

    Returns frontend-safe structured inspection dictionary.
    """
    if cert_source is None:
        return {
            "status": "NOT_AVAILABLE",
            "reason": "No embedded signer certificate was found in the digital signature.",
            "certificate": None,
            "public_key": None,
            "validity": {
                "status": "NOT_CHECKED",
                "not_before": None,
                "not_after": None,
            },
            "trust": {
                "status": "NOT_CHECKED",
                "reason": "No certificate available to evaluate trust.",
            },
            "fingerprint": None,
            "chain": [],
            "extensions": [],
            "security_assessment": {
                "key_strength": "UNKNOWN",
                "policy": KeySecurityPolicy.POLICY_NAME,
                "observations": ["No certificate available."],
            },
            "findings": [
                {
                    "code": "CERTIFICATE_NOT_FOUND",
                    "severity": "HIGH",
                    "title": "Signer certificate not found",
                    "description": "The digital signature does not contain an embedded X.509 signer certificate.",
                }
            ],
        }

    # Normalize primary cert to cryptography.x509.Certificate or parsed dict
    parsed_cert = _load_and_parse_certificate(cert_source)
    if parsed_cert is None:
        return {
            "status": "EXTRACTION_FAILED",
            "reason": "Failed to parse the embedded certificate structure.",
            "certificate": None,
            "public_key": None,
            "validity": {"status": "NOT_CHECKED", "not_before": None, "not_after": None},
            "trust": {"status": "UNKNOWN", "reason": "Malformed certificate data."},
            "fingerprint": None,
            "chain": [],
            "extensions": [],
            "security_assessment": {
                "key_strength": "UNKNOWN",
                "policy": KeySecurityPolicy.POLICY_NAME,
                "observations": ["Certificate structure could not be decoded."],
            },
            "findings": [
                {
                    "code": "CERTIFICATE_EXTRACTION_FAILED",
                    "severity": "HIGH",
                    "title": "Certificate parsing failed",
                    "description": "The embedded certificate structure is malformed or corrupted.",
                }
            ],
        }

    # Certificate validity check (timezone-aware)
    validity_info = _evaluate_validity(parsed_cert.get("not_valid_before"), parsed_cert.get("not_valid_after"))

    # Public key inspection
    public_key_info = parsed_cert.get("public_key") or {
        "algorithm": "UNKNOWN",
        "key_size": None,
        "curve": None,
        "exponent": None,
    }

    # Key security assessment
    sec_assessment = evaluate_key_security(
        algorithm=public_key_info.get("algorithm"),
        key_size=public_key_info.get("key_size"),
        curve=public_key_info.get("curve"),
        exponent=public_key_info.get("exponent"),
    )

    # Trust evaluation
    is_self_signed = parsed_cert.get("is_self_signed", False)
    trust_info = _evaluate_trust(validity_info, is_self_signed)

    # Certificate chain resolution
    chain = _resolve_certificate_chain(parsed_cert, all_certs)

    # Security findings compilation
    findings = _generate_findings(
        parsed_cert=parsed_cert,
        validity_info=validity_info,
        trust_info=trust_info,
        sec_assessment=sec_assessment,
        chain=chain,
        doc_sig_algo=document_signature_algo,
        doc_digest_algo=document_digest_algo,
    )

    # Compile final structured response
    return {
        "status": "SUCCESS",
        "certificate": {
            "version": parsed_cert.get("version"),
            "serial_number": parsed_cert.get("serial_number"),
            "subject": parsed_cert.get("subject"),
            "issuer": parsed_cert.get("issuer"),
            "signature_algorithm": parsed_cert.get("signature_algorithm"),
            "is_self_signed": is_self_signed,
        },
        "public_key": public_key_info,
        "validity": validity_info,
        "trust": trust_info,
        "fingerprint": parsed_cert.get("fingerprint"),
        "chain": chain,
        "extensions": parsed_cert.get("extensions", []),
        "security_assessment": sec_assessment,
        "findings": findings,
    }


# ── Internal Certificate Parser ───────────────────────────────────────────────

def _load_and_parse_certificate(cert_obj: Any) -> dict[str, Any] | None:
    """Extract and parse X.509 attributes using cryptography or asn1crypto."""
    from cryptography import x509

    # Case 1: Already cryptography.x509.Certificate
    if isinstance(cert_obj, x509.Certificate):
        return _parse_cryptography_x509(cert_obj)

    # Case 2: DER bytes or bytearray
    if isinstance(cert_obj, (bytes, bytearray)):
        try:
            crypto_cert = x509.load_der_x509_certificate(cert_obj)
            return _parse_cryptography_x509(crypto_cert)
        except Exception:
            try:
                crypto_cert = x509.load_pem_x509_certificate(cert_obj)
                return _parse_cryptography_x509(crypto_cert)
            except Exception:
                pass

    # Case 3: asn1crypto certificate (e.g. from pyHanko)
    try:
        if hasattr(cert_obj, "dump"):
            der_bytes = cert_obj.dump()
            crypto_cert = x509.load_der_x509_certificate(der_bytes)
            return _parse_cryptography_x509(crypto_cert)
    except Exception:
        pass

    # Fallback to direct asn1crypto parsing if cryptography load failed
    try:
        return _parse_asn1crypto_direct(cert_obj)
    except Exception as exc:
        logger.error("Failed to parse certificate object: %s", exc)
        return None


def _parse_cryptography_x509(cert: Any) -> dict[str, Any]:
    """Parse a cryptography.x509.Certificate instance into clean normalized dictionary."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

    # 1. Version
    try:
        version = cert.version.value + 1 if hasattr(cert.version, "value") else 3
    except Exception:
        version = 3

    # 2. Serial Number
    try:
        serial_hex = format(cert.serial_number, "X")
        if len(serial_hex) % 2 != 0:
            serial_hex = "0" + serial_hex
        # Format as colon-separated hex bytes or upper hex
        serial_formatted = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
    except Exception:
        serial_formatted = str(getattr(cert, "serial_number", "UNKNOWN"))

    # 3. Subject and Issuer
    subject_dict = _extract_name_dict(cert.subject)
    issuer_dict = _extract_name_dict(cert.issuer)
    is_self_signed = (cert.subject == cert.issuer)

    # 4. Validity Timestamps (timezone-aware UTC)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older cryptography versions
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    # 5. Certificate Signature Algorithm
    try:
        sig_algo = cert.signature_algorithm_oid._name
    except Exception:
        try:
            sig_algo = cert.signature_hash_algorithm.name.upper() + "-RSA"
        except Exception:
            sig_algo = "UNKNOWN"

    # 6. SHA-256 Fingerprint
    try:
        fp_bytes = cert.fingerprint(hashes.SHA256())
        fp_hex = binascii.hexlify(fp_bytes).decode("ascii").upper()
        fp_formatted = ":".join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))
        fingerprint = {
            "algorithm": "SHA-256",
            "value": fp_formatted,
        }
    except Exception:
        fingerprint = {"algorithm": "SHA-256", "value": "UNKNOWN"}

    # 7. Public Key Extraction
    pub_key_info = _extract_public_key(cert.public_key())

    # 8. X.509 Extensions
    extensions = _extract_extensions(cert.extensions)

    return {
        "version": version,
        "serial_number": serial_formatted,
        "subject": subject_dict,
        "issuer": issuer_dict,
        "not_valid_before": not_before,
        "not_valid_after": not_after,
        "signature_algorithm": sig_algo,
        "is_self_signed": is_self_signed,
        "fingerprint": fingerprint,
        "public_key": pub_key_info,
        "extensions": extensions,
        "_raw_cert": cert,
    }


def _extract_name_dict(name: Any) -> dict[str, str | None]:
    """Extract standard Distinguished Name components."""
    from cryptography.x509.oid import NameOID

    res: dict[str, str | None] = {
        "common_name": None,
        "organization": None,
        "organizational_unit": None,
        "country": None,
        "state": None,
        "locality": None,
        "raw_dn": None,
    }

    try:
        res["raw_dn"] = name.rfc4514_string()
    except Exception:
        pass

    try:
        cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            res["common_name"] = str(cns[0].value)
    except Exception:
        pass

    try:
        orgs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if orgs:
            res["organization"] = str(orgs[0].value)
    except Exception:
        pass

    try:
        ous = name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if ous:
            res["organizational_unit"] = str(ous[0].value)
    except Exception:
        pass

    try:
        countries = name.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        if countries:
            res["country"] = str(countries[0].value)
    except Exception:
        pass

    try:
        states = name.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
        if states:
            res["state"] = str(states[0].value)
    except Exception:
        pass

    try:
        localities = name.get_attributes_for_oid(NameOID.LOCALITY_NAME)
        if localities:
            res["locality"] = str(localities[0].value)
    except Exception:
        pass

    return res


def _extract_public_key(pub_key: Any) -> dict[str, Any]:
    """Inspect and extract public key details without exposing secret material."""
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

    if isinstance(pub_key, rsa.RSAPublicKey):
        numbers = pub_key.public_numbers()
        return {
            "algorithm": "RSA",
            "key_size": pub_key.key_size,
            "curve": None,
            "exponent": numbers.e,
        }

    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return {
            "algorithm": "EC",
            "key_size": pub_key.key_size,
            "curve": pub_key.curve.name,
            "exponent": None,
        }

    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        return {
            "algorithm": "Ed25519",
            "key_size": 256,
            "curve": "Ed25519",
            "exponent": None,
        }

    elif isinstance(pub_key, ed448.Ed448PublicKey):
        return {
            "algorithm": "Ed448",
            "key_size": 448,
            "curve": "Ed448",
            "exponent": None,
        }

    elif isinstance(pub_key, dsa.DSAPublicKey):
        return {
            "algorithm": "DSA",
            "key_size": pub_key.key_size,
            "curve": None,
            "exponent": None,
        }

    # Fallback inspection by introspection
    algo_name = type(pub_key).__name__.replace("PublicKey", "").upper()
    key_size = getattr(pub_key, "key_size", None)
    curve_name = getattr(getattr(pub_key, "curve", None), "name", None)

    return {
        "algorithm": algo_name or "UNKNOWN",
        "key_size": key_size,
        "curve": curve_name,
        "exponent": None,
    }


def _extract_extensions(extensions: Any) -> list[dict[str, Any]]:
    """Parse and normalize critical X.509 extensions into readable records."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    normalized: list[dict[str, Any]] = []

    for ext in extensions:
        oid = ext.oid
        critical = ext.critical
        name = oid._name if hasattr(oid, "_name") else oid.dotted_string
        if name in ("subjectAltName", "issuerAltName"):
            name = "subjectAlternativeName" if name == "subjectAltName" else "issuerAlternativeName"
        val_str = ""

        try:
            val = ext.value
            if isinstance(val, x509.KeyUsage):
                usages = []
                if val.digital_signature:
                    usages.append("Digital Signature")
                if val.content_commitment:
                    usages.append("Non-Repudiation (Content Commitment)")
                if val.key_encipherment:
                    usages.append("Key Encipherment")
                if val.data_encipherment:
                    usages.append("Data Encipherment")
                if val.key_agreement:
                    usages.append("Key Agreement")
                if val.key_cert_sign:
                    usages.append("Certificate Signing")
                if val.crl_sign:
                    usages.append("CRL Signing")
                val_str = ", ".join(usages) if usages else "None"

            elif isinstance(val, x509.ExtendedKeyUsage):
                eku_list = []
                for e in val:
                    eku_list.append(e._name if hasattr(e, "_name") else e.dotted_string)
                val_str = ", ".join(eku_list)

            elif isinstance(val, x509.BasicConstraints):
                val_str = f"CA: {val.ca}, Path Length: {val.path_length}"

            elif isinstance(val, x509.SubjectAlternativeName):
                sans = []
                for name_item in val:
                    sans.append(f"{type(name_item).__name__}:{name_item.value}")
                val_str = ", ".join(sans)

            elif isinstance(val, x509.AuthorityKeyIdentifier):
                if val.key_identifier:
                    key_id_hex = binascii.hexlify(val.key_identifier).decode("ascii").upper()
                    val_str = ":".join(key_id_hex[i:i+2] for i in range(0, len(key_id_hex), 2))
                else:
                    val_str = "Present"

            elif isinstance(val, x509.SubjectKeyIdentifier):
                key_id_hex = binascii.hexlify(val.digest).decode("ascii").upper()
                val_str = ":".join(key_id_hex[i:i+2] for i in range(0, len(key_id_hex), 2))

            else:
                val_str = str(val)

        except Exception as e:
            val_str = f"Extension data parsed ({e})"

        normalized.append({
            "name": name,
            "critical": critical,
            "value": val_str,
        })

    return normalized


def _parse_asn1crypto_direct(cert: Any) -> dict[str, Any] | None:
    """Fallback parser for direct asn1crypto objects if cryptography fails."""
    try:
        tbs = cert["tbs_certificate"]
        version = int(tbs["version"].native) + 1 if "version" in tbs else 3
        serial = format(int(tbs["serial_number"].native), "X")
        if len(serial) % 2 != 0:
            serial = "0" + serial
        serial_formatted = ":".join(serial[i:i+2] for i in range(0, len(serial), 2))

        validity = tbs["validity"]
        not_before = validity["not_before"].native
        not_after = validity["not_after"].native

        if not hasattr(not_before, "utcoffset") or not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not hasattr(not_after, "utcoffset") or not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

        subj_str = str(cert.subject.human_friendly) if hasattr(cert.subject, "human_friendly") else str(cert.subject)
        issu_str = str(cert.issuer.human_friendly) if hasattr(cert.issuer, "human_friendly") else str(cert.issuer)
        is_self_signed = (cert.subject.hashable == cert.issuer.hashable)

        # SHA-256 fingerprint
        der_bytes = cert.dump()
        fp_hex = hashlib.sha256(der_bytes).hexdigest().upper()
        fp_formatted = ":".join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))

        pub_key = cert.public_key
        algo_name = getattr(pub_key, "algorithm", "UNKNOWN").upper()
        key_size = getattr(pub_key, "bit_size", None)

        return {
            "version": version,
            "serial_number": serial_formatted,
            "subject": {"common_name": subj_str, "organization": None, "raw_dn": subj_str},
            "issuer": {"common_name": issu_str, "organization": None, "raw_dn": issu_str},
            "not_valid_before": not_before,
            "not_valid_after": not_after,
            "signature_algorithm": str(cert.signature_algo).upper(),
            "is_self_signed": is_self_signed,
            "fingerprint": {"algorithm": "SHA-256", "value": fp_formatted},
            "public_key": {"algorithm": algo_name, "key_size": key_size, "curve": None, "exponent": None},
            "extensions": [],
            "_raw_cert": cert,
        }
    except Exception as exc:
        logger.error("asn1crypto direct parsing failed: %s", exc)
        return None


# ── Validity & Trust Evaluators ───────────────────────────────────────────────

def _evaluate_validity(not_before: datetime | None, not_after: datetime | None) -> dict[str, Any]:
    """Check certificate validity against current UTC time."""
    now = datetime.now(timezone.utc)
    not_before_iso = not_before.isoformat() if not_before else None
    not_after_iso = not_after.isoformat() if not_after else None

    if not not_before or not not_after:
        return {
            "status": "UNKNOWN",
            "not_before": not_before_iso,
            "not_after": not_after_iso,
        }

    # Ensure timezone awareness
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    if now < not_before:
        status = "NOT_YET_VALID"
    elif now > not_after:
        status = "EXPIRED"
    else:
        status = "VALID"

    return {
        "status": status,
        "not_before": not_before_iso,
        "not_after": not_after_iso,
    }


def _evaluate_trust(validity_info: dict[str, Any], is_self_signed: bool) -> dict[str, Any]:
    """
    Evaluate certificate trust independently from cryptographic validity.
    Distinguishes:
      - TRUSTED (if validated against trusted root store)
      - SELF_SIGNED (self-issued certificate)
      - UNTRUSTED / UNKNOWN (no configured PKI root chain available)
    """
    val_status = validity_info.get("status")

    if val_status == "EXPIRED":
        return {
            "status": "UNTRUSTED",
            "reason": "The certificate validity period has expired.",
            "is_trusted": False,
        }

    if val_status == "NOT_YET_VALID":
        return {
            "status": "UNTRUSTED",
            "reason": "The certificate is not yet valid.",
            "is_trusted": False,
        }

    if is_self_signed:
        return {
            "status": "SELF_SIGNED",
            "reason": "The certificate is self-signed (Subject matches Issuer) without a trusted CA chain.",
            "is_trusted": False,
        }

    # If full external PKI trust store is not configured, explicitly report UNKNOWN
    return {
        "status": "UNKNOWN",
        "reason": "Certificate parsed successfully; external PKI trust store evaluation is not configured.",
        "is_trusted": False,
    }


# ── Certificate Chain Resolution ──────────────────────────────────────────────

def _resolve_certificate_chain(
    signer_cert_parsed: dict[str, Any],
    all_certs: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Build ordered certificate chain from available embedded certificates:
    Signer -> Intermediate CA(s) -> Root CA.
    """
    chain: list[dict[str, Any]] = []

    # Add Signer
    signer_subj = signer_cert_parsed.get("subject", {})
    signer_issu = signer_cert_parsed.get("issuer", {})
    signer_cn = signer_subj.get("common_name") or signer_subj.get("raw_dn") or "Signer Certificate"
    signer_issuer_cn = signer_issu.get("common_name") or signer_issu.get("raw_dn") or "Unknown Issuer"

    chain.append({
        "role": "SIGNER",
        "chain_position": 0,
        "subject": signer_cn,
        "issuer": signer_issuer_cn,
        "serial_number": signer_cert_parsed.get("serial_number"),
        "validity": signer_cert_parsed.get("not_valid_after").isoformat() if signer_cert_parsed.get("not_valid_after") else None,
        "is_self_signed": signer_cert_parsed.get("is_self_signed", False),
    })

    if not all_certs or len(all_certs) <= 1:
        return chain

    # Parse all other certificates
    other_parsed = []
    for c in all_certs:
        p = _load_and_parse_certificate(c)
        if p and p.get("serial_number") != signer_cert_parsed.get("serial_number"):
            other_parsed.append(p)

    # Simple chain walk by matching Issuer -> Subject
    current_issuer = signer_issu.get("raw_dn") or signer_issu.get("common_name")
    pos = 1

    visited_serials = {signer_cert_parsed.get("serial_number")}

    while current_issuer and other_parsed:
        match_found = None
        for cand in other_parsed:
            cand_serial = cand.get("serial_number")
            if cand_serial in visited_serials:
                continue
            cand_subj = cand.get("subject", {})
            cand_subj_str = cand_subj.get("raw_dn") or cand_subj.get("common_name")
            if cand_subj_str == current_issuer:
                match_found = cand
                break

        if not match_found:
            # Add any remaining unlinked certs as INTERMEDIATE or UNKNOWN
            for remaining in other_parsed:
                rem_serial = remaining.get("serial_number")
                if rem_serial not in visited_serials:
                    visited_serials.add(rem_serial)
                    rem_subj = remaining.get("subject", {})
                    rem_issu = remaining.get("issuer", {})
                    rem_is_ca = remaining.get("is_self_signed", False)
                    chain.append({
                        "role": "ROOT_CA" if rem_is_ca else "INTERMEDIATE_CA",
                        "chain_position": pos,
                        "subject": rem_subj.get("common_name") or rem_subj.get("raw_dn") or "CA Certificate",
                        "issuer": rem_issu.get("common_name") or rem_issu.get("raw_dn") or "CA Issuer",
                        "serial_number": rem_serial,
                        "validity": remaining.get("not_valid_after").isoformat() if remaining.get("not_valid_after") else None,
                        "is_self_signed": rem_is_ca,
                    })
                    pos += 1
            break

        visited_serials.add(match_found.get("serial_number"))
        m_subj = match_found.get("subject", {})
        m_issu = match_found.get("issuer", {})
        is_root = match_found.get("is_self_signed", False) or (
            m_subj.get("raw_dn") == m_issu.get("raw_dn")
        )

        chain.append({
            "role": "ROOT_CA" if is_root else "INTERMEDIATE_CA",
            "chain_position": pos,
            "subject": m_subj.get("common_name") or m_subj.get("raw_dn") or "CA Certificate",
            "issuer": m_issu.get("common_name") or m_issu.get("raw_dn") or "CA Issuer",
            "serial_number": match_found.get("serial_number"),
            "validity": match_found.get("not_valid_after").isoformat() if match_found.get("not_valid_after") else None,
            "is_self_signed": match_found.get("is_self_signed", False),
        })
        pos += 1

        if is_root:
            break
        current_issuer = m_issu.get("raw_dn") or m_issu.get("common_name")

    return chain


# ── Security Findings Generator ───────────────────────────────────────────────

def _generate_findings(
    parsed_cert: dict[str, Any],
    validity_info: dict[str, Any],
    trust_info: dict[str, Any],
    sec_assessment: dict[str, Any],
    chain: list[dict[str, Any]],
    doc_sig_algo: str | None = None,
    doc_digest_algo: str | None = None,
) -> list[dict[str, Any]]:
    """
    Generate evidence-based structured security findings.
    Only emits a finding when the corresponding evidence actually exists.
    """
    findings: list[dict[str, Any]] = []

    val_status = validity_info.get("status")
    if val_status == "EXPIRED":
        findings.append({
            "code": "CERTIFICATE_EXPIRED",
            "severity": "HIGH",
            "title": "Signer certificate has expired",
            "description": f"The signer certificate expired on {validity_info.get('not_after')}.",
        })
    elif val_status == "NOT_YET_VALID":
        findings.append({
            "code": "CERTIFICATE_NOT_YET_VALID",
            "severity": "HIGH",
            "title": "Certificate is not yet valid",
            "description": f"The certificate validity period begins in the future at {validity_info.get('not_before')}.",
        })

    # Trust findings
    trust_status = trust_info.get("status")
    if trust_status == "SELF_SIGNED":
        findings.append({
            "code": "CERTIFICATE_SELF_SIGNED",
            "severity": "MEDIUM",
            "title": "Self-signed certificate detected",
            "description": "The certificate is signed by its own subject key and has not been issued by an established Certificate Authority.",
        })
    elif trust_status == "UNTRUSTED":
        findings.append({
            "code": "CERTIFICATE_UNTRUSTED",
            "severity": "MEDIUM",
            "title": "Certificate trust could not be established",
            "description": trust_info.get("reason", "The certificate is not verified against a trusted trust store."),
        })

    # Weak public key finding
    if sec_assessment.get("key_strength") == "WEAK":
        findings.append({
            "code": "WEAK_PUBLIC_KEY",
            "severity": "HIGH",
            "title": "Weak or deprecated public key",
            "description": " ".join(sec_assessment.get("observations", [])),
        })
    elif sec_assessment.get("key_strength") == "UNSUPPORTED":
        findings.append({
            "code": "UNSUPPORTED_PUBLIC_KEY_ALGORITHM",
            "severity": "MEDIUM",
            "title": "Unsupported public key algorithm",
            "description": " ".join(sec_assessment.get("observations", [])),
        })

    # Certificate signature algorithm strength
    cert_sig_algo = (parsed_cert.get("signature_algorithm") or "").upper()
    if any(weak in cert_sig_algo for weak in KeySecurityPolicy.WEAK_DIGESTS_IN_CERT):
        findings.append({
            "code": "UNSUPPORTED_CERTIFICATE_ALGORITHM",
            "severity": "HIGH",
            "title": "Weak certificate signature algorithm",
            "description": f"The certificate was signed using a cryptographically compromised hash algorithm ({cert_sig_algo}).",
        })

    # Extensions / Key Usage findings
    extensions = parsed_cert.get("extensions", [])
    ku_ext = next((e for e in extensions if "keyusage" in e.get("name", "").lower().replace(" ", "")), None)
    if ku_ext:
        ku_val = ku_ext.get("value", "")
        if "Digital Signature" not in ku_val and "Non-Repudiation" not in ku_val:
            findings.append({
                "code": "MISSING_KEY_USAGE",
                "severity": "MEDIUM",
                "title": "Missing document signing key usage",
                "description": "The certificate's Key Usage extension does not explicitly authorize Digital Signature or Non-Repudiation.",
            })

    # Certificate chain incomplete
    if len(chain) == 1 and not parsed_cert.get("is_self_signed", False):
        findings.append({
            "code": "CERTIFICATE_CHAIN_INCOMPLETE",
            "severity": "LOW",
            "title": "Certificate chain is incomplete",
            "description": "No intermediate or root CA certificates are embedded in the signature container.",
        })

    return findings
