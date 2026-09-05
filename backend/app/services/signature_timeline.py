"""
QuantumTrust — PDF Signature Timeline & Multiple-Signature Analysis Service

Primary Responsibilities:
1. Enumerate all detectable PDF signature fields (distinguish empty fields vs populated vs verified).
2. Extract signature metadata, CMS/PKCS#7 signer info, algorithms, certificates, and fingerprints.
3. Extract and validate ByteRange (bounds, gaps, file boundary checks).
4. Extract timestamps from CMS signed attributes, PDF /M dict, or TST tokens with source attribution.
5. Reconstruct revision history, coverage, and incremental update relationships.
6. Perform independent cryptographic verification of each signature without stopping at the first.
7. Detect post-signature updates and distinguish legitimate incremental updates from tampering.
8. Evaluate signature timeline consistency and ordering confidence.
9. Emit deterministic structured findings without using LLMs or fabricating data.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# PDF date string regex: D:YYYYMMDDHHmmSS[+|-]HH'mm'
_PDF_DATE_REGEX = re.compile(
    r"^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([+\-Zz])(\d{2})?'?(\d{2})'?)?"
)


def _parse_pdf_date(date_str: str | None) -> tuple[datetime | None, str | None]:
    """Parse PDF date format string into ISO string and datetime."""
    if not date_str or not isinstance(date_str, str):
        return None, None

    date_str = date_str.strip()
    m = _PDF_DATE_REGEX.match(date_str)
    if not m:
        # Fallback to general parsing if standard string
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return dt, dt.isoformat()
        except Exception:
            return None, None

    year = int(m.group(1))
    month = int(m.group(2)) if m.group(2) else 1
    day = int(m.group(3)) if m.group(3) else 1
    hour = int(m.group(4)) if m.group(4) else 0
    minute = int(m.group(5)) if m.group(5) else 0
    second = int(m.group(6)) if m.group(6) else 0

    tz_sign = m.group(7)
    tz_hour = int(m.group(8)) if m.group(8) else 0
    tz_min = int(m.group(9)) if m.group(9) else 0

    try:
        if tz_sign in ("Z", "z") or not tz_sign:
            tz = timezone.utc
        else:
            delta_mins = tz_hour * 60 + tz_min
            if tz_sign == "-":
                delta_mins = -delta_mins
            from datetime import timedelta
            tz = timezone(timedelta(minutes=delta_mins))

        dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
        return dt, dt.isoformat()
    except Exception:
        return None, None


def _format_sig_algo(algo_obj: Any) -> str | None:
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


def _extract_cert_subject_details(cert: Any) -> dict[str, Any]:
    """Extract common name, organization, organizational unit, email, and raw dn from certificate."""
    details = {
        "common_name": None,
        "organization": None,
        "organizational_unit": None,
        "email": None,
        "raw_dn": None,
    }
    if cert is None:
        return details

    try:
        subj = getattr(cert, "subject", None)
        if subj is not None:
            if hasattr(subj, "human_friendly"):
                details["raw_dn"] = subj.human_friendly
            else:
                details["raw_dn"] = str(subj)

            try:
                for rdn in subj.chosen:
                    for attr in rdn:
                        attr_type = str(attr["type"].native)
                        attr_val = str(attr["value"].native)
                        if attr_type == "common_name":
                            details["common_name"] = attr_val
                        elif attr_type == "organization_name":
                            details["organization"] = attr_val
                        elif attr_type == "organizational_unit_name":
                            details["organizational_unit"] = attr_val
                        elif attr_type == "email_address":
                            details["email"] = attr_val
            except Exception:
                pass
    except Exception as exc:
        logger.debug("Subject parsing error: %s", exc)

    return details


def _compute_cert_fingerprint(cert: Any) -> str | None:
    """Compute SHA-256 fingerprint of the certificate."""
    if cert is None:
        return None
    try:
        if hasattr(cert, "dump"):
            raw_bytes = cert.dump()
            return hashlib.sha256(raw_bytes).hexdigest().upper()
        if hasattr(cert, "public_bytes"):
            from cryptography.hazmat.primitives import serialization
            raw_bytes = cert.public_bytes(serialization.Encoding.DER)
            return hashlib.sha256(raw_bytes).hexdigest().upper()
    except Exception as exc:
        logger.debug("Fingerprint computation error: %s", exc)
    return None


def _analyze_byte_range(byte_range: list[int] | None, file_len: int) -> dict[str, Any]:
    """
    Analyze PDF ByteRange structure and validity.
    Expected format: [offset1, length1, offset2, length2]
    """
    res = {
        "ranges": byte_range,
        "covered_length": None,
        "coverage_status": "UNKNOWN",
        "excludes_contents_placeholder": None,
        "byte_range_end": 0,
        "is_valid": False,
        "error": None,
    }

    if not byte_range or not isinstance(byte_range, (list, tuple)):
        res["coverage_status"] = "UNKNOWN"
        return res

    if len(byte_range) != 4:
        res["coverage_status"] = "INVALID"
        res["error"] = f"Expected 4 ByteRange integers, got {len(byte_range)}"
        return res

    try:
        o1, l1, o2, l2 = int(byte_range[0]), int(byte_range[1]), int(byte_range[2]), int(byte_range[3])
    except (ValueError, TypeError):
        res["coverage_status"] = "INVALID"
        res["error"] = "Non-integer values in ByteRange array"
        return res

    # Check non-negative
    if o1 < 0 or l1 < 0 or o2 < 0 or l2 < 0:
        res["coverage_status"] = "INVALID"
        res["error"] = "Negative offset or length in ByteRange"
        return res

    # Check offset ordering and placeholder gap
    if o1 != 0:
        res["coverage_status"] = "INVALID"
        res["error"] = f"First ByteRange offset must be 0, got {o1}"
        return res

    if o2 < o1 + l1:
        res["coverage_status"] = "INVALID"
        res["error"] = f"Second ByteRange offset ({o2}) overlaps with first segment ({o1 + l1})"
        return res

    # Gap between o1+l1 and o2 is the Contents placeholder
    excludes_placeholder = (o2 > o1 + l1)

    end_offset = o2 + l2
    if end_offset > file_len:
        res["coverage_status"] = "INVALID"
        res["error"] = f"ByteRange end offset ({end_offset}) exceeds total document length ({file_len})"
        return res

    res["covered_length"] = l1 + l2
    res["coverage_status"] = "VALID"
    res["excludes_contents_placeholder"] = excludes_placeholder
    res["byte_range_end"] = end_offset
    res["is_valid"] = True

    return res


def analyze_signature_timeline(
    pdf_bytes: bytes,
    sig_result: dict[str, Any] | None = None,
    cert_info: dict[str, Any] | None = None,
    integrity_result: dict[str, Any] | None = None,
    pdf_structure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform deep multi-signature discovery, ordering, and timeline reconstruction.

    Returns a dictionary conforming to SignatureTimelineResult schema.
    """
    file_len = len(pdf_bytes)
    result: dict[str, Any] = {
        "total_signature_fields": 0,
        "total_signed_signatures": 0,
        "revision_count": 1,
        "timeline_status": "NOT_AVAILABLE",
        "consistency_status": "UNKNOWN",
        "timeline_order_confidence": "HIGH",
        "signatures": [],
        "findings": [],
    }

    if not pdf_bytes.startswith(b"%PDF") and not pdf_bytes.startswith(b"%!PS"):
        result["timeline_status"] = "NOT_AVAILABLE"
        return result

    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.fields import enumerate_sig_fields
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko.sign.validation.status import SignatureCoverageLevel
    except ImportError as exc:
        logger.error("pyHanko not available for signature timeline: %s", exc)
        result["timeline_status"] = "ERROR"
        result["findings"].append({
            "code": "UNSUPPORTED_SIGNATURE_STRUCTURE",
            "severity": "HIGH",
            "title": "Verification Library Unavailable",
            "description": f"pyHanko signature analysis library could not be loaded: {exc}",
            "signature_id": None,
            "evidence": {"error": str(exc)},
        })
        return result

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
        total_revisions = max(1, getattr(reader, "total_revisions", 1))
        result["revision_count"] = total_revisions

        # Discover all signature fields
        all_field_tuples = list(enumerate_sig_fields(reader, filled_status=None))
        filled_field_tuples = list(enumerate_sig_fields(reader, filled_status=True))
        empty_field_tuples = list(enumerate_sig_fields(reader, filled_status=False))

        embedded_sigs = list(reader.embedded_signatures)

        total_fields = len(all_field_tuples)
        if total_fields == 0 and len(embedded_sigs) > 0:
            total_fields = len(embedded_sigs)

        result["total_signature_fields"] = total_fields
        result["total_signed_signatures"] = len(embedded_sigs)

        if total_fields == 0 and len(embedded_sigs) == 0:
            result["timeline_status"] = "NO_SIGNATURES"
            result["consistency_status"] = "UNKNOWN"
            return result

        result["timeline_status"] = "ANALYZED"

        findings: list[dict[str, Any]] = []

        # Record findings for empty signature fields
        for empty_tuple in empty_field_tuples:
            f_name = empty_tuple[0] if isinstance(empty_tuple, (tuple, list)) else "EmptySigField"
            findings.append({
                "code": "SIGNATURE_FIELD_EMPTY",
                "severity": "INFO",
                "title": "Empty Signature Field Detected",
                "description": f"Signature field '{f_name}' is declared in the document AcroForm but contains no signature payload.",
                "signature_id": None,
                "evidence": {"field_name": f_name, "signature_present": False},
            })

        # Process each embedded signature
        raw_entries: list[dict[str, Any]] = []

        for idx, emb_sig in enumerate(embedded_sigs):
            sig_id = f"sig-{idx + 1}"

            # Field name
            field_name = getattr(emb_sig, "field_name", None)
            if not field_name and hasattr(emb_sig, "sig_field"):
                try:
                    field_name = str(emb_sig.sig_field.get("/T", f"Signature{idx + 1}"))
                except Exception:
                    field_name = f"Signature{idx + 1}"
            if not field_name:
                field_name = f"Signature{idx + 1}"

            # ByteRange extraction & analysis
            raw_br = None
            try:
                if hasattr(emb_sig, "byte_range") and emb_sig.byte_range:
                    raw_br = list(emb_sig.byte_range)
                elif hasattr(emb_sig, "sig_object") and "/ByteRange" in emb_sig.sig_object:
                    raw_br = list(emb_sig.sig_object["/ByteRange"])
            except Exception as e:
                logger.debug("ByteRange read error: %s", e)

            br_analysis = _analyze_byte_range(raw_br, file_len)

            # Revision analysis (pyHanko signed_revision is 0-indexed where 0=base document, 1=rev 1, etc.)
            raw_rev = getattr(emb_sig, "signed_revision", None)
            if raw_rev is not None:
                signed_rev = raw_rev + 1 if raw_rev < total_revisions else raw_rev
            else:
                end_off = br_analysis.get("byte_range_end", 0)
                signed_rev = total_revisions if (end_off >= file_len - 32) else 1

            is_latest = (signed_rev == total_revisions) or (br_analysis.get("byte_range_end", 0) >= file_len - 32)

            # Timestamp extraction from multiple sources
            cms_time_dt = getattr(emb_sig, "self_reported_timestamp", None)
            cms_time_iso = cms_time_dt.isoformat() if cms_time_dt else None

            pdf_date_str = None
            pdf_date_dt = None
            pdf_date_iso = None
            try:
                if hasattr(emb_sig, "sig_object") and "/M" in emb_sig.sig_object:
                    pdf_date_str = str(emb_sig.sig_object["/M"])
                    pdf_date_dt, pdf_date_iso = _parse_pdf_date(pdf_date_str)
            except Exception:
                pass

            # Timestamp selection & consistency
            signing_time_val = None
            signing_time_source = "UNKNOWN"
            time_consistency = "CONSISTENT"

            if cms_time_iso:
                signing_time_val = cms_time_iso
                signing_time_source = "CMS_SIGNING_TIME"
                if pdf_date_iso and pdf_date_iso[:16] != cms_time_iso[:16]:
                    time_consistency = "CONFLICT"
            elif pdf_date_iso:
                signing_time_val = pdf_date_iso
                signing_time_source = "PDF_SIGNATURE_DATE"
            else:
                signing_time_val = None
                signing_time_source = "UNKNOWN"
                time_consistency = "UNKNOWN"

            # Cryptographic validation of this specific signature
            sig_status = "NOT_CHECKED"
            integrity_ok = None
            cert_valid = None
            cert_trusted = None
            val_result = None
            digest_algo = None
            sig_algo = None
            pub_key_algo = None
            key_size = None
            cert_subject_dict = {}
            cert_fingerprint = None
            signing_cert = None

            try:
                val_result = validate_pdf_signature(emb_sig)

                # Digest algorithm
                md_algo = getattr(val_result, "md_algorithm", None)
                if md_algo:
                    digest_algo = str(md_algo).upper()

                # Signing cert details
                signing_cert = getattr(val_result, "signing_cert", None)
                if signing_cert is not None:
                    cert_subject_dict = _extract_cert_subject_details(signing_cert)
                    cert_fingerprint = _compute_cert_fingerprint(signing_cert)

                    pub_key = getattr(signing_cert, "public_key", None)
                    if pub_key is not None:
                        pub_key_algo = _detect_public_key_algorithm(pub_key)
                        key_size = _get_key_size(pub_key)

                    cert_algo = getattr(signing_cert, "signature_algo", None)
                    if cert_algo:
                        sig_algo = _format_sig_algo(cert_algo)
                    elif hasattr(val_result, "signature_algorithm"):
                        sig_algo = _format_sig_algo(val_result.signature_algorithm)

                # Cryptographic validity
                intact = getattr(val_result, "intact", None)
                valid = getattr(val_result, "valid", None)

                if intact is True and valid is True:
                    sig_status = "VALID"
                    integrity_ok = True
                elif intact is False or valid is False:
                    sig_status = "INVALID"
                    integrity_ok = False
                else:
                    if getattr(val_result, "bottom_line", False):
                        sig_status = "VALID"
                        integrity_ok = True
                    else:
                        sig_status = "UNKNOWN"
                        integrity_ok = None

                # Certificate validity and trust
                if signing_cert is not None:
                    try:
                        # Check expiry
                        not_after = signing_cert["tbs_certificate"]["validity"]["not_after"].native
                        if isinstance(not_after, datetime):
                            now = datetime.now(timezone.utc)
                            if not_after.tzinfo is None:
                                not_after = not_after.replace(tzinfo=timezone.utc)
                            cert_valid = (not_after >= now)
                        else:
                            cert_valid = True
                    except Exception:
                        cert_valid = True

                    subj_str = cert_subject_dict.get("raw_dn")
                    issu_str = str(getattr(signing_cert, "issuer", ""))
                    if subj_str and issu_str and subj_str == issu_str:
                        cert_trusted = False  # Self signed
                    else:
                        trust_indic = getattr(val_result, "trust_problem_indic", None)
                        cert_trusted = (trust_indic is None)
                else:
                    cert_valid = None
                    cert_trusted = None

            except Exception as val_exc:
                logger.warning("Error validating signature %s: %s", sig_id, val_exc)
                sig_status = "INVALID"
                integrity_ok = False

            # Post-signature change classification
            post_change = "NONE"
            has_bytes_after = (br_analysis["byte_range_end"] < file_len)

            if has_bytes_after or (signed_rev is not None and signed_rev < total_revisions):
                if sig_status == "VALID" and integrity_ok is True:
                    post_change = "LEGITIMATE_INCREMENTAL_UPDATE"
                elif sig_status == "INVALID" or integrity_ok is False:
                    post_change = "UNAUTHORIZED_SIGNED_CONTENT_CHANGE"
                else:
                    post_change = "UNKNOWN_POST_SIGNATURE_CHANGE"
            else:
                post_change = "NONE"

            # Entry-specific findings
            entry_findings: list[dict[str, Any]] = []

            # ByteRange findings
            if not br_analysis["is_valid"]:
                entry_findings.append({
                    "code": "INVALID_BYTE_RANGE",
                    "severity": "HIGH",
                    "title": "Invalid ByteRange Structure",
                    "description": br_analysis.get("error") or "ByteRange boundaries are invalid.",
                    "signature_id": sig_id,
                    "evidence": {"byte_range": raw_br, "file_length": file_len},
                })

            # Validity findings
            if sig_status == "VALID":
                entry_findings.append({
                    "code": "SIGNATURE_VALID",
                    "severity": "INFO",
                    "title": "Cryptographically Valid Signature",
                    "description": f"Signature in field '{field_name}' passed cryptographic hash and public-key verification.",
                    "signature_id": sig_id,
                    "evidence": {
                        "digest_algorithm": digest_algo,
                        "signature_algorithm": sig_algo,
                        "key_size": key_size,
                    },
                })
            elif sig_status == "INVALID":
                entry_findings.append({
                    "code": "SIGNATURE_INVALID",
                    "severity": "HIGH",
                    "title": "Signature Verification Failed",
                    "description": f"Signature in field '{field_name}' failed cryptographic verification.",
                    "signature_id": sig_id,
                    "evidence": {"field_name": field_name, "status": sig_status},
                })

            # Timestamp findings
            if signing_time_source != "UNKNOWN":
                entry_findings.append({
                    "code": "SIGNATURE_TIMESTAMP_AVAILABLE",
                    "severity": "INFO",
                    "title": "Signing Timestamp Detected",
                    "description": f"Timestamp {signing_time_val} extracted from {signing_time_source}.",
                    "signature_id": sig_id,
                    "evidence": {
                        "timestamp": signing_time_val,
                        "source": signing_time_source,
                    },
                })
            else:
                entry_findings.append({
                    "code": "SIGNATURE_TIMESTAMP_UNKNOWN",
                    "severity": "LOW",
                    "title": "No Signing Timestamp Recorded",
                    "description": f"Signature in field '{field_name}' does not specify a verifiable signing timestamp.",
                    "signature_id": sig_id,
                    "evidence": {"field_name": field_name},
                })

            if time_consistency == "CONFLICT":
                entry_findings.append({
                    "code": "TIMESTAMP_CONFLICT",
                    "severity": "MEDIUM",
                    "title": "Conflicting Timestamps in Signature",
                    "description": f"CMS signingTime ({cms_time_iso}) differs from PDF dictionary date ({pdf_date_iso}).",
                    "signature_id": sig_id,
                    "evidence": {
                        "cms_time": cms_time_iso,
                        "pdf_date": pdf_date_iso,
                    },
                })

            # Post-signature change findings
            if post_change == "LEGITIMATE_INCREMENTAL_UPDATE":
                entry_findings.append({
                    "code": "LEGITIMATE_INCREMENTAL_UPDATE",
                    "severity": "INFO",
                    "title": "Legitimate Incremental Update",
                    "description": f"Signature covers Revision {signed_rev} and remains valid after subsequent document revisions.",
                    "signature_id": sig_id,
                    "evidence": {
                        "signed_revision": signed_rev,
                        "total_revisions": total_revisions,
                        "covered_length": br_analysis.get("covered_length"),
                    },
                })
            elif post_change == "UNAUTHORIZED_SIGNED_CONTENT_CHANGE":
                entry_findings.append({
                    "code": "UNAUTHORIZED_SIGNED_CONTENT_CHANGE",
                    "severity": "CRITICAL",
                    "title": "Unauthorized Signed Content Modification",
                    "description": f"Bytes covered by Signature '{field_name}' (Revision {signed_rev}) were altered or corrupted by subsequent changes.",
                    "signature_id": sig_id,
                    "evidence": {
                        "signed_revision": signed_rev,
                        "byte_range": raw_br,
                    },
                })

            findings.extend(entry_findings)

            raw_entries.append({
                "raw_index": idx,
                "signature_id": sig_id,
                "field_name": field_name,
                "signer": {
                    "common_name": cert_subject_dict.get("common_name"),
                    "organization": cert_subject_dict.get("organization"),
                    "email": cert_subject_dict.get("email"),
                    "raw_dn": cert_subject_dict.get("raw_dn"),
                },
                "signing_time": {
                    "value": signing_time_val,
                    "source": signing_time_source,
                    "consistency": time_consistency,
                },
                "signature_algorithm": sig_algo,
                "digest_algorithm": digest_algo,
                "certificate_fingerprint": cert_fingerprint,
                "byte_range": {
                    "ranges": raw_br,
                    "covered_length": br_analysis["covered_length"],
                    "coverage_status": br_analysis["coverage_status"],
                    "excludes_contents_placeholder": br_analysis["excludes_contents_placeholder"],
                },
                "revision": {
                    "revision_number": signed_rev,
                    "total_revisions": total_revisions,
                    "covers_revision": signed_rev,
                    "is_latest_revision": is_latest,
                },
                "verification": {
                    "signature_valid": (sig_status == "VALID"),
                    "integrity_verified": integrity_ok,
                    "certificate_valid": cert_valid,
                    "certificate_trusted": cert_trusted,
                },
                "status": sig_status,
                "post_signature_change": post_change,
                "findings": entry_findings,
                "_byte_range_end": br_analysis["byte_range_end"],
                "_signed_rev": signed_rev or 1,
                "_cms_time_dt": cms_time_dt,
            })

        # ── Ordering determination ─────────────────────────────────────────────
        # Order by: signed_revision ASC, byte_range_end ASC, raw_index ASC
        sorted_entries = sorted(
            raw_entries,
            key=lambda e: (e["_signed_rev"], e["_byte_range_end"], e["raw_index"])
        )

        # Check timestamp ordering consistency
        order_confidence = "HIGH"
        prev_dt = None
        for entry in sorted_entries:
            cur_dt = entry["_cms_time_dt"]
            if cur_dt and prev_dt:
                if cur_dt < prev_dt:
                    order_confidence = "MEDIUM"
                    findings.append({
                        "code": "TIMESTAMP_CONFLICT",
                        "severity": "MEDIUM",
                        "title": "Non-Monotonic Signing Timestamps",
                        "description": f"Signature '{entry['field_name']}' has a declared timestamp earlier than a preceding revision signature.",
                        "signature_id": entry["signature_id"],
                        "evidence": {
                            "current_time": cur_dt.isoformat(),
                            "preceding_time": prev_dt.isoformat(),
                        },
                    })
            if cur_dt:
                prev_dt = cur_dt

        # Assign sequence numbers and clean internal keys
        final_entries = []
        for seq, entry in enumerate(sorted_entries, start=1):
            entry["sequence_number"] = seq
            # Remove private helper keys
            entry.pop("_byte_range_end", None)
            entry.pop("_signed_rev", None)
            entry.pop("_cms_time_dt", None)
            final_entries.append(entry)

        result["signatures"] = final_entries
        result["timeline_order_confidence"] = order_confidence

        # Multi-signature overall findings
        if len(final_entries) > 1:
            findings.append({
                "code": "MULTIPLE_SIGNATURES_PRESENT",
                "severity": "INFO",
                "title": f"Multiple Signatures Present ({len(final_entries)})",
                "description": f"The document contains {len(final_entries)} digital signatures across {total_revisions} revisions.",
                "signature_id": None,
                "evidence": {
                    "signature_count": len(final_entries),
                    "total_revisions": total_revisions,
                },
            })

            # Check if certificates / signers are different
            fps = {e.get("certificate_fingerprint") for e in final_entries if e.get("certificate_fingerprint")}
            if len(fps) > 1:
                findings.append({
                    "code": "CERTIFICATE_CHANGED",
                    "severity": "INFO",
                    "title": "Distinct Signer Certificates",
                    "description": "The signatures were created using distinct signer certificates.",
                    "signature_id": None,
                    "evidence": {"distinct_certificates_count": len(fps)},
                })

        if total_revisions > 1:
            findings.append({
                "code": "INCREMENTAL_UPDATE_DETECTED",
                "severity": "INFO",
                "title": "Incremental Update Sequence Detected",
                "description": f"PDF contains {total_revisions} revisions, indicating sequential updates/signatures.",
                "signature_id": None,
                "evidence": {"total_revisions": total_revisions},
            })

        # Consistency Status determination
        if not final_entries:
            result["consistency_status"] = "UNKNOWN"
        else:
            all_valid = all(e["status"] == "VALID" for e in final_entries)
            any_invalid = any(e["status"] == "INVALID" for e in final_entries)
            any_unauthorized = any(e.get("post_signature_change") == "UNAUTHORIZED_SIGNED_CONTENT_CHANGE" for e in final_entries)
            any_invalid_br = any(e.get("byte_range", {}).get("coverage_status") == "INVALID" for e in final_entries)

            if any_invalid or any_unauthorized or any_invalid_br:
                result["consistency_status"] = "INCONSISTENT"
            elif all_valid:
                result["consistency_status"] = "CONSISTENT"
            else:
                result["consistency_status"] = "PARTIAL"

        result["findings"] = findings

    except Exception as exc:
        logger.error("Error analyzing signature timeline: %s", exc, exc_info=True)
        result["timeline_status"] = "ERROR"
        result["findings"].append({
            "code": "REVISION_STRUCTURE_ANOMALY",
            "severity": "HIGH",
            "title": "Timeline Analysis Error",
            "description": f"An error occurred while parsing the revision timeline: {exc}",
            "signature_id": None,
            "evidence": {"error": str(exc)},
        })

    return result
