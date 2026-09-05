"""
Unit & Integration Tests for QuantumTrust Explainable Verification Engine

Verifies complete format-aware, deterministic, rule-based verdict explanation generation
covering all prompt test cases (1–21+), cross-format tests, anti-fabrication rules,
and real-file end-to-end verification.
"""
import unittest
from pathlib import Path
from app.schemas.analysis import (
    DecisionFactor,
    EvidenceItem,
    ExplanationResult,
    VerificationStep,
)
from app.services.explainable_verification import (
    VerificationEvidence,
    StepStatus,
    EvidenceStatus,
    EvidenceCategory,
    ConfidenceLevel,
    generate_explanation,
    generate_verdict_explanation,
    extract_evidence_from_analysis,
)


class TestExplainableVerificationEngine(unittest.TestCase):
    """Comprehensive test suite for Explainable Verification Engine."""

    def test_01_valid_signed_document_authentic(self):
        """Case 1: Valid signed document -> AUTHENTIC explanation with HIGH confidence."""
        evidence = VerificationEvidence(
            file_type="PDF",
            filename="invoice_signed.pdf",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PSS",
            public_key_algorithm="RSA",
            public_key_size=2048,
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=True,
            certificate_expired=False,
            byte_range_present=True,
            byte_range_valid=True,
            structural_anomalies=[],
            detected_threats=[],
            threat_score=0,
            threat_level="LOW",
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")

        self.assertIsInstance(res, ExplanationResult)
        self.assertEqual(res.verdict, "AUTHENTIC")
        self.assertEqual(res.confidence, ConfidenceLevel.HIGH.value)
        self.assertIn("AUTHENTIC", res.summary)
        self.assertIn("successfully verified", res.final_reason.lower())
        self.assertIn("SHA-256", res.final_reason)
        self.assertIn("RSA-PSS", res.final_reason)

        # Trace check
        step_ids = [s.step_id for s in res.verification_steps]
        self.assertIn("file_identification", step_ids)
        self.assertIn("sig_presence", step_ids)
        self.assertIn("algo_detection", step_ids)
        self.assertIn("crypto_signature", step_ids)
        self.assertIn("content_integrity", step_ids)
        self.assertIn("cert_validation", step_ids)
        self.assertIn("final_verdict", step_ids)

        sig_step = next(s for s in res.verification_steps if s.step_id == "crypto_signature")
        self.assertEqual(sig_step.status, StepStatus.PASS.value)

        integ_step = next(s for s in res.verification_steps if s.step_id == "content_integrity")
        self.assertEqual(integ_step.status, StepStatus.PASS.value)

        self.assertEqual(len(res.failed_checks), 0)
        self.assertTrue(len(res.passed_checks) >= 4)
        self.assertEqual(len(res.why_not_authentic), 0)

    def test_02_tampered_signed_document_tampered(self):
        """Case 2: Tampered signed document -> TAMPERED verdict with localized or unlocalized evidence."""
        evidence = VerificationEvidence(
            file_type="PDF",
            filename="contract_tampered.pdf",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PKCS#1 v1.5",
            public_key_algorithm="RSA",
            public_key_size=2048,
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=True,
            byte_range_present=True,
            byte_range_valid=False,
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "PAGE_LEVEL",
                "comparison_source": "EARLIER_SIGNED_REVISION",
                "affected_items": [
                    {"location": "Page 3", "location_type": "PAGE", "change_type": "TEXT_CHANGED", "evidence": ["Font stream mismatch on page 3"]}
                ]
            },
            threat_score=90,
            threat_level="CRITICAL",
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertEqual(res.verdict, "TAMPERED")
        self.assertEqual(res.confidence, ConfidenceLevel.HIGH.value)
        self.assertIn("TAMPERED", res.summary)
        self.assertIn("failed", res.final_reason.lower())
        self.assertIn("Page 3", res.summary)

        # Ensure Why Not Authentic lists failures
        self.assertTrue(len(res.why_not_authentic) >= 1)
        all_reasons = " ".join(res.why_not_authentic).lower()
        self.assertIn("signature", all_reasons)
        self.assertIn("integrity", all_reasons)

        failed_codes = [f.code for f in res.failed_checks]
        self.assertIn("CRYPTO_SIG_INVALID", failed_codes)
        self.assertIn("INTEGRITY_FAILED", failed_codes)

        # Check decision factors
        factors = {df.factor: df for df in res.decision_factors}
        self.assertIn("SIGNATURE_VERIFICATION", factors)
        self.assertEqual(factors["SIGNATURE_VERIFICATION"].status, "FAIL")

    def test_03_suspicious_certificate_warnings(self):
        """Case 3: Valid crypto signature with self-signed certificate -> SUSPICIOUS without claiming malicious."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PSS",
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=False,
            certificate_expired=False,
            byte_range_present=True,
            byte_range_valid=True,
            threat_score=35,
            threat_level="MEDIUM",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        self.assertEqual(res.verdict, "SUSPICIOUS")
        self.assertIn("SUSPICIOUS", res.summary)
        self.assertNotIn("malicious", res.final_reason.lower())

        cert_step = next(s for s in res.verification_steps if s.step_id == "cert_validation")
        self.assertEqual(cert_step.status, StepStatus.WARNING.value)

    def test_04_expired_certificate_suspicious(self):
        """Case 4: Expired certificate -> explains expiration clearly, doesn't conflate with integrity."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PSS",
            certificate_present=True,
            certificate_valid=False,
            certificate_trusted=False,
            certificate_expired=True,
            byte_range_present=True,
            byte_range_valid=True,
            threat_score=40,
            threat_level="MEDIUM",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        self.assertIn("expired", res.final_reason.lower())
        self.assertTrue(any("expired" in w.lower() for w in res.why_not_authentic))

        # Check Decision Factor
        df = next((d for d in res.decision_factors if d.factor == "CERTIFICATE_VALIDITY"), None)
        self.assertIsNotNone(df)
        self.assertEqual(df.status, "WARNING")

    def test_05_unknown_certificate_trust_not_fail(self):
        """Case 5: Unknown certificate trust remains warning/disclosure, never converted to FAIL or malicious."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            certificate_present=True,
            certificate_valid=None,
            certificate_trusted=None,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PSS",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        cert_item = next((e for e in res.evidence if e.code in ("CERT_PARSED", "CERT_UNTRUSTED", "CERT_ABSENT")), None)
        self.assertIsNotNone(cert_item)
        self.assertNotEqual(cert_item.status, EvidenceStatus.FAIL.value)

    def test_06_multiple_signatures_timeline(self):
        """Case 6: Multiple signatures -> explained as timeline revisions, never as tampering."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=2,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA",
            signature_timeline={
                "status": "AVAILABLE",
                "format": "PDF",
                "signature_count": 2,
                "total_revisions": 2,
                "consistency_status": "CONSISTENT",
                "chronology_confidence": "HIGH",
                "events": [
                    {"signature_id": "sig-1", "sequence": 1, "status": "VALID", "field_name": "Sig1", "revision": {"covers_revision": 1}},
                    {"signature_id": "sig-2", "sequence": 2, "status": "VALID", "field_name": "Sig2", "revision": {"covers_revision": 2}},
                ]
            }
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")

        self.assertEqual(res.verdict, "AUTHENTIC")
        tl_step = next(s for s in res.verification_steps if s.step_id == "signature_timeline")
        self.assertEqual(tl_step.status, StepStatus.PASS.value)
        self.assertIn("2 signatures detected", tl_step.explanation)
        self.assertNotIn("tamper", tl_step.explanation.lower())

    def test_07_legitimate_incremental_update_not_tampered(self):
        """Case 7: Legitimate incremental update (PERMITTED_CHANGES) is recognized as authentic."""
        evidence_dict_sig = {
            "present": True,
            "count": 1,
            "overall_status": "VALID",
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "RSA",
            "byte_range": [0, 1000, 1500, 500],
        }
        evidence_dict_integ = {
            "integrity_status": "PERMITTED_CHANGES",
            "modification_status": "PERMITTED_CHANGES",
            "byte_range": [0, 1000, 1500, 500],
        }
        cert_info = {"subject": "Signer A", "trust_status": "TRUSTED", "is_expired": False}

        evidence = extract_evidence_from_analysis(
            sig_result=evidence_dict_sig,
            cert_info=cert_info,
            integrity_result=evidence_dict_integ,
            pdf_structure={"suspicious_signals": []},
            dup_result={"is_duplicate": False},
            threat_result={"threat_score": 0, "threat_level": "LOW", "detected_threats": []},
        )

        self.assertTrue(evidence.integrity_verified)
        self.assertFalse(evidence.signed_content_modified)

        res = generate_explanation(evidence, verdict="AUTHENTIC")
        integ_step = next(s for s in res.verification_steps if s.step_id == "content_integrity")
        self.assertEqual(integ_step.status, StepStatus.PASS.value)
        self.assertEqual(len(res.failed_checks), 0)

    def test_08_invalid_signature_tampered(self):
        """Case 8: Invalid cryptographic signature -> classified as TAMPERED with clear rationale."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PSS",
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertEqual(res.verdict, "TAMPERED")
        self.assertIn("failed", res.final_reason.lower())
        self.assertTrue(any("signature" in r.lower() for r in res.why_not_authentic))

    def test_09_invalid_byte_range_integrity_failure(self):
        """Case 9: Invalid ByteRange coverage results in document integrity failure."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            byte_range_present=True,
            byte_range_valid=False,
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        integ_step = next(s for s in res.verification_steps if s.step_id == "content_integrity")
        self.assertEqual(integ_step.status, StepStatus.FAIL.value)

    def test_10_tampering_localized_coordinates(self):
        """Case 10: Tampering localized produces structured location coordinates in trace and summary."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "PAGE_LEVEL",
                "affected_items": [
                    {"location": "Page 2, Table 1", "location_type": "PAGE", "change_type": "CONTENT_CHANGED", "evidence": ["Byte offset shift"]}
                ]
            }
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertIn("Page 2, Table 1", res.summary)
        loc_df = next((d for d in res.decision_factors if d.factor == "TAMPERING_LOCALIZATION"), None)
        self.assertIsNotNone(loc_df)
        self.assertEqual(loc_df.status, "LOCALIZED")

    def test_11_tampering_not_localized_fallback_no_invention(self):
        """Case 11: Tampering detected but not localized explicitly states limitation without inventing pages."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            tampering_localization={
                "status": "NOT_LOCALIZED",
                "affected_items": []
            }
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertNotIn("Page ", res.summary)
        self.assertTrue(any("insufficient" in lim.lower() for lim in res.limitations))

    def test_12_no_signature_present_suspicious(self):
        """Case 12: No signature present -> SUSPICIOUS with clear notice and downstream NOT_CHECKED."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=False,
            signature_count=0,
            signature_valid=None,
            integrity_verified=None,
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        self.assertIn("No digital signature", res.final_reason)
        step_map = {s.step_id: s.status for s in res.verification_steps}
        self.assertEqual(step_map["sig_presence"], StepStatus.FAIL.value)
        self.assertEqual(step_map["crypto_signature"], StepStatus.NOT_CHECKED.value)
        self.assertEqual(step_map["content_integrity"], StepStatus.NOT_CHECKED.value)
        self.assertEqual(step_map["cert_validation"], StepStatus.NOT_CHECKED.value)

    def test_13_unsupported_signature_format(self):
        """Case 13: Unsupported signature format records disclosure without fake defaults."""
        evidence = VerificationEvidence(
            file_type="BINARY",
            signature_present=True,
            signature_count=1,
            signature_valid=None,
            signature_algorithm=None,
            digest_algorithm=None,
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        algo_step = next(s for s in res.verification_steps if s.step_id == "algo_detection")
        self.assertEqual(algo_step.status, StepStatus.WARNING.value)
        self.assertIn("Unknown", algo_step.observed_value)
        self.assertNotIn("SHA-256", algo_step.observed_value)

    def test_14_missing_signing_time_not_invented(self):
        """Case 14: Missing signing time does not fabricate a timestamp."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA",
            signature_timeline={"status": "AVAILABLE", "events": [{"signature_id": "s1", "signing_time": None}]}
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")
        self.assertNotIn("1970", str(res.model_dump()))

    def test_15_conflicting_timestamps_disclosure(self):
        """Case 15: Conflicting timestamps are handled deterministically."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA",
            limitations=["Signing time conflicts with document modification timestamp."]
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")
        self.assertTrue(any("conflicts" in lim.lower() for lim in res.limitations))

    def test_16_unsupported_algorithm_no_fake_defaults(self):
        """Case 16: Non-standard digest algorithm (e.g. SHA-384 / Ed25519) preserved exactly."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-384",
            signature_algorithm="Ed25519",
            public_key_algorithm="Ed25519",
            public_key_size=256,
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=True,
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")

        self.assertIn("SHA-384", res.final_reason)
        self.assertIn("Ed25519", res.final_reason)

    def test_17_quantum_anomaly_secondary_signal_does_not_override_crypto(self):
        """Case 17: Elevated quantum-inspired anomaly distance serves strictly as secondary signal."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-PSS",
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=True,
            quantum_analysis={
                "state_dimension": 14,
                "state_similarity": 0.65,
                "anomaly_distance": 0.75,  # High anomaly
                "entropy": 0.90,
            }
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")

        self.assertEqual(res.verdict, "AUTHENTIC")
        q_step = next(s for s in res.verification_steps if s.step_id == "quantum_simulation")
        self.assertEqual(q_step.status, StepStatus.WARNING.value)
        self.assertIn("classical simulation", q_step.explanation.lower())

    def test_18_threat_level_high_and_low(self):
        """Case 18: Threat level high vs low maps accurately to trace and factors."""
        ev_low = VerificationEvidence(file_type="PDF", signature_present=True, signature_valid=True, integrity_verified=True, threat_score=10, threat_level="LOW")
        res_low = generate_explanation(ev_low, verdict="AUTHENTIC")
        t_step_low = next(s for s in res_low.verification_steps if s.step_id == "threat_analysis")
        self.assertEqual(t_step_low.status, StepStatus.PASS.value)

        ev_high = VerificationEvidence(file_type="PDF", signature_present=True, signature_valid=False, integrity_verified=False, threat_score=85, threat_level="HIGH", detected_threats=["Signature forgery"])
        res_high = generate_explanation(ev_high, verdict="TAMPERED")
        t_step_high = next(s for s in res_high.verification_steps if s.step_id == "threat_analysis")
        self.assertEqual(t_step_high.status, StepStatus.FAIL.value)

    def test_19_multiple_simultaneous_findings(self):
        """Case 19: Multiple findings (expired cert + weak digest + threat) are all compiled without dropping."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="MD5",  # Weak
            signature_algorithm="RSA",
            certificate_present=True,
            certificate_expired=True,  # Expired
            threat_score=60,
            threat_level="MEDIUM",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        self.assertTrue(len(res.why_not_authentic) >= 2)
        warning_codes = [w.code for w in res.warnings]
        self.assertIn("ALGO_WEAK", warning_codes)
        self.assertIn("CERT_EXPIRED", warning_codes)

    def test_20_unknown_missing_evidence_preservation(self):
        """Case 20: Missing evidence stays UNKNOWN, never fabricates values."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=None,
            integrity_verified=None,
            certificate_present=False,
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")
        self.assertEqual(res.confidence, ConfidenceLevel.LOW.value)

    def test_21_cross_format_xml_xades(self):
        """Case 21: XMLDSig / XAdES format uses XML terminology (Element, XPath, References)."""
        evidence = VerificationEvidence(
            file_type="XML",
            filename="invoice.xml",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA-SHA256",
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "ELEMENT_LEVEL",
                "affected_items": [
                    {"location": "Element /Invoice/Payment/Amount", "location_type": "XML_ELEMENT", "change_type": "VALUE_CHANGED"}
                ]
            }
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertIn("XML", res.summary)
        self.assertIn("/Invoice/Payment/Amount", res.summary)
        self.assertNotIn("Page", res.summary)

    def test_22_cross_format_json_jws(self):
        """Case 22: JSON / JWS format uses JSON terminology (JSON Path, Field, Payload)."""
        evidence = VerificationEvidence(
            file_type="JSON",
            filename="payload.jws",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            digest_algorithm="SHA-256",
            signature_algorithm="ES256",
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "FIELD_LEVEL",
                "affected_items": [
                    {"location": "Field $.employee.salary", "location_type": "JSON_PATH", "change_type": "VALUE_CHANGED"}
                ]
            }
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertIn("JSON", res.summary)
        self.assertIn("$.employee.salary", res.summary)
        self.assertNotIn("Page", res.summary)

    def test_23_cross_format_xlsx_and_docx(self):
        """Case 23: Office OpenXML format uses Sheet/Cell/Paragraph/Part terminology."""
        ev_xlsx = VerificationEvidence(
            file_type="XLSX",
            filename="salaries.xlsx",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "FIELD_LEVEL",
                "affected_items": [
                    {"location": "Sheet 'Employees', Cell D17", "location_type": "TABLE_CELL", "change_type": "VALUE_CHANGED"}
                ]
            }
        )
        res_xlsx = generate_explanation(ev_xlsx, verdict="TAMPERED")
        self.assertIn("XLSX", res_xlsx.summary)
        self.assertIn("Cell D17", res_xlsx.summary)

        ev_docx = VerificationEvidence(
            file_type="DOCX",
            filename="letter.docx",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "STRUCTURAL",
                "affected_items": [
                    {"location": "Paragraph 4 in word/document.xml", "location_type": "PARAGRAPH", "change_type": "TEXT_CHANGED"}
                ]
            }
        )
        res_docx = generate_explanation(ev_docx, verdict="TAMPERED")
        self.assertIn("DOCX", res_docx.summary)
        self.assertIn("Paragraph 4", res_docx.summary)

    def test_24_cross_format_cms_and_binary(self):
        """Case 24: Binary format uses Byte Range terminology."""
        evidence = VerificationEvidence(
            file_type="BINARY",
            filename="firmware.bin",
            signature_present=True,
            signature_count=1,
            signature_valid=False,
            integrity_verified=False,
            signed_content_modified=True,
            tampering_localization={
                "status": "LOCALIZED",
                "localization_level": "BYTE_LEVEL",
                "affected_items": [
                    {"location": "Byte range 10240–10496", "location_type": "BYTE_RANGE", "change_type": "BYTES_MODIFIED"}
                ]
            }
        )
        res = generate_explanation(evidence, verdict="TAMPERED")
        self.assertIn("BINARY", res.summary)
        self.assertIn("Byte range 10240–10496", res.summary)

    def test_25_generate_verdict_explanation_api(self):
        """Case 25: Direct call to generate_verdict_explanation API."""
        res = generate_verdict_explanation(
            verification_result={"present": True, "count": 1, "overall_status": "VALID", "digest_algorithm": "SHA-256", "signature_algorithm": "RSA"},
            certificate_inspection={"status": "SUCCESS", "validity": {"status": "VALID"}, "trust": {"status": "TRUSTED"}},
            signature_timeline={"status": "AVAILABLE", "signature_count": 1, "consistency_status": "CONSISTENT"},
            tampering_localization={"status": "NO_TAMPERING_DETECTED"},
            threat_analysis={"threat_score": 0, "threat_level": "LOW", "detected_threats": []},
            final_verdict="AUTHENTIC",
            file_type="PDF",
            filename="sample.pdf"
        )
        self.assertIsInstance(res, ExplanationResult)
        self.assertEqual(res.verdict, "AUTHENTIC")

    def test_26_deterministic_reproducibility(self):
        """Case 26: 100% deterministic reproducibility across multiple runs."""
        evidence = VerificationEvidence(
            file_type="PDF",
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-512",
            signature_algorithm="RSA-PSS",
            public_key_algorithm="RSA",
            public_key_size=4096,
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=True,
        )
        res1 = generate_explanation(evidence, verdict="AUTHENTIC")
        res2 = generate_explanation(evidence, verdict="AUTHENTIC")

        self.assertEqual(res1.model_dump(), res2.model_dump())

    def test_27_real_pdf_files_e2e(self):
        """Case 27: End-to-end testing against existing real repository PDF files."""
        from app.services import (
            signature_verifier,
            certificate_analyzer,
            pdf_parser,
            threat_engine,
            quantum_analysis,
        )

        repo_root = Path(__file__).resolve().parent.parent.parent
        pdf_cases = [
            ("original_signed_document.pdf", "AUTHENTIC"),
            ("forgery_tampered_signed_document.pdf", "TAMPERED"),
            ("demo_expired_cert_signed_document.pdf", "SUSPICIOUS"),
        ]

        for filename, expected_verdict in pdf_cases:
            pdf_path = repo_root / filename
            if not pdf_path.exists():
                continue

            pdf_bytes = pdf_path.read_bytes()
            sig_res = signature_verifier.verify_pdf_signatures(pdf_bytes)
            pdf_struct = pdf_parser.parse_pdf_structure(pdf_bytes)

            cert_info = {"trust_status": "UNAVAILABLE"}
            if sig_res.get("signatures"):
                cert_raw = sig_res["signatures"][0].get("_cert_object")
                if cert_raw is not None:
                    cert_info = certificate_analyzer.analyze_certificate(cert_raw)
                else:
                    cert_info["subject"] = sig_res["signatures"][0].get("cert_subject")
                    cert_info["trust_status"] = sig_res["signatures"][0].get("trust_status") or "UNAVAILABLE"

            intg_res = {
                "integrity_status": sig_res.get("integrity_status", "UNKNOWN"),
                "modification_status": sig_res.get("integrity_modification_status", "UNKNOWN"),
                "byte_range": sig_res.get("byte_range"),
            }
            dup_res = {"is_duplicate": False, "match_type": "NONE"}
            q_res = quantum_analysis.run_quantum_analysis(sig_res, cert_info, intg_res, pdf_struct, dup_res)
            threat_res = threat_engine.calculate_threat(sig_res, cert_info, intg_res, pdf_struct, dup_res, q_res)
            verdict = threat_engine.determine_verdict(sig_res, cert_info, intg_res, threat_res)

            self.assertEqual(verdict, expected_verdict)

            evidence = extract_evidence_from_analysis(
                sig_result=sig_res,
                cert_info=cert_info,
                integrity_result=intg_res,
                pdf_structure=pdf_struct,
                dup_result=dup_res,
                threat_result=threat_res,
                quantum_result=q_res,
                filename=filename,
            )
            explanation = generate_explanation(evidence, verdict)

            self.assertIsInstance(explanation, ExplanationResult)
            self.assertTrue(len(explanation.verification_steps) >= 5)
            self.assertTrue(len(explanation.evidence) >= 4)
            self.assertIn(expected_verdict, explanation.summary)
            self.assertTrue(explanation.confidence in ["HIGH", "MEDIUM", "LOW"])


if __name__ == "__main__":
    unittest.main()
