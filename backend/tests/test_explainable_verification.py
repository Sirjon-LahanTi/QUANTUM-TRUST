"""
Unit & Integration tests for QuantumTrust Explainable Verification Engine
"""
import unittest
from app.services.explainable_verification import (
    VerificationEvidence,
    VerificationStep,
    EvidenceItem,
    ExplanationResult,
    StepStatus,
    EvidenceStatus,
    EvidenceCategory,
    ConfidenceLevel,
    generate_explanation,
    extract_evidence_from_analysis,
)


class TestExplainableVerificationEngine(unittest.TestCase):
    """Test suite for deterministic explainable verification."""

    def test_1_valid_signature_and_integrity_authentic(self):
        """Case 1: Valid signature + valid integrity -> AUTHENTIC explanation with HIGH confidence."""
        evidence = VerificationEvidence(
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
        self.assertEqual(res.confidence, ConfidenceLevel.HIGH.value)
        self.assertIn("AUTHENTIC", res.summary)
        self.assertIn("succeeded", res.final_reason.lower())
        self.assertIn("SHA-256", res.final_reason)
        self.assertIn("RSA-PSS", res.final_reason)

        # Check steps in trace
        step_checks = [s.check for s in res.verification_steps]
        self.assertIn("Digital signature presence", step_checks)
        self.assertIn("Cryptographic algorithm identification", step_checks)
        self.assertIn("Signature cryptographic verification", step_checks)
        self.assertIn("Signed content integrity (ByteRange)", step_checks)
        self.assertIn("Signer certificate parsing & validation", step_checks)
        self.assertIn("Final security verdict", step_checks)

        # All core steps should be PASS
        sig_step = next(s for s in res.verification_steps if s.id == "crypto_signature")
        self.assertEqual(sig_step.status, StepStatus.PASS.value)

        integ_step = next(s for s in res.verification_steps if s.id == "content_integrity")
        self.assertEqual(integ_step.status, StepStatus.PASS.value)

        self.assertEqual(len(res.failed_checks), 0)
        self.assertTrue(len(res.passed_checks) >= 4)

    def test_2_invalid_signature_tampered(self):
        """Case 2: Invalid signature + failed integrity -> TAMPERED explanation without speculative claims."""
        evidence = VerificationEvidence(
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
            threat_score=95,
            threat_level="CRITICAL",
        )
        res = generate_explanation(evidence, verdict="TAMPERED")

        self.assertEqual(res.confidence, ConfidenceLevel.HIGH.value)
        self.assertIn("TAMPERED", res.summary)
        self.assertIn("failed", res.final_reason.lower())

        # Assert no speculative author/time claims
        self.assertNotIn("modified by", res.final_reason.lower())
        self.assertNotIn("hacker", res.final_reason.lower())

        # Failed checks must list crypto signature & integrity
        failed_codes = [f.code for f in res.failed_checks]
        self.assertIn("CRYPTO_SIG_INVALID", failed_codes)
        self.assertIn("INTEGRITY_FAILED", failed_codes)

    def test_3_valid_signature_with_expired_certificate_suspicious(self):
        """Case 3: Valid signature + certificate expired -> SUSPICIOUS explanation with warnings."""
        evidence = VerificationEvidence(
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
            threat_score=25,
            threat_level="LOW",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        self.assertIn("SUSPICIOUS", res.summary)
        self.assertIn("expired", res.final_reason.lower())

        warning_codes = [w.code for w in res.warnings]
        self.assertIn("CERT_EXPIRED", warning_codes)

        cert_step = next(s for s in res.verification_steps if s.id == "cert_validation")
        self.assertEqual(cert_step.status, StepStatus.WARNING.value)

    def test_4_no_signature_present(self):
        """Case 4: No signature -> signature presence fails and downstream crypto is NOT_CHECKED."""
        evidence = VerificationEvidence(
            signature_present=False,
            signature_count=0,
            signature_valid=None,
            integrity_verified=None,
            certificate_present=False,
            structural_anomalies=[],
            threat_score=0,
            threat_level="LOW",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        self.assertIn("No digital signature", res.final_reason)
        failed_codes = [f.code for f in res.failed_checks]
        self.assertIn("SIG_ABSENT", failed_codes)

        # Downstream checks must be NOT_CHECKED
        step_dict = {s.id: s.status for s in res.verification_steps}
        self.assertEqual(step_dict["sig_presence"], StepStatus.FAIL.value)
        self.assertEqual(step_dict["crypto_signature"], StepStatus.NOT_CHECKED.value)
        self.assertEqual(step_dict["content_integrity"], StepStatus.NOT_CHECKED.value)
        self.assertEqual(step_dict["cert_validation"], StepStatus.NOT_CHECKED.value)

    def test_5_missing_certificate_data_not_false(self):
        """Case 5: Missing certificate data is treated as warning / NOT_CHECKED, never coerced to false."""
        evidence = VerificationEvidence(
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            certificate_present=False,
            certificate_valid=None,
            certificate_trusted=None,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA",
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        cert_step = next(s for s in res.verification_steps if s.id == "cert_validation")
        self.assertEqual(cert_step.status, StepStatus.WARNING.value)
        self.assertIn("No certificate embedded", cert_step.observed_value)

        # Confidence should reflect partial completeness
        self.assertEqual(res.confidence, ConfidenceLevel.HIGH.value)

    def test_6_unsupported_algorithm_no_assumptions(self):
        """Case 6: Unsupported or unknown algorithm must NOT assume SHA-256 or RSA."""
        evidence = VerificationEvidence(
            signature_present=True,
            signature_count=1,
            signature_valid=None,
            integrity_verified=None,
            digest_algorithm=None,
            signature_algorithm=None,
            certificate_present=True,
        )
        res = generate_explanation(evidence, verdict="SUSPICIOUS")

        algo_step = next(s for s in res.verification_steps if s.id == "algo_detection")
        self.assertEqual(algo_step.status, StepStatus.WARNING.value)
        self.assertIn("Unknown", algo_step.observed_value)
        self.assertNotIn("SHA-256", algo_step.observed_value)

    def test_7_multiple_signatures_separate_evidence(self):
        """Case 7: Multiple signatures produce distinct evidence items for each signature."""
        evidence = VerificationEvidence(
            signature_present=True,
            signature_count=2,
            signature_valid=True,
            integrity_verified=True,
            digest_algorithm="SHA-256",
            signature_algorithm="RSA",
            signatures_detail=[
                {
                    "field_name": "ApprovalSignature",
                    "status": "VALID",
                    "digest_algorithm": "SHA-256",
                    "signature_algorithm": "RSA-PKCS#1 v1.5",
                },
                {
                    "field_name": "ReviewerSignature",
                    "status": "VALID",
                    "digest_algorithm": "SHA-384",
                    "signature_algorithm": "ECDSA",
                },
            ],
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")

        sig_1_item = next((e for e in res.evidence if e.code == "SIG_1_DETAIL"), None)
        sig_2_item = next((e for e in res.evidence if e.code == "SIG_2_DETAIL"), None)

        self.assertIsNotNone(sig_1_item)
        self.assertIsNotNone(sig_2_item)
        self.assertIn("ApprovalSignature", sig_1_item.title)
        self.assertIn("ReviewerSignature", sig_2_item.title)

    def test_8_legitimate_incremental_updates_not_tampered(self):
        """Case 8: Legitimate incremental updates (PERMITTED_CHANGES) remain valid and NOT tampered."""
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
        integ_step = next(s for s in res.verification_steps if s.id == "content_integrity")
        self.assertEqual(integ_step.status, StepStatus.PASS.value)
        self.assertEqual(len(res.failed_checks), 0)

    def test_9_quantum_anomaly_does_not_override_cryptographic_verdict(self):
        """Case 9: Quantum-inspired anomaly present while crypto verification is valid -> secondary signal only."""
        evidence = VerificationEvidence(
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
                "state_similarity": 0.72,
                "anomaly_distance": 0.61,  # Elevated anomaly
                "entropy": 0.85,
            },
        )
        res = generate_explanation(evidence, verdict="AUTHENTIC")

        # Authoritative verdict remains AUTHENTIC
        self.assertIn("AUTHENTIC", res.summary)
        
        # Quantum step has warning as secondary signal
        q_step = next(s for s in res.verification_steps if s.id == "quantum_simulation")
        self.assertEqual(q_step.status, StepStatus.WARNING.value)
        self.assertIn("classical mathematical anomaly signal", q_step.explanation.lower())

    def test_10_deterministic_output(self):
        """Case 10: Same input evidence produces 100% identical explanation outputs."""
        evidence = VerificationEvidence(
            signature_present=True,
            signature_count=1,
            signature_valid=True,
            integrity_verified=True,
            signed_content_modified=False,
            digest_algorithm="SHA-512",
            signature_algorithm="Ed25519",
            public_key_algorithm="Ed25519",
            public_key_size=256,
            certificate_present=True,
            certificate_valid=True,
            certificate_trusted=True,
            certificate_expired=False,
        )

        res1 = generate_explanation(evidence, verdict="AUTHENTIC")
        res2 = generate_explanation(evidence, verdict="AUTHENTIC")

        self.assertEqual(res1.model_dump(), res2.model_dump())
        self.assertEqual(res1.summary, res2.summary)
        self.assertEqual(res1.final_reason, res2.final_reason)
        self.assertEqual(len(res1.verification_steps), len(res2.verification_steps))
        for s1, s2 in zip(res1.verification_steps, res2.verification_steps):
            self.assertEqual(s1.model_dump(), s2.model_dump())

    def test_11_e2e_real_pdf_files(self):
        """End-to-end testing of real PDF files verifying explanation output structures."""
        from pathlib import Path
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
            )
            explanation = generate_explanation(evidence, verdict)

            self.assertIsInstance(explanation, ExplanationResult)
            self.assertTrue(len(explanation.verification_steps) >= 5)
            self.assertTrue(len(explanation.evidence) >= 4)
            self.assertIn(expected_verdict, explanation.summary)
            self.assertTrue(explanation.confidence in ["HIGH", "MEDIUM", "LOW"])


if __name__ == "__main__":
    unittest.main()

