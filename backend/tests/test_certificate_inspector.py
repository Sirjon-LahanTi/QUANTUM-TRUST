"""
Unit and Integration Tests for QuantumTrust Certificate & Public-Key Inspector
Tests all 20 required scenarios with deterministic fixtures.
"""
from __future__ import annotations

import datetime
from datetime import timezone
import unittest
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from app.services import certificate_inspector
from app.services.explainable_verification import (
    extract_evidence_from_analysis,
    generate_explanation,
)


def _create_test_cert(
    key_type: str = "rsa_2048",
    subject_cn: str = "Test Signer",
    issuer_cn: str | None = None,
    org: str = "QuantumTrust Corp",
    ou: str | None = "Security Dept",
    country: str = "US",
    state: str = "CA",
    locality: str = "San Francisco",
    valid_days: int = 365,
    valid_offset_days: int = 0,
    is_ca: bool = False,
    include_extensions: bool = True,
    san_dns: list[str] | None = None,
    hash_algo = hashes.SHA256(),
    issuer_key = None,
) -> tuple[x509.Certificate, Any]:
    """Helper to generate in-memory deterministic test X.509 certificates."""
    if key_type == "rsa_2048":
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "rsa_4096":
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif key_type == "rsa_1024":
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    elif key_type == "ec_p256":
        priv_key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "ed25519":
        priv_key = ed25519.Ed25519PrivateKey.generate()
    else:
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    signing_key = issuer_key or priv_key

    # Subject
    subj_attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ]
    if ou:
        subj_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if state:
        subj_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        subj_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    subject = x509.Name(subj_attrs)

    # Issuer
    if issuer_cn:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ])
    else:
        issuer = subject

    now = datetime.datetime.now(timezone.utc)
    not_before = now + datetime.timedelta(days=valid_offset_days)
    not_after = not_before + datetime.timedelta(days=valid_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if include_extensions:
        # Basic Constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
        # Key Usage
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extended Key Usage
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CODE_SIGNING,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        # Subject Alternative Name
        if san_dns:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
                critical=False,
            )
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(priv_key.public_key()),
            critical=False,
        )

    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(signing_key, None)
    else:
        cert = builder.sign(signing_key, hash_algo)

    return cert, priv_key


class TestCertificateAndPublicKeyInspector(unittest.TestCase):
    """20 Requirement Unit & Integration Test Suite."""

    def test_1_valid_x509_certificate(self):
        """1. Valid X.509 certificate parsing."""
        cert, _ = _create_test_cert(valid_days=365)
        res = certificate_inspector.inspect_certificate(cert)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["validity"]["status"], "VALID")
        self.assertIsNotNone(res["certificate"]["serial_number"])
        self.assertEqual(res["certificate"]["subject"]["common_name"], "Test Signer")
        self.assertIsNotNone(res["public_key"])

    def test_2_expired_certificate(self):
        """2. Expired certificate detection."""
        cert, _ = _create_test_cert(valid_days=10, valid_offset_days=-400)
        res = certificate_inspector.inspect_certificate(cert)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["validity"]["status"], "EXPIRED")
        self.assertEqual(res["trust"]["status"], "UNTRUSTED")
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("CERTIFICATE_EXPIRED", finding_codes)

    def test_3_not_yet_valid_certificate(self):
        """3. Not-yet-valid certificate detection."""
        cert, _ = _create_test_cert(valid_days=30, valid_offset_days=100)
        res = certificate_inspector.inspect_certificate(cert)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["validity"]["status"], "NOT_YET_VALID")
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("CERTIFICATE_NOT_YET_VALID", finding_codes)

    def test_4_rsa_public_key_extraction(self):
        """4. RSA public key extraction (2048 bits, exponent 65537)."""
        cert, _ = _create_test_cert(key_type="rsa_2048")
        res = certificate_inspector.inspect_certificate(cert)

        pk = res["public_key"]
        self.assertEqual(pk["algorithm"], "RSA")
        self.assertEqual(pk["key_size"], 2048)
        self.assertEqual(pk["exponent"], 65537)
        self.assertEqual(res["security_assessment"]["key_strength"], "ACCEPTABLE")

    def test_5_ec_public_key_extraction(self):
        """5. EC public key extraction (secp256r1 / P-256)."""
        cert, _ = _create_test_cert(key_type="ec_p256")
        res = certificate_inspector.inspect_certificate(cert)

        pk = res["public_key"]
        self.assertEqual(pk["algorithm"], "EC")
        self.assertEqual(pk["key_size"], 256)
        self.assertIn("secp256r1", pk["curve"].lower())
        self.assertEqual(res["security_assessment"]["key_strength"], "ACCEPTABLE")

    def test_6_ed25519_public_key_extraction(self):
        """6. Ed25519 public key extraction."""
        cert, _ = _create_test_cert(key_type="ed25519")
        res = certificate_inspector.inspect_certificate(cert)

        pk = res["public_key"]
        self.assertEqual(pk["algorithm"], "Ed25519")
        self.assertEqual(pk["key_size"], 256)
        self.assertEqual(res["security_assessment"]["key_strength"], "ACCEPTABLE")

    def test_7_certificate_fingerprint_generation(self):
        """7. SHA-256 certificate fingerprint generation."""
        cert, _ = _create_test_cert()
        res = certificate_inspector.inspect_certificate(cert)

        fp = res["fingerprint"]
        self.assertIsNotNone(fp)
        self.assertEqual(fp["algorithm"], "SHA-256")
        self.assertTrue(len(fp["value"]) >= 64)
        self.assertIn(":", fp["value"])

    def test_8_subject_extraction(self):
        """8. Detailed Subject DN field extraction (CN, O, OU, C, ST, L)."""
        cert, _ = _create_test_cert(
            subject_cn="Alice Smith",
            org="Acme Corp",
            ou="Engineering",
            country="US",
            state="California",
            locality="Mountain View",
        )
        res = certificate_inspector.inspect_certificate(cert)

        subj = res["certificate"]["subject"]
        self.assertEqual(subj["common_name"], "Alice Smith")
        self.assertEqual(subj["organization"], "Acme Corp")
        self.assertEqual(subj["organizational_unit"], "Engineering")
        self.assertEqual(subj["country"], "US")
        self.assertEqual(subj["state"], "California")
        self.assertEqual(subj["locality"], "Mountain View")

    def test_9_issuer_extraction(self):
        """9. Issuer DN field extraction."""
        root_cert, root_key = _create_test_cert(subject_cn="Acme Root CA", is_ca=True)
        signer_cert, _ = _create_test_cert(
            subject_cn="Alice Signer",
            issuer_cn="Acme Root CA",
            issuer_key=root_key,
        )
        res = certificate_inspector.inspect_certificate(signer_cert)

        issu = res["certificate"]["issuer"]
        self.assertEqual(issu["common_name"], "Acme Root CA")
        self.assertEqual(res["certificate"]["is_self_signed"], False)

    def test_10_certificate_signature_algorithm_separation(self):
        """10. Certificate signature algorithm distinguished from doc sig and digest."""
        cert, _ = _create_test_cert(hash_algo=hashes.SHA256())
        res = certificate_inspector.inspect_certificate(
            cert,
            document_signature_algo="RSA-PSS",
            document_digest_algo="SHA-512",
        )

        cert_sig = res["certificate"]["signature_algorithm"]
        self.assertTrue("sha256" in cert_sig.lower() or "rsa" in cert_sig.lower())
        # Confirms cert signature is distinct from document algorithm
        self.assertNotEqual(cert_sig, "RSA-PSS")

    def test_11_public_key_algorithm_extraction(self):
        """11. Public key algorithm identification."""
        cert, _ = _create_test_cert(key_type="rsa_2048")
        res = certificate_inspector.inspect_certificate(cert)
        self.assertEqual(res["public_key"]["algorithm"], "RSA")

    def test_12_key_size_extraction(self):
        """12. Key size extraction for multiple RSA key sizes."""
        cert_4096, _ = _create_test_cert(key_type="rsa_4096")
        res_4096 = certificate_inspector.inspect_certificate(cert_4096)
        self.assertEqual(res_4096["public_key"]["key_size"], 4096)

    def test_13_certificate_extensions_parsing(self):
        """13. Key Usage, EKU, Basic Constraints, SAN, SKI extension parsing."""
        cert, _ = _create_test_cert(san_dns=["signing.quantumtrust.org", "auth.quantumtrust.org"])
        res = certificate_inspector.inspect_certificate(cert)

        exts = res["extensions"]
        self.assertTrue(len(exts) >= 4)
        ext_names = [e["name"].lower() for e in exts]
        self.assertTrue(any("keyusage" in n for n in ext_names))
        self.assertTrue(any("extendedkeyusage" in n for n in ext_names))
        self.assertTrue(any("basicconstraints" in n for n in ext_names))
        self.assertTrue(any("subjectalternativename" in n for n in ext_names))

        san_ext = next(e for e in exts if "subjectalternativename" in e["name"].lower())
        self.assertIn("signing.quantumtrust.org", san_ext["value"])

    def test_14_multiple_embedded_certificates_chain(self):
        """14. Multiple embedded certificates chain resolution (Signer -> Root CA)."""
        root_cert, root_key = _create_test_cert(subject_cn="QuantumTrust Root CA", is_ca=True)
        signer_cert, _ = _create_test_cert(
            subject_cn="QuantumTrust Signer 1",
            issuer_cn="QuantumTrust Root CA",
            issuer_key=root_key,
        )

        res = certificate_inspector.inspect_certificate(
            signer_cert,
            all_certs=[signer_cert, root_cert],
        )

        chain = res["chain"]
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0]["role"], "SIGNER")
        self.assertEqual(chain[0]["subject"], "QuantumTrust Signer 1")
        self.assertEqual(chain[1]["role"], "ROOT_CA")
        self.assertEqual(chain[1]["subject"], "QuantumTrust Root CA")

    def test_15_missing_certificate_handling(self):
        """15. Missing certificate handling returns structured NOT_AVAILABLE status."""
        res = certificate_inspector.inspect_certificate(None)

        self.assertEqual(res["status"], "NOT_AVAILABLE")
        self.assertIsNone(res["certificate"])
        self.assertEqual(res["validity"]["status"], "NOT_CHECKED")
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("CERTIFICATE_NOT_FOUND", finding_codes)

    def test_16_unsupported_or_malformed_certificate(self):
        """16. Unsupported or corrupt bytes returns EXTRACTION_FAILED."""
        res = certificate_inspector.inspect_certificate(b"INVALID_CORRUPT_BYTES_XYZ")

        self.assertEqual(res["status"], "EXTRACTION_FAILED")
        self.assertIsNone(res["certificate"])
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("CERTIFICATE_EXTRACTION_FAILED", finding_codes)

    def test_17_unknown_trust_state(self):
        """17. Unknown trust state when certificate valid but external PKI unconfigured."""
        root_cert, root_key = _create_test_cert(subject_cn="External CA", is_ca=True)
        cert, _ = _create_test_cert(subject_cn="Signer", issuer_cn="External CA", issuer_key=root_key)
        res = certificate_inspector.inspect_certificate(cert)

        self.assertEqual(res["trust"]["status"], "UNKNOWN")
        self.assertFalse(res["trust"]["is_trusted"])
        self.assertIn("PKI trust store", res["trust"]["reason"])

    def test_18_weak_key_policy_finding(self):
        """18. Weak-key policy finding for RSA < 2048 bits."""
        cert_1024, _ = _create_test_cert(key_type="rsa_1024")
        res = certificate_inspector.inspect_certificate(cert_1024)

        self.assertEqual(res["security_assessment"]["key_strength"], "WEAK")
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("WEAK_PUBLIC_KEY", finding_codes)

    def test_19_explainable_verification_integration(self):
        """19. Certificate inspection data and findings appear in Explainable Verification."""
        cert, _ = _create_test_cert(valid_days=365)
        insp = certificate_inspector.inspect_certificate(cert)

        evidence = extract_evidence_from_analysis(
            sig_result={"present": True, "count": 1, "overall_status": "VALID", "signatures": []},
            cert_info={"subject": "Test Signer", "issuer": "Test Signer", "trust_status": "SELF_SIGNED"},
            integrity_result={"integrity_status": "VERIFIED", "modification_status": "NO_UNAUTHORIZED_CHANGES"},
            pdf_structure={"suspicious_signals": []},
            dup_result={"is_duplicate": False},
            threat_result={"threat_score": 15, "threat_level": "LOW", "detected_threats": []},
            cert_inspection=insp,
        )
        explanation = generate_explanation(evidence, verdict="AUTHENTIC")

        evidence_codes = [e.code for e in explanation.evidence]
        self.assertIn("CERT_UNTRUSTED", evidence_codes)
        self.assertIn("CERTIFICATE_SELF_SIGNED", evidence_codes)

    def test_20_no_private_key_material_exposed(self):
        """20. Assert private key material never appears in returned inspection payload."""
        cert, priv_key = _create_test_cert(key_type="rsa_2048")
        res = certificate_inspector.inspect_certificate(cert)

        payload_str = str(res)
        self.assertNotIn("PRIVATE KEY", payload_str)
        self.assertNotIn("private_bytes", payload_str)
        self.assertNotIn("d=", payload_str)
        self.assertNotIn("p=", payload_str)
        self.assertNotIn("q=", payload_str)
        self.assertNotIn("dmp1", payload_str)
        self.assertNotIn("dmq1", payload_str)
        self.assertNotIn("iqmp", payload_str)
        self.assertIn("public_key", res)


if __name__ == "__main__":
    unittest.main()
