"""
Unit & Integration Tests for QuantumTrust Signature Timeline & Multiple-Signature Analysis
"""
import datetime
import io
import os
import tempfile
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pypdf import PdfWriter

from app.services.signature_timeline import (
    analyze_signature_timeline,
    _analyze_byte_range,
    _parse_pdf_date,
)
from app.services import signature_verifier, certificate_analyzer


def _create_signer(common_name: str, org_name: str) -> signers.SimpleSigner:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
        kf.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        c_path, k_path = cf.name, kf.name

    signer = signers.SimpleSigner.load(key_file=k_path, cert_file=c_path)
    os.unlink(c_path)
    os.unlink(k_path)
    return signer


def _generate_multi_signed_pdf() -> bytes:
    """Generates a PDF with 2 valid incremental signatures."""
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buf0 = io.BytesIO()
    writer.write(buf0)
    buf0.seek(0)

    # Signature 1
    s1 = _create_signer("Alice Authority", "QuantumTrust Root Security")
    w1 = IncrementalPdfFileWriter(buf0)
    fields.append_signature_field(w1, fields.SigFieldSpec("Signature1", box=(50, 500, 250, 550)))
    out1 = io.BytesIO()
    signers.sign_pdf(
        w1,
        signers.PdfSignatureMetadata(
            field_name="Signature1",
            reason="Primary Document Approval",
            location="San Francisco, CA"
        ),
        signer=s1,
        output=out1
    )

    # Signature 2 (Incremental Co-Signer)
    s2 = _create_signer("Bob CoSigner", "QuantumTrust Audit Dept")
    w2 = IncrementalPdfFileWriter(io.BytesIO(out1.getvalue()))
    fields.append_signature_field(w2, fields.SigFieldSpec("Signature2", box=(50, 400, 250, 450)))
    out2 = io.BytesIO()
    signers.sign_pdf(
        w2,
        signers.PdfSignatureMetadata(
            field_name="Signature2",
            reason="Secondary Counter-Signature",
            location="New York, NY"
        ),
        signer=s2,
        output=out2
    )

    return out2.getvalue()


def _generate_pdf_with_empty_field() -> bytes:
    """Generates a PDF with an AcroForm signature field that is left empty."""
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buf0 = io.BytesIO()
    writer.write(buf0)
    buf0.seek(0)

    w1 = IncrementalPdfFileWriter(buf0)
    fields.append_signature_field(w1, fields.SigFieldSpec("EmptySignatureField", box=(50, 500, 250, 550)))
    out = io.BytesIO()
    w1.write(out)
    return out.getvalue()


class TestSignatureTimeline:

    def test_01_byte_range_analysis_valid(self):
        """Test ByteRange analysis with valid 4-tuple and boundary checks."""
        br = [0, 500, 600, 400]
        res = _analyze_byte_range(br, file_len=1000)
        assert res["is_valid"] is True
        assert res["coverage_status"] == "VALID"
        assert res["covered_length"] == 900
        assert res["excludes_contents_placeholder"] is True
        assert res["byte_range_end"] == 1000

    def test_02_byte_range_analysis_invalid(self):
        """Test ByteRange analysis with out of bounds or negative values."""
        # Out of bounds
        res1 = _analyze_byte_range([0, 500, 600, 600], file_len=1000)
        assert res1["is_valid"] is False
        assert res1["coverage_status"] == "INVALID"

        # Overlapping ranges
        res2 = _analyze_byte_range([0, 500, 400, 200], file_len=1000)
        assert res2["is_valid"] is False
        assert res2["coverage_status"] == "INVALID"

        # Not starting at 0
        res3 = _analyze_byte_range([10, 500, 600, 200], file_len=1000)
        assert res3["is_valid"] is False
        assert res3["coverage_status"] == "INVALID"

    def test_03_parse_pdf_date(self):
        """Test parsing of standard PDF date string."""
        pdf_date = "D:20260905103000+05'30'"
        dt, iso_str = _parse_pdf_date(pdf_date)
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 9
        assert dt.day == 5
        assert dt.hour == 10
        assert dt.minute == 30
        assert iso_str is not None

    def test_04_empty_signature_field_detection(self):
        """Test that an unsigned PDF with AcroForm field returns SIGNATURE_FIELD_EMPTY."""
        pdf_bytes = _generate_pdf_with_empty_field()
        res = analyze_signature_timeline(pdf_bytes)

        assert res["timeline_status"] == "ANALYZED"
        assert res["total_signature_fields"] >= 1
        assert res["total_signed_signatures"] == 0
        assert res["consistency_status"] == "UNKNOWN"

        empty_findings = [f for f in res["findings"] if f["code"] == "SIGNATURE_FIELD_EMPTY"]
        assert len(empty_findings) >= 1
        assert "EmptySignatureField" in empty_findings[0]["description"]

    def test_05_multi_signature_valid_timeline(self):
        """Test full timeline extraction and verification for multi-signed PDF."""
        pdf_bytes = _generate_multi_signed_pdf()
        res = analyze_signature_timeline(pdf_bytes)

        assert res["timeline_status"] == "ANALYZED"
        assert res["total_signed_signatures"] == 2
        assert res["total_signature_fields"] >= 2
        assert res["consistency_status"] == "CONSISTENT"
        assert res["timeline_order_confidence"] == "HIGH"
        assert len(res["signatures"]) == 2

        # Check Signature 1
        sig1 = res["signatures"][0]
        assert sig1["sequence_number"] == 1
        assert sig1["field_name"] == "Signature1"
        assert sig1["signer"]["common_name"] == "Alice Authority"
        assert sig1["signer"]["organization"] == "QuantumTrust Root Security"
        assert sig1["status"] == "VALID"
        assert sig1["post_signature_change"] == "LEGITIMATE_INCREMENTAL_UPDATE"
        assert sig1["byte_range"]["coverage_status"] == "VALID"

        # Check Signature 2
        sig2 = res["signatures"][1]
        assert sig2["sequence_number"] == 2
        assert sig2["field_name"] == "Signature2"
        assert sig2["signer"]["common_name"] == "Bob CoSigner"
        assert sig2["signer"]["organization"] == "QuantumTrust Audit Dept"
        assert sig2["status"] == "VALID"
        assert sig2["revision"]["is_latest_revision"] is True

        # Check Findings
        finding_codes = [f["code"] for f in res["findings"]]
        assert "MULTIPLE_SIGNATURES_PRESENT" in finding_codes
        assert "INCREMENTAL_UPDATE_DETECTED" in finding_codes
        assert "LEGITIMATE_INCREMENTAL_UPDATE" in finding_codes
        assert "CERTIFICATE_CHANGED" in finding_codes

    def test_06_tampered_multi_signature_pdf(self):
        """Test that altering bytes in Revision 1 marks Signature 1 as UNAUTHORIZED_SIGNED_CONTENT_CHANGE."""
        pdf_bytes = bytearray(_generate_multi_signed_pdf())

        # Modify bytes in earlier signed region (e.g. at offset 1000)
        pdf_bytes[1000:1015] = b"FORGERY_MOD_RAW"

        res = analyze_signature_timeline(bytes(pdf_bytes))
        assert res["timeline_status"] == "ANALYZED"
        assert res["consistency_status"] == "INCONSISTENT"

        # At least one signature should be marked INVALID
        invalid_sigs = [s for s in res["signatures"] if s["status"] == "INVALID"]
        assert len(invalid_sigs) >= 1

    def test_07_single_signature_pdf_timeline(self):
        """Test timeline analysis on single signed document from test fixtures."""
        with open("original_signed_document.pdf", "rb") as f:
            pdf_bytes = f.read()

        res = analyze_signature_timeline(pdf_bytes)
        assert res["timeline_status"] == "ANALYZED"
        assert res["total_signed_signatures"] == 1
        assert res["consistency_status"] == "CONSISTENT"
        assert len(res["signatures"]) == 1
        assert res["signatures"][0]["status"] == "VALID"
