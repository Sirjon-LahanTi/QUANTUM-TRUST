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
from asn1crypto import cms

from app.services.signature_timeline import (
    analyze_signature_timeline,
    get_adapter,
    _analyze_byte_range,
    _parse_pdf_date,
    PdfSignatureTimelineAdapter,
    Pkcs7CmsSignatureTimelineAdapter,
    XmlSignatureTimelineAdapter,
    OfficeDocxXlsxTimelineAdapter,
    GenericUnsupportedTimelineAdapter,
)


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


def _generate_multi_signed_pdf(num_sigs: int = 2, same_signer: bool = False) -> bytes:
    """Generates a PDF with num_sigs valid incremental signatures."""
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buf0 = io.BytesIO()
    writer.write(buf0)
    buf0.seek(0)

    current_bytes = buf0.getvalue()
    signer1 = _create_signer("Alice Authority", "QuantumTrust Root Security")
    signer2 = signer1 if same_signer else _create_signer("Bob CoSigner", "QuantumTrust Audit Dept")
    signer3 = signer1 if same_signer else _create_signer("Charlie Compliance", "QuantumTrust Compliance")

    signers_list = [signer1, signer2, signer3]

    for i in range(num_sigs):
        w = IncrementalPdfFileWriter(io.BytesIO(current_bytes))
        f_name = f"Signature{i + 1}"
        box_y = 500 - (i * 100)
        fields.append_signature_field(w, fields.SigFieldSpec(f_name, box=(50, box_y, 250, box_y + 50)))
        out = io.BytesIO()
        s = signers_list[i % len(signers_list)]
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name=f_name,
                reason=f"Stage {i + 1} Document Approval",
                location="San Francisco, CA"
            ),
            signer=s,
            output=out
        )
        current_bytes = out.getvalue()

    return current_bytes


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
        assert res["status"] == "AVAILABLE"
        assert res["total_signature_fields"] >= 1
        assert res["total_signed_signatures"] == 0
        assert res["consistency_status"] == "UNKNOWN"

        empty_findings = [f for f in res["findings"] if f["code"] == "SIGNATURE_FIELD_EMPTY"]
        assert len(empty_findings) >= 1
        assert "EmptySignatureField" in empty_findings[0]["description"]

    def test_05_multi_signature_valid_timeline(self):
        """Test full timeline extraction and verification for multi-signed PDF."""
        pdf_bytes = _generate_multi_signed_pdf(num_sigs=2)
        res = analyze_signature_timeline(pdf_bytes)

        assert res["timeline_status"] == "ANALYZED"
        assert res["status"] == "AVAILABLE"
        assert res["format"] == "PDF"
        assert res["signature_count"] == 2
        assert res["total_signed_signatures"] == 2
        assert res["total_signature_fields"] >= 2
        assert res["consistency_status"] == "CONSISTENT"
        assert res["chronology_confidence"] == "HIGH"
        assert res["timeline_order_confidence"] == "HIGH"
        assert len(res["events"]) == 2
        assert len(res["signatures"]) == 2

        # Check Signature 1 Event
        sig1 = res["events"][0]
        assert sig1["sequence"] == 1
        assert sig1["field_name"] == "Signature1"
        assert sig1["signer_name"] == "Alice Authority"
        assert sig1["cryptographic_status"] == "VALID"
        assert sig1["post_signature_change"] == "LEGITIMATE_INCREMENTAL_UPDATE"
        assert sig1["coverage_status"] == "VALID"
        assert sig1["signature_format"] == "CMS"

        # Check Signature 2 Event
        sig2 = res["events"][1]
        assert sig2["sequence"] == 2
        assert sig2["field_name"] == "Signature2"
        assert sig2["signer_name"] == "Bob CoSigner"
        assert sig2["cryptographic_status"] == "VALID"

        # Check Findings
        finding_codes = [f["code"] for f in res["findings"]]
        assert "MULTIPLE_SIGNATURES_PRESENT" in finding_codes
        assert "REVISION_SEQUENCE_DETECTED" in finding_codes
        assert "INCREMENTAL_UPDATE_DETECTED" in finding_codes
        assert "LEGITIMATE_INCREMENTAL_UPDATE" in finding_codes
        assert "CERTIFICATE_CHANGED" in finding_codes

    def test_06_tampered_multi_signature_pdf(self):
        """Test that altering bytes in Revision 1 marks Signature 1 as UNAUTHORIZED_SIGNED_CONTENT_CHANGE / INVALID."""
        pdf_bytes = bytearray(_generate_multi_signed_pdf(num_sigs=2))

        # Modify bytes in earlier signed region (e.g. at offset 1000)
        pdf_bytes[1000:1015] = b"FORGERY_MOD_RAW"

        res = analyze_signature_timeline(bytes(pdf_bytes))
        assert res["timeline_status"] == "ANALYZED"
        assert res["consistency_status"] == "INCONSISTENT"

        # At least one signature should be marked INVALID
        invalid_sigs = [s for s in res["events"] if s["cryptographic_status"] == "INVALID"]
        assert len(invalid_sigs) >= 1

    def test_07_single_signature_pdf_timeline(self):
        """Test timeline analysis on single signed document from test fixtures."""
        with open("original_signed_document.pdf", "rb") as f:
            pdf_bytes = f.read()

        res = analyze_signature_timeline(pdf_bytes)
        assert res["timeline_status"] == "ANALYZED"
        assert res["status"] == "AVAILABLE"
        assert res["signature_count"] == 1
        assert res["consistency_status"] == "CONSISTENT"
        assert len(res["events"]) == 1
        assert res["events"][0]["cryptographic_status"] == "VALID"

    def test_08_no_signatures_empty_pdf(self):
        """Test PDF with zero signatures returns NO_SIGNATURES status."""
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        buf0 = io.BytesIO()
        writer.write(buf0)

        res = analyze_signature_timeline(buf0.getvalue())
        assert res["status"] == "NO_SIGNATURES"
        assert res["signature_count"] == 0
        assert len(res["events"]) == 0
        finding_codes = [f["code"] for f in res["findings"]]
        assert "NO_SIGNATURES_PRESENT" in finding_codes

    def test_09_three_signatures_incremental_timeline(self):
        """Test PDF with 3 incremental co-signers."""
        pdf_bytes = _generate_multi_signed_pdf(num_sigs=3)
        res = analyze_signature_timeline(pdf_bytes)

        assert res["status"] == "AVAILABLE"
        assert res["signature_count"] == 3
        assert res["consistency_status"] == "CONSISTENT"
        assert res["chronology_confidence"] == "HIGH"
        assert len(res["events"]) == 3
        assert res["events"][0]["sequence"] == 1
        assert res["events"][1]["sequence"] == 2
        assert res["events"][2]["sequence"] == 3

    def test_10_same_signer_multiple_times(self):
        """Test multi-signature document where same signer signs multiple revisions."""
        pdf_bytes = _generate_multi_signed_pdf(num_sigs=2, same_signer=True)
        res = analyze_signature_timeline(pdf_bytes)

        assert res["status"] == "AVAILABLE"
        assert res["signature_count"] == 2
        assert res["events"][0]["signer_name"] == res["events"][1]["signer_name"]
        finding_codes = [f["code"] for f in res["findings"]]
        assert "MULTIPLE_SIGNATURES_PRESENT" in finding_codes
        # Since certificates are identical, CERTIFICATE_CHANGED should not be emitted
        assert "CERTIFICATE_CHANGED" not in finding_codes

    def test_11_cms_pkcs7_standalone_adapter(self):
        """Test standalone CMS/PKCS#7 adapter with synthetic ContentInfo."""
        # Simple synthetic test for Pkcs7CmsSignatureTimelineAdapter
        adapter = Pkcs7CmsSignatureTimelineAdapter(b"INVALID_OR_EMPTY_CMS_BYTES", "test.p7s")
        res = adapter.analyze()
        assert res["format"] == "CMS/PKCS#7"
        assert res["status"] in ("NOT_AVAILABLE", "NO_SIGNATURES")

    def test_12_xmldsig_adapter(self):
        """Test XMLDSig adapter with a structured XMLDSig document."""
        xml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<document>
  <data id="d1">Approved Content</data>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig-xml-1">
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    </ds:SignedInfo>
    <ds:SignatureValue>dummySigVal==</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:KeyName>Alice Authority</ds:KeyName>
    </ds:KeyInfo>
  </ds:Signature>
</document>"""
        res = analyze_signature_timeline(xml_content, file_type="XML", filename="document.xml")
        assert res["status"] == "AVAILABLE"
        assert res["format"] == "XMLDSig"
        assert res["signature_count"] == 1
        assert res["events"][0]["signature_id"] == "sig-xml-1"
        assert res["events"][0]["signature_format"] == "XMLDSig"

    def test_13_unsupported_format_docx_no_fabrication(self):
        """Test DOCX format returns explicit NOT_AVAILABLE with zero fabricated events."""
        docx_bytes = b"PK\x03\x04synthetic_docx_archive"
        res = analyze_signature_timeline(docx_bytes, file_type="DOCX", filename="contract.docx")
        assert res["status"] == "NOT_AVAILABLE"
        assert res["format"] == "DOCX"
        assert res["signature_count"] == 0
        assert len(res["events"]) == 0
        assert "Reliable signature chronology is not available" in res["reason"]
        finding_codes = [f["code"] for f in res["findings"]]
        assert "TIMELINE_NOT_AVAILABLE" in finding_codes

    def test_14_unsupported_binary_format_no_fabrication(self):
        """Test generic binary / text format returns NOT_AVAILABLE."""
        text_bytes = b"Hello, this is a plain text document without any signatures."
        res = analyze_signature_timeline(text_bytes, file_type="TXT", filename="notes.txt")
        assert res["status"] == "NOT_AVAILABLE"
        assert res["format"] == "TXT"
        assert res["signature_count"] == 0
        assert len(res["events"]) == 0
        assert res["reason"] is not None

    def test_15_anti_fabrication_explicit_values(self):
        """Test that unavailable information is explicitly marked UNKNOWN/null and never fabricated."""
        res = analyze_signature_timeline(b"", file_type="PDF", filename="empty.pdf")
        assert res["status"] == "NO_SIGNATURES"
        assert res["signature_count"] == 0
        assert res["events"] == []
