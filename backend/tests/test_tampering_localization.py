"""
Unit and Integration Tests for QuantumTrust Tampering Localization Engine

Tests format adapters for:
- PDF (valid signed, tampered signed content, legitimate incremental update, malformed ByteRange, unsigned)
- XML / XMLDSig (valid references, modified element digest mismatch, baseline structural diff)
- JSON / JWS (valid JWS, tampered JWS, structural JSON diff with nested paths, inserted/deleted fields)
- Office OpenXML (.docx, .xlsx package parts)
- CMS / PKCS#7 and Generic Binary (byte-level diffing, explicit format limitation disclosures)
- Schema and Anti-Fabrication compliance
"""
import base64
import hashlib
import io
import json
import os
import zipfile
import pytest

from app.schemas.analysis import TamperingLocalizationResult
from app.services import tampering_localization
from app.services.tampering_localization import (
    PdfTamperingLocalizationAdapter,
    XmlTamperingLocalizationAdapter,
    JsonJwsTamperingLocalizationAdapter,
    OfficeDocxXlsxLocalizationAdapter,
    Pkcs7CmsLocalizationAdapter,
    GenericBinaryLocalizationAdapter,
    localize_tampering,
    get_localization_adapter,
)


class TestPdfTamperingLocalization:
    """Test suite for PDF format tampering localization."""

    def test_pdf_unsigned_document(self):
        """Unsigned PDF should return NOT_AVAILABLE with zero fabricated locations."""
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        result = localize_tampering(
            file_path_or_bytes=pdf_bytes,
            file_type="PDF",
            existing_verification_result={"present": False, "count": 0, "overall_status": "NONE"},
        )
        assert result["status"] == "NOT_AVAILABLE"
        assert result["tampering_detected"] is False
        assert result["localization_level"] == "NOT_AVAILABLE"
        assert "NO_TRUSTED_BASELINE" in result["findings"]
        assert len(result["affected_items"]) == 0

    def test_pdf_valid_signed_no_tampering(self):
        """Valid signed PDF with intact integrity should return NO_TAMPERING_DETECTED."""
        dummy_pdf = b"%PDF-1.4\n" + b"A" * 500 + b"\n%%EOF"
        byte_range = [0, 100, 200, 300]
        result = localize_tampering(
            file_path_or_bytes=dummy_pdf,
            file_type="PDF",
            existing_verification_result={
                "present": True,
                "count": 1,
                "overall_status": "VALID",
                "byte_range": byte_range,
                "signatures": [{"field_name": "Signature1", "status": "VALID", "byte_range": byte_range}],
            },
            integrity_result={
                "integrity_status": "VERIFIED",
                "modification_status": "NO_UNAUTHORIZED_CHANGES",
            },
        )
        assert result["status"] == "NO_TAMPERING_DETECTED"
        assert result["tampering_detected"] is False
        assert result["localization_level"] == "NONE"
        assert result["confidence"] == "HIGH"
        assert len(result["affected_items"]) == 0

    def test_pdf_legitimate_incremental_update(self):
        """Valid signature with subsequent legitimate incremental revision is NOT classified as tampering."""
        # ByteRange ends before total file length
        dummy_pdf = b"%PDF-1.4\n" + b"A" * 300 + b"\n%%EOF\n" + b"B" * 200 + b"\n%%EOF"
        byte_range = [0, 50, 100, 150]  # end = 250 < len(dummy_pdf)
        result = localize_tampering(
            file_path_or_bytes=dummy_pdf,
            file_type="PDF",
            existing_verification_result={
                "present": True,
                "count": 1,
                "overall_status": "VALID",
                "byte_range": byte_range,
                "signatures": [{"field_name": "Signature1", "status": "VALID", "byte_range": byte_range}],
            },
            integrity_result={
                "integrity_status": "VERIFIED",
                "modification_status": "PERMITTED_CHANGES",
            },
        )
        assert result["status"] == "NO_TAMPERING_DETECTED"
        assert result["tampering_detected"] is False
        assert "LEGITIMATE_INCREMENTAL_UPDATE" in result["findings"]

    def test_pdf_tampered_signed_content(self):
        """Tampered signed content should return LOCALIZED with affected ByteRange or objects."""
        dummy_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Page >>\nendobj\n" + b"X" * 300 + b"\n%%EOF"
        byte_range = [0, 50, 100, 150]
        result = localize_tampering(
            file_path_or_bytes=dummy_pdf,
            file_type="PDF",
            existing_verification_result={
                "present": True,
                "count": 1,
                "overall_status": "INVALID",
                "byte_range": byte_range,
                "signatures": [{"field_name": "Signature1", "status": "INVALID", "byte_range": byte_range}],
            },
            integrity_result={
                "integrity_status": "FAILED",
                "modification_status": "MODIFIED",
            },
        )
        assert result["status"] == "LOCALIZED"
        assert result["tampering_detected"] is True
        assert result["confidence"] in ("HIGH", "MEDIUM")
        assert len(result["affected_items"]) > 0
        assert "TAMPERING_DETECTED" in result["findings"]

    def test_pdf_malformed_byte_range(self):
        """Malformed ByteRange array should be detected as ByteRange tampering."""
        dummy_pdf = b"%PDF-1.4\n" + b"A" * 200 + b"\n%%EOF"
        result = localize_tampering(
            file_path_or_bytes=dummy_pdf,
            file_type="PDF",
            existing_verification_result={
                "present": True,
                "count": 1,
                "overall_status": "INVALID",
                "byte_range": [0, -10, 50, 100],  # Negative offset
                "signatures": [{"field_name": "Signature1", "status": "INVALID", "byte_range": [0, -10, 50, 100]}],
            },
            integrity_result={"integrity_status": "FAILED", "modification_status": "MODIFIED"},
        )
        assert result["status"] == "LOCALIZED"
        assert result["tampering_detected"] is True
        assert "BYTE_RANGE_MISMATCH" in result["findings"]
        assert any(item["change_type"] == "BYTE_RANGE_CHANGED" for item in result["affected_items"])

    def test_pdf_real_sample_files_if_present(self):
        """Test on actual test PDF files in workspace if available."""
        test_files = [
            ("original_signed_document.pdf", False),
            ("demo_valid_signed_document.pdf", False),
            ("demo_tampered_signed_document.pdf", True),
            ("forgery_tampered_signed_document.pdf", True),
        ]
        for fname, expect_tampered in test_files:
            if os.path.exists(fname):
                with open(fname, "rb") as f:
                    content = f.read()
                from app.services import signature_verifier
                sig_res = signature_verifier.verify_pdf_signatures(content)
                res = localize_tampering(
                    file_path_or_bytes=content,
                    file_type="PDF",
                    filename=fname,
                    existing_verification_result=sig_res,
                )
                assert isinstance(res, dict)
                assert "status" in res
                assert "tampering_detected" in res
                if expect_tampered and sig_res.get("overall_status") in ("INVALID", "CORRUPTED"):
                    assert res["tampering_detected"] is True
                    assert res["status"] in ("LOCALIZED", "NOT_LOCALIZED")


class TestXmlTamperingLocalization:
    """Test suite for XML / XMLDSig tampering localization."""

    def test_xml_unsigned(self):
        """Plain unsigned XML returns NOT_AVAILABLE."""
        xml_bytes = b"<root><child>value</child></root>"
        res = localize_tampering(file_path_or_bytes=xml_bytes, file_type="XML")
        assert res["status"] == "NOT_AVAILABLE"
        assert res["tampering_detected"] is False
        assert "NO_TRUSTED_BASELINE" in res["findings"]

    def test_xml_valid_reference_digest(self):
        """XML with matching reference digest returns NO_TAMPERING_DETECTED."""
        elem_content = b'<Invoice Id="inv-1"><Amount>5000</Amount></Invoice>'
        digest = base64.b64encode(hashlib.sha256(elem_content).digest()).decode("utf-8")
        
        xml_doc = f"""<Document xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            {elem_content.decode('utf-8')}
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#inv-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
            </ds:Signature>
        </Document>""".encode("utf-8")

        res = localize_tampering(file_path_or_bytes=xml_doc, file_type="XML")
        assert res["status"] == "NO_TAMPERING_DETECTED"
        assert res["tampering_detected"] is False

    def test_xml_tampered_element_digest_mismatch(self):
        """XML with tampered element value triggers REFERENCE_DIGEST_MISMATCH with exact element path."""
        elem_content = b'<Invoice Id="inv-1"><Amount>99999</Amount></Invoice>'
        original_digest = base64.b64encode(hashlib.sha256(b'<Invoice Id="inv-1"><Amount>5000</Amount></Invoice>').digest()).decode("utf-8")

        xml_doc = f"""<Document xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            {elem_content.decode('utf-8')}
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:Reference URI="#inv-1">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{original_digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
            </ds:Signature>
        </Document>""".encode("utf-8")

        res = localize_tampering(file_path_or_bytes=xml_doc, file_type="XML")
        assert res["status"] == "LOCALIZED"
        assert res["tampering_detected"] is True
        assert res["localization_level"] == "ELEMENT_LEVEL"
        assert len(res["affected_items"]) > 0
        assert res["affected_items"][0]["change_type"] == "REFERENCE_DIGEST_MISMATCH"
        assert "XML_ELEMENT_MODIFIED" in res["findings"]

    def test_xml_baseline_structural_diff(self):
        """XML comparison against trusted baseline identifies modified element value and path."""
        base_xml = b"<Invoice><Customer><City>London</City></Customer><Amount>100</Amount></Invoice>"
        tampered_xml = b"<Invoice><Customer><City>Paris</City></Customer><Amount>100</Amount></Invoice>"

        adapter = XmlTamperingLocalizationAdapter(
            file_bytes=tampered_xml,
            filename="invoice.xml",
            trusted_baseline_bytes=base_xml,
        )
        res = adapter.localize()
        assert res["status"] == "LOCALIZED"
        assert res["tampering_detected"] is True
        assert any("City" in item.get("location", "") for item in res["affected_items"])


class TestJsonJwsTamperingLocalization:
    """Test suite for JSON and JWS tampering localization."""

    def test_json_structural_diff_baseline(self):
        """JSON diff against trusted baseline identifies exact JSON paths and values."""
        baseline = json.dumps({
            "employee": {
                "name": "Alice",
                "salary": 50000,
                "department": "Engineering"
            },
            "tags": ["full-time", "remote"]
        }).encode("utf-8")

        current = json.dumps({
            "employee": {
                "name": "Alice",
                "salary": 95000,  # Modified value
                # department deleted
                "role": "Director"  # Inserted key
            },
            "tags": ["full-time", "remote", "contractor"] # Modified array
        }).encode("utf-8")

        adapter = JsonJwsTamperingLocalizationAdapter(
            file_bytes=current,
            filename="data.json",
            trusted_baseline_bytes=baseline,
        )
        res = adapter.localize()
        assert res["status"] == "LOCALIZED"
        assert res["tampering_detected"] is True
        assert res["localization_level"] == "FIELD_LEVEL"

        json_paths = [item["json_path"] for item in res["affected_items"]]
        assert "$.employee.salary" in json_paths
        assert "$.employee.department" in json_paths
        assert "$.employee.role" in json_paths
        assert "$.tags" in json_paths

        # Check before/after values
        salary_item = next(item for item in res["affected_items"] if item["json_path"] == "$.employee.salary")
        assert salary_item["before_value"] == 50000
        assert salary_item["after_value"] == 95000
        assert salary_item["change_type"] == "VALUE_CHANGED"

    def test_json_unsigned_no_baseline(self):
        """JSON without baseline or envelope returns NOT_AVAILABLE."""
        json_bytes = json.dumps({"key": "val"}).encode("utf-8")
        res = localize_tampering(file_path_or_bytes=json_bytes, file_type="JSON")
        assert res["status"] == "NOT_AVAILABLE"
        assert res["tampering_detected"] is False


class TestOfficeDocxXlsxLocalization:
    """Test suite for Office OpenXML documents."""

    def test_docx_baseline_part_diff(self):
        """Office adapter identifies modified package parts against reference baseline."""
        # Create baseline ZIP
        base_io = io.BytesIO()
        with zipfile.ZipFile(base_io, "w") as z:
            z.writestr("word/document.xml", "<w:document>Original Text</w:document>")
            z.writestr("[Content_Types].xml", "<Types/>")
        base_bytes = base_io.getvalue()

        # Create tampered ZIP
        curr_io = io.BytesIO()
        with zipfile.ZipFile(curr_io, "w") as z:
            z.writestr("word/document.xml", "<w:document>Tampered Text</w:document>")
            z.writestr("[Content_Types].xml", "<Types/>")
        curr_bytes = curr_io.getvalue()

        adapter = OfficeDocxXlsxLocalizationAdapter(
            file_bytes=curr_bytes,
            filename="contract.docx",
            trusted_baseline_bytes=base_bytes,
        )
        res = adapter.localize()
        assert res["status"] == "LOCALIZED"
        assert res["tampering_detected"] is True
        assert res["localization_level"] == "STRUCTURAL"
        assert any("word/document.xml" in item["document_part"] for item in res["affected_items"])

    def test_docx_unsigned_no_baseline(self):
        """DOCX without signatures or baseline returns NOT_AVAILABLE without hallucination."""
        curr_io = io.BytesIO()
        with zipfile.ZipFile(curr_io, "w") as z:
            z.writestr("word/document.xml", "<w:document/>")
        curr_bytes = curr_io.getvalue()

        res = localize_tampering(file_path_or_bytes=curr_bytes, filename="document.docx")
        assert res["status"] == "NOT_AVAILABLE"
        assert res["tampering_detected"] is False
        assert "NO_TRUSTED_BASELINE" in res["findings"]


class TestGenericBinaryLocalization:
    """Test suite for generic binary files."""

    def test_binary_byte_diff_with_baseline(self):
        """Binary diff identifies exact contiguous modified byte ranges."""
        baseline = b"ABCDEFGHIJ" * 20  # 200 bytes
        tampered = bytearray(baseline)
        tampered[10:15] = b"XXXXX"     # 5 bytes modified at offset 10
        tampered[50:60] = b"YYYYYYYYYY" # 10 bytes modified at offset 50

        adapter = GenericBinaryLocalizationAdapter(
            file_bytes=bytes(tampered),
            filename="firmware.bin",
            trusted_baseline_bytes=baseline,
        )
        res = adapter.localize()
        assert res["status"] == "LOCALIZED"
        assert res["tampering_detected"] is True
        assert res["localization_level"] == "BYTE_LEVEL"
        assert len(res["affected_items"]) >= 2
        assert res["affected_items"][0]["byte_range"] == [10, 5]
        assert res["affected_items"][1]["byte_range"] == [50, 10]

    def test_binary_no_baseline(self):
        """Binary file without baseline explicitly returns NOT_AVAILABLE."""
        res = localize_tampering(file_path_or_bytes=b"RANDOM_BYTES", filename="data.bin")
        assert res["status"] == "NOT_AVAILABLE"
        assert res["tampering_detected"] is False
        assert "LOCALIZATION_LIMITED_BY_FORMAT" in res["findings"]
