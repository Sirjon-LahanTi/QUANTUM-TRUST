import io
import os
import datetime
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pypdf import PdfWriter
from pypdf.generic import (
    DictionaryObject,
    ArrayObject,
    NameObject,
    NumberObject,
    DecodedStreamObject,
)

def create_base_pdf(title: str, body_lines: list[str]) -> io.BytesIO:
    """Creates a formatted PDF document with standard vector text."""
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)

    # Build PDF operators
    ops = []
    # Header bar
    ops.append("0.08 0.12 0.20 rg")
    ops.append("0 710 612 82 re f")
    
    # Title
    ops.append("BT /Helvetica-Bold 18 Tf 1 1 1 rg 50 748 Td (" + title + ") Tj ET")
    ops.append("BT /Courier-Bold 9 Tf 0.6 0.8 1.0 rg 50 728 Td (QUANTUMTRUST VERIFIED CRYPTOGRAPHIC SPECIMEN) Tj ET")

    # Document body
    y = 660
    ops.append("BT /Helvetica-Bold 12 Tf 0.1 0.1 0.1 rg 50 " + str(y) + " Td (DOCUMENT METADATA & CRYPTOGRAPHIC PAYLOAD) Tj ET")
    y -= 25

    for line in body_lines:
        if line.startswith("## "):
            y -= 12
            ops.append("BT /Helvetica-Bold 11 Tf 0.15 0.2 0.3 rg 50 " + str(y) + " Td (" + line[3:] + ") Tj ET")
            y -= 18
        elif line == "":
            y -= 8
        else:
            clean_line = line.replace("(", "\\(").replace(")", "\\)")
            ops.append("BT /Helvetica 10 Tf 0.2 0.2 0.2 rg 50 " + str(y) + " Td (" + clean_line + ") Tj ET")
            y -= 16

    # Footer
    ops.append("0.8 0.8 0.8 RG 1 w 50 75 m 562 75 l S")
    ops.append("BT /Courier 8 Tf 0.4 0.4 0.4 rg 50 60 Td (Digital Signature Protection: PKCS#7 / PAdES-BES RSA-2048 SHA-256) Tj ET")
    ops.append("BT /Courier 8 Tf 0.4 0.4 0.4 rg 50 48 Td (QuantumTrust Digital Signature Security Engine - Verification Sample) Tj ET")

    # Fonts dictionary
    font_dict = DictionaryObject({
        NameObject('/Helvetica'): DictionaryObject({
            NameObject('/Type'): NameObject('/Font'),
            NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/Helvetica'),
        }),
        NameObject('/Helvetica-Bold'): DictionaryObject({
            NameObject('/Type'): NameObject('/Font'),
            NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/Helvetica-Bold'),
        }),
        NameObject('/Courier'): DictionaryObject({
            NameObject('/Type'): NameObject('/Font'),
            NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/Courier'),
        }),
        NameObject('/Courier-Bold'): DictionaryObject({
            NameObject('/Type'): NameObject('/Font'),
            NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/Courier-Bold'),
        }),
    })

    if '/Resources' not in page:
        page[NameObject('/Resources')] = DictionaryObject()
    page['/Resources'][NameObject('/Font')] = font_dict

    stream_content = "\n".join(ops).encode("latin-1")
    stream_obj = DecodedStreamObject()
    stream_obj.set_data(stream_content)
    page[NameObject('/Contents')] = writer._add_object(stream_obj)

    buf = io.BytesIO()
    writer.write(buf)
    buf.seek(0)
    return buf

def generate_signed_pdf(
    output_path: str,
    subject_cn: str,
    org_name: str,
    valid_days_offset: int = 365,
    is_tampered: bool = False,
    is_expired: bool = False,
):
    print(f"Generating: {os.path.basename(output_path)} ...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Security & Trust Infrastructure'),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])

    if is_expired:
        not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=730)
        not_after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
    else:
        not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=valid_days_offset)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    ).sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        cf.write(cert_pem)
        kf.write(key_pem)
        c_path = cf.name
        k_path = kf.name

    signer = signers.SimpleSigner.load(
        key_file=k_path,
        cert_file=c_path,
        key_passphrase=None
    )

    os.unlink(c_path)
    os.unlink(k_path)

    body = [
        f"Document ID: QT-DOC-{os.path.basename(output_path).replace('.pdf','').upper()}",
        f"Signer Identity: {subject_cn}",
        f"Issuing Organization: {org_name}",
        f"Timestamp: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Security Verification Statement",
        "This official document is certified and cryptographically sealed under the",
        "QuantumTrust Digital Signature Verification Protocol. The cryptographic hash",
        "protects the integrity of all content elements, byte ranges, and associated metadata.",
        "",
        "## Technical Cryptographic Profile",
        "- Key Algorithm: RSA-2048 (2048-bit modulus)",
        "- Signature SubFilter: adbe.pkcs7.detached (PAdES compatible)",
        "- Hash Function: SHA-256 (256-bit cryptographic digest)",
        "- Trust Model: X.509 v3 Digital Certificate",
        "",
        "## Verification Notice",
        "Any unauthorized byte alteration or structural injection invalidates the cryptographic",
        "seal and triggers a TAMPERED verdict during automated document audit."
    ]

    base_pdf_buf = create_base_pdf(
        title="DIGITALLY SIGNED CERTIFICATE OF AUTHENTICITY",
        body_lines=body
    )

    w_inc = IncrementalPdfFileWriter(base_pdf_buf)
    fields.append_signature_field(
        w_inc,
        fields.SigFieldSpec(
            sig_field_name='Signature_QuantumTrust_1',
            box=(50, 95, 300, 140)
        )
    )
    
    out = io.BytesIO()
    signers.sign_pdf(
        w_inc,
        signers.PdfSignatureMetadata(
            field_name='Signature_QuantumTrust_1',
            reason='Certified and Digitally Sealed by QuantumTrust Authority',
            location='San Francisco, CA',
            contact_info='security@quantumtrust.org'
        ),
        signer=signer,
        output=out
    )
    
    signed_bytes = bytearray(out.getvalue())

    if is_tampered:
        print("  -> Injecting post-signature byte modification to test TAMPERED detection...")
        # Alter a byte in the signed range
        pos = signed_bytes.find(b"AUTHENTICITY")
        if pos != -1:
            signed_bytes[pos:pos+12] = b"FORGERY_MOD!"
        else:
            signed_bytes[500:512] = b"TAMPEREDBYTE"

    with open(output_path, "wb") as f:
        f.write(signed_bytes)
    
    print(f"  [OK] Created: {output_path} ({len(signed_bytes)} bytes)\n")


def generate_multi_signed_pdf(
    output_path: str,
    signer1_cn: str,
    signer1_org: str,
    signer2_cn: str,
    signer2_org: str,
    add_empty_field: bool = False,
):
    print(f"Generating Multi-Signed PDF: {os.path.basename(output_path)} ...")
    body = [
        f"Document ID: QT-MULTI-{os.path.basename(output_path).replace('.pdf','').upper()}",
        f"Primary Signer: {signer1_cn} ({signer1_org})",
        f"Secondary Signer: {signer2_cn} ({signer2_org})",
        f"Timestamp: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Dual-Party Authorization & Workflow Agreement",
        "This multi-party agreement is signed across sequential revisions using PAdES digital signatures.",
        "Both parties attest to the veracity and authenticity of the enclosed transaction payload.",
        "",
        "## Revision History Specification",
        "- Revision 1: Signed by Initial Approval Authority",
        "- Revision 2: Counter-signed via Legitimate Incremental Update by Second Authority",
        "- Structure: ByteRanges exclude signature /Contents placeholders cleanly",
    ]

    base_pdf_buf = create_base_pdf(
        title="DUAL-AUTHORIZED MULTI-SIGNATURE CERTIFICATE",
        body_lines=body
    )

    # 1. Signer 1
    key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject1 = issuer1 = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, signer1_org),
        x509.NameAttribute(NameOID.COMMON_NAME, signer1_cn),
    ])
    cert1 = x509.CertificateBuilder().subject_name(subject1).issuer_name(issuer1).public_key(key1.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).sign(key1, hashes.SHA256())

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf1, tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf1:
        cf1.write(cert1.public_bytes(serialization.Encoding.PEM))
        kf1.write(key1.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        c1_path, k1_path = cf1.name, kf1.name
    s1 = signers.SimpleSigner.load(key_file=k1_path, cert_file=c1_path)
    os.unlink(c1_path); os.unlink(k1_path)

    w1 = IncrementalPdfFileWriter(base_pdf_buf)
    fields.append_signature_field(w1, fields.SigFieldSpec('Signature_PrimaryAuthority_1', box=(50, 95, 270, 140)))
    if add_empty_field:
        fields.append_signature_field(w1, fields.SigFieldSpec('Signature_PendingApproval_3', box=(300, 45, 520, 90)))

    out1 = io.BytesIO()
    signers.sign_pdf(
        w1,
        signers.PdfSignatureMetadata(
            field_name='Signature_PrimaryAuthority_1',
            reason='Initial Document Certification & Authorization',
            location='San Francisco, CA',
            contact_info='sec-lead@quantumtrust.org'
        ),
        signer=s1,
        output=out1
    )

    # 2. Signer 2 (Incremental Co-Signer)
    key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject2 = issuer2 = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, signer2_org),
        x509.NameAttribute(NameOID.COMMON_NAME, signer2_cn),
    ])
    cert2 = x509.CertificateBuilder().subject_name(subject2).issuer_name(issuer2).public_key(key2.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).sign(key2, hashes.SHA256())

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf2, tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf2:
        cf2.write(cert2.public_bytes(serialization.Encoding.PEM))
        kf2.write(key2.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        c2_path, k2_path = cf2.name, kf2.name
    s2 = signers.SimpleSigner.load(key_file=k2_path, cert_file=c2_path)
    os.unlink(c2_path); os.unlink(k2_path)

    w2 = IncrementalPdfFileWriter(io.BytesIO(out1.getvalue()))
    fields.append_signature_field(w2, fields.SigFieldSpec('Signature_SecondaryCoSigner_2', box=(300, 95, 520, 140)))
    out2 = io.BytesIO()
    signers.sign_pdf(
        w2,
        signers.PdfSignatureMetadata(
            field_name='Signature_SecondaryCoSigner_2',
            reason='Counter-Signature & Risk Management Approval',
            location='Zurich, Switzerland',
            contact_info='audit@quantumtrust.ch'
        ),
        signer=s2,
        output=out2
    )

    final_bytes = out2.getvalue()
    with open(output_path, "wb") as f:
        f.write(final_bytes)
    print(f"  [OK] Created: {output_path} ({len(final_bytes)} bytes)\n")


if __name__ == "__main__":
    root_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Authentic / Valid signed document
    valid_pdf = os.path.join(root_dir, "demo_valid_signed_document.pdf")
    generate_signed_pdf(
        valid_pdf,
        subject_cn="Alice Smith (Chief Information Security Officer)",
        org_name="QuantumTrust Global Security Inc.",
        valid_days_offset=365
    )

    # 2. Tampered signed document (Modified post-signature)
    tampered_pdf = os.path.join(root_dir, "demo_tampered_signed_document.pdf")
    generate_signed_pdf(
        tampered_pdf,
        subject_cn="Dr. Robert Vance (VP Engineering)",
        org_name="QuantumTrust Enterprise Labs",
        is_tampered=True
    )

    # 3. Expired certificate signed document
    expired_pdf = os.path.join(root_dir, "demo_expired_cert_signed_document.pdf")
    generate_signed_pdf(
        expired_pdf,
        subject_cn="Legacy Signer CA",
        org_name="Old Security Authority",
        is_expired=True
    )

    # 4. Multi-signed valid PDF (2 valid signatures across incremental updates)
    multisig_valid_pdf = os.path.join(root_dir, "demo_multisig_valid_signed_document.pdf")
    generate_multi_signed_pdf(
        multisig_valid_pdf,
        signer1_cn="Alice Smith (CISO)",
        signer1_org="QuantumTrust Global Security Inc.",
        signer2_cn="Dr. Bob Vance (VP Engineering)",
        signer2_org="QuantumTrust Enterprise Labs",
        add_empty_field=False
    )

    # 5. Multi-signed PDF with empty pending field
    multisig_empty_field_pdf = os.path.join(root_dir, "demo_multisig_with_empty_field.pdf")
    generate_multi_signed_pdf(
        multisig_empty_field_pdf,
        signer1_cn="Director Sarah Connor",
        signer1_org="QuantumTrust Defense Authority",
        signer2_cn="Chief Auditor John Smith",
        signer2_org="Independent Trust Auditor Corp",
        add_empty_field=True
    )

    print("All demo test PDFs created successfully in project root!")
