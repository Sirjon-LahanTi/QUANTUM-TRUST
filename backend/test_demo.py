import io
import json
import os
import tempfile
import urllib.request
import uuid
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pypdf import PdfWriter

# 1. Generate key and certificate
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'QuantumTrust Demo Org'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'Demo Signer'),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
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

# 2. Build PDF
w = PdfWriter()
w.add_blank_page(width=300, height=300)
buf = io.BytesIO()
w.write(buf)
buf.seek(0)

# 3. Sign PDF
w_inc = IncrementalPdfFileWriter(buf)
fields.append_signature_field(
    w_inc, fields.SigFieldSpec(sig_field_name='Signature1')
)
out = io.BytesIO()
signers.sign_pdf(
    w_inc,
    signers.PdfSignatureMetadata(field_name='Signature1'),
    signer=signer,
    output=out
)
signed_pdf_bytes = out.getvalue()
print(f"Generated signed PDF: {len(signed_pdf_bytes)} bytes")

# Save as demo_signed.pdf in project root for user testing
demo_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_signed.pdf"))
with open(demo_file_path, "wb") as f:
    f.write(signed_pdf_bytes)
print(f"Saved demo PDF to {demo_file_path}")

# 4. Upload to API
boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

body = bytearray()
body.extend(f"--{boundary}\r\n".encode("utf-8"))
body.extend(b'Content-Disposition: form-data; name="file"; filename="demo_signed.pdf"\r\n')
body.extend(b"Content-Type: application/pdf\r\n\r\n")
body.extend(signed_pdf_bytes)
body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

req = urllib.request.Request("http://127.0.0.1:8000/api/analyze", data=bytes(body), headers=headers)
try:
    with urllib.request.urlopen(req) as resp:
        print("HTTP Status:", resp.status)
        data = json.loads(resp.read().decode("utf-8"))
        print("\n--- ANALYSIS RESULT ---")
        print("Analysis ID:", data.get("analysis_id"))
        print("Verdict:", data.get("verdict"))
        print("Signature Info:", data.get("signature"))
        print("Certificate Info:", data.get("certificate"))
        print("Integrity Info:", data.get("integrity"))
        print("Threat Level:", data.get("security", {}).get("threat_level"))
        print("Threat Score:", data.get("security", {}).get("threat_score"))
except Exception as e:
    print("Request failed:", e)
