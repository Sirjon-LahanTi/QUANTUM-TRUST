import urllib.request
import uuid
import json
import os

files = [
    'demo_valid_signed_document.pdf',
    'demo_tampered_signed_document.pdf',
    'demo_expired_cert_signed_document.pdf',
]

for name in files:
    if not os.path.exists(name):
        print(f"File {name} not found.")
        continue
    with open(name, 'rb') as f:
        data = f.read()
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'.encode("utf-8"))
    body.extend(b"Content-Type: application/pdf\r\n\r\n")
    body.extend(data)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request("http://127.0.0.1:8000/api/analyze", data=bytes(body), headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            print(f"File: {name}")
            print(f"  Verdict:       {res.get('verdict')}")
            print(f"  Signature:     {res.get('signature', {}).get('status')}")
            print(f"  Signer:        {res.get('certificate', {}).get('subject')}")
            print(f"  Integrity:     {res.get('integrity', {}).get('status')}")
            print(f"  Threat Score:  {res.get('security', {}).get('threat_score')} / 100 ({res.get('security', {}).get('threat_level')})")
            print(f"  Analysis URL:  http://localhost:4321/security?id={res.get('analysis_id')}")
            print()
    except Exception as e:
        print(f"Error testing {name}: {e}")
