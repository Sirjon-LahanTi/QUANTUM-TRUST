import os
import sys

sys.path.insert(0, ".")
from app.services import signature_verifier, certificate_analyzer, duplicate_detector, pdf_parser, threat_engine, quantum_analysis

test_files = [
    "../demo_valid_signed_document.pdf",
    "../demo_tampered_signed_document.pdf",
    "../demo_expired_cert_signed_document.pdf",
]

for fpath in test_files:
    if not os.path.exists(fpath):
        continue
    with open(fpath, "rb") as f:
        data = f.read()

    pdf_s = pdf_parser.parse_pdf_structure(data)
    sig_s = signature_verifier.verify_pdf_signatures(data)
    cert_info = {}
    if sig_s.get("signatures") and sig_s["signatures"][0].get("_cert_object"):
        cert_info = certificate_analyzer.analyze_certificate(sig_s["signatures"][0]["_cert_object"])
    
    integ = {
        "integrity_status": sig_s.get("integrity_status", "UNKNOWN"),
        "modification_status": sig_s.get("integrity_modification_status", "UNKNOWN"),
        "byte_range": sig_s.get("byte_range"),
    }
    dup = {"is_duplicate": False}

    q = quantum_analysis.run_quantum_analysis(sig_s, cert_info, integ, pdf_s, dup)
    threat = threat_engine.calculate_threat(sig_s, cert_info, integ, pdf_s, dup, q)
    verdict = threat_engine.determine_verdict(sig_s, cert_info, integ, threat)

    print(f"=== {os.path.basename(fpath)} ===")
    print(f"  Verdict:           {verdict}")
    print(f"  Signature Status:  {sig_s.get('overall_status')}")
    print(f"  Threat Score:      {threat.get('threat_score')} / 100 ({threat.get('threat_level')})")
    print(f"  State Dimension:   {q.get('state_dimension')}")
    print(f"  State Similarity:  {q.get('state_similarity')}")
    print(f"  Correlation Score: {q.get('correlation_score')}")
    print(f"  Disturbance Score: {q.get('disturbance_score')}")
    print(f"  Anomaly Distance:  {q.get('anomaly_distance')}")
    print(f"  Entropy:           {q.get('entropy')}")
    print(f"  Reference Type:    {q.get('reference_type')}")
    print()
