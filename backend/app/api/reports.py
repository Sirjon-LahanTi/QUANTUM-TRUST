"""
QuantumTrust — GET /api/analysis/{id}/report
Returns an HTML security report for a given analysis.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.analysis import Analysis

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/analysis/{analysis_id}/report", response_class=HTMLResponse)
async def get_report(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Generate and return an HTML security analysis report."""
    stmt = select(Analysis).where(Analysis.analysis_id == analysis_id)
    record = await db.scalar(stmt)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found.",
        )

    r = record.get_full_result()
    generated_at = datetime.now(timezone.utc).isoformat()

    doc  = r.get("document", {})
    sig  = r.get("signature", {})
    cert = r.get("certificate", {})
    intg = r.get("integrity", {})
    dup  = r.get("duplicate", {})
    sec  = r.get("security", {})
    q    = r.get("quantum_analysis", {})
    verdict = r.get("verdict", "UNKNOWN")

    verdict_color = {
        "AUTHENTIC": "#22C55E",
        "TAMPERED":  "#EF4444",
        "SUSPICIOUS":"#F59E0B",
    }.get(verdict, "#4A5A78")

    threat_color = {
        "LOW":      "#22C55E",
        "MEDIUM":   "#F59E0B",
        "HIGH":     "#F59E0B",
        "CRITICAL": "#EF4444",
    }.get((sec.get("threat_level") or "").upper(), "#4A5A78")

    threats_html = "".join(
        f"<li style='margin:4px 0;color:#EF4444;font-family:monospace;font-size:13px;'>⚠ {t}</li>"
        for t in sec.get("detected_threats", [])
    ) or "<li style='color:#4A5A78;font-family:monospace;font-size:13px;'>No threats detected</li>"

    def val(v: Any, fallback: str = "Not available") -> str:
        return str(v) if v is not None else fallback

    def row(label: str, value: Any, mono: bool = False) -> str:
        style = "font-family:monospace;color:#A8C4F0;" if mono else ""
        return f"""
        <tr>
          <td style='padding:8px 12px;color:#7A90B8;font-family:monospace;font-size:12px;width:200px;border-bottom:1px solid #131D2E;'>{label}</td>
          <td style='padding:8px 12px;{style}font-size:13px;border-bottom:1px solid #131D2E;'>{val(value)}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>QuantumTrust Security Report — {doc.get('filename','Document')}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #080C12; color: #E2E8F5; font-family: 'Segoe UI', system-ui, sans-serif; font-size: 15px; line-height: 1.6; padding: 40px; }}
  .report-header {{ border-bottom: 2px solid #1E2D45; padding-bottom: 24px; margin-bottom: 32px; }}
  .brand {{ font-family: monospace; font-size: 13px; color: #3B7DD8; margin-bottom: 8px; letter-spacing: 0.04em; }}
  h1 {{ font-family: monospace; font-size: 28px; font-weight: 700; color: #E2E8F5; margin-bottom: 4px; }}
  .meta {{ font-family: monospace; font-size: 12px; color: #3D4F6A; margin-top: 8px; }}
  .verdict-box {{ text-align: center; padding: 32px; border: 1px solid; border-radius: 4px; margin-bottom: 32px; }}
  .verdict-word {{ font-family: monospace; font-size: 44px; font-weight: 700; letter-spacing: 0.08em; }}
  .verdict-sub  {{ font-family: monospace; font-size: 12px; color: #3D4F6A; margin-top: 8px; }}
  .section {{ margin-bottom: 32px; }}
  .section-title {{ font-family: monospace; font-size: 12px; color: #3D4F6A; font-weight: 600; padding-bottom: 8px; border-bottom: 1px solid #131D2E; margin-bottom: 16px; letter-spacing: 0.04em; }}
  table {{ width: 100%; border-collapse: collapse; background: #0F1520; border: 1px solid #1E2D45; border-radius: 4px; }}
  .footer {{ margin-top: 40px; padding-top: 24px; border-top: 1px solid #131D2E; font-family: monospace; font-size: 11px; color: #3D4F6A; }}
  @media print {{ body {{ background: white; color: black; }} }}
</style>
</head>
<body>
  <div class="report-header">
    <div class="brand">QUANTUMTRUST — SECURITY ANALYSIS REPORT</div>
    <h1>{val(doc.get('filename'), 'Document Analysis')}</h1>
    <div class="meta">
      Analysis ID: {val(analysis_id)} &nbsp;&nbsp;|&nbsp;&nbsp;
      Generated: {generated_at} &nbsp;&nbsp;|&nbsp;&nbsp;
      Original analysis: {val(r.get('created_at'))}
    </div>
  </div>

  <div class="verdict-box" style="background:{verdict_color}18;border-color:{verdict_color}40;">
    <div class="verdict-word" style="color:{verdict_color};">{verdict}</div>
    <div class="verdict-sub">Final Security Verdict</div>
  </div>

  <div class="section">
    <div class="section-title">DOCUMENT INFORMATION</div>
    <table>
      {row('Filename', doc.get('filename'))}
      {row('File Size', f"{doc.get('file_size', 0):,} bytes")}
      {row('PDF Version', doc.get('pdf_version'))}
      {row('Fingerprint (SHA-256)', doc.get('fingerprint'), mono=True)}
    </table>
  </div>

  <div class="section">
    <div class="section-title">DIGITAL SIGNATURE</div>
    <table>
      {row('Signature Present', 'Yes' if sig.get('present') else 'No')}
      {row('Signature Count', sig.get('count'))}
      {row('Signature Status', sig.get('status'))}
      {row('Signature Type', sig.get('signature_type'))}
      {row('Digest Algorithm', sig.get('digest_algorithm'), mono=True)}
      {row('Signature Algorithm', sig.get('signature_algorithm'), mono=True)}
      {row('Public Key Algorithm', sig.get('public_key_algorithm'), mono=True)}
      {row('Key Size', f"{sig.get('key_size')} bits" if sig.get('key_size') else None)}
    </table>
  </div>

  <div class="section">
    <div class="section-title">CERTIFICATE</div>
    <table>
      {row('Subject', cert.get('subject'))}
      {row('Issuer', cert.get('issuer'))}
      {row('Serial Number', cert.get('serial_number'), mono=True)}
      {row('Valid From', cert.get('valid_from'))}
      {row('Valid Until', cert.get('valid_until'))}
      {row('Trust Status', cert.get('trust_status'))}
    </table>
  </div>

  <div class="section">
    <div class="section-title">DOCUMENT INTEGRITY</div>
    <table>
      {row('Integrity Status', intg.get('status'))}
      {row('Modification Status', intg.get('modification_status'))}
      {row('Signed ByteRange', str(intg.get('byte_range', 'Not available')), mono=True)}
    </table>
  </div>

  <div class="section">
    <div class="section-title">DUPLICATE DETECTION</div>
    <table>
      {row('Is Duplicate', 'Yes' if dup.get('is_duplicate') else 'No')}
      {row('Match Type', dup.get('match_type'))}
      {row('Matching Analysis ID', dup.get('matching_analysis_id'), mono=True)}
    </table>
  </div>

  <div class="section">
    <div class="section-title">THREAT ANALYSIS</div>
    <table>
      <tr>
        <td style='padding:8px 12px;color:#7A90B8;font-family:monospace;font-size:12px;width:200px;border-bottom:1px solid #131D2E;'>Threat Score</td>
        <td style='padding:8px 12px;font-family:monospace;font-size:18px;font-weight:700;color:{threat_color};border-bottom:1px solid #131D2E;'>{val(sec.get('threat_score'))} / 100</td>
      </tr>
      <tr>
        <td style='padding:8px 12px;color:#7A90B8;font-family:monospace;font-size:12px;width:200px;border-bottom:1px solid #131D2E;'>Threat Level</td>
        <td style='padding:8px 12px;font-family:monospace;font-size:13px;color:{threat_color};border-bottom:1px solid #131D2E;'>{val(sec.get('threat_level'))}</td>
      </tr>
      <tr>
        <td style='padding:8px 12px;color:#7A90B8;font-family:monospace;font-size:12px;width:200px;'>Detected Threats</td>
        <td style='padding:8px 12px;'>
          <ul style='list-style:none;padding:0;margin:0;'>{threats_html}</ul>
        </td>
      </tr>
    </table>
  </div>

  <div class="section">
    <div class="section-title">QUANTUM-INSPIRED ANALYSIS (CLASSICAL SIMULATION)</div>
    <table>
      {row('State Dimension',   q.get('state_dimension', 14), mono=True)}
      {row('State Similarity',  q.get('state_similarity'),  mono=True)}
      {row('Correlation Score', q.get('correlation_score'), mono=True)}
      {row('Disturbance Score', q.get('disturbance_score'), mono=True)}
      {row('Anomaly Distance',  q.get('anomaly_distance'),  mono=True)}
      {row('Entropy',           q.get('entropy'),           mono=True)}
      {row('Reference Baseline',q.get('reference_type', 'deterministic_baseline'), mono=True)}
    </table>
    <p style='margin-top:8px;font-size:11px;color:#3D4F6A;font-family:monospace;'>
      Classical simulation of quantum-inspired mathematical representations used as an additional security signal.
      This does not involve real quantum hardware, quantum entanglement, or quantum measurements.
    </p>
  </div>

  <div class="footer">
    QuantumTrust &mdash; Quantum-Inspired Digital Signature Security &nbsp;|&nbsp;
    This report was generated automatically. &nbsp;|&nbsp;
    QuantumTrust never requires or stores private signing keys.
  </div>
</body>
</html>"""

    return HTMLResponse(content=html, status_code=200)
