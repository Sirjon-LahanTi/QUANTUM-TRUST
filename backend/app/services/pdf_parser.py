"""
QuantumTrust — PDF structural parser (pypdf layer)

Responsible for:
- PDF version detection
- Page count, metadata
- Suspicious structural signals
- Does NOT perform signature cryptography (that's signature_verifier.py)
"""
from __future__ import annotations
import io
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_pdf_structure(pdf_bytes: bytes) -> dict[str, Any]:
    """
    Parse PDF structural information using pypdf.

    Returns a dict with:
        pdf_version, page_count, metadata, suspicious_signals, parse_error
    """
    result: dict[str, Any] = {
        "pdf_version": None,
        "page_count": None,
        "metadata": {},
        "suspicious_signals": [],
        "has_js": False,
        "has_embedded_files": False,
        "has_form_fields": False,
        "incremental_update_count": 0,
        "parse_error": None,
    }

    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError

        reader = PdfReader(io.BytesIO(pdf_bytes), strict=False)

        # PDF version
        try:
            header = pdf_bytes[:8].decode("latin-1", errors="replace")
            if header.startswith("%PDF-"):
                result["pdf_version"] = header[5:8].strip()
        except Exception:
            pass

        # Page count
        try:
            result["page_count"] = len(reader.pages)
        except Exception:
            pass

        # Metadata (sanitized — do not trust)
        try:
            meta = reader.metadata
            if meta:
                safe_meta: dict[str, str] = {}
                for k, v in meta.items():
                    try:
                        safe_meta[str(k)] = str(v)[:512]
                    except Exception:
                        pass
                result["metadata"] = safe_meta
        except Exception:
            pass

        # Suspicious structural signals
        signals: list[str] = []

        # JavaScript
        try:
            root = reader.trailer.get("/Root", {})
            if root and "/Names" in root:
                names = root["/Names"]
                if "/JavaScript" in names or "/JS" in names:
                    result["has_js"] = True
                    signals.append("JavaScript present in PDF")
        except Exception:
            pass

        # Embedded files
        try:
            root = reader.trailer.get("/Root", {})
            if root and "/Names" in root:
                names = root["/Names"]
                if "/EmbeddedFiles" in names:
                    result["has_embedded_files"] = True
                    signals.append("Embedded files detected")
        except Exception:
            pass

        # Form fields
        try:
            if reader.get_fields():
                result["has_form_fields"] = True
        except Exception:
            pass

        # Count incremental updates (%%EOF occurrences)
        try:
            eof_count = pdf_bytes.count(b"%%EOF")
            result["incremental_update_count"] = max(0, eof_count - 1)
            if eof_count > 3:
                signals.append(f"Excessive incremental updates detected ({eof_count - 1})")
        except Exception:
            pass

        result["suspicious_signals"] = signals

    except Exception as exc:
        logger.warning("PDF structural parse error: %s", exc)
        result["parse_error"] = str(exc)

    return result
