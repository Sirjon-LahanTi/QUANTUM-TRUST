# QuantumTrust

**Quantum-Inspired Digital Signature Security**

A professional cybersecurity web application that analyzes digitally signed PDF documents using real cryptographic verification.

---

## Architecture

```
SIH/
├── src/                    # Astro frontend
│   ├── pages/
│   │   ├── index.astro     # Landing page
│   │   ├── dashboard/      # /dashboard — system stats
│   │   ├── verify/         # /verify — document upload & verification
│   │   ├── security/       # /security — threat analysis
│   │   └── analysis/[id]   # /analysis/:id — detail view
│   ├── components/
│   ├── layouts/
│   └── styles/global.css
├── backend/                # FastAPI backend
│   └── app/
│       ├── main.py
│       ├── api/            # Route handlers
│       ├── services/       # Analysis pipeline
│       ├── models/         # SQLAlchemy ORM
│       ├── schemas/        # Pydantic response schemas
│       ├── config/
│       └── db/
├── DESIGN.md               # Visual design specification
└── README.md
```

---

## Frontend Setup

**Requirements:** Node.js 22+

```bash
# From project root (SIH/)
npm install
npx astro dev --host --port 4321
```

Frontend: http://localhost:4321

---

## Backend Setup

**Requirements:** Python 3.10+

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate (Windows cmd)
.venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt

# Start the API server
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API: http://localhost:8000  
API Docs: http://localhost:8000/api/docs

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Upload and analyze a signed PDF |
| `GET`  | `/api/analysis/{id}` | Retrieve full analysis result |
| `GET`  | `/api/analysis/{id}/report` | Generate HTML security report |
| `GET`  | `/api/analyses` | List recent analyses (dashboard) |
| `GET`  | `/api/health` | Health check |
| `GET`  | `/api/docs` | Interactive API documentation |

### POST /api/analyze

```
Content-Type: multipart/form-data
Field: file (PDF, max 50MB)
```

Returns full analysis JSON including:
- Document fingerprint
- Signature status (VALID/INVALID/NONE/UNKNOWN)
- Detected digest algorithm (auto-detected, not assumed)
- Detected signature algorithm (auto-detected)
- Certificate details and trust status
- Document integrity verification
- Duplicate detection result
- Deterministic threat score (0–100)
- Quantum-inspired simulation metrics
- Final verdict: **AUTHENTIC**, **TAMPERED**, or **SUSPICIOUS**

---

## Environment Variables

Create `backend/.env` (optional, all have defaults):

```env
QT_HOST=0.0.0.0
QT_PORT=8000
QT_DEBUG=false
QT_DATABASE_URL=sqlite+aiosqlite:///./quantumtrust.db
QT_MAX_FILE_SIZE_MB=50
QT_CORS_ORIGINS=["http://localhost:4321","http://localhost:4322"]
```

---

## Security Notes

- QuantumTrust **never requests or stores private signing keys**
- Uploaded PDFs are processed in memory and not stored permanently
- PDF digital signatures are verified via `pyHanko` using proper ByteRange/CMS semantics
- Algorithm detection is automatic — SHA-256/RSA are not assumed
- Duplicate detection uses SHA-256 content fingerprints, separate from authenticity
- The quantum-inspired module is a **classical numerical simulation** — not real quantum hardware

---

## Tech Stack

### Frontend
- [Astro](https://astro.build) 7.x — multipage, file-based routing
- IBM Plex Mono + Inter (Google Fonts)
- Vanilla CSS with custom properties

### Backend
- [FastAPI](https://fastapi.tiangolo.com) — REST API
- [pyHanko](https://pyhanko.readthedocs.io) — PDF signature verification (primary)
- [cryptography](https://cryptography.io) — X.509 certificate parsing
- [pypdf](https://pypdf.readthedocs.io) — PDF structural inspection
- SQLAlchemy (async) + aiosqlite — SQLite persistence
- NumPy — quantum-inspired metric computation

---

## Testing PDFs

Recommended test cases:

1. **Valid signed PDF** → expect AUTHENTIC
2. **Tampered signed PDF** (content modified after signing) → expect TAMPERED
3. **Unsigned PDF** → expect SUSPICIOUS (no signature)
4. **Expired certificate PDF** → expect SUSPICIOUS
5. **Self-signed certificate** → expect SUSPICIOUS
6. **Multiple signatures** → check all signatures analyzed
7. **Corrupted PDF** → expect graceful error state
8. **Non-PDF upload** → expect file validation error
9. **File > 50MB** → expect size validation error
10. **Same PDF uploaded twice** → expect duplicate detection flagged

---

## Dashboards

Each dashboard opens in a **new browser tab** (per `target="_blank"`):

| Route | Description |
|-------|-------------|
| `/` | Landing page |
| `/dashboard` | System statistics and recent analyses |
| `/verify` | Document upload and verification |
| `/security?id={id}` | Threat analysis and quantum metrics |
| `/analysis/{id}` | Full analysis detail |
