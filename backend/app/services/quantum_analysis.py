"""
QuantumTrust — Quantum-Inspired Analysis Module

IMPORTANT NOTICE:
This module is a CLASSICAL MATHEMATICAL SIMULATION inspired by quantum state
representations, density matrices, and quantum information geometry.
It runs entirely on classical computing hardware using standard linear algebra.
It does NOT use real quantum hardware, real quantum entanglement, or real quantum measurements.

Mathematical Formulation:
1. Normalized Security Feature Vector:
   x = [x_1, x_2, ..., x_N]^T in [0.0, 1.0]^N
   where 1.0 represents a clean, fully verified, trustworthy state,
   and 0.0 represents a compromised or high-risk state.

2. Quantum-Inspired State Vector Representation:
   |ψ⟩ = [a_1, a_2, ..., a_N]^T
   Amplitudes a_i = x_i / ||x||_2  such that sum(|a_i|^2) = 1.0

3. Deterministic Reference Baseline:
   |ψ_ref⟩ = [1/√N, 1/√N, ..., 1/√N]^T (ideal authentic state)

4. Metrics:
   - State Similarity (Quantum Fidelity):
     F(|ψ⟩, |ψ_ref⟩) = |⟨ψ_ref|ψ⟩|^2 in [0.0, 1.0]

   - Correlation Score (Density Matrix Coherence):
     C = ((sum(a_i))^2 - 1) / (N - 1) in [0.0, 1.0]

   - Disturbance Score (Quantum State Displacement):
     D = sqrt(1 - F(|ψ⟩, |ψ_ref⟩)) in [0.0, 1.0]

   - Anomaly Distance (Normalized Fubini-Study Distance):
     A = (2 / π) * arccos(⟨ψ_ref|ψ⟩) in [0.0, 1.0]

   - Entropy (Normalized Shannon/Von Neumann Measurement Entropy):
     p_i = |a_i|^2
     H = - sum(p_i * log2(p_i))
     H_norm = H / log2(N) in [0.0, 1.0]
"""
from __future__ import annotations
import math
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Dimension of the real security feature space
STATE_DIMENSION = 14
REFERENCE_TYPE = "deterministic_baseline"
SIMULATION_DISCLAIMER = "Classical simulation of quantum-inspired mathematical representations used as an additional security signal."

FEATURE_DEFINITIONS: list[dict[str, str]] = [
    {"index": 0,  "id": "sig_validity",       "name": "Signature Validity",          "category": "Cryptography", "desc": "Cryptographic signature validity and verification status"},
    {"index": 1,  "id": "integrity_status",   "name": "Document Integrity",          "category": "Integrity",    "desc": "ByteRange verification and unauthorized modification detection"},
    {"index": 2,  "id": "cert_trust",         "name": "Certificate Trust",           "category": "Certificate",  "desc": "Signer CA hierarchy and trust anchor verification"},
    {"index": 3,  "id": "cert_validity",      "name": "Certificate Lifetime",        "category": "Certificate",  "desc": "Temporal validity window and expiration status"},
    {"index": 4,  "id": "digest_algorithm",   "name": "Digest Strength",             "category": "Cryptography", "desc": "Hash digest cryptographic robustness (SHA-256/384/512 vs legacy)"},
    {"index": 5,  "id": "sig_algorithm",      "name": "Signature Algorithm",         "category": "Cryptography", "desc": "Signature scheme strength (RSA-PSS/Ed25519/ECDSA vs legacy)"},
    {"index": 6,  "id": "key_size",           "name": "Public Key Size",             "category": "Cryptography", "desc": "Asymmetric key length security margin (2048/3072+ bits)"},
    {"index": 7,  "id": "signature_count",    "name": "Signature Coherence",         "category": "Structure",    "desc": "Coherent digital signature count and structure"},
    {"index": 8,  "id": "pdf_structure",      "name": "PDF Structural Health",       "category": "Structure",    "desc": "Absence of structural anomalies and parser errors"},
    {"index": 9,  "id": "active_content",     "name": "Active Content Shield",       "category": "Payload",      "desc": "Absence of executable JavaScript actions in PDF dictionary"},
    {"index": 10, "id": "embedded_payloads",  "name": "Embedded Payloads Shield",    "category": "Payload",      "desc": "Absence of suspicious embedded streams or binary attachments"},
    {"index": 11, "id": "incremental_updates","name": "Revision History Margin",     "category": "Structure",    "desc": "Incremental update revision count within safe parameters"},
    {"index": 12, "id": "anti_replay",        "name": "Anti-Replay Uniqueness",      "category": "Integrity",    "desc": "Document uniqueness and absence of exact duplicate replays"},
    {"index": 13, "id": "byterange_coverage", "name": "ByteRange Coverage",          "category": "Integrity",    "desc": "Full document ByteRange coverage by the digital signature"},
]

# Ideal authentic reference vector (unnormalized)
_REFERENCE_VECTOR_VALUES = [1.0] * STATE_DIMENSION


def get_reference_state(dimension: int = STATE_DIMENSION) -> list[float]:
    """
    Generate the deterministic reference baseline state vector |ψ_ref⟩.
    Represents an ideal, authenticated document with uniform high integrity across all dimensions.
    """
    amp = 1.0 / math.sqrt(dimension)
    return [amp] * dimension


def build_feature_vector(
    sig_result: dict[str, Any],
    cert_info: dict[str, Any],
    integrity_result: dict[str, Any],
    pdf_structure: dict[str, Any],
    duplicate_result: dict[str, Any],
    threat_result: dict[str, Any] | None = None,
) -> list[float]:
    """
    Extract and normalize real security features into an N-dimensional vector [0.0, 1.0]^N.
    
    Missing features are explicitly handled with documented neutral or default priors,
    never with random values.
    """
    # 1. Cryptographic signature validity
    def score_signature_validity() -> float:
        s = (sig_result.get("overall_status") or "NONE").upper()
        mapping = {
            "VALID": 1.0,
            "UNSUPPORTED": 0.4,
            "UNKNOWN": 0.4,
            "CORRUPTED": 0.1,
            "INVALID": 0.0,
            "NONE": 0.0,
        }
        return mapping.get(s, 0.4)

    # 2. Document integrity verification status
    def score_integrity_status() -> float:
        s = (integrity_result.get("integrity_status") or "UNKNOWN").upper()
        m = (integrity_result.get("modification_status") or "UNKNOWN").upper()
        if s == "VERIFIED" and m == "NO_UNAUTHORIZED_CHANGES":
            return 1.0
        if s == "VERIFIED" and m == "PERMITTED_CHANGES":
            return 0.85
        if s == "VERIFIED":
            return 0.8
        if s == "UNKNOWN":
            return 0.4
        if s == "FAILED" or m == "MODIFIED":
            return 0.0
        return 0.4

    # 3. Certificate trust status
    def score_cert_trust() -> float:
        t = (cert_info.get("trust_status") or "UNAVAILABLE").upper()
        mapping = {
            "TRUSTED": 1.0,
            "SELF_SIGNED": 0.5,
            "UNKNOWN": 0.4,
            "UNAVAILABLE": 0.3,
            "EXPIRED": 0.1,
            "UNTRUSTED": 0.0,
            "REVOKED": 0.0,
        }
        return mapping.get(t, 0.3)

    # 4. Certificate temporal validity (expiration)
    def score_cert_validity_period() -> float:
        is_exp = cert_info.get("is_expired")
        if is_exp is False:
            return 1.0
        if is_exp is True:
            return 0.0
        return 0.5  # Unknown / unparsed

    # 5. Digest algorithm cryptographic strength
    def score_digest_algorithm() -> float:
        digest = (sig_result.get("digest_algorithm") or "").upper().replace("-", "")
        if digest in ("SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512"):
            return 1.0
        if digest in ("SHA224", "RIPEMD160"):
            return 0.7
        if digest in ("SHA1", "SHA"):
            return 0.3
        if digest in ("MD5", "MD2"):
            return 0.0
        return 0.5 if sig_result.get("present") else 0.3

    # 6. Signature algorithm type & robustness
    def score_sig_algorithm() -> float:
        algo = (sig_result.get("signature_algorithm") or "").upper()
        if "PSS" in algo or "ED25519" in algo or "ECDSA" in algo:
            return 1.0
        if "RSA" in algo:
            return 0.9
        if "DSA" in algo:
            return 0.4
        return 0.5 if sig_result.get("present") else 0.3

    # 7. Public key size strength
    def score_key_size() -> float:
        key_size = sig_result.get("key_size")
        if key_size is None:
            return 0.5 if sig_result.get("present") else 0.3
        if isinstance(key_size, int):
            if key_size >= 3072:
                return 1.0
            if key_size >= 2048:
                return 0.85
            if key_size >= 1024:
                return 0.3
            return 0.0
        return 0.5

    # 8. Signature count & integrity coherence
    def score_signature_count() -> float:
        count = sig_result.get("count", 0)
        present = sig_result.get("present", False)
        if present and count == 1:
            return 1.0
        if present and count > 1:
            return 0.9  # Multi-signed valid document
        if not present or count == 0:
            return 0.0
        return 0.5

    # 9. PDF structural anomaly signals
    def score_pdf_structural_integrity() -> float:
        signals = pdf_structure.get("suspicious_signals", [])
        parse_err = pdf_structure.get("parse_error")
        if parse_err:
            return 0.1
        count = len(signals) if isinstance(signals, list) else 0
        return max(0.0, 1.0 - count * 0.2)

    # 10. Active executable content (JavaScript)
    def score_pdf_active_content() -> float:
        has_js = bool(pdf_structure.get("has_js", False))
        return 0.0 if has_js else 1.0

    # 11. Embedded payloads & attachments
    def score_pdf_embedded_payloads() -> float:
        has_embedded = bool(pdf_structure.get("has_embedded_files", False))
        return 0.4 if has_embedded else 1.0

    # 12. Incremental update count (structural history)
    def score_pdf_incremental_updates() -> float:
        try:
            cnt = int(pdf_structure.get("incremental_update_count", 0))
        except (ValueError, TypeError):
            cnt = 0
        if cnt == 0:
            return 1.0
        if cnt <= 2:
            return 0.85
        return max(0.0, 1.0 - cnt * 0.15)

    # 13. Anti-replay and document uniqueness
    def score_anti_replay() -> float:
        is_dup = duplicate_result.get("is_duplicate", False)
        return 0.4 if is_dup else 1.0

    # 14. ByteRange signature coverage
    def score_byte_range_coherence() -> float:
        br = integrity_result.get("byte_range")
        if isinstance(br, (list, tuple)) and len(br) == 4:
            # Valid standard PDF ByteRange [offset1, len1, offset2, len2]
            if br[0] == 0 and br[1] > 0 and br[2] > br[1] and br[3] > 0:
                return 1.0
            return 0.3
        if sig_result.get("present"):
            return 0.5
        return 0.2

    features = [
        score_signature_validity(),          # 1
        score_integrity_status(),            # 2
        score_cert_trust(),                  # 3
        score_cert_validity_period(),        # 4
        score_digest_algorithm(),            # 5
        score_sig_algorithm(),               # 6
        score_key_size(),                    # 7
        score_signature_count(),             # 8
        score_pdf_structural_integrity(),    # 9
        score_pdf_active_content(),          # 10
        score_pdf_embedded_payloads(),       # 11
        score_pdf_incremental_updates(),     # 12
        score_anti_replay(),                 # 13
        score_byte_range_coherence(),        # 14
    ]

    # Ensure all values are bounded [0.0, 1.0]
    return [max(0.0, min(1.0, float(f))) for f in features]


def normalize_to_state_vector(feature_vector: list[float]) -> list[float]:
    """
    Map a non-negative feature vector x into a normalized quantum-inspired state vector |ψ⟩
    such that sum(|a_i|^2) = 1.0.
    
    If the input vector has zero norm (all features zero), returns equal superposition.
    """
    dim = len(feature_vector)
    if dim == 0:
        return []

    norm_sq = sum(f * f for f in feature_vector)
    if norm_sq <= 1e-15:
        # Uniform superposition
        uniform_amp = 1.0 / math.sqrt(dim)
        return [uniform_amp] * dim

    norm = math.sqrt(norm_sq)
    return [f / norm for f in feature_vector]


def compute_state_similarity(state_a: list[float], state_b: list[float]) -> float:
    """
    Compute Quantum Fidelity (state overlap) between two pure states |ψ_a⟩ and |ψ_b⟩:
    F = |⟨ψ_a|ψ_b⟩|^2 in [0.0, 1.0]
    """
    if len(state_a) != len(state_b) or len(state_a) == 0:
        return 0.0
    inner_prod = sum(a * b for a, b in zip(state_a, state_b))
    fidelity = inner_prod * inner_prod
    return max(0.0, min(1.0, fidelity))


def compute_correlation_score(state: list[float]) -> float:
    """
    Compute density matrix off-diagonal quantum coherence for pure state ρ = |ψ⟩⟨ψ|:
    C = ( (sum(a_i))^2 - 1 ) / (N - 1)
    
    For uniform baseline |ψ_ref⟩, C = 1.0.
    For a fully localized state with only 1 non-zero component, C = 0.0.
    Bounded in [0.0, 1.0].
    """
    n = len(state)
    if n <= 1:
        return 1.0
    sum_a = sum(state)
    coherence = ((sum_a * sum_a) - 1.0) / (n - 1)
    return max(0.0, min(1.0, coherence))


def compute_disturbance_score(fidelity: float) -> float:
    """
    Compute the quantum disturbance score (state displacement from baseline):
    D = sqrt(1 - Fidelity) in [0.0, 1.0]
    
    When state matches reference baseline perfectly, D = 0.0.
    When state is orthogonal to baseline, D = 1.0.
    """
    clamped_fid = max(0.0, min(1.0, fidelity))
    return math.sqrt(1.0 - clamped_fid)


def compute_anomaly_distance(state: list[float], ref_state: list[float]) -> float:
    """
    Compute normalized Fubini-Study quantum geodesic angle distance:
    θ = arccos(⟨ψ_ref|ψ⟩) in [0, π/2]
    A = (2 / π) * θ in [0.0, 1.0]
    """
    if len(state) != len(ref_state) or len(state) == 0:
        return 1.0
    inner_prod = sum(a * b for a, b in zip(state, ref_state))
    clamped_inner = max(0.0, min(1.0, inner_prod))
    theta = math.acos(clamped_inner)
    distance = (2.0 / math.pi) * theta
    return max(0.0, min(1.0, distance))


def compute_entropy(state: list[float]) -> float:
    """
    Compute normalized Shannon / Von Neumann measurement entropy on probability distribution p_i = |a_i|^2:
    H = - sum(p_i * log2(p_i))
    H_norm = H / log2(N) in [0.0, 1.0]
    
    Uniform baseline |ψ_ref⟩ gives H_norm = 1.0.
    Localized/skewed states give H_norm < 1.0.
    """
    n = len(state)
    if n <= 1:
        return 1.0
    
    max_entropy = math.log2(n)
    if max_entropy <= 0:
        return 1.0

    entropy = 0.0
    for amp in state:
        prob = amp * amp
        if prob > 1e-12:
            entropy -= prob * math.log2(prob)

    norm_entropy = entropy / max_entropy
    return max(0.0, min(1.0, norm_entropy))


def compute_quantum_metrics(state: list[float], ref_state: list[float] | None = None) -> dict[str, Any]:
    """
    Compute all quantum-inspired mathematical metrics for a given state vector.
    """
    if ref_state is None:
        ref_state = get_reference_state(len(state))

    fidelity = compute_state_similarity(state, ref_state)
    correlation = compute_correlation_score(state)
    disturbance = compute_disturbance_score(fidelity)
    anomaly = compute_anomaly_distance(state, ref_state)
    entropy = compute_entropy(state)

    return {
        "state_dimension":   len(state),
        "state_similarity":  round(fidelity, 6),
        "correlation_score": round(correlation, 6),
        "disturbance_score": round(disturbance, 6),
        "anomaly_distance":  round(anomaly, 6),
        "entropy":           round(entropy, 6),
        "reference_type":    REFERENCE_TYPE,
        "simulation_note":   SIMULATION_DISCLAIMER,
    }


def evaluate_custom_vector(features: list[float]) -> dict[str, Any]:
    """
    Evaluate arbitrary feature vector x in [0, 1]^N through the quantum simulation.
    Returns the state vector, probabilities, metrics, and detailed dimension breakdown.
    """
    if len(features) != STATE_DIMENSION:
        # Pad or truncate to STATE_DIMENSION
        if len(features) < STATE_DIMENSION:
            features = features + [0.5] * (STATE_DIMENSION - len(features))
        else:
            features = features[:STATE_DIMENSION]

    clamped = [max(0.0, min(1.0, float(f))) for f in features]
    state = normalize_to_state_vector(clamped)
    ref_state = get_reference_state(len(state))
    metrics = compute_quantum_metrics(state, ref_state)

    dimensions = []
    for i, f_val in enumerate(clamped):
        meta = FEATURE_DEFINITIONS[i] if i < len(FEATURE_DEFINITIONS) else {"id": f"dim_{i}", "name": f"Feature {i+1}", "category": "General", "desc": ""}
        amp = state[i] if i < len(state) else 0.0
        prob = amp * amp
        ref_amp = ref_state[i] if i < len(ref_state) else 0.0
        dimensions.append({
            "index": i,
            "id": meta.get("id"),
            "name": meta.get("name"),
            "category": meta.get("category"),
            "description": meta.get("desc"),
            "feature_value": round(f_val, 4),
            "amplitude": round(amp, 6),
            "probability": round(prob, 6),
            "reference_amplitude": round(ref_amp, 6),
            "reference_probability": round(ref_amp * ref_amp, 6),
        })

    return {
        **metrics,
        "raw_features": clamped,
        "state_vector": [round(a, 6) for a in state],
        "reference_state": [round(a, 6) for a in ref_state],
        "probabilities": [round(a * a, 6) for a in state],
        "dimensions": dimensions,
    }


def get_simulation_presets() -> list[dict[str, Any]]:
    """
    Return curated deterministic presets representing known document states.
    """
    presets = [
        {
            "id": "authentic_ideal",
            "name": "Authentic Fully Verified PDF",
            "verdict": "AUTHENTIC",
            "description": "Valid signature (RSA-2048 / SHA-256), trusted CA, ByteRange verified, clean structure.",
            "features": [1.0, 1.0, 1.0, 1.0, 1.0, 0.9, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        },
        {
            "id": "tampered_signature",
            "name": "Tampered Signed PDF",
            "verdict": "TAMPERED",
            "description": "Invalid signature, content modified after signing, untrusted root, structural anomalies.",
            "features": [0.0, 0.0, 0.0, 0.0, 1.0, 0.9, 0.85, 1.0, 0.4, 1.0, 0.4, 0.4, 1.0, 0.3],
        },
        {
            "id": "expired_certificate",
            "name": "Expired Certificate PDF",
            "verdict": "SUSPICIOUS",
            "description": "Valid cryptographic signature, but certificate validity period has expired.",
            "features": [1.0, 1.0, 0.1, 0.0, 1.0, 0.9, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        },
        {
            "id": "unsigned_document",
            "name": "Unsigned PDF Document",
            "verdict": "SUSPICIOUS",
            "description": "No digital signature present, unauthenticated, clean document structure.",
            "features": [0.0, 0.4, 0.3, 0.5, 0.3, 0.3, 0.3, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.2],
        },
    ]

    results = []
    for p in presets:
        evaluated = evaluate_custom_vector(p["features"])
        results.append({
            "id": p["id"],
            "name": p["name"],
            "verdict": p["verdict"],
            "description": p["description"],
            "features": p["features"],
            "simulation": evaluated,
        })
    return results


def run_quantum_analysis(
    sig_result: dict[str, Any],
    cert_info: dict[str, Any],
    integrity_result: dict[str, Any],
    pdf_structure: dict[str, Any],
    duplicate_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Execute quantum-inspired simulation analysis on extracted PDF document features.
    """
    raw_features = build_feature_vector(
        sig_result, cert_info, integrity_result, pdf_structure, duplicate_result
    )
    state = normalize_to_state_vector(raw_features)
    ref_state = get_reference_state(len(state))
    metrics = compute_quantum_metrics(state, ref_state)
    return {
        **metrics,
        "raw_features": raw_features,
        "state_vector": [round(a, 6) for a in state],
        "reference_state": [round(a, 6) for a in ref_state],
    }


