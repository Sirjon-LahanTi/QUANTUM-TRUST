"""
Unit tests for QuantumTrust Quantum-Inspired Simulation Module
"""
import math
import unittest
from typing import Any

from app.services.quantum_analysis import (
    STATE_DIMENSION,
    REFERENCE_TYPE,
    SIMULATION_DISCLAIMER,
    get_reference_state,
    build_feature_vector,
    normalize_to_state_vector,
    compute_state_similarity,
    compute_correlation_score,
    compute_disturbance_score,
    compute_anomaly_distance,
    compute_entropy,
    compute_quantum_metrics,
    run_quantum_analysis,
)


class TestQuantumAnalysis(unittest.TestCase):
    """Test suite for quantum-inspired mathematical simulation."""

    def test_reference_state_properties(self):
        """Test baseline reference state properties."""
        ref = get_reference_state(STATE_DIMENSION)
        self.assertEqual(len(ref), STATE_DIMENSION)
        # Unit norm: sum(|a_i|^2) == 1.0
        norm_sq = sum(a * a for a in ref)
        self.assertAlmostEqual(norm_sq, 1.0, places=6)
        # Equal superposition: each amplitude == 1 / sqrt(N)
        expected_amp = 1.0 / math.sqrt(STATE_DIMENSION)
        for a in ref:
            self.assertAlmostEqual(a, expected_amp, places=6)

    def test_normalization_arbitrary_vectors(self):
        """Test normalization maps non-negative vectors to unit Euclidean norm."""
        test_vectors = [
            [1.0] * 14,
            [0.5, 0.2, 0.9, 0.1, 0.8, 0.4, 0.6, 0.7, 1.0, 0.0, 0.3, 0.5, 0.9, 0.8],
            [10.0, 0.0, 0.0, 0.0],
            [0.1, 0.1],
        ]
        for vec in test_vectors:
            state = normalize_to_state_vector(vec)
            self.assertEqual(len(state), len(vec))
            norm_sq = sum(a * a for a in state)
            self.assertAlmostEqual(norm_sq, 1.0, places=6)

    def test_normalization_zero_and_empty_vectors(self):
        """Test zero vector produces uniform superposition and empty produces empty list."""
        zero_vec = [0.0] * 10
        state = normalize_to_state_vector(zero_vec)
        self.assertEqual(len(state), 10)
        norm_sq = sum(a * a for a in state)
        self.assertAlmostEqual(norm_sq, 1.0, places=6)
        for a in state:
            self.assertAlmostEqual(a, 1.0 / math.sqrt(10), places=6)

        empty_state = normalize_to_state_vector([])
        self.assertEqual(empty_state, [])

    def test_state_generation_deterministic(self):
        """Test state vector generation is strictly deterministic."""
        raw = [0.8, 0.7, 0.9, 1.0, 0.5, 0.4, 0.6, 0.3, 0.2, 0.1, 0.0, 0.5, 0.8, 0.9]
        state1 = normalize_to_state_vector(raw)
        state2 = normalize_to_state_vector(raw)
        self.assertEqual(state1, state2)

    def test_state_similarity_fidelity(self):
        """Test quantum fidelity (state overlap) F = |<psi_a|psi_b>|^2."""
        ref = get_reference_state(4)
        # Self-overlap must be exactly 1.0
        self.assertAlmostEqual(compute_state_similarity(ref, ref), 1.0, places=6)

        # Orthogonal states must have overlap 0.0
        ortho_a = [1.0, 0.0, 0.0, 0.0]
        ortho_b = [0.0, 1.0, 0.0, 0.0]
        self.assertAlmostEqual(compute_state_similarity(ortho_a, ortho_b), 0.0, places=6)

        # Partial overlap bounded in [0.0, 1.0]
        vec_c = normalize_to_state_vector([1.0, 1.0, 0.0, 0.0])
        fid = compute_state_similarity(ref, vec_c)
        self.assertTrue(0.0 <= fid <= 1.0)
        # Expected: inner product = 2 * (1/2 * 1/sqrt(2)) = 1/sqrt(2) => fid = 0.5
        self.assertAlmostEqual(fid, 0.5, places=6)

    def test_correlation_score_density_matrix_coherence(self):
        """Test density matrix coherence C = ((sum a_i)^2 - 1) / (N - 1)."""
        dim = 4
        # Uniform state should yield coherence 1.0
        uniform = get_reference_state(dim)
        self.assertAlmostEqual(compute_correlation_score(uniform), 1.0, places=6)

        # Localized state (single non-zero basis) should yield coherence 0.0
        localized = [1.0, 0.0, 0.0, 0.0]
        self.assertAlmostEqual(compute_correlation_score(localized), 0.0, places=6)

        # Boundedness
        test_state = normalize_to_state_vector([0.9, 0.1, 0.5, 0.8])
        c = compute_correlation_score(test_state)
        self.assertTrue(0.0 <= c <= 1.0)

    def test_disturbance_score(self):
        """Test quantum disturbance score D = sqrt(1 - Fidelity)."""
        # Perfect match: Fidelity = 1.0 => Disturbance = 0.0
        self.assertAlmostEqual(compute_disturbance_score(1.0), 0.0, places=6)

        # Orthogonal: Fidelity = 0.0 => Disturbance = 1.0
        self.assertAlmostEqual(compute_disturbance_score(0.0), 1.0, places=6)

        # Half fidelity: Fidelity = 0.5 => Disturbance = sqrt(0.5)
        self.assertAlmostEqual(compute_disturbance_score(0.5), math.sqrt(0.5), places=6)

    def test_anomaly_distance_fubini_study(self):
        """Test normalized Fubini-Study geodesic angle distance A = (2/pi) * arccos(<psi_ref|psi>)."""
        ref = get_reference_state(4)
        # Identical to reference baseline => distance 0.0
        self.assertAlmostEqual(compute_anomaly_distance(ref, ref), 0.0, places=6)

        # Orthogonal => distance 1.0
        ortho_a = [1.0, 0.0, 0.0, 0.0]
        ortho_b = [0.0, 1.0, 0.0, 0.0]
        self.assertAlmostEqual(compute_anomaly_distance(ortho_a, ortho_b), 1.0, places=6)

        # Boundedness
        test_state = normalize_to_state_vector([0.9, 0.2, 0.8, 0.5])
        a = compute_anomaly_distance(test_state, ref)
        self.assertTrue(0.0 <= a <= 1.0)

    def test_entropy_measurement_entropy(self):
        """Test normalized measurement entropy H_norm = H / log2(N)."""
        dim = 4
        # Uniform superposition gives maximum entropy = 1.0
        uniform = get_reference_state(dim)
        self.assertAlmostEqual(compute_entropy(uniform), 1.0, places=6)

        # Localized state gives minimum entropy = 0.0
        localized = [1.0, 0.0, 0.0, 0.0]
        self.assertAlmostEqual(compute_entropy(localized), 0.0, places=6)

        # Skewed state gives entropy strictly between 0 and 1
        skewed = normalize_to_state_vector([0.9, 0.3, 0.1, 0.05])
        ent = compute_entropy(skewed)
        self.assertTrue(0.0 < ent < 1.0)

    def test_feature_vector_extraction_valid_doc(self):
        """Test building feature vector from a fully valid authentic document."""
        sig_result = {
            "present": True,
            "count": 1,
            "overall_status": "VALID",
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "RSA-PSS",
            "key_size": 2048,
        }
        cert_info = {
            "trust_status": "TRUSTED",
            "is_expired": False,
        }
        integrity_result = {
            "integrity_status": "VERIFIED",
            "modification_status": "NO_UNAUTHORIZED_CHANGES",
            "byte_range": [0, 1000, 2000, 3000],
        }
        pdf_structure = {
            "suspicious_signals": [],
            "has_js": False,
            "has_embedded_files": False,
            "incremental_update_count": 0,
        }
        duplicate_result = {
            "is_duplicate": False,
        }

        vec = build_feature_vector(
            sig_result=sig_result,
            cert_info=cert_info,
            integrity_result=integrity_result,
            pdf_structure=pdf_structure,
            duplicate_result=duplicate_result,
        )
        self.assertEqual(len(vec), STATE_DIMENSION)
        # All features in healthy doc should be close to 1.0
        for val in vec:
            self.assertGreaterEqual(val, 0.8)
            self.assertLessEqual(val, 1.0)

    def test_feature_vector_extraction_tampered_doc(self):
        """Test building feature vector from a tampered document with invalid signature."""
        sig_result = {
            "present": True,
            "count": 1,
            "overall_status": "INVALID",
            "digest_algorithm": "MD5",
            "signature_algorithm": "DSA",
            "key_size": 512,
        }
        cert_info = {
            "trust_status": "UNTRUSTED",
            "is_expired": True,
        }
        integrity_result = {
            "integrity_status": "FAILED",
            "modification_status": "MODIFIED",
            "byte_range": None,
        }
        pdf_structure = {
            "suspicious_signals": ["sig1", "sig2", "sig3"],
            "has_js": True,
            "has_embedded_files": True,
            "incremental_update_count": 5,
        }
        duplicate_result = {
            "is_duplicate": True,
        }

        vec = build_feature_vector(
            sig_result=sig_result,
            cert_info=cert_info,
            integrity_result=integrity_result,
            pdf_structure=pdf_structure,
            duplicate_result=duplicate_result,
        )
        self.assertEqual(len(vec), STATE_DIMENSION)
        # Most features in tampered doc should be low
        avg_score = sum(vec) / len(vec)
        self.assertLess(avg_score, 0.4)

    def test_feature_vector_handles_missing_fields_gracefully(self):
        """Test that missing/empty inputs are handled cleanly without exceptions or random numbers."""
        vec = build_feature_vector(
            sig_result={},
            cert_info={},
            integrity_result={},
            pdf_structure={},
            duplicate_result={},
        )
        self.assertEqual(len(vec), STATE_DIMENSION)
        for val in vec:
            self.assertTrue(0.0 <= val <= 1.0)

    def test_run_quantum_analysis_end_to_end(self):
        """Test full end-to-end execution of run_quantum_analysis."""
        sig_result = {
            "present": True,
            "count": 1,
            "overall_status": "VALID",
            "digest_algorithm": "SHA-256",
            "signature_algorithm": "RSA",
            "key_size": 2048,
        }
        cert_info = {"trust_status": "TRUSTED", "is_expired": False}
        integrity_result = {
            "integrity_status": "VERIFIED",
            "modification_status": "NO_UNAUTHORIZED_CHANGES",
            "byte_range": [0, 500, 1000, 1500],
        }
        pdf_structure = {"suspicious_signals": [], "has_js": False, "has_embedded_files": False}
        duplicate_result = {"is_duplicate": False}

        result = run_quantum_analysis(
            sig_result, cert_info, integrity_result, pdf_structure, duplicate_result
        )

        # Check required schema keys
        self.assertEqual(result["state_dimension"], STATE_DIMENSION)
        self.assertIsInstance(result["state_similarity"], float)
        self.assertIsInstance(result["correlation_score"], float)
        self.assertIsInstance(result["disturbance_score"], float)
        self.assertIsInstance(result["anomaly_distance"], float)
        self.assertIsInstance(result["entropy"], float)
        self.assertEqual(result["reference_type"], REFERENCE_TYPE)
        self.assertEqual(result["simulation_note"], SIMULATION_DISCLAIMER)

        # Check values for healthy document
        self.assertGreater(result["state_similarity"], 0.9)
        self.assertGreater(result["correlation_score"], 0.9)
        self.assertLess(result["disturbance_score"], 0.3)
        self.assertLess(result["anomaly_distance"], 0.3)
        self.assertGreater(result["entropy"], 0.9)


if __name__ == "__main__":
    unittest.main()
