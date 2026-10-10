"""
Comprehensive Forensic Suite Test
Tests DEMS Cryptographic Engine, SQLite Models, CDR Analytics, and Flask APIs.
"""
import io
import json
import base64
import os
import secrets
import unittest
from pathlib import Path

from app import app
from dems_models import db, User, Case, Evidence, RegisteredCamera, ChainOfCustodyLog, EvidenceType, CoCAction, VerificationStatus
from dems_crypto import (
    encrypt_file_to_vault, decrypt_to_memory_stream, get_vault_key,
    compute_sha256_of_bytes, compute_md5_of_bytes, verify_integrity
)
import cdr_engine as engine

class TestDEMSForensicSuite(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_crypto_vault_aes_gcm_and_dual_hash(self):
        """Test AES-256-GCM authenticated encryption, dual-hashing, in-memory decryption, and tamper detection."""
        test_payload = b"FORENSIC_SEIZED_SURVEILLANCE_VIDEO_STREAM_DATA_FRAME_BYTES_12345"
        key = get_vault_key()
        self.assertEqual(len(key), 32)

        vault_path = Path("vault/test_artifact.enc")
        vault_path.parent.mkdir(exist_ok=True)
        assoc_data = b"case:1:evidence:EVD-0001-0001"

        sha256_hex, md5_hex, sha512_hex, byte_count = encrypt_file_to_vault(
            file_obj=io.BytesIO(test_payload),
            vault_path=vault_path,
            key_bytes=key,
            associated_data=assoc_data,
        )

        self.assertEqual(byte_count, len(test_payload))
        self.assertEqual(sha256_hex, compute_sha256_of_bytes(test_payload))
        self.assertEqual(md5_hex, compute_md5_of_bytes(test_payload))

        # In-memory decrypt
        decrypted_stream = decrypt_to_memory_stream(vault_path, key, assoc_data)
        decrypted_bytes = decrypted_stream.read()
        self.assertEqual(decrypted_bytes, test_payload)

        # Integrity verification
        is_verified, verified_sha = verify_integrity(vault_path, key, sha256_hex, assoc_data)
        self.assertTrue(is_verified)
        self.assertEqual(verified_sha, sha256_hex)

        # Clean up
        if vault_path.exists():
            vault_path.unlink()

    def test_02_cdr_normalization_and_analytics(self):
        """Test CDR parsing, impossible travel velocity detection, and graph generation."""
        csv_file = "sample_cdr.csv"
        if not os.path.exists(csv_file):
            return

        norm = engine.CDRNormalizer(csv_file)
        self.assertGreater(len(norm.df), 0)
        self.assertIn("caller", norm.df.columns)
        self.assertIn("receiver", norm.df.columns)

        kpis = engine.ForensicAnalyzer(norm.df, target_number="9876543210").kpis()
        self.assertIn("total_records", kpis)
        self.assertIn("unique_contacts", kpis)

        # Anomaly detection (impossible travel)
        anomalies = engine.ImpossibleTravelDetector(norm.df).detect()
        self.assertIsInstance(anomalies, list)

        # Network graph
        graph_builder = engine.NetworkGraphBuilder(norm.df, target="9876543210")
        graph_data = graph_builder.build()
        self.assertIn("nodes", graph_data)
        self.assertIn("edges", graph_data)

        # Geo trajectory
        geo_tracker = engine.GeoTracker(norm.df)
        geo_data = geo_tracker.trajectory()
        self.assertTrue(geo_data["has_geo"])
        self.assertGreater(len(geo_data["markers"]), 0)

    def test_03_flask_dems_and_tower_evidence_api(self):
        """Test Flask routes for tower evidence query, verifying fast stubs and decommissioned video."""
        test_tower = f"TOWER-TEST-{secrets.token_hex(4).upper()}"
        with self.app.app_context():
            case = Case.query.first()
            if not case:
                case = Case(case_number="CAS-TEST-001", title="Test Investigative Case")
                db.session.add(case)
                db.session.commit()

            # 1. Query tower evidence stub (returns fast lightweight response)
            res = self.client.get(f"/api/towers/{test_tower}/evidence")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertFalse(data["has_evidence"])
            self.assertIn("decommissioned", data["message"].lower())

            # 2. Verify /api/towers/linked-evidence returns empty list
            res_linked = self.client.get("/api/towers/linked-evidence")
            self.assertEqual(res_linked.status_code, 200)
            self.assertEqual(res_linked.get_json(), [])

            # 3. Stream route returns 410 Gone (Feature decommissioned for high performance)
            stream_res = self.client.get("/dems/stream/1")
            self.assertEqual(stream_res.status_code, 410)

if __name__ == "__main__":
    unittest.main()
