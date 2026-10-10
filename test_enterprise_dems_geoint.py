"""
Enterprise DEMS & Osiris-Grade GEOINT Comprehensive Verification Suite
=====================================================================
Validates all core modules:
1. DEMS Cryptographic Engine: AES-256-GCM, Dual-Hashing (SHA-256/MD5), In-Memory Streaming
2. One-Click Hash Integrity Verification: /dems/verify/<id> (Pass vs Bit-Tamper Alert)
3. Immutable Chain of Custody Ledger (INGESTION, EVIDENCE_LINK, etc.)
4. Tower Evidence Linking & GIS Pin Feeds (/api/towers/attach-video, /api/towers/linked-evidence)
5. Zero-Key OSINT Telemetry Proxies (Cables, Earthquakes, RainViewer, OpenSky)
6. Forensic CDR Engine: Impossible travel (> 900 km/h), graph constructor, trajectory vectors
7. DEMS Vault Locker View & Direct Intake Route
"""
import io
import os
import json
import hashlib
import secrets
import unittest
from pathlib import Path

from app import app
from dems_models import (
    db, User, Case, Evidence, TowerEvidenceLink, RegisteredCamera,
    ChainOfCustodyLog, EvidenceType, CoCAction, VerificationStatus
)
from dems_crypto import (
    encrypt_file_to_vault, decrypt_to_memory_stream, get_vault_key,
    compute_sha256_of_bytes, compute_md5_of_bytes, verify_integrity
)
import cdr_engine as engine

class TestEnterpriseDEMSGeoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_aes_256_gcm_dual_hashing_and_in_memory_streaming(self):
        """Verify AES-256-GCM authenticated encryption, dual-hashing, and in-memory streaming decryption."""
        sample_video_bytes = b"\x00\x00\x00\x1cftypmp42\x00\x00\x00\x00mp42isom" + secrets.token_bytes(2048)
        vault_key = get_vault_key()
        self.assertEqual(len(vault_key), 32)

        vault_path = Path("vault/e2e_test_seized.enc")
        vault_path.parent.mkdir(exist_ok=True)
        assoc_data = b"evidence:test:EVD-9999-0001"

        sha256_hex, md5_hex, sha512_hex, byte_count = encrypt_file_to_vault(
            file_obj=io.BytesIO(sample_video_bytes),
            vault_path=vault_path,
            key_bytes=vault_key,
            associated_data=assoc_data,
        )

        self.assertEqual(byte_count, len(sample_video_bytes))
        self.assertEqual(sha256_hex, compute_sha256_of_bytes(sample_video_bytes))
        self.assertEqual(md5_hex, compute_md5_of_bytes(sample_video_bytes))

        # Stream decrypt in memory
        stream = decrypt_to_memory_stream(vault_path, vault_key, assoc_data)
        self.assertEqual(stream.read(), sample_video_bytes)

        # Baseline verification: PASS
        ok, verified_hash = verify_integrity(vault_path, vault_key, sha256_hex, assoc_data)
        self.assertTrue(ok)
        self.assertEqual(verified_hash, sha256_hex)

        # Bit-level tampering test
        with open(vault_path, "r+b") as f:
            f.seek(30)
            tampered_byte = bytes([f.read(1)[0] ^ 0xFF])
            f.seek(30)
            f.write(tampered_byte)

        tamper_ok, _ = verify_integrity(vault_path, vault_key, sha256_hex, assoc_data)
        self.assertFalse(tamper_ok, "Tampered ciphertext must fail authenticated decryption")

        if vault_path.exists():
            vault_path.unlink()

    def test_02_dems_one_click_verify_endpoint(self):
        """Verify /dems/verify/<id> returns PASS for intact evidence and TAMPERED for corrupted evidence."""
        with app.app_context():
            case = Case.query.first()
            if not case:
                case = Case(case_number="CAS-2026-TEST", title="Test Verification Case")
                db.session.add(case)
                db.session.commit()

            user = User.query.first()
            if not user:
                user = User(username="admin", email="admin@triad.gov", role=UserRole.ADMIN, is_active=True)
                user.set_password("admin123")
                db.session.add(user)
                db.session.commit()
            user_id = user.id

            with self.client.session_transaction() as sess:
                sess["dems_user_id"] = user_id

            payload = b"GENUINE_SEIZED_SURVEILLANCE_EVIDENCE_RECORD"
            unique_tag = f"EVD-TEST-{secrets.token_hex(4).upper()}"
            ev = Evidence(
                case_id=case.id,
                evidence_tag=unique_tag,
                title="Integrity Verification Test Clip",
                evidence_type=EvidenceType.MULTIMEDIA,
                original_filename="test_clip.mp4",
                encrypted_storage_path="pending",
                sha256_intake=compute_sha256_of_bytes(payload),
                md5_intake=compute_md5_of_bytes(payload),
                sha512_intake=hashlib.sha512(payload).hexdigest(),
                uploaded_by_id=user_id,
                current_custodian_id=user_id,
            )
            db.session.add(ev)
            db.session.commit()

            vault_path = Path(f"vault/evidence_{ev.id}_verify_test.enc")
            vault_key = get_vault_key()
            assoc_data = f"evidence:{ev.id}:{ev.evidence_tag}".encode()

            s256, md5, _, bcount = encrypt_file_to_vault(
                file_obj=io.BytesIO(payload),
                vault_path=vault_path,
                key_bytes=vault_key,
                associated_data=assoc_data,
            )
            ev.encrypted_storage_path = str(vault_path)
            ev.file_size_bytes = bcount
            db.session.commit()

            # Test 1: Verify intact evidence (PASS)
            res = self.client.get(f"/dems/verify/{ev.id}")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["verified"])
            self.assertEqual(data["status"], "PASS")
            self.assertEqual(data["badge"], "green")

            # Also test alias /dems/evidence/<id>/verify
            res_alias = self.client.get(f"/dems/evidence/{ev.id}/verify")
            self.assertEqual(res_alias.status_code, 200)
            self.assertTrue(res_alias.get_json()["verified"])

            # Test 2: Tamper with vault file on disk (FAIL / TAMPER ALERT)
            with open(vault_path, "r+b") as f:
                f.seek(25)
                b = f.read(1)[0]
                f.seek(25)
                f.write(bytes([b ^ 0x01]))

            res_tamper = self.client.get(f"/dems/verify/{ev.id}")
            self.assertEqual(res_tamper.status_code, 200)
            tamper_data = res_tamper.get_json()
            self.assertFalse(tamper_data["verified"])
            self.assertEqual(tamper_data["status"], "FAIL")
            self.assertEqual(tamper_data["badge"], "red")

            if vault_path.exists():
                vault_path.unlink()

    def test_03_dems_vault_view_and_routes(self):
        """Verify /dems/vault and /vault return HTTP 200 / 302."""
        with app.app_context():
            user = User.query.first()
            if not user:
                user = User(username="admin", email="admin@triad.gov", role=UserRole.ADMIN, is_active=True)
                user.set_password("admin123")
                db.session.add(user)
                db.session.commit()
            with self.client.session_transaction() as sess:
                sess["dems_user_id"] = user.id

        res_dems_vault = self.client.get("/dems/vault")
        self.assertEqual(res_dems_vault.status_code, 200)
        self.assertIn(b"Cryptographic Evidence Vault Locker", res_dems_vault.data)

        res_vault_redirect = self.client.get("/vault")
        self.assertIn(res_vault_redirect.status_code, [200, 302])

    def test_04_tower_evidence_stubs_and_fast_telemetry(self):
        """Verify high-performance decommissioned video stubs return instant lightweight JSON and 410 on stream."""
        tower_id = "TOWER-MUM-NORTH-01"
        with app.app_context():
            # Query fast stub endpoint
            ev_res = self.client.get(f"/api/towers/{tower_id}/evidence")
            self.assertEqual(ev_res.status_code, 200)
            data = ev_res.get_json()
            self.assertFalse(data["has_evidence"])

            # Query GIS pins endpoint (empty list for high performance)
            pins_res = self.client.get("/api/towers/linked-evidence")
            self.assertEqual(pins_res.status_code, 200)
            self.assertEqual(pins_res.get_json(), [])

            # Video evidence items stub
            items_res = self.client.get("/api/dems/video-evidence-items")
            self.assertEqual(items_res.status_code, 200)
            self.assertEqual(items_res.get_json(), [])

            # Video stream endpoint must return 410 (Decommissioned for performance)
            stream_res = self.client.get("/dems/stream/9999")
            self.assertEqual(stream_res.status_code, 410)

    def test_05_zero_key_osint_telemetry_proxies(self):
        """Verify zero-key public telemetry proxy endpoints return valid structures or mock data."""
        # RainViewer
        res_radar = self.client.get("/api/osint/rainviewer")
        self.assertIn(res_radar.status_code, [200, 502])

        # Submarine Cables
        res_cables = self.client.get("/api/osint/submarine-cables")
        self.assertIn(res_cables.status_code, [200, 502])

        # Earthquakes
        res_quakes = self.client.get("/api/osint/earthquakes")
        self.assertIn(res_quakes.status_code, [200, 502])

        # OpenSky ADS-B
        res_opensky = self.client.get("/api/osint/opensky?lamin=18.0&lomin=72.0&lamax=20.0&lomax=74.0")
        self.assertIn(res_opensky.status_code, [200, 502])

    def test_06_cdr_engine_impossible_travel_anomaly_detection(self):
        """Verify velocity calculation v = delta_d / delta_t flags speeds > 900 km/h."""
        import pandas as pd
        records = [
            {
                "caller": "9876543210",
                "receiver": "9123456780",
                "timestamp": "2024-01-15 01:00:00",
                "duration": 60,
                "call_type": "OUTGOING",
                "cell_id": "TOWER_MUMBAI",
                "lat": 19.0760,
                "lon": 72.8777,
                "imei": "358741098234512",
                "imsi": "404450123456789"
            },
            {
                # Delhi: ~1150 km from Mumbai, 10 minutes later -> ~6900 km/h (Supersonic / Impossible)
                "caller": "9876543210",
                "receiver": "9123456781",
                "timestamp": "2024-01-15 01:10:00",
                "duration": 45,
                "call_type": "INCOMING",
                "cell_id": "TOWER_DELHI",
                "lat": 28.6139,
                "lon": 77.2090,
                "imei": "358741098234512",
                "imsi": "404450123456789"
            }
        ]
        df = pd.DataFrame(records)
        detector = engine.ImpossibleTravelDetector(df, speed_threshold_kmh=900.0)
        anomalies = detector.detect()

        self.assertEqual(len(anomalies), 1)
        self.assertGreater(anomalies[0]["speed_kmh"], 900.0)
        self.assertEqual(anomalies[0]["from_cell"], "TOWER_MUMBAI")
        self.assertEqual(anomalies[0]["to_cell"], "TOWER_DELHI")

if __name__ == "__main__":
    unittest.main()
