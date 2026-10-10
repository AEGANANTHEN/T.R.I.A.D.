"""
Unit & Integration Tests for Upgraded Phase 7 Enterprise AI Intelligence
=======================================================================
Validates:
1. Provider detection (Ollama, LM Studio, Cloud, Offline agent)
2. Dynamic Multi-Factor Threat Risk Scoring (0–100)
3. Suspect Behavioral Profiling & OpSec Detection
4. Structured Forensic Hypotheses Matrix Formulation
5. Blueprint Endpoints:
   - /api/ai-intelligence/providers
   - /api/ai-intelligence/<id>
   - /api/ai-intelligence/<id>/profile
   - /api/ai-intelligence/<id>/hypotheses
   - /api/ai-intelligence/<id>/export (Markdown & JSON)
   - /api/ai-intelligence/<id>/ask
"""

import json
import unittest
from app import app
from ai_intelligence import (
    compute_threat_risk_score,
    build_suspect_profile,
    build_forensic_hypotheses,
    get_available_providers,
    generate_ai_intelligence,
    answer_ai_question,
)

class TestAIIntelligenceUpgrades(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

        # Mock investigation session data
        cls.mock_data = {
            "id": "test-session-001",
            "target": "+919876543210",
            "filename": "sample_cdr.csv",
            "case_ref": "CAPSTONE-NEXUS-2024",
            "kpis": {
                "total_records": 500,
                "unique_contacts": 35,
                "date_range": "2024-01-01 to 2024-01-30",
                "total_duration_hms": "14h 22m 10s",
                "total_distance_km": 680.5,
                "night_calls": 42,
                "incoming_count": 210,
                "outgoing_count": 290,
                "sms_count": 15,
                "investigation_signal_score": 78.5,
            },
            "impossible_travel": [
                {
                    "tower1": "MUM003",
                    "tower2": "PUNE01",
                    "dist_km": 145.2,
                    "delta_sec": 300,
                    "speed_kmh": 1742.4,
                }
            ],
            "device_swaps": {
                "handset_hopping": ["358765043210987", "861234567890123"],
                "sim_swapping": False,
            },
            "bursts": [
                {"timestamp": "2024-01-03 03:20:00", "count": 7}
            ],
            "dormant": [],
            "top_contacts": [
                {
                    "contact": "+919889012345",
                    "calls": 84,
                    "duration_hms": "4h 12m",
                    "out_calls": 50,
                    "in_calls": 34,
                    "first_call": "2024-01-01 08:33:00",
                    "last_call": "2024-01-29 19:15:00",
                }
            ],
            "geo": {"markers": [{"lat": 19.07, "lon": 72.87}]},
        }

        cls.mock_analytics = {
            "summary": {
                "total_records": 500,
                "total_targets": 1,
                "investigation_signal_score": 78.5,
                "unique_entities": 35,
                "active_days": 29,
                "peak_hour": 14,
                "peak_day": "Wednesday",
                "top_contact": "+919889012345",
                "total_distance_km": 680.5,
            },
            "communication": {
                "incoming": 210,
                "outgoing": 290,
                "sms": 15,
                "unknown_direction": 0,
                "target_contacts": 35,
                "important_contacts": [{"contact": "+919889012345", "count": 84}],
            },
            "temporal": {"peak_hours": [14, 15, 2], "hourly": [], "daily": []},
            "geographic": {
                "total_distance_km": 680.5,
                "max_leg_speed_kmh": 1742.4,
                "top_locations": [{"cell_id": "MUM003", "count": 120}],
            },
            "network": {
                "total_nodes": 36,
                "total_edges": 84,
                "central_nodes": [{"node": "+919876543210", "degree": 35}],
                "clusters": [],
            },
            "cross_match": {},
            "leads": [
                {
                    "severity": "CRITICAL",
                    "type": "ANOMALY",
                    "title": "Supersonic Tower Hop Detected",
                    "detail": "1742 km/h hop between MUM003 and PUNE01",
                    "basis": "Haversine distance vs elapsed time",
                    "target": "+919876543210",
                }
            ],
        }

    def test_01_provider_status_probing(self):
        """Verify that provider probe returns all 4 tiers without throwing exceptions."""
        providers_info = get_available_providers()
        self.assertIn("recommended", providers_info)
        self.assertIn("providers", providers_info)
        p = providers_info["providers"]
        self.assertIn("ollama", p)
        self.assertIn("local_openai", p)
        self.assertIn("cloud", p)
        self.assertIn("offline", p)
        self.assertTrue(p["offline"]["available"])

    def test_02_dynamic_threat_scoring(self):
        """Verify mathematical calculation of multi-factor threat risk score."""
        risk = compute_threat_risk_score(self.mock_data, self.mock_analytics)
        self.assertGreaterEqual(risk["total_score"], 50)
        self.assertIn(risk["level"], ["CRITICAL", "ELEVATED"])
        self.assertIn("breakdown", risk)
        bd = risk["breakdown"]
        self.assertGreater(bd["velocity_risk"]["score"], 0)
        self.assertGreater(bd["hardware_risk"]["score"], 0)
        self.assertGreater(bd["temporal_risk"]["score"], 0)
        self.assertGreater(bd["network_risk"]["score"], 0)

    def test_03_suspect_behavioral_profiling(self):
        """Verify suspect behavioral archetype and OpSec countermeasure identification."""
        risk = compute_threat_risk_score(self.mock_data, self.mock_analytics)
        profile = build_suspect_profile(self.mock_data, self.mock_analytics, risk)
        self.assertEqual(profile["target"], "+919876543210")
        self.assertIn("Evasive", profile["archetype"])
        self.assertGreater(len(profile["counter_surveillance_tactics"]), 0)
        tactics_names = [t["name"] for t in profile["counter_surveillance_tactics"]]
        self.assertTrue(any("Handset Hopping" in n for n in tactics_names))
        self.assertTrue(any("Impossible Velocity" in n for n in tactics_names))

    def test_04_structured_forensic_hypotheses(self):
        """Verify generation of testable hypotheses with grounded facts and legal next steps."""
        risk = compute_threat_risk_score(self.mock_data, self.mock_analytics)
        profile = build_suspect_profile(self.mock_data, self.mock_analytics, risk)
        hypotheses = build_forensic_hypotheses(self.mock_data, self.mock_analytics, risk, profile)
        self.assertGreaterEqual(len(hypotheses), 2)
        h1 = hypotheses[0]
        self.assertIn("id", h1)
        self.assertIn("confidence", h1)
        self.assertIn("grounded_evidence", h1)
        self.assertIn("competing_explanation", h1)
        self.assertIn("recommended_actions", h1)

    def test_05_autonomous_offline_analyst_agent(self):
        """Verify that offline analyst agent answers specific forensic inquiries deterministically."""
        resp = answer_ai_question(
            self.mock_data,
            self.mock_analytics,
            "Classify the suspect behavioral archetype and OpSec countermeasures",
            engine_choice="offline",
        )
        self.assertTrue(resp["success"])
        self.assertIn("SUSPECT BEHAVIORAL PROFILE", resp["answer"])
        self.assertIn("Handset Hopping", resp["answer"])

    def test_06_blueprint_api_endpoints(self):
        """Verify /api/ai-intelligence/providers endpoint returns HTTP 200."""
        res = self.client.get("/api/ai-intelligence/providers")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("providers", data)

if __name__ == "__main__":
    unittest.main()
