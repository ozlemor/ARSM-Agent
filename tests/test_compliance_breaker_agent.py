"""Tests unitaires pour compliance_breaker_agent (API Grok simulée)."""

import json
import unittest
from unittest.mock import MagicMock, patch

import compliance_breaker_agent as cba


class TestComputeRiskScore(unittest.TestCase):
    def test_empty_low(self):
        s = cba.ComplianceBreakerAgent.compute_risk_score([], "Low")
        self.assertGreaterEqual(s, 1)
        self.assertLessEqual(s, 10)

    def test_severities_aggregate(self):
        violations = [
            {"severity": "Critical"},
            {"severity": "High"},
        ]
        s = cba.ComplianceBreakerAgent.compute_risk_score(violations, "High")
        self.assertGreaterEqual(s, 7)


class TestAnalyze(unittest.TestCase):
    def test_missing_api_key(self):
        with patch.dict(cba.os.environ, {"GROK_API_KEY": ""}, clear=False):
            agent = cba.ComplianceBreakerAgent()
            r = agent.analyze("test incident")
        self.assertFalse(r["success"])
        self.assertEqual(r["error"]["code"], "cle_api_absente")

    def test_empty_attack(self):
        agent = cba.ComplianceBreakerAgent(api_key="x")
        r = agent.analyze("   ")
        self.assertFalse(r["success"])
        self.assertEqual(r["error"]["code"], "entree_invalide")

    def test_success_mocked_grok(self):
        payload = {
            "audit_metadata": {"report_title": "T", "limitations": ""},
            "violations": [
                {
                    "regulation_framework": "GDPR",
                    "article_reference": "Art. 32",
                    "violation_summary": "Manque de sécurité",
                    "severity": "High",
                    "mitigation_actions": ["Renforcer contrôles"],
                    "linkage_to_attack_evidence": "Exfiltration",
                }
            ],
            "overall_risk_level": "High",
            "model_risk_score_1_to_10": 8,
            "executive_summary": "Synthèse d'audit.",
            "observations_for_supervisory_dialogue": ["Point 1"],
        }
        api_body = {
            "choices": [
                {"message": {"content": json.dumps(payload, ensure_ascii=False)}}
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_body

        with patch.object(cba.requests, "post", return_value=mock_resp):
            agent = cba.ComplianceBreakerAgent(api_key="sk-test")
            r = agent.analyze("Exfiltration PII constatée.")

        self.assertTrue(r["success"])
        self.assertEqual(len(r["violations"]), 1)
        self.assertEqual(r["violations"][0]["regulation_framework"], "GDPR")
        self.assertEqual(r["risk_level"], "High")
        self.assertIsNotNone(r["risk_score"])
        self.assertIn("Synthèse", r["explanation"])
        self.assertEqual(r["error"], None)

    def test_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.reason = "Unauthorized"
        mock_resp.json.return_value = {"error": {"message": "Invalid key"}}

        with patch.object(cba.requests, "post", return_value=mock_resp):
            agent = cba.ComplianceBreakerAgent(api_key="bad")
            r = agent.analyze("incident")

        self.assertFalse(r["success"])
        self.assertEqual(r["error"]["code"], "erreur_http")
        self.assertEqual(r["error"]["http_status"], 401)


if __name__ == "__main__":
    unittest.main()
