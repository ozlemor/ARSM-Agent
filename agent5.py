import json
import os

class DefenseAgent:
    def __init__(self):
        self.name = "Defense Agent"

    def run(self, input_data):
        results = []
        total_score = 0

        for item in input_data:
            vulnerability = item.get("vulnerability", "unknown")
            severity = self.get_severity(vulnerability)
            priority = self.get_priority(severity)
            defense = self.generate_defense(vulnerability)
            score = self.get_risk_score(severity)
            total_score += score
            results.append({
                "vulnerability": vulnerability,
                "severity": severity,
                "priority": priority,
                "risk_score": score,
                "defense": defense
            })

        global_score = self.compute_global_score(total_score, len(results))
        report = {
            "summary": {
                "total_vulnerabilities": len(results),
                "global_risk_score": global_score,
                "risk_level": self.get_global_risk_level(global_score)
            },
            "details": results,
            "recommendations": self.generate_global_recommendations(results)
        }
        return report

    def get_severity(self, vulnerability):
        severity_map = {
            "sql_injection": "critical",
            "rce": "critical",
            "xss": "medium",
            "csrf": "medium",
            "open_port": "low"
        }
        return severity_map.get(vulnerability, "low")

    def get_priority(self, severity):
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        return priority_map.get(severity, 4)

    def get_risk_score(self, severity):
        score_map = {"critical": 10, "high": 7, "medium": 5, "low": 2}
        return score_map.get(severity, 1)

    def generate_defense(self, vulnerability):
        defenses = {
            "sql_injection": "Use parameterized queries, ORM, and input validation",
            "rce": "Sanitize inputs and restrict execution permissions",
            "xss": "Escape outputs and sanitize user inputs",
            "csrf": "Implement CSRF tokens and secure cookies",
            "open_port": "Close unused ports and configure firewall",
            "unknown": "Apply OWASP Top 10 security best practices"
        }
        return defenses.get(vulnerability, defenses["unknown"])

    def compute_global_score(self, total_score, count):
        if count == 0:
            return 0
        return round(total_score / count, 2)

    def get_global_risk_level(self, score):
        if score >= 8:
            return "CRITICAL"
        elif score >= 6:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_global_recommendations(self, results):
        recommendations = []
        critical_issues = [r for r in results if r["severity"] == "critical"]
        if critical_issues:
            recommendations.append("Fix critical vulnerabilities immediately")
        if len(results) > 5:
            recommendations.append("Implement continuous security monitoring")
        recommendations.append("Apply security best practices (OWASP Top 10)")
        recommendations.append("Perform regular penetration testing")
        return recommendations


if __name__ == "__main__":

    input_data = []

    if os.path.exists("rapport_reconnaissance.json"):
        with open("rapport_reconnaissance.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            for vuln in data.get("vulnerabilites", []):
                input_data.append({"vulnerability": vuln.get("composant", "unknown")})

    if os.path.exists("rapport_ia_adversaire.json"):
        with open("rapport_ia_adversaire.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            for attaque in data.get("attaques", []):
                input_data.append({"vulnerability": attaque.get("technique", "unknown")})

    if not input_data:
        input_data = [
            {"vulnerability": "sql_injection"},
            {"vulnerability": "rce"},
            {"vulnerability": "xss"},
            {"vulnerability": "open_port"}
        ]

    agent = DefenseAgent()
    rapport = agent.run(input_data)

    print("\n===== RAPPORT AGENT 5 - IMPACT & RISK SCORING =====\n")
    print(f"Total vulnerabilites : {rapport['summary']['total_vulnerabilities']}")
    print(f"Score global         : {rapport['summary']['global_risk_score']}")
    print(f"Niveau de risque     : {rapport['summary']['risk_level']}")
    print("\nDetails :")
    for detail in rapport["details"]:
        print(f"  - {detail['vulnerability']} | Severite: {detail['severity']} | Score: {detail['risk_score']}")
    print("\nRecommandations :")
    for rec in rapport["recommendations"]:
        print(f"  - {rec}")

    with open("rapport_final_scoring.json", "w", encoding="utf-8") as f:
        json.dump(rapport, f, ensure_ascii=False, indent=2)

    print("\nRapport exporte -> rapport_final_scoring.json")