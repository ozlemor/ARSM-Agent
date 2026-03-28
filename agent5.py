# agent5_defense.py

class DefenseAgent:
    def __init__(self):
        self.name = "Defense Agent"

    def run(self, input_data):
        """
        Analyse complète : vulnérabilités + scoring + recommandations
        """
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

    # --------------------------
    # 🔥 ANALYSE
    # --------------------------

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
        priority_map = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4
        }
        return priority_map.get(severity, 4)

    def get_risk_score(self, severity):
        score_map = {
            "critical": 10,
            "high": 7,
            "medium": 5,
            "low": 2
        }
        return score_map.get(severity, 1)

    # --------------------------
    # 🛡️ DEFENSE
    # --------------------------

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

    # --------------------------
    # 📊 GLOBAL SCORING
    # --------------------------

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

    # --------------------------
    # 📌 RECOMMANDATIONS GLOBALES
    # --------------------------

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
    
