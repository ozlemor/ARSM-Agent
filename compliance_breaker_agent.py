"""
Analyse post-incident : lecture réglementaire de récits d'attaques cyber ou d'IA
vis-à-vis des systèmes financiers.

S'appuie sur l'API HTTP xAI Grok. Les sorties sont des évaluations de style conformité
à titre illustratif et ne constituent ni un avis juridique ni une position de supervision.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import requests

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

DEFAULT_CHAT_URL = "https://api.x.ai/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("GROK_MODEL", "grok-4-1-fast-non-reasoning")


class ComplianceBreakerError(Exception):
    """Levé pour une configuration invalide ou une panne API irrécupérable si analyze(..., raise_on_error=True)."""


class ComplianceBreakerAgent:
    """Analyse des traces d'attaque au regard de DORA, MiCA, EU AI Act et RGPD via Grok."""

    # Gravité et niveau de risque : le modèle doit renvoyer ces libellés EN ANGLAIS (contrat JSON).
    _SEVERITY_ALIASES = {
        "low": "low",
        "faible": "low",
        "medium": "medium",
        "modéré": "medium",
        "modere": "medium",
        "moyen": "medium",
        "high": "high",
        "élevé": "high",
        "eleve": "high",
        "critical": "critical",
        "critique": "critical",
    }

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        api_url: str = DEFAULT_CHAT_URL,
        timeout: float = 120.0,
        temperature: float = 0.3,
    ) -> None:
        self.api_key = api_key or os.environ.get("GROK_API_KEY")
        self.model = model or DEFAULT_MODEL
        self.api_url = api_url
        self.timeout = timeout
        self.temperature = temperature

    @staticmethod
    def compute_risk_score(
        violations: list[dict[str, Any]],
        risk_level: str | None = None,
    ) -> int:
        """
        Score déterministe sur 1 à 10 à partir des gravités des violations et du bandeau de risque global.
        """
        weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
        total = 0.0
        for v in violations:
            raw = str(v.get("severity", "medium")).strip().lower()
            canon = ComplianceBreakerAgent._SEVERITY_ALIASES.get(raw, raw)
            total += weights.get(canon, 1.0)
        base = 1.0 + min(6.0, total * 0.85)
        score = int(max(1, min(10, round(base))))
        band = str(risk_level or "").strip().lower()
        band = ComplianceBreakerAgent._SEVERITY_ALIASES.get(band, band)
        if band in ("high", "critical"):
            score = max(score, 7)
        elif band == "medium":
            score = max(score, 4)
        elif band == "low" and not violations:
            score = min(score, 3)
        return int(max(1, min(10, score)))

    def _system_instruction(self) -> str:
        return (
            "Vous êtes un expert senior conformité et risques IT rédigeant une note d'audit réglementaire "
            "interne confidentielle pour un groupe bancaire européen (contexte CRR/CRD). "
            "Soyez précis, prudent dans vos assertions et citez les textes avec rigueur. "
            "Si le récit d'incident ne permet pas d'établir une infraction, énoncez les hypothèses "
            "et signalez l'incertitude résiduelle. "
            "Ne rattachez une problématique à DORA, MiCA, le règlement européen sur l'IA ou le RGPD "
            "que si les faits le soutiennent ; sinon abstenez-vous ou qualifiez en « potentiel / incertain ». "
            "N'inventez pas de données personnelles ni d'échanges avec les autorités non suggérés par l'entrée utilisateur. "
            "Rédigez en français professionnel (style rapport d'audit)."
        )

    def _user_prompt(self, attack_data: str) -> str:
        schema_hint = """{
  "audit_metadata": {
    "report_title": "string",
    "entity_context": "string",
    "scope": "string",
    "limitations": "string"
  },
  "violations": [
    {
      "regulation_framework": "DORA | MiCA | EU AI Act | GDPR",
      "article_reference": "string",
      "violation_summary": "string",
      "severity": "Low | Medium | High | Critical",
      "mitigation_actions": ["string"],
      "linkage_to_attack_evidence": "string"
    }
  ],
  "overall_risk_level": "Low | Medium | High",
  "model_risk_score_1_to_10": 0,
  "executive_summary": "string",
  "observations_for_supervisory_dialogue": ["string"]
}"""
        return f"""### Mission
Rédiger une note de synthèse d'audit réglementaire (format banque européenne) à partir du récit d'attaque
cyber ou d'IA / compte-rendu d'incident ci-dessous. Évaluer l'exposition conformité substantielle au regard de :
- **DORA** (résilience opérationnelle numérique)
- **MiCA** (crypto-actifs et services connexes), lorsque le périmètre l'impose
- **EU AI Act** (systèmes d'IA, modèles ou décisions automatisées concernées)
- **GDPR / RGPD** (traitement de données personnelles, sécurité, notification de violation, AIPD, rôles responsable/sous-traitant)

### Récit incident (contexte pour analyse)
```
{attack_data.strip()}
```

### Livrable (JSON uniquement)
Retourner **uniquement** un objet JSON valide, sans blocs markdown ni commentaire hors JSON, avec la structure suivante :
{schema_hint}

**Contraintes techniques :** les noms de clés JSON ci-dessus doivent rester **exactement** tels qu'indiqués.
Pour `regulation_framework`, utiliser impérativement l'une des chaînes : DORA, MiCA, EU AI Act, GDPR.
Pour `severity` et `overall_risk_level`, utiliser **obligatoirement** les valeurs en anglais listées (Low, Medium, High, Critical).

Règles de fond :
1. Chaque violation doit être reliée à **au moins une référence d'article** (ou base légalement équivalente) lorsque vous affirmez un écart matériel ; en cas de doute, réduisez la gravité et précisez-le dans `linkage_to_attack_evidence`.
2. Les `mitigation_actions` doivent être opérationnelles pour un établissement soumis à la supervision bancaire de l'Union (gouvernance, risque TIC, sous-traitance, reporting d'incident, sécurité des flux crypto, gouvernance IA, privacy by design, etc.).
3. `overall_risk_level` doit être cohérent avec l'agrégat des gravités et l'impact systémique décrit.
4. `model_risk_score_1_to_10` : votre score numérique global (1 = faible, 10 = risque systémique grave / escalade superviseur plausible).
5. Ton : rapport d'audit formel à la troisième personne, adapté à un comité d'audit et à un dialogue de type **ACPR / BCE–SSM** (sans nommer de superviseurs réels sauf s'ils figurent dans l'entrée).

Commencez l'objet JSON maintenant."""

    @staticmethod
    def _extract_json_object(text: str) -> dict[str, Any]:
        text = text.strip()
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if fence:
            text = fence.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise json.JSONDecodeError("Aucun objet JSON dans la sortie du modèle", text, 0)

    def _call_grok(self, attack_data: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if not self.api_key:
            return None, {
                "code": "cle_api_absente",
                "message": "La variable d'environnement GROK_API_KEY n'est pas définie.",
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": self._system_instruction()},
                {"role": "user", "content": self._user_prompt(attack_data)},
            ],
        }

        try:
            r = requests.post(self.api_url, headers=headers, json=payload, timeout=self.timeout)
        except requests.exceptions.Timeout:
            return None, {
                "code": "timeout",
                "message": f"Dépassement du délai ({self.timeout}s).",
            }
        except requests.exceptions.ConnectionError as e:
            return None, {"code": "erreur_connexion", "message": str(e)}
        except requests.exceptions.RequestException as e:
            return None, {"code": "erreur_requete", "message": str(e)}

        err_body: dict[str, Any] | None = None
        try:
            err_body = r.json()
        except json.JSONDecodeError:
            err_body = {"raw": r.text[:2000]}

        if r.status_code >= 400:
            return None, {
                "code": "erreur_http",
                "http_status": r.status_code,
                "message": err_body.get("error", {}).get("message", r.reason)
                if isinstance(err_body.get("error"), dict)
                else str(err_body),
                "details": err_body,
            }

        try:
            data = r.json()
        except json.JSONDecodeError:
            return None, {
                "code": "reponse_json_invalide",
                "message": "L'API Grok a renvoyé un corps non JSON.",
                "details": {"body_preview": str(r.text)[:2000]},
            }

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            return None, {
                "code": "reponse_mal_formee",
                "message": "Structure de réponse Grok inattendue.",
                "details": {"parse_error": str(e), "body_preview": str(data)[:2000]},
            }

        try:
            parsed = self._extract_json_object(content)
        except json.JSONDecodeError as e:
            return None, {
                "code": "erreur_parse_json",
                "message": str(e),
                "details": {"raw_model_text": content[:8000]},
            }

        return parsed, None

    def _normalize_severity(self, value: str) -> str:
        raw = str(value or "Medium").strip().lower()
        return self._SEVERITY_ALIASES.get(raw, raw if raw in ("low", "medium", "high", "critical") else "medium").title()

    def _normalize_violations(self, raw: list[Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not isinstance(raw, list):
            return out
        for item in raw:
            if not isinstance(item, dict):
                continue
            mitigation = item.get("mitigation_actions")
            if isinstance(mitigation, str):
                mitigation = [mitigation]
            elif not isinstance(mitigation, list):
                mitigation = []
            out.append(
                {
                    "regulation_framework": str(item.get("regulation_framework", "")),
                    "article_reference": str(item.get("article_reference", "")),
                    "violation_summary": str(item.get("violation_summary", "")),
                    "severity": self._normalize_severity(str(item.get("severity", "Medium"))),
                    "mitigation_actions": [str(m) for m in mitigation],
                    "linkage_to_attack_evidence": str(
                        item.get("linkage_to_attack_evidence", "")
                    ),
                }
            )
        return out

    def analyze(
        self,
        attack_data: str,
        *,
        raise_on_error: bool = False,
    ) -> dict[str, Any]:
        """
        Exécute l'analyse Grok et renvoie un dictionnaire structuré.

        En cas d'échec : success=False et objet ``error``, sauf si raise_on_error=True (exception).
        """
        if not attack_data or not str(attack_data).strip():
            err = {
                "code": "entree_invalide",
                "message": "attack_data doit être une chaîne non vide.",
            }
            if raise_on_error:
                raise ComplianceBreakerError(err["message"])
            return {
                "success": False,
                "violations": [],
                "risk_level": None,
                "risk_score": None,
                "explanation": None,
                "error": err,
            }

        parsed, err = self._call_grok(attack_data)
        if err:
            if raise_on_error:
                raise ComplianceBreakerError(json.dumps(err, ensure_ascii=False))
            return {
                "success": False,
                "violations": [],
                "risk_level": None,
                "risk_score": None,
                "explanation": None,
                "error": err,
            }

        assert parsed is not None
        violations = self._normalize_violations(parsed.get("violations", []))
        meta = parsed.get("audit_metadata") if isinstance(parsed.get("audit_metadata"), dict) else {}
        risk_raw = str(parsed.get("overall_risk_level", "Medium")).strip()
        risk_level = self._normalize_severity(risk_raw)
        # overall_risk_level est Low/Medium/High (pas Critical en schéma)
        if risk_level == "Critical":
            risk_level = "High"

        model_score = parsed.get("model_risk_score_1_to_10")
        try:
            model_score_int = int(model_score) if model_score is not None else None
        except (TypeError, ValueError):
            model_score_int = None
        if model_score_int is not None:
            model_score_int = max(1, min(10, model_score_int))

        computed = self.compute_risk_score(violations, risk_level)
        if model_score_int is not None:
            risk_score = max(computed, model_score_int)
        else:
            risk_score = computed

        explanation = str(
            parsed.get("executive_summary") or parsed.get("explanation") or ""
        ).strip()
        observations = parsed.get("observations_for_supervisory_dialogue")
        if not isinstance(observations, list):
            observations = []

        return {
            "success": True,
            "audit_metadata": meta,
            "violations": violations,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_score_computed": computed,
            "model_risk_score": model_score_int,
            "explanation": explanation,
            "observations_for_supervisory_dialogue": [str(x) for x in observations],
            "raw_model_json": parsed,
            "error": None,
        }


if __name__ == "__main__":
    example_attack = """
    Synthèse post-exploitation — exercice red team sur cœur de paiement (synthétique)
    - L'acteur a obtenu un compte administrateur du domaine ; MFA sur le VPN désactivée 6 heures.
    - Déploiement d'un collecteur d'identifiants sur le poste de l'équipe analytique risques.
    - Accès à une réplique PostgreSQL avec ~340k enregistrements clients (noms, fragments d'IBAN, scores risque).
    - Modification du feature store du modèle temps réel de scoring fraude (GBT) :
      abaissement des seuils d'alerte virement sortant pour 22 comptes corporate à forte valeur.
    - Bureau crypto : matériel de clé API de signature hot-wallet exposé dans une sauvegarde d'état Terraform
      stockée sur un compartiment objet S3-équivalent mal configuré ; 2 transferts sortants tentés, un bloqué.
    - Incident détecté à T+4h ; confinement à T+9h. Aucune notification au référent TIC DORA (tiers)
      ni à l'autorité de protection des données sous 24h dans le journal d'exercice. Intégrité des sauvegardes non vérifiée avant restauration.
    """

    agent = ComplianceBreakerAgent()
    result = agent.analyze(example_attack)
    print(json.dumps(result, indent=2, ensure_ascii=False))
