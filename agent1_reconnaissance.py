from dotenv import load_dotenv
load_dotenv()

from agno.agent import Agent
from agno.models.groq import Groq
import json

# ─── Architecture ARMS ───────────────────────────────────────────
arms_architecture = {
    "source_données": {
        "core_banking": "Système bancaire principal",
        "transactions_db": "Base de données des transactions",
        "clients_db": "Base de données des profils clients",
        "blacklist_db": "Base de données AML/LCB-FT"
    },
    "connexions_externes": {
        "swift": "Réseau de transferts internationaux",
        "crypto_api": "Connexions Binance/Coinbase",
        "kyc": "Service de vérification d'identité",
        "banque_centrale": "Connexion Banque de France",
        "visa_mastercard": "Réseau de paiement carte"
    },
    "infrastructure": {
        "cloud": "AWS/Azure",
        "api_gateway": "Point d'entrée des requêtes",
        "load_balancer": "Répartition de charge",
        "firewall": "Protection réseau",
        "logs": "Système de journalisation",
        "monitoring": "Surveillance en temps réel"
    },
    "couche_ia": {
        "fraud_detection": "Modèle de détection de fraude",
        "aml_engine": "Moteur anti-blanchiment",
        "risk_scoring": "Calcul de score de risque",
        "anomaly_detection": "Détection d'anomalies comportementales"
    }
}

# ─── Agent Reconnaissance ─────────────────────────────────────────
agent = Agent(
    name="Reconnaissance",
    model=Groq(id="llama-3.3-70b-versatile"),
    description=f"""Tu es un agent de reconnaissance expert en cybersécurité bancaire.
Tu analyses l'architecture du système ARMS de BNP Paribas.
Architecture cible :
{arms_architecture}
INSTRUCTIONS :
- Analyse CHAQUE composant des 4 couches
- Identifie les TOP 3 vulnérabilités les plus critiques
- Relie chaque faille à DORA, MiCA ou AI Act
- Fournis des recommandations concrètes pour Agent 2 et Agent 3
- Priorise : crypto_api, api_gateway, aml_engine (cibles prioritaires)

Reponds UNIQUEMENT avec ce JSON sans texte avant ou apres :
{{
  "vulnerabilites": [
    {{
      "composant": "nom du composant",
      "description": "description de la faille",
      "criticite": "Faible|Moyen|Eleve|Critique",
      "vecteur_attaque": "comment exploiter cette faille",
      "lien_reglementaire": "DORA|MiCA|AI Act|RGPD",
      "recommandation_agent2": "instruction pour attaque technique",
      "recommandation_agent3": "instruction pour attaque IA"
    }}
  ],
  "surface_attaque_globale": "resume global des surfaces d attaque",
  "priorite_cibles": ["cible1", "cible2", "cible3"]
}}"""
)

# ─── Lancement + export du rapport ───────────────────────────────
if __name__ == "__main__":
    print("Agent 1 - Reconnaissance en cours d analyse...\n")

    reponse = agent.run("Analyse le systeme ARMS et genere un rapport.")

    texte = reponse.content

    if "```json" in texte:
        texte = texte.split("```json")[1].split("```")[0].strip()
    elif "```" in texte:
        texte = texte.split("```")[1].split("```")[0].strip()

    try:
        rapport = json.loads(texte)

        print("===== RAPPORT DE RECONNAISSANCE =====\n")

        for i, vuln in enumerate(rapport["vulnerabilites"], 1):
            print(f"[{i}] Composant      : {vuln['composant']}")
            print(f"    Description    : {vuln['description']}")
            print(f"    Criticite      : {vuln['criticite']}")
            print(f"    Vecteur        : {vuln['vecteur_attaque']}")
            print(f"    Reglementation : {vuln['lien_reglementaire']}")
            print(f"    Agent 2        : {vuln['recommandation_agent2']}")
            print(f"    Agent 3        : {vuln['recommandation_agent3']}")
            print()

        print(f"Surface globale : {rapport['surface_attaque_globale']}")
        print(f"Priorites       : {rapport['priorite_cibles']}")

        with open("rapport_reconnaissance.json", "w", encoding="utf-8") as f:
            json.dump(rapport, f, ensure_ascii=False, indent=2)

        print("\nRapport exporte -> rapport_reconnaissance.json")

    except json.JSONDecodeError as e:
        print(f"Erreur parsing JSON : {e}")
        with open("rapport_reconnaissance.json", "w", encoding="utf-8") as f:
            json.dump({"contenu_brut": reponse.content}, f, ensure_ascii=False, indent=2)
        print("Rapport brut exporte -> rapport_reconnaissance.json")