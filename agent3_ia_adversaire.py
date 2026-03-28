from dotenv import load_dotenv
load_dotenv()
from agno.agent import Agent
from agno.models.groq import Groq
from pydantic import BaseModel
from typing import List

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

# ─── Modèles de sortie structurée ────────────────────────────────
class Vulnerabilite(BaseModel):
    composant: str
    description: str
    criticite: str
    vecteur_attaque: str
    lien_reglementaire: str
    recommandation_agent2: str
    recommandation_agent3: str

class RapportReconnaissance(BaseModel):
    vulnerabilites: List[Vulnerabilite]
    surface_attaque_globale: str
    priorite_cibles: List[str]

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
Réponds uniquement en JSON structuré."""
)

# ─── Lancement + export du rapport ───────────────────────────────
if __name__ == "__main__":
    agent.print_response("Analyse le système ARMS et génère un rapport.")
    
    print("\n===== RAPPORT DE RECONNAISSANCE =====\n")