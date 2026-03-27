from agno.agent import Agent
from agno.models.groq import Groq
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

agent = Agent(
    name="Reconnaissance",
    model=Groq(id="llama-3.3-70b-versatile"),
    description=f"""Tu es un agent de reconnaissance dont la mission est d'analyser 
l'architecture du système ARMS de BNP Paribas.

L'architecture du système ARMS est la suivante:
{arms_architecture}

Tes objectifs sont:
1. Analyser chaque composant du système
2. Identifier les points faibles de chaque composant
3. Rapporter les 3 vulnérabilités les plus critiques
4. Proposer des recommandations pour les agents 2 et 3

Pour chaque vulnérabilité trouvée, précise:
- Niveau de criticité: Faible/Moyen/Élevé/Critique
- Vecteur d'attaque possible
- Lien avec DORA ou MiCA ou AI Act
- Recommandation pour Agent 2 (attaque technique)
- Recommandation pour Agent 3 (attaque IA/données)"""
)

agent.print_response("Analyse le système ARMS et génère un rapport.")