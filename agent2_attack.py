from agno.agent import Agent
from agno.models.groq import Groq

recon_summary = """
Résultats du Recon Agent :

- crypto_api : dépendance critique, risque de phishing ou mauvaise authentification
- api_gateway : point d'entrée exposé (risque de saturation ou indisponibilité)
- aml_engine : risque de mauvaise détection de fraude si données biaisées

Contexte :
- système bancaire (ARMS)
- APIs externes (crypto, paiement, KYC)
- infrastructure cloud
- IA de détection de fraude
"""

attack_agent = Agent(
    name="Attack Agent",
    model=Groq(id="llama-3.3-70b-versatile"),
    description=f"""
Tu es l'agent 2 (Attaquant) de la Red Team.

Ta mission :
Créer des scénarios d’attaque réalistes à partir des vulnérabilités détectées.

Données :
{recon_summary}

Objectifs :
1. Créer 2 scénarios :
   - 1 cyber classique
   - 1 attaque data / IA
2. Identifier le point de rupture
3. Décrire les impacts business
4. Préparer la suite pour les agents suivants

Format :

SCÉNARIO 1 — cyber
- cible
- faiblesse
- déroulement
- point de rupture
- impact

SCÉNARIO 2 — data / IA
- cible
- faiblesse
- déroulement
- point de rupture
- impact

SYNTHÈSE
- scénario critique
- pourquoi
- recommandations
""",
    markdown=True,
)

if __name__ == "__main__":
    attack_agent.print_response(
        "Génère deux scénarios d’attaque contre le système ARMS."
    )
