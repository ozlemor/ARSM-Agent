from dotenv import load_dotenv
load_dotenv()

from agno.agent import Agent
from agno.models.groq import Groq
import json

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
Ta mission : Créer des scénarios d'attaque réalistes.
Données :
{recon_summary}
Objectifs :
1. Créer 2 scénarios :
   - 1 cyber classique
   - 1 attaque data / IA
2. Identifier le point de rupture
3. Décrire les impacts business

Reponds UNIQUEMENT avec ce JSON sans texte avant ou apres :
{{
  "scenarios": [
    {{
      "type": "CYBER_CLASSIQUE",
      "cible": "",
      "faiblesse": "",
      "deroulement": "",
      "point_de_rupture": "",
      "impact": ""
    }},
    {{
      "type": "DATA_IA",
      "cible": "",
      "faiblesse": "",
      "deroulement": "",
      "point_de_rupture": "",
      "impact": ""
    }}
  ],
  "synthese": {{
    "scenario_critique": "",
    "pourquoi": "",
    "recommandations": ""
  }}
}}""",
    markdown=False,
)

if __name__ == "__main__":
    reponse = attack_agent.run(
        "Genere deux scenarios d attaque contre le systeme ARMS."
    )

    texte = reponse.content

    if "```json" in texte:
        texte = texte.split("```json")[1].split("```")[0].strip()
    elif "```" in texte:
        texte = texte.split("```")[1].split("```")[0].strip()

    try:
        rapport = json.loads(texte)

        print("\n===== RAPPORT AGENT 2 - ATTAQUANT =====\n")
        for scenario in rapport["scenarios"]:
            print(f"Type           : {scenario['type']}")
            print(f"Cible          : {scenario['cible']}")
            print(f"Faiblesse      : {scenario['faiblesse']}")
            print(f"Deroulement    : {scenario['deroulement']}")
            print(f"Point rupture  : {scenario['point_de_rupture']}")
            print(f"Impact         : {scenario['impact']}")
            print()

        print(f"Scenario critique : {rapport['synthese']['scenario_critique']}")
        print(f"Pourquoi          : {rapport['synthese']['pourquoi']}")
        print(f"Recommandations   : {rapport['synthese']['recommandations']}")

        with open("rapport_attaquant.json", "w", encoding="utf-8") as f:
            json.dump(rapport, f, ensure_ascii=False, indent=2)

        print("\nRapport exporte -> rapport_attaquant.json")

    except json.JSONDecodeError as e:
        print(f"Erreur parsing JSON : {e}")
        rapport_brut = {"contenu_brut": reponse.content}
        with open("rapport_attaquant.json", "w", encoding="utf-8") as f:
            json.dump(rapport_brut, f, ensure_ascii=False, indent=2)
        print("Rapport brut exporte -> rapport_attaquant.json")
