from dotenv import load_dotenv
load_dotenv()

from agno.agent import Agent
from agno.models.groq import Groq
import json
import os

# ----------------------------------------------------------------
# CHARGEMENT DES RAPPORTS PRECEDENTS
# ----------------------------------------------------------------
def charger_rapports():
    contexte = ""
    
    if os.path.exists("rapport_reconnaissance.json"):
        with open("rapport_reconnaissance.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            contexte += f"\nRAPPORT AGENT 1 - RECONNAISSANCE:\n{json.dumps(data, ensure_ascii=False, indent=2)}"
    
    if os.path.exists("rapport_attaquant.json"):
        with open("rapport_attaquant.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            contexte += f"\nRAPPORT AGENT 2 - ATTAQUANT:\n{json.dumps(data, ensure_ascii=False, indent=2)}"
    
    if os.path.exists("rapport_ia_adversaire.json"):
        with open("rapport_ia_adversaire.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            contexte += f"\nRAPPORT AGENT 3 - IA ADVERSAIRE:\n{json.dumps(data, ensure_ascii=False, indent=2)}"
    
    return contexte

contexte_attaques = charger_rapports()

# ----------------------------------------------------------------
# CREATION DE L'AGENT
# ----------------------------------------------------------------
compliance_agent = Agent(
    name="Compliance Breaker",
    model=Groq(id="llama-3.3-70b-versatile"),
    description=f"""Tu es un expert senior en conformite reglementaire bancaire europeenne.

Ta mission : analyser les attaques detectees et identifier les violations reglementaires.

=== RAPPORTS DES AGENTS PRECEDENTS ===
{contexte_attaques}

=== REGLEMENTATIONS A VERIFIER ===

1. DORA (Digital Operational Resilience Act)
   - Art.28 : maitrise des dependances critiques externes
   - Art.17 : gestion des incidents TIC
   - Art.11 : continuite des activites

2. MiCA (Markets in Crypto-Assets)
   - Art.70 : securite des portefeuilles crypto
   - Art.16 : obligations des emetteurs

3. EU AI Act
   - Art.13 : transparence et explicabilite
   - Art.9  : systeme de gestion des risques IA
   - Art.17 : documentation technique

4. RGPD
   - Art.25 : privacy by design
   - Art.32 : securite du traitement
   - Art.33 : notification des violations

=== FORMAT DE REPONSE (JSON strict) ===
Reponds UNIQUEMENT avec ce JSON, sans texte avant ou apres :
{{
  "violations": [
    {{
      "reglementation": "DORA|MiCA|AI Act|RGPD",
      "article": "numero article",
      "description": "description de la violation",
      "severite": "Faible|Moyen|Eleve|Critique",
      "preuve": "lien avec l attaque detectee",
      "action_corrective": "mesure concrete a prendre"
    }}
  ],
  "niveau_risque_global": "Faible|Moyen|Eleve|Critique",
  "score_conformite": 0.0,
  "resume_audit": "synthese executive de l audit",
  "recommandations_prioritaires": ["action1", "action2", "action3"]
}}"""
)

# ----------------------------------------------------------------
# LANCEMENT
# ----------------------------------------------------------------
if __name__ == "__main__":
    print("Agent 4 - Compliance Breaker en cours d analyse...\n")

    reponse = compliance_agent.run(
        """Analyse tous les rapports des agents precedents et identifie
        toutes les violations reglementaires DORA, MiCA, AI Act et RGPD.
        Pour chaque violation, cite l article exact et propose une action corrective concrete."""
    )

    texte = reponse.content

    if "```json" in texte:
        texte = texte.split("```json")[1].split("```")[0].strip()
    elif "```" in texte:
        texte = texte.split("```")[1].split("```")[0].strip()

    try:
        rapport = json.loads(texte)

        print("===== RAPPORT AGENT 4 - COMPLIANCE BREAKER =====\n")

        for i, violation in enumerate(rapport["violations"], 1):
            print(f"[{i}] Reglementation : {violation['reglementation']}")
            print(f"    Article        : {violation['article']}")
            print(f"    Description    : {violation['description']}")
            print(f"    Severite       : {violation['severite']}")
            print(f"    Preuve         : {violation['preuve']}")
            print(f"    Correction     : {violation['action_corrective']}")
            print()

        print(f"Niveau risque global : {rapport['niveau_risque_global']}")
        print(f"Score conformite     : {rapport['score_conformite']}")
        print(f"Resume audit         : {rapport['resume_audit']}")
        print("\nRecommandations prioritaires :")
        for rec in rapport["recommandations_prioritaires"]:
            print(f"  - {rec}")

        with open("rapport_compliance.json", "w", encoding="utf-8") as f:
            json.dump(rapport, f, ensure_ascii=False, indent=2)

        print("\nRapport exporte -> rapport_compliance.json")

    except json.JSONDecodeError as e:
        print(f"Erreur parsing JSON : {e}")
        with open("rapport_compliance.json", "w", encoding="utf-8") as f:
            json.dump({"contenu_brut": reponse.content}, f, ensure_ascii=False, indent=2)
        print("Rapport brut exporte -> rapport_compliance.json")