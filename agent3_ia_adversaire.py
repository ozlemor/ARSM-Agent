from dotenv import load_dotenv
load_dotenv()

from agno.agent import Agent
from agno.models.groq import Groq
import json
import os

# ----------------------------------------------------------------
# CHARGEMENT DU RAPPORT DE L'AGENT 1
# ----------------------------------------------------------------
def charger_rapport_reconnaissance():
    if os.path.exists("rapport_reconnaissance.json"):
        with open("rapport_reconnaissance.json", "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "priorite_cibles": [
            "fraud_detection",
            "aml_engine",
            "anomaly_detection"
        ]
    }

rapport_recon = charger_rapport_reconnaissance()

# ----------------------------------------------------------------
# DESCRIPTION DES MODELES IA D'ARMS
# ----------------------------------------------------------------
couche_ia_arms = {
    "fraud_detection": {
        "type": "Modele de classification binaire",
        "input": "montant, frequence, localisation, historique client",
        "output": "score fraude 0-1 (seuil alerte = 0.75)",
        "donnees_entrainement": "24 mois de transactions historiques"
    },
    "aml_engine": {
        "type": "Moteur de regles + ML hybride",
        "input": "patterns de transactions, profil client, blacklist",
        "output": "alerte LCB-FT oui/non + score de risque",
        "seuil_detection": "transactions > 10 000 EUR ou patterns suspects"
    },
    "anomaly_detection": {
        "type": "Modele non supervise (clustering)",
        "input": "comportement transactionnel en temps reel",
        "output": "score anomalie + categorie de risque",
        "baseline": "comportement normal des 90 derniers jours"
    },
    "risk_scoring": {
        "type": "Modele de regression",
        "input": "donnees agregees des 3 autres modeles",
        "output": "score de risque global client 0-100"
    }
}

# ----------------------------------------------------------------
# CREATION DE L'AGENT
# ----------------------------------------------------------------
agent_ia_adversaire = Agent(
    name="IA Adversaire",
    model=Groq(id="llama-3.3-70b-versatile"),
    description=f"""Tu es un expert en attaques adversariales contre les systemes IA bancaires.

Ta mission : simuler des attaques realistes sur les modeles IA du systeme ARMS de BNP Paribas.

=== MODELES IA CIBLES ===
{json.dumps(couche_ia_arms, ensure_ascii=False, indent=2)}

=== CIBLES PRIORITAIRES IDENTIFIEES PAR AGENT 1 ===
{rapport_recon.get('priorite_cibles', ['fraud_detection', 'aml_engine'])}

=== TES 3 TECHNIQUES D'ATTAQUE ===

1. DATA POISONING
   - Injecte de fausses transactions dans les donnees d entrainement
   - Objectif : corrompre le modele pour qu il rate les fraudes
   - Exemple : creer 500 fausses transactions propres associees a un compte frauduleux

2. INPUT PERTURBATION
   - Modifie subtilement les donnees en temps reel
   - Objectif : passer sous le seuil de detection
   - Exemple : fractionner 50 000 EUR en 51 virements de 980 EUR

3. INJECTION DE BIAIS
   - Introduis un biais systematique dans la detection
   - Objectif : que l IA ignore un pattern de fraude precis
   - Exemple : transactions crypto systematiquement sous-scorees

Reponds UNIQUEMENT avec ce JSON sans texte avant ou apres :
{{
  "attaques": [
    {{
      "technique": "DATA_POISONING",
      "modele_cible": "nom du modele attaque",
      "description_attaque": "explication detaillee",
      "donnees_injectees": "exemple concret avec chiffres reels",
      "effet_attendu": "quel comportement errone est provoque",
      "detection_possible": "oui|non|partielle",
      "raison_non_detection": "pourquoi ARMS ne voit pas l attaque",
      "lien_reglementaire": "AI Act Art.13 / DORA / MiCA",
      "score_danger": 0.9
    }},
    {{
      "technique": "INPUT_PERTURBATION",
      "modele_cible": "",
      "description_attaque": "",
      "donnees_injectees": "",
      "effet_attendu": "",
      "detection_possible": "",
      "raison_non_detection": "",
      "lien_reglementaire": "",
      "score_danger": 0.0
    }},
    {{
      "technique": "INJECTION_BIAIS",
      "modele_cible": "",
      "description_attaque": "",
      "donnees_injectees": "",
      "effet_attendu": "",
      "detection_possible": "",
      "raison_non_detection": "",
      "lien_reglementaire": "",
      "score_danger": 0.0
    }}
  ],
  "resume_impact": "description globale de l impact sur ARMS",
  "recommandation_agent4": "quelles violations reglementaires signaler",
  "recommandation_agent5": "comment scorer l impact financier"
}}"""
)

# ----------------------------------------------------------------
# LANCEMENT ET TRAITEMENT DE LA REPONSE
# ----------------------------------------------------------------
if __name__ == "__main__":

    print("Agent 3 - IA Adversaire en cours d analyse...\n")

    reponse = agent_ia_adversaire.run(
        """Simule les 3 attaques adversariales sur les modeles IA d ARMS.
        Donne des exemples concrets avec des donnees chiffrees realistes.
        Explique precisement pourquoi ARMS ne detecte pas ces attaques."""
    )

    texte = reponse.content

    if "```json" in texte:
        texte = texte.split("```json")[1].split("```")[0].strip()
    elif "```" in texte:
        texte = texte.split("```")[1].split("```")[0].strip()

    try:
        rapport = json.loads(texte)

        print("===== RAPPORT ATTAQUES IA ADVERSARIALES =====\n")

        for i, attaque in enumerate(rapport["attaques"], 1):
            print(f"[{i}] Technique      : {attaque['technique']}")
            print(f"    Modele cible   : {attaque['modele_cible']}")
            print(f"    Description    : {attaque['description_attaque']}")
            print(f"    Donnees        : {attaque['donnees_injectees']}")
            print(f"    Effet attendu  : {attaque['effet_attendu']}")
            print(f"    Detection      : {attaque['detection_possible']}")
            print(f"    Pourquoi       : {attaque['raison_non_detection']}")
            print(f"    Reglementation : {attaque['lien_reglementaire']}")
            print(f"    Danger         : {attaque['score_danger']}/1.0")
            print()

        print(f"Impact global  : {rapport['resume_impact']}")
        print(f"Agent 4        : {rapport['recommandation_agent4']}")
        print(f"Agent 5        : {rapport['recommandation_agent5']}")

        with open("rapport_ia_adversaire.json", "w", encoding="utf-8") as f:
            json.dump(rapport, f, ensure_ascii=False, indent=2)

        print("\nRapport exporte -> rapport_ia_adversaire.json")

    except json.JSONDecodeError as e:
        print(f"Erreur parsing JSON : {e}")
        with open("rapport_ia_adversaire.json", "w", encoding="utf-8") as f:
            json.dump({"contenu_brut": reponse.content}, f, ensure_ascii=False, indent=2)
        print("Rapport brut exporte -> rapport_ia_adversaire.json")