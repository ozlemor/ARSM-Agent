from dotenv import load_dotenv
load_dotenv()

import subprocess
import os
import time

def lancer_agent(nom_fichier, nom_agent):
    print(f"\n{'='*50}")
    print(f"Lancement : {nom_agent}")
    print(f"{'='*50}")
    subprocess.run(["python", nom_fichier])
    time.sleep(2)

def verifier_rapport(fichier_json):
    if os.path.exists(fichier_json):
        print(f"Rapport {fichier_json} : OK")
    else:
        print(f"Rapport {fichier_json} : MANQUANT")

if __name__ == "__main__":

    print("RED TEAM ARMS — PIPELINE COMPLET")

    lancer_agent("agent1_reconnaissance.py", "Agent 1 - Reconnaissance")
    verifier_rapport("rapport_reconnaissance.json")

    lancer_agent("agent2_attack.py", "Agent 2 - Attaquant")
    verifier_rapport("rapport_attaquant.json")

    lancer_agent("agent3_ia_adversaire.py", "Agent 3 - IA Adversaire")
    verifier_rapport("rapport_ia_adversaire.json")

    lancer_agent("compliance_breaker_agent.py", "Agent 4 - Compliance Breaker")
    verifier_rapport("rapport_compliance.json")

    lancer_agent("agent5.py", "Agent 5 - Impact & Risk Scoring")
    verifier_rapport("rapport_final_scoring.json")

    print("\nPipeline termine")