import sys
import os
sys.path.append(os.getcwd())

from backend.app.db import SessionLocal
from backend.app.models import Device

def check():
    db = SessionLocal()
    try:
        devices = db.query(Device).all()
        print(f"--- DIAGNOSTIC INVENTAIRE ---")
        print(f"Nombre d'appareils trouvés : {len(devices)}")
        for d in devices:
            status = "ONLINE" if d.is_online else "OFFLINE"
            print(f"ID: {d.id} | IP: {d.ip} | MAC: {d.mac} | Status: {status}")
        
        if len(devices) == 0:
            print("\nAVERTISSEMENT : La base de données est vide.")
            print("Causes possibles :")
            print("1. Le scanner n'a pas les droits Administrateur (requis pour Scapy sur Windows).")
            print("2. Npcap n'est pas installé sur la machine.")
            print("3. Aucune interface réseau physique active n'a été détectée.")
    except Exception as e:
        print(f"ERREUR : {e}")
    finally:
        db.close()

if __name__ == "__main__":
    check()
