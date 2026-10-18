# Build SentinelAgent.exe — Windows

Tu veux un `SentinelAgent.exe` à double-clic/télécharger, sans installer Python sur le PC cible — c'est le cas.

## Option 1 — Télécharger l'artefact déjà buildé (sans build local)

1. Va sur GitHub: **Actions** → workflow **Build Agent EXE (Windows)** → dernier run vert → **Artifacts** → `SentinelAgent-Windows.zip`
2. Dézippe sur le PC cible (ex: `C:\SentinelAgent\`)
3. Tu obtiens: `SentinelAgent.exe` + `config.example.json` + `README.md`
4. Renomme `config.example.json` → `config.json` et édite `server_url` / `token` (voir `docs/agent/INSTALL_WINDOWS.md`)
5. Test: double-clic ou PowerShell `.\SentinelAgent.exe --check`
6. Service: `.\sentinel_agent\service\install_windows_exe.ps1` (Admin)

> Si aucun artefact: le workflow se lance au prochain `git push` touchant `agent/`. Tu peux aussi lancer **Run workflow** manuellement dans Actions.

## Option 2 — Builder en local sur ton Windows

Prérequis: Python 3.11+ dans le PATH.

```powershell
cd agent
powershell -ExecutionPolicy Bypass -File build.ps1
# ou step-by-step:
pip install -r requirements.txt
pip install pyinstaller
pyinstaller sentinel-agent.spec --noconfirm
dir dist\SentinelAgent.exe   # ~15-20 MB, portable, pas d'install Python requise
```

Distribuer: copie `dist\SentinelAgent.exe` + `config.example.json` sur chaque PC.

## Option 3 — Release GitHub (tag)

```bash
git tag agent-v1.0.0
git push origin agent-v1.0.0
# → workflow publie automatiquement SentinelAgent.exe dans Releases
```

## FAQ

**L'exe fait 15-20 MB, c'est normal ?** Oui, il embarque l'interpréteur Python + psutil + requests. One-file = tout dans un seul .exe.

**Faux positif antivirus ?** PyInstaller peut être signalé par certains AV heuristiques (faux positif classique). Signe le .exe ou ajoute une exception. Alternative: distribue en dossier (remplace `EXE` one-file par `COLLECT` one-dir, plus rapide et moins suspect).

**PyInstaller lent au démarrage (10s) ?** Normal en one-file (extraction). Passe en one-dir si besoin.

**Besoin d'icône ?** Ajoute un `.ico` dans `sentinel-agent.spec` ligne `icon='assets/icon.ico'`.

**Mise à jour agent ?** Remplace simplement `SentinelAgent.exe` (service arrêté) et relance.

## D'où vient le .exe ?

Build **uniquement depuis ton dépôt** (`agent/sentinel_agent/`), pas de binaire externe opaque. Code auditable sur ta branche. Le workflow GitHub build sur `windows-latest` vierge.
