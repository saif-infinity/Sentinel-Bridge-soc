@echo off
setlocal enabledelayedexpansion
title Sentinel SOC - All Services
cd /d "%~dp0"

set "ROOT_DIR=%~dp0"
set "WAZUH_DIR=%USERPROFILE%\OneDrive\Desktop\projet soc ips+siem(xdr)\wazuh version(4.7.2)-pfe\wazuh-docker\single-node"
set "BACKEND_LOG=%ROOT_DIR%backend.log"
set "WORKER_LOG=%ROOT_DIR%worker.log"
set "FRONTEND_LOG=%ROOT_DIR%frontend.log"
set "ADMIN_LOG=%ROOT_DIR%admin-frontend.log"

echo ============================================
echo     Sentinel Bridge - SOC Platform v4
echo     Demarrage de tous les services
echo ============================================
echo.

REM --- Check prerequisites ---
where docker >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Docker introuvable. Installez Docker Desktop.
    pause & exit /b 1
)
where node >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Node.js introuvable. Installez Node.js.
    pause & exit /b 1
)
where python >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python introuvable. Installez Python 3.12+.
    pause & exit /b 1
)

echo [ OK ] Pre-requis verifies.
echo.

REM ============================================
REM  Step 1/8: Infrastructure (Redis)
REM ============================================
echo [1/8] Demarrage de l'infrastructure (Redis^)...

REM Verifier si le container sentinel-redis existe deja (arrete ou en cours)
docker inspect sentinel-redis >nul 2>&1
if not errorlevel 1 (
    echo       Container sentinel-redis existe deja. Suppression...
    docker rm -f sentinel-redis >nul 2>&1
    echo       Ancien container supprime.
)

docker compose up -d 2>>"%BACKEND_LOG%"
if errorlevel 1 (
    echo [WARN] Docker Compose a echoue. Tentative avec --force-recreate...
    docker compose up -d --force-recreate 2>>"%BACKEND_LOG%"
    if errorlevel 1 (
        echo [WARN] Docker Compose a echoue meme avec --force-recreate. Verifiez que Docker Desktop tourne.
    ) else (
        echo [ OK ] Redis demarre (force-recreate^).
    )
) else (
    echo [ OK ] Redis demarre.
)
timeout /t 3 /nobreak >nul

REM ============================================
REM  Step 2/8: Wazuh SIEM (single-node)
REM ============================================
echo [2/8] Demarrage de Wazuh SIEM...
if not exist "%WAZUH_DIR%\docker-compose.yml" goto :skip_wazuh
pushd "%WAZUH_DIR%"
docker compose up -d 2>>"%BACKEND_LOG%"
popd
echo [ OK ] Wazuh demarre (comptez 2-3 min pour l'initialisation^).
goto :wazuh_done
:skip_wazuh
echo [WARN] Wazuh introuvable dans %WAZUH_DIR%. Demarrage ignore.
echo       Telechargez Wazuh Docker depuis https://github.com/wazuh/wazuh-docker
:wazuh_done
timeout /t 5 /nobreak >nul

REM ============================================
REM  Step 3/8: Ollama LLM (optionnel)
REM ============================================
echo [3/8] Demarrage d'Ollama (LLM local^)...
where ollama >nul 2>&1
if errorlevel 1 goto :skip_ollama
start /b "ollama" ollama serve >nul 2>&1
echo [ OK ] Ollama lance sur http://localhost:11434
goto :ollama_done
:skip_ollama
echo [INFO] Ollama non installe. L'analyse IA ne fonctionnera pas.
echo       Installez Ollama depuis https://ollama.ai
:ollama_done
timeout /t 2 /nobreak >nul

REM ============================================
REM  Step 4/8: Backend FastAPI
REM ============================================
echo [4/8] Demarrage du backend FastAPI (port 8000^)...
if exist "%ROOT_DIR%backend\venv" goto :backend_install_done
echo       Installation de l'environnement Python...
pushd "%ROOT_DIR%backend"
python -m venv venv
if not exist "venv\Scripts\pip.exe" goto :backend_pip_done
call venv\Scripts\pip install -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Echec de l'installation des dependances Python.
    popd
    pause & exit /b 1
)
:backend_pip_done
popd
echo [ OK ] Environnement Python installe.
:backend_install_done

REM Tuer les anciens processus backend sur le port 8000
echo       Arret des anciens processus backend (port 8000^)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)

pushd "%ROOT_DIR%backend"
start /b "backend" cmd /c ".\venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000" >> "%BACKEND_LOG%" 2>&1
popd
timeout /t 5 /nobreak >nul
findstr /m /c:"Uvicorn running on" "%BACKEND_LOG%" >nul 2>&1
if errorlevel 1 (
    echo [WARN] Backend en cours de demarrage... consultez "%BACKEND_LOG%"
) else (
    echo [ OK ] Backend lance sur http://127.0.0.1:8000
)

REM ============================================
REM  Step 5/8: Celery Worker
REM ============================================
echo [5/8] Demarrage du worker Celery (taches asynchrones^)...

REM Tuer les anciens workers Celery
taskkill /F /FI "WINDOWTITLE eq worker" >nul 2>&1

pushd "%ROOT_DIR%backend"
start /b "worker" cmd /c ".\venv\Scripts\python.exe -m celery -A app.worker:celery_app worker --loglevel=info --pool=solo" >> "%WORKER_LOG%" 2>&1
popd
timeout /t 3 /nobreak >nul
echo [ OK ] Worker Celery lance.

REM ============================================
REM  Step 6/8: Frontend Utilisateur (Vite^)
REM ============================================
echo [6/8] Demarrage du frontend utilisateur (port 5173^)...
if exist "%ROOT_DIR%frontend\node_modules" goto :frontend_install_done
echo       Installation des dependances frontend...
pushd "%ROOT_DIR%frontend"
call npm install >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Echec de npm install. Verifiez que Node.js est installe.
    popd
    pause & exit /b 1
)
popd
echo [ OK ] Dependances frontend installees.
:frontend_install_done

REM Tuer les anciens processus sur le port 5173
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)

pushd "%ROOT_DIR%frontend"
start /b "frontend" cmd /c "npm run dev" >> "%FRONTEND_LOG%" 2>&1
popd
timeout /t 3 /nobreak >nul
echo [ OK ] Frontend lance sur http://localhost:5173

REM ============================================
REM  Step 7/8: Frontend Admin (supervision^)
REM ============================================
echo [7/8] Demarrage du panneau admin (port 5174^)...
if exist "%ROOT_DIR%admin-frontend\node_modules" goto :admin_install_done
echo       Installation des dependances admin...
pushd "%ROOT_DIR%admin-frontend"
call npm install >nul 2>&1
if errorlevel 1 (
    echo [WARN] Echec de npm install pour admin-frontend.
) else (
    echo [ OK ] Dependances admin installees.
)
popd
:admin_install_done

REM Tuer les anciens processus sur le port 5174
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5174 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)

pushd "%ROOT_DIR%admin-frontend"
start /b "admin" cmd /c "npm run dev -- --port 5174" >> "%ADMIN_LOG%" 2>&1
popd
echo [ OK ] Admin lance sur http://localhost:5174

REM ============================================
REM  Step 8/8: Suricata IPS
REM ============================================
echo [8/8] Verification de la connexion Suricata IPS...
if not exist "%ROOT_DIR%backend\.env" (
    echo [INFO] Fichier .env introuvable. Les alertes reseau ne seront pas recues.
    goto :suricata_done
)
findstr /m /c:"SURICATA_HOST" "%ROOT_DIR%backend\.env" >nul 2>&1
if not errorlevel 1 (
    echo [ OK ] Suricata configure dans .env (acces SSH^)
) else (
    echo [INFO] Suricata non configure. Les alertes reseau ne seront pas recues.
)
:suricata_done

echo.
echo ============================================
echo  Tous les services sont demarres !
echo.
echo  URLS:
echo    Backend API  : http://127.0.0.1:8000
echo    Frontend SOC : http://localhost:5173
echo    Admin Panel  : http://localhost:5174
echo    Redis CLI    : docker compose exec redis redis-cli
echo.
echo  LOGS:
echo    Backend      : %BACKEND_LOG%
echo    Worker       : %WORKER_LOG%
echo    Frontend     : %FRONTEND_LOG%
echo    Admin        : %ADMIN_LOG%
echo.
echo  ARRETER:
echo    Appuyez sur Ctrl+C pour arreter les processus,
echo    ou lancez stop.bat pour un arret propre.
echo ============================================
echo.

REM --- Wait for cleanup signal ---
echo En attente... Appuyez sur Ctrl+C pour arreter.
echo.

:loop
timeout /t 10 /nobreak >nul
goto loop
