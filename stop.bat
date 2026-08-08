@echo off
title Sentinel SOC - Arret des services
cd /d "%~dp0"

echo ============================================
echo  Arret de tous les services Sentinel SOC
echo ============================================
echo.

REM --- Arreter les processus npm (frontend + admin) ---
echo [1/5] Arret des frontends...
for %%p in (node.exe) do (
    taskkill /f /im %%p >nul 2>&1
)
echo  OK - Frontends arretes.

REM --- Arreter le backend uvicorn ---
echo [2/5] Arret du backend FastAPI...
taskkill /f /im uvicorn.exe >nul 2>&1
taskkill /f /im python.exe /fi "WINDOWTITLE eq backend" >nul 2>&1
echo  OK - Backend arrete.

REM --- Arreter le worker Celery ---
echo [3/5] Arret du worker Celery...
taskkill /f /im celery.exe >nul 2>&1
taskkill /f /im python.exe /fi "WINDOWTITLE eq worker" >nul 2>&1
echo  OK - Worker Celery arrete.

REM --- Arreter Wazuh (docker) ---
echo [4/5] Arret de Wazuh SIEM...
set "WAZUH_DIR=%USERPROFILE%\OneDrive\Desktop\wazuh version(4.7.2)-pfe\wazuh-docker\single-node"
if exist "%WAZUH_DIR%\docker-compose.yml" (
    pushd "%WAZUH_DIR%"
    docker compose down 2>nul
    popd
    echo  OK - Wazuh SIEM arrete.
) else (
    echo  WARN - Wazuh introuvable, ignore.
)

REM --- Arreter l'infrastructure locale (Redis) ---
echo [5/5] Arret de l'infrastructure locale...
docker compose down 2>nul
echo  OK - Infrastructure locale arretee.

echo.
echo ============================================
echo  Tous les services sont arretes.
echo ============================================
echo.
pause
