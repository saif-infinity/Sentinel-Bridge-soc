# Build SentinelAgent.exe on Windows (local)
# Prérequis: Python 3.11+ et pip
# Usage: powershell -ExecutionPolicy Bypass -File build.ps1
# Output: dist/SentinelAgent.exe (à distribuer) + dist/config.example.json

param(
  [string]$Python = "python",
  [switch]$Clean
)

$ErrorActionPreference = "Stop"
$AgentDir = $PSScriptRoot
Set-Location $AgentDir

Write-Host "=== Build SentinelAgent.exe ===" -ForegroundColor Cyan

if ($Clean) {
  Remove-Item -Recurse -Force build, dist, *.spec.bak -ErrorAction SilentlyContinue
  Write-Host "Clean done"
}

# 1. Venv (optionnel, mais propre)
if (-not (Test-Path "build-venv")) {
  Write-Host "[1/4] Création venv..."
  & $Python -m venv build-venv
}
$VenvPython = ".\build-venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) { $VenvPython = $Python }

Write-Host "[2/4] Installation deps build..."
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r requirements.txt
& $VenvPython -m pip install pyinstaller

Write-Host "[3/4] PyInstaller (one-file)..."
# Utilise le .spec (one-file) — plus simple à distribuer
& $VenvPython -m PyInstaller sentinel-agent.spec --noconfirm

if (-not (Test-Path "dist\SentinelAgent.exe")) {
  Write-Host "ERREUR: dist\SentinelAgent.exe non généré" -ForegroundColor Red
  # fallback one-dir debug
  Get-ChildItem dist -Recurse | Out-Host
  exit 1
}

Write-Host "[4/4] Vérification..."
Get-Item "dist\SentinelAgent.exe" | Format-List Name, Length, LastWriteTime
& "dist\SentinelAgent.exe" --help | Select-Object -First 20

Write-Host ""
Write-Host "✓ Build OK: dist\SentinelAgent.exe" -ForegroundColor Green
Write-Host "  Taille: $([math]::Round((Get-Item dist\SentinelAgent.exe).Length/1MB,1)) MB (one-file, incl. Python+psutil+requests)"
Write-Host ""
Write-Host "Distribution:"
Write-Host "  1) Copiez dist\SentinelAgent.exe + config.example.json sur le PC cible (ex: C:\SentinelAgent\)"
Write-Host "  2) Sur PC cible: renommez config.example.json → config.json et éditez server_url/agent_id/token"
Write-Host "  3) Test: SentinelAgent.exe --check"
Write-Host "  4) Install service: .\sentinel_agent\service\install_windows_exe.ps1  (voir ci-dessous)"
Write-Host ""
Write-Host "Astuce: le .exe embarque Python — aucune installation Python requise sur le PC cible."
