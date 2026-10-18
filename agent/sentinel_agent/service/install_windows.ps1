# Install Sentinel Agent as Windows Service via NSSM or Task Scheduler fallback
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_windows.ps1
param(
  [string]$ConfigPath = "$PSScriptRoot\..\..\config.json"
)

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
  Write-Host "ERREUR: Lancez PowerShell en Administrateur (clic droit -> Exécuter en tant qu'administrateur)" -ForegroundColor Red
  exit 1
}

$AgentDir = Resolve-Path "$PSScriptRoot\..\.."
$Config = Resolve-Path $ConfigPath -ErrorAction SilentlyContinue
if (-not $Config) {
  Write-Host "ERREUR: $ConfigPath introuvable. Copiez config.example.json -> config.json et éditez server_url/agent_id/token" -ForegroundColor Red
  exit 1
}

Write-Host "[1/4] Vérification Python..."
try { python --version | Out-Host } catch { Write-Host "Python non trouvé dans PATH"; exit 1 }

Write-Host "[2/4] Installation dépendances..."
pip install -r "$AgentDir\requirements.txt"
if ($LASTEXITCODE -ne 0) { Write-Host "pip install échoué — vérifiez internet (non requis pour lab local si déjà installé)"; }

Write-Host "[3/4] Test connectivité..."
python -m sentinel_agent --config "$Config" --check
if ($LASTEXITCODE -ne 0) {
  Write-Host "⚠️  Connectivité échouée — vérifiez pare-feu et server_url (IP LAN, pas localhost)" -ForegroundColor Yellow
  $cont = Read-Host "Continuer quand même? (o/N)"
  if ($cont -ne "o" -and $cont -ne "O") { exit 1 }
}

# NSSM preferred, Task Scheduler fallback
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {
  Write-Host "[4/4] Installation service NSSM..."
  $ServiceName = "SentinelAgent"
  $Python = (Get-Command python).Source
  nssm install $ServiceName $Python "-m sentinel_agent --config `"$Config`""
  nssm set $ServiceName AppDirectory "$AgentDir"
  nssm set $ServiceName DisplayName "Sentinel Bridge Agent"
  nssm set $ServiceName Description "Agent lab local — envoie télémétrie au SOC sur Wi-Fi"
  nssm set $ServiceName Start SERVICE_AUTO_START
  nssm start $ServiceName
  Write-Host "✓ Service $ServiceName installé (NSSM). Logs: nssm status $ServiceName" -ForegroundColor Green
} else {
  Write-Host "[4/4] NSSM non trouvé — installation via Task Scheduler (fallback)..."
  Write-Host "Téléchargez NSSM pour un vrai service: https://nssm.cc/" -ForegroundColor Yellow
  $TaskName = "SentinelAgent"
  $Python = (Get-Command python).Source
  $Action = New-ScheduledTaskAction -Execute $Python -Argument "-m sentinel_agent --config `"$Config`""
  $Trigger = New-ScheduledTaskTrigger -AtStartup
  $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "✓ Tâche planifiée $TaskName créée (démarre au boot). Voir Task Scheduler." -ForegroundColor Green
}

Write-Host ""
Write-Host "Pare-feu Windows — à exécuter sur le SERVEUR (PC SOC):"
Write-Host "  netsh advfirewall firewall add rule name=`"Sentinel SOC 8001`" dir=in action=allow protocol=TCP localport=8001"
Write-Host ""
Write-Host "Désinstaller: .\uninstall_windows.ps1 (en Admin)"
