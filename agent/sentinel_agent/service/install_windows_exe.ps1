# Install SentinelAgent.exe as Windows Service (NSSM or Task Scheduler)
# Prérequis: SentinelAgent.exe + config.json côte à côte (ex: C:\SentinelAgent\)
# Lancer en Admin: powershell -ExecutionPolicy Bypass -File install_windows_exe.ps1

param(
  [string]$Dir = "C:\SentinelAgent",
  [string]$ExeName = "SentinelAgent.exe",
  [string]$ConfigName = "config.json"
)

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) { Write-Host "Admin requis: clic droit → Exécuter en tant qu'administrateur" -ForegroundColor Red; exit 1 }

$ExePath = Join-Path $Dir $ExeName
$ConfigPath = Join-Path $Dir $ConfigName

if (-not (Test-Path $ExePath)) { Write-Host "ERREUR: $ExePath introuvable" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $ConfigPath)) { Write-Host "ERREUR: $ConfigPath introuvable. Copiez config.example.json → config.json et éditez token" -ForegroundColor Red; exit 1 }

Write-Host "Test config..."
& $ExePath --check
if ($LASTEXITCODE -ne 0) {
  Write-Host "⚠️  --check a échoué — vérifiez server_url (IP LAN, pas localhost) et token" -ForegroundColor Yellow
  $c = Read-Host "Continuer quand même? (o/N)"
  if ($c -ne "o") { exit 1 }
}

# NSSM si dispo
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {
  $ServiceName = "SentinelAgent"
  Write-Host "Installation service NSSM: $ServiceName"
  # Nettoyage ancien
  nssm stop $ServiceName 2>$null; nssm remove $ServiceName confirm 2>$null
  nssm install $ServiceName $ExePath
  nssm set $ServiceName AppDirectory $Dir
  nssm set $ServiceName AppParameters "--config `"$ConfigPath`""
  nssm set $ServiceName DisplayName "Sentinel Bridge Agent"
  nssm set $ServiceName Description "Agent lab local Sentinel Bridge (Wi-Fi)"
  nssm set $ServiceName Start SERVICE_AUTO_START
  nssm set $ServiceName AppStdout "$Dir\agent.log"
  nssm set $ServiceName AppStderr "$Dir\agent-error.log"
  nssm start $ServiceName
  Write-Host "✓ Service NSSM démarré" -ForegroundColor Green
  nssm status $ServiceName
} else {
  Write-Host "NSSM non trouvé — fallback Task Scheduler (recommandé: télécharger https://nssm.cc)" -ForegroundColor Yellow
  $TaskName = "SentinelAgent"
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  $Action = New-ScheduledTaskAction -Execute $ExePath -Argument "--config `"$ConfigPath`""
  $Trigger = New-ScheduledTaskTrigger -AtStartup
  $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  # Utilise SYSTEM (pas besoin de mot de passe)
  Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "✓ Tâche planifiée créée: $TaskName (démarre au boot)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Logs: $Dir\agent.log, queue: $Dir\data\queue.jsonl"
Write-Host "Désinstaller: .\sentinel_agent\service\uninstall_windows_exe.ps1"
Write-Host "Pare-feu serveur: netsh advfirewall firewall add rule name=`"Sentinel SOC 8001`" dir=in action=allow protocol=TCP localport=8001"
