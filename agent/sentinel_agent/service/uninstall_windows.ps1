# Uninstall Sentinel Agent (Windows)
param([string]$TaskName = "SentinelAgent", [string]$ServiceName = "SentinelAgent")
function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) { Write-Host "Admin requis"; exit 1 }
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {
  nssm stop $ServiceName; nssm remove $ServiceName confirm
  Write-Host "Service $ServiceName supprimé"
} else {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Tâche $TaskName supprimée"
}
Write-Host "Données queue conservées — supprimez .\data\ manuellement si besoin."
