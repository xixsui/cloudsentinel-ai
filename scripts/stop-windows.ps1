param([string]$Distro = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$linuxRoot = & wsl @wslArgs --exec wslpath -a $projectRoot
if ($LASTEXITCODE -ne 0) { throw 'Unable to access the selected WSL distribution.' }
& wsl @wslArgs --exec bash "$linuxRoot/scripts/stop-linux.sh"
if ($LASTEXITCODE -ne 0) { throw 'Unable to stop CloudSentinel. Check the selected WSL distribution.' }
