param([string]$Distro = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$linuxRoot = & wsl @wslArgs --exec wslpath -a $projectRoot
if ($LASTEXITCODE -ne 0) { throw 'Install/configure WSL and its Linux environment first.' }
& wsl @wslArgs --exec bash "$linuxRoot/scripts/start-linux.sh"
if ($LASTEXITCODE -ne 0) { throw 'CloudSentinel did not start. Review the message above and .runtime/service.log.' }
Start-Process 'http://127.0.0.1:3000'
