param([string]$Distro = '')
$ErrorActionPreference = 'Stop'
if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) { throw 'WSL is not installed. Install WSL and a Linux distribution first.' }
$projectRoot = Split-Path $PSScriptRoot -Parent
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$linuxRoot = & wsl @wslArgs --exec wslpath -a $projectRoot
if ($LASTEXITCODE -ne 0) { throw 'Unable to use WSL. Check wsl --list --verbose and select your distribution with -Distro.' }
& wsl @wslArgs --exec bash "$linuxRoot/scripts/check-linux.sh"
exit $LASTEXITCODE
