<#
.SYNOPSIS
    Prepare secassess on Windows: Python environment plus every optional tool.

.DESCRIPTION
    Installs uv, Nmap and smartmontools with winget and Semgrep with uv when they are missing, then
    builds .venv with Python 3.12. A .venv that does not run (for example one copied from another
    computer) is moved to the TEMP folder, not deleted. Safe to run again at any time.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
#>
[CmdletBinding()]
param([switch]$SkipTools)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'

function Update-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
        [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Install-WingetTool([string]$Command, [string]$Id, [string[]]$Locations = @()) {
    if (Get-Command $Command -ErrorAction SilentlyContinue) { return }
    foreach ($location in $Locations) { if (Test-Path $location) { return } }
    Write-Host "installing $Id ..."
    winget install --id $Id -e --silent --accept-source-agreements --accept-package-agreements
    Update-SessionPath
}

Install-WingetTool 'uv' 'astral-sh.uv'
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw 'uv could not be installed' }

if (-not $SkipTools) {
    Install-WingetTool 'nmap' 'Insecure.Nmap' @("${env:ProgramFiles(x86)}\Nmap\nmap.exe")
    Install-WingetTool 'smartctl' 'smartmontools.smartmontools' @(
        "$env:ProgramFiles\smartmontools\bin\smartctl.exe")
    if (-not (Test-Path "$env:USERPROFILE\.local\bin\semgrep.exe") -and
        -not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
        uv tool install semgrep --python 3.13
    }
}

Push-Location $root
try {
    $works = $false
    if (Test-Path $python) {
        & $python --version > $null 2> $null
        $works = ($LASTEXITCODE -eq 0)
    }
    if (-not $works) {
        if (Test-Path '.venv') {
            # Outside the project, so that project reviews do not analyze it.
            $backup = Join-Path $env:TEMP ('secassess-venv-' + (Get-Date -Format 'yyyyMMddHHmmss'))
            Write-Host ".venv does not run on this computer; moving it to $backup"
            Move-Item '.venv' $backup -ErrorAction Stop
        }
        uv venv --seed --python 3.12 .venv
        if ($LASTEXITCODE -ne 0) { throw 'could not create .venv' }
    }
    uv pip install --python $python -e '.[dev,all]'
    if ($LASTEXITCODE -ne 0) { throw 'could not install Python dependencies' }
    & (Join-Path $root '.venv\Scripts\secassess.exe') check-tools
} finally {
    Pop-Location
}
