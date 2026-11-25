<#
.SYNOPSIS
    Full secassess scan on Windows: every assessment, every available tool, JSON + Word report.

.DESCRIPTION
    Wraps `secassess full` from the project's virtual environment. With -Elevate the script
    relaunches itself as Administrator (needed for SMART disk health and Nmap OS detection).
    Any extra arguments are passed through to `secassess full`.

.EXAMPLE
    .\scripts\full-scan.ps1
    .\scripts\full-scan.ps1 -Elevate
    .\scripts\full-scan.ps1 -c my-scope.toml -t 10.20.30.0/28
    .\scripts\full-scan.ps1 -Elevate -c my-scope.toml -t 10.20.30.0/28 --active --confirm-scope <ID>
#>
[CmdletBinding()]
param(
    [switch]$Elevate,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScanArgs
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root '.venv\Scripts\secassess.exe'
if (-not (Test-Path $exe)) {
    $cmd = Get-Command secassess -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "secassess not found. Run scripts\setup.ps1" }
    $exe = $cmd.Source
}

# A virtual environment copied from another computer still contains secassess.exe, but it points at
# a Python that does not exist here. Detect that instead of failing with a cryptic launcher error.
$ErrorActionPreference = 'Continue'
& $exe --version > $null 2> $null
$works = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = 'Stop'
if (-not $works) {
    throw "$exe does not run (was .venv copied from another computer?). Run scripts\setup.ps1"
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Elevate -and -not $isAdmin) {
    # Without the filter, a null $ScanArgs would yield one empty argument that argparse rejects.
    $quoted = ($ScanArgs | Where-Object { $_ } | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ' '
    $argLine = "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`" $quoted"
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argLine -WorkingDirectory $root
    return
}

Push-Location $root
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $env:PYTHONIOENCODING = 'utf-8'
    & $exe full @ScanArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
