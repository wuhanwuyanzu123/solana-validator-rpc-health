param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    & $python.Source --version *> $null
    if ($LASTEXITCODE -ne 0) {
        $python = $null
    }
}
if (-not $python) {
    $pythonExe = Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"
    if (-not (Test-Path $pythonExe)) {
        throw "Python was not found. Install Python or pass a working python.exe on PATH."
    }
    & $pythonExe (Join-Path $scriptDir "solana-validator-rpc-health.py") @Args
    exit $LASTEXITCODE
}

& $python.Source (Join-Path $scriptDir "solana-validator-rpc-health.py") @Args
