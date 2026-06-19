param(
    [string]$RepoRoot = "C:\UltraBalloonDB",
    [Parameter(Mandatory=$true)][string]$Report,
    [Parameter(Mandatory=$true)][string]$Summary,
    [Parameter(Mandatory=$true)][string]$EvidenceManifest,
    [Parameter(Mandatory=$true)][string]$OutputJson
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Python = (Get-Command python.exe -ErrorAction Stop).Source
$Verifier = Join-Path $RepoRoot "tools\closure\verify_final_closure_audit_v00r3z9.py"

if (-not (Test-Path -LiteralPath $Verifier -PathType Leaf)) {
    throw "FAIL_V00R3Z9_VERIFIER_NOT_FOUND: $Verifier"
}

& $Python $Verifier `
    --repo-root $RepoRoot `
    --report $Report `
    --summary $Summary `
    --evidence-manifest $EvidenceManifest `
    --output-json $OutputJson

if ($LASTEXITCODE -ne 0) {
    throw "FAIL_V00R3Z9_INDEPENDENT_VERIFIER"
}

Write-Host "PASS_VERIFY_ULTRABALLOONDB_FINAL_CLOSURE_V00R3Z9"
