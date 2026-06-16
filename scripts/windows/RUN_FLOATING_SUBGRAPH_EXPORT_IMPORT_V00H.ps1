param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [string]$EventSizes = "10000,100000,1000000",
    [int]$RecallSamples = 1000
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00H FLOATING SUBGRAPH EXPORT IMPORT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_MISSING: $RepoRoot"
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

$TargetCore = Join-Path $RepoRoot "python_ref\ultraballoondb_core"
$TargetSelftest = Join-Path $TargetCore "selftest"
$TargetDocs = Join-Path $RepoRoot "docs"
$TargetScripts = Join-Path $RepoRoot "scripts\windows"

New-Item -ItemType Directory -Force -Path $TargetCore | Out-Null
New-Item -ItemType Directory -Force -Path $TargetSelftest | Out-Null
New-Item -ItemType Directory -Force -Path $TargetDocs | Out-Null
New-Item -ItemType Directory -Force -Path $TargetScripts | Out-Null

Copy-Item -Force (Join-Path $PackageRoot "python_ref\ultraballoondb_core\floating_subgraph.py") (Join-Path $TargetCore "floating_subgraph.py")
Copy-Item -Force (Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_floating_subgraph_export_import_v00h.py") (Join-Path $TargetSelftest "run_floating_subgraph_export_import_v00h.py")
Copy-Item -Force (Join-Path $PackageRoot "docs\V00H_FLOATING_SUBGRAPH_EXPORT_IMPORT.md") (Join-Path $TargetDocs "V00H_FLOATING_SUBGRAPH_EXPORT_IMPORT.md")
Copy-Item -Force (Join-Path $PackageRoot "scripts\windows\RUN_FLOATING_SUBGRAPH_EXPORT_IMPORT_V00H.ps1") (Join-Path $TargetScripts "RUN_FLOATING_SUBGRAPH_EXPORT_IMPORT_V00H.ps1")

$RunId = "RUN_" + (Get-Date -Format "yyyyMMdd_HHmmss")
$RunDir = Join-Path $RepoRoot ("audit\v00h_floating_subgraph_export_import\" + $RunId)
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$Selftest = Join-Path $TargetSelftest "run_floating_subgraph_export_import_v00h.py"

python $Selftest --repo-root $RepoRoot --event-sizes $EventSizes --recall-samples $RecallSamples --run-dir $RunDir
if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00H_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_FLOATING_SUBGRAPH_EXPORT_IMPORT_V00H_SCRIPT"
