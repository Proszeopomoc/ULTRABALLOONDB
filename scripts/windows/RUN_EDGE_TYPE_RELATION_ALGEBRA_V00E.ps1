param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [string]$EventSizes = "10000,100000,1000000",
    [int]$RecallSamples = 1000
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00E EDGE TYPE RELATION ALGEBRA ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_MISSING: $RepoRoot"
}

$PackageRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$RepoRootResolved = Resolve-Path $RepoRoot

$copyItems = @(
    @{ Source = "python_ref\ultraballoondb_core\relation_algebra.py"; Dest = "python_ref\ultraballoondb_core\relation_algebra.py" },
    @{ Source = "python_ref\ultraballoondb_core\selftest\run_edge_type_relation_algebra_v00e.py"; Dest = "python_ref\ultraballoondb_core\selftest\run_edge_type_relation_algebra_v00e.py" },
    @{ Source = "docs\V00E_EDGE_TYPE_RELATION_ALGEBRA.md"; Dest = "docs\V00E_EDGE_TYPE_RELATION_ALGEBRA.md" },
    @{ Source = "scripts\windows\RUN_EDGE_TYPE_RELATION_ALGEBRA_V00E.ps1"; Dest = "scripts\windows\RUN_EDGE_TYPE_RELATION_ALGEBRA_V00E.ps1" }
)

foreach ($item in $copyItems) {
    $src = Join-Path $PackageRoot $item.Source
    $dst = Join-Path $RepoRootResolved $item.Dest
    if (!(Test-Path $src)) {
        throw "NO_GO_PACKAGE_FILE_MISSING: $src"
    }
    $dstDir = Split-Path $dst -Parent
    if (!(Test-Path $dstDir)) {
        New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    }
    Copy-Item $src $dst -Force
}

$env:PYTHONPATH = (Join-Path $RepoRootResolved "python_ref")
$runner = Join-Path $RepoRootResolved "python_ref\ultraballoondb_core\selftest\run_edge_type_relation_algebra_v00e.py"

python $runner --repo-root $RepoRootResolved --event-sizes $EventSizes --recall-samples $RecallSamples
if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00E_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_EDGE_TYPE_RELATION_ALGEBRA_V00E_SCRIPT"
