param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [string]$EventSizes = "10000,100000,1000000",
    [int]$RecallSamples = 1000
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00F CRYSTALLIZATION PATHS ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_MISSING: $RepoRoot"
}

$PackageRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$RepoRootResolved = Resolve-Path $RepoRoot

$copyItems = @(
    @{ Source = "python_ref\ultraballoondb_core\crystallization.py"; Dest = "python_ref\ultraballoondb_core\crystallization.py" },
    @{ Source = "python_ref\ultraballoondb_core\selftest\run_crystallization_paths_v00f.py"; Dest = "python_ref\ultraballoondb_core\selftest\run_crystallization_paths_v00f.py" },
    @{ Source = "docs\V00F_CRYSTALLIZATION_PATHS.md"; Dest = "docs\V00F_CRYSTALLIZATION_PATHS.md" },
    @{ Source = "scripts\windows\RUN_CRYSTALLIZATION_PATHS_V00F.ps1"; Dest = "scripts\windows\RUN_CRYSTALLIZATION_PATHS_V00F.ps1" }
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
$runner = Join-Path $RepoRootResolved "python_ref\ultraballoondb_core\selftest\run_crystallization_paths_v00f.py"

python $runner --repo-root $RepoRootResolved --event-sizes $EventSizes --recall-samples $RecallSamples
if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00F_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_CRYSTALLIZATION_PATHS_V00F_SCRIPT"
