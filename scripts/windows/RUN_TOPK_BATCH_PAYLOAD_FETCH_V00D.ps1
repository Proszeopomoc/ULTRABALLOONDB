param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [string]$EventSizes = "10000,100000,1000000",
    [int]$RecallSamples = 1000,
    [int]$MaxEffectiveSamples = 250
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00D TOPK BATCH PAYLOAD FETCH ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"
Write-Host "MAX_EFFECTIVE_SAMPLES=$MaxEffectiveSamples"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_MISSING: $RepoRoot"
}

$PackageRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$RepoRootResolved = Resolve-Path $RepoRoot

$copyItems = @(
    @{ Source = "python_ref\ultraballoondb_core\payload_fetch.py"; Dest = "python_ref\ultraballoondb_core\payload_fetch.py" },
    @{ Source = "python_ref\ultraballoondb_core\selftest\run_topk_batch_payload_fetch_v00d.py"; Dest = "python_ref\ultraballoondb_core\selftest\run_topk_batch_payload_fetch_v00d.py" },
    @{ Source = "docs\V00D_TOPK_BATCH_PAYLOAD_FETCH.md"; Dest = "docs\V00D_TOPK_BATCH_PAYLOAD_FETCH.md" },
    @{ Source = "scripts\windows\RUN_TOPK_BATCH_PAYLOAD_FETCH_V00D.ps1"; Dest = "scripts\windows\RUN_TOPK_BATCH_PAYLOAD_FETCH_V00D.ps1" }
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
$runner = Join-Path $RepoRootResolved "python_ref\ultraballoondb_core\selftest\run_topk_batch_payload_fetch_v00d.py"

python $runner --repo-root $RepoRootResolved --event-sizes $EventSizes --recall-samples $RecallSamples --max-effective-samples $MaxEffectiveSamples
if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00D_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_TOPK_BATCH_PAYLOAD_FETCH_V00D_SCRIPT"
