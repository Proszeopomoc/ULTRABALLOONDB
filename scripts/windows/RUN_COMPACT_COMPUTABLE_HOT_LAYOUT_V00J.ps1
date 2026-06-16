param(
    [Parameter(Mandatory=$true)] [string] $RepoRoot,
    [string] $EventSizes = "10000,100000,1000000",
    [int] $Theta = 256,
    [int] $TopK = 128,
    [int] $PayloadEstimateBytes = 8192
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00J COMPACT COMPUTABLE HOT LAYOUT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "THETA=$Theta"
Write-Host "TOP_K=$TopK"
Write-Host "PAYLOAD_ESTIMATE_BYTES=$PayloadEstimateBytes"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_NOT_FOUND: $RepoRoot"
}

$PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

$Files = @(
    @{ Source = "python_ref\ultraballoondb_core\compact_hot_layout.py"; Target = "python_ref\ultraballoondb_core\compact_hot_layout.py" },
    @{ Source = "python_ref\ultraballoondb_core\selftest\run_compact_computable_hot_layout_v00j.py"; Target = "python_ref\ultraballoondb_core\selftest\run_compact_computable_hot_layout_v00j.py" },
    @{ Source = "docs\V00J_COMPACT_COMPUTABLE_HOT_LAYOUT.md"; Target = "docs\V00J_COMPACT_COMPUTABLE_HOT_LAYOUT.md" },
    @{ Source = "scripts\windows\RUN_COMPACT_COMPUTABLE_HOT_LAYOUT_V00J.ps1"; Target = "scripts\windows\RUN_COMPACT_COMPUTABLE_HOT_LAYOUT_V00J.ps1" }
)

foreach ($f in $Files) {
    $src = Join-Path $PackageRoot $f.Source
    $dst = Join-Path $RepoRoot $f.Target
    $dstDir = Split-Path -Parent $dst
    if (!(Test-Path $src)) { throw "NO_GO_PACKAGE_FILE_MISSING: $src" }
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    Copy-Item -Force $src $dst
}

$Python = "python"
$Selftest = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_compact_computable_hot_layout_v00j.py"

& $Python $Selftest `
    --repo-root $RepoRoot `
    --event-sizes $EventSizes `
    --theta $Theta `
    --top-k $TopK `
    --payload-estimate-bytes $PayloadEstimateBytes

if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00J_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_COMPACT_COMPUTABLE_HOT_LAYOUT_V00J_SCRIPT"
