param(
    [Parameter(Mandatory=$true)] [string] $RepoRoot,
    [string] $EventSizes = "10000,100000,1000000",
    [int] $RecallSamples = 1000,
    [int] $MaxEffectiveSamples = 250,
    [string] $PageSizes = "16384,65536",
    [string] $TopKValues = "32,64,128"
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00I3 DECODE CHECKSUM HOTPATH SPLIT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"
Write-Host "MAX_EFFECTIVE_SAMPLES=$MaxEffectiveSamples"
Write-Host "PAGE_SIZES=$PageSizes"
Write-Host "TOP_K_VALUES=$TopKValues"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_NOT_FOUND: $RepoRoot"
}

$PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

$Files = @(
    @{ Source = "python_ref\ultraballoondb_core\decode_checksum_split.py"; Target = "python_ref\ultraballoondb_core\decode_checksum_split.py" },
    @{ Source = "python_ref\ultraballoondb_core\selftest\run_decode_checksum_hotpath_split_v00i3.py"; Target = "python_ref\ultraballoondb_core\selftest\run_decode_checksum_hotpath_split_v00i3.py" },
    @{ Source = "docs\V00I3_DECODE_CHECKSUM_HOTPATH_SPLIT.md"; Target = "docs\V00I3_DECODE_CHECKSUM_HOTPATH_SPLIT.md" },
    @{ Source = "scripts\windows\RUN_DECODE_CHECKSUM_HOTPATH_SPLIT_V00I3.ps1"; Target = "scripts\windows\RUN_DECODE_CHECKSUM_HOTPATH_SPLIT_V00I3.ps1" }
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
$Selftest = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_decode_checksum_hotpath_split_v00i3.py"

& $Python $Selftest `
    --repo-root $RepoRoot `
    --event-sizes $EventSizes `
    --recall-samples $RecallSamples `
    --max-effective-samples $MaxEffectiveSamples `
    --page-sizes $PageSizes `
    --top-k-values $TopKValues

if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00I3_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_DECODE_CHECKSUM_HOTPATH_SPLIT_V00I3_SCRIPT"
