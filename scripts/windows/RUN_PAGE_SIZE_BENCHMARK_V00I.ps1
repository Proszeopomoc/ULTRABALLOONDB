param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$EventSizes,
    [Parameter(Mandatory=$true)][int]$RecallSamples,
    [string]$TopKValues = "32,64,128"
)

$ErrorActionPreference = "Stop"
Write-Host "=== ULTRABALLOONDB V00I1 PAGE SIZE BENCHMARK TEXT SCAN FIX ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"
Write-Host "TOP_K_VALUES=$TopKValues"

if (!(Test-Path $RepoRoot)) { throw "NO_GO_V00I_REPO_ROOT_MISSING: $RepoRoot" }

$PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$PySrc = Join-Path $PackageRoot "python_ref\ultraballoondb_core\page_size_benchmark.py"
$SelftestSrc = Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_page_size_benchmark_v00i.py"
$DocSrc = Join-Path $PackageRoot "docs\V00I_PAGE_SIZE_BENCHMARK.md"
$ScriptSrc = $MyInvocation.MyCommand.Path

$CoreDst = Join-Path $RepoRoot "python_ref\ultraballoondb_core"
$SelftestDstDir = Join-Path $CoreDst "selftest"
$DocsDst = Join-Path $RepoRoot "docs"
$ScriptsDst = Join-Path $RepoRoot "scripts\windows"

New-Item -ItemType Directory -Force -Path $CoreDst | Out-Null
New-Item -ItemType Directory -Force -Path $SelftestDstDir | Out-Null
New-Item -ItemType Directory -Force -Path $DocsDst | Out-Null
New-Item -ItemType Directory -Force -Path $ScriptsDst | Out-Null

Copy-Item $PySrc (Join-Path $CoreDst "page_size_benchmark.py") -Force
Copy-Item $SelftestSrc (Join-Path $SelftestDstDir "run_page_size_benchmark_v00i.py") -Force
Copy-Item $DocSrc (Join-Path $DocsDst "V00I_PAGE_SIZE_BENCHMARK.md") -Force
Copy-Item $ScriptSrc (Join-Path $ScriptsDst "RUN_PAGE_SIZE_BENCHMARK_V00I.ps1") -Force

$Selftest = Join-Path $SelftestDstDir "run_page_size_benchmark_v00i.py"
python $Selftest --repo-root $RepoRoot --event-sizes $EventSizes --recall-samples $RecallSamples --top-k-values $TopKValues
if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00I1_SELFTEST_FAILED: exit=$LASTEXITCODE"
}
Write-Host "PASS_RUN_PAGE_SIZE_BENCHMARK_V00I1_TEXT_SCAN_FIX_SCRIPT"
