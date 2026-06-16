param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$EventSizes,
    [Parameter(Mandatory=$true)][int]$RecallSamples,
    [int]$MaxEffectiveSamples = 250,
    [string]$TopKValues = "32,64,128",
    [string]$PageSizes = "4096,16384,65536,262144",
    [int]$CacheDisturbanceMB = 256
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00I2 COLD IO AND TRAVERSAL SPLIT AUDIT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"
Write-Host "MAX_EFFECTIVE_SAMPLES=$MaxEffectiveSamples"
Write-Host "EFFECTIVE_RECALL_SAMPLES=$([Math]::Min($RecallSamples, $MaxEffectiveSamples)) REQUESTED_RECALL_SAMPLES=$RecallSamples"
Write-Host "TOP_K_VALUES=$TopKValues"
Write-Host "PAGE_SIZES=$PageSizes"
Write-Host "CACHE_DISTURBANCE_MB=$CacheDisturbanceMB"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_V00I2_REPO_ROOT_MISSING: $RepoRoot"
}

$PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

$PythonRefDest = Join-Path $RepoRoot "python_ref"
$DocsDest = Join-Path $RepoRoot "docs"
$ScriptsDest = Join-Path $RepoRoot "scripts\windows"
New-Item -ItemType Directory -Force -Path $PythonRefDest | Out-Null
New-Item -ItemType Directory -Force -Path $DocsDest | Out-Null
New-Item -ItemType Directory -Force -Path $ScriptsDest | Out-Null

Copy-Item -Path (Join-Path $PackageRoot "python_ref\*") -Destination $PythonRefDest -Recurse -Force
Copy-Item -Path (Join-Path $PackageRoot "docs\*") -Destination $DocsDest -Recurse -Force
Copy-Item -Path (Join-Path $PackageRoot "scripts\windows\RUN_COLD_IO_AND_TRAVERSAL_SPLIT_AUDIT_V00I2.ps1") -Destination $ScriptsDest -Force

$Selftest = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_page_io_split_audit_v00i2.py"
if (!(Test-Path $Selftest)) {
    throw "NO_GO_V00I2_SELFTEST_MISSING_AFTER_COPY: $Selftest"
}

$PythonExe = $null
$pyCmd = Get-Command py -ErrorAction SilentlyContinue
if ($pyCmd) {
    $PythonExe = "py"
    & py -3 $Selftest `
        --repo-root $RepoRoot `
        --event-sizes $EventSizes `
        --recall-samples $RecallSamples `
        --max-effective-samples $MaxEffectiveSamples `
        --top-k-values $TopKValues `
        --page-sizes $PageSizes `
        --cache-disturbance-mb $CacheDisturbanceMB
} else {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (!$pythonCmd) {
        throw "NO_GO_V00I2_PYTHON_NOT_FOUND"
    }
    $PythonExe = "python"
    & python $Selftest `
        --repo-root $RepoRoot `
        --event-sizes $EventSizes `
        --recall-samples $RecallSamples `
        --max-effective-samples $MaxEffectiveSamples `
        --top-k-values $TopKValues `
        --page-sizes $PageSizes `
        --cache-disturbance-mb $CacheDisturbanceMB
}

if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00I2_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_COLD_IO_AND_TRAVERSAL_SPLIT_AUDIT_V00I2_SCRIPT"
