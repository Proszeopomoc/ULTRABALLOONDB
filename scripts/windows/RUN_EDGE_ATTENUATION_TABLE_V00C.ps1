param(
    [Parameter(Mandatory=$true)] [string] $RepoRoot,
    [string] $EventSizes = "10000,100000,1000000",
    [int] $RecallSamples = 1000
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00C EDGE ATTENUATION TABLE ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$OverlayRoot = Join-Path $PackageRoot "repo_overlay"

if (-not (Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_NOT_FOUND=$RepoRoot"
}
if (-not (Test-Path $OverlayRoot)) {
    throw "NO_GO_OVERLAY_ROOT_NOT_FOUND=$OverlayRoot"
}

$RequiredDirs = @(
    "python_ref\ultraballoondb_core",
    "python_ref\ultraballoondb_core\selftest",
    "docs",
    "scripts\windows"
)
foreach ($rel in $RequiredDirs) {
    $target = Join-Path $RepoRoot $rel
    if (-not (Test-Path $target)) {
        New-Item -ItemType Directory -Path $target | Out-Null
    }
}

$FilesToCopy = @(
    "python_ref\ultraballoondb_core\attenuation.py",
    "python_ref\ultraballoondb_core\selftest\run_edge_attenuation_table_v00c.py",
    "docs\V00C_EDGE_ATTENUATION_TABLE.md",
    "scripts\windows\RUN_EDGE_ATTENUATION_TABLE_V00C.ps1"
)
foreach ($rel in $FilesToCopy) {
    $src = Join-Path $OverlayRoot $rel
    $dst = Join-Path $RepoRoot $rel
    if (-not (Test-Path $src)) {
        throw "NO_GO_PACKAGE_FILE_MISSING=$src"
    }
    Copy-Item -Path $src -Destination $dst -Force
}

$PythonExe = "python"
$Selftest = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_edge_attenuation_table_v00c.py"
$PythonPath = Join-Path $RepoRoot "python_ref"
$oldPythonPath = $env:PYTHONPATH
if ([string]::IsNullOrWhiteSpace($oldPythonPath)) {
    $env:PYTHONPATH = $PythonPath
} else {
    $env:PYTHONPATH = "$PythonPath;$oldPythonPath"
}

& $PythonExe $Selftest --repo-root $RepoRoot --event-sizes $EventSizes --recall-samples $RecallSamples
$exitCode = $LASTEXITCODE
$env:PYTHONPATH = $oldPythonPath
if ($exitCode -ne 0) {
    throw "NO_GO_V00C_SELFTEST_EXIT_CODE=$exitCode"
}

Write-Host "PASS_RUN_EDGE_ATTENUATION_TABLE_V00C_SCRIPT"
