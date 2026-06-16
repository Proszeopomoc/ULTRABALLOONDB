param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [string]$EventSizes = "10000,100000,1000000",
    [int]$RecallSamples = 1000
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00G HOT SNAPSHOT ARCHIVE SPLIT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_SIZES=$EventSizes"
Write-Host "RECALL_SAMPLES=$RecallSamples"

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_V00G_REPO_ROOT_MISSING: $RepoRoot"
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent (Split-Path -Parent $ScriptRoot)

$Targets = @(
    "python_ref\ultraballoondb_core\hot_snapshot.py",
    "python_ref\ultraballoondb_core\selftest\run_hot_snapshot_archive_split_v00g.py",
    "docs\V00G_HOT_SNAPSHOT_ARCHIVE_SPLIT.md",
    "scripts\windows\RUN_HOT_SNAPSHOT_ARCHIVE_SPLIT_V00G.ps1"
)

foreach ($rel in $Targets) {
    $src = Join-Path $PackageRoot $rel
    $dst = Join-Path $RepoRoot $rel
    if (!(Test-Path $src)) {
        throw "NO_GO_V00G_PACKAGE_FILE_MISSING: $src"
    }
    $dstDir = Split-Path -Parent $dst
    if (!(Test-Path $dstDir)) {
        New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $src -Destination $dst -Force
}

$PythonPath = Join-Path $RepoRoot "python_ref"
$env:PYTHONPATH = "$PythonPath;$env:PYTHONPATH"
$Runner = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_hot_snapshot_archive_split_v00g.py"

python $Runner --repo-root $RepoRoot --event-sizes $EventSizes --recall-samples $RecallSamples
if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00G_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_HOT_SNAPSHOT_ARCHIVE_SPLIT_V00G_SCRIPT"
