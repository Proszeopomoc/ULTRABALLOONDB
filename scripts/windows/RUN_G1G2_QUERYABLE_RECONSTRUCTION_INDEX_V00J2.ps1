param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [int]$MatrixN = 1024,
    [int]$ExceptionCount = 8,
    [int]$PrefixRecords = 10000,
    [int]$QuerySamples = 8
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00J2 G1G2 QUERYABLE RECONSTRUCTION INDEX ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "MATRIX_N=$MatrixN"
Write-Host "EXCEPTION_COUNT=$ExceptionCount"
Write-Host "PREFIX_RECORDS=$PrefixRecords"
Write-Host "QUERY_SAMPLES=$QuerySamples"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$Repo = Resolve-Path $RepoRoot

$Copies = @(
    @{Src="python_ref\ultraballoondb_core\g1g2_query_index.py"; Dst="python_ref\ultraballoondb_core\g1g2_query_index.py"},
    @{Src="python_ref\ultraballoondb_core\selftest\run_g1g2_queryable_reconstruction_index_v00j2.py"; Dst="python_ref\ultraballoondb_core\selftest\run_g1g2_queryable_reconstruction_index_v00j2.py"},
    @{Src="docs\V00J2_G1G2_QUERYABLE_RECONSTRUCTION_INDEX.md"; Dst="docs\V00J2_G1G2_QUERYABLE_RECONSTRUCTION_INDEX.md"},
    @{Src="scripts\windows\RUN_G1G2_QUERYABLE_RECONSTRUCTION_INDEX_V00J2.ps1"; Dst="scripts\windows\RUN_G1G2_QUERYABLE_RECONSTRUCTION_INDEX_V00J2.ps1"}
)

foreach ($Item in $Copies) {
    $Src = Join-Path $PackageRoot $Item.Src
    $Dst = Join-Path $Repo $Item.Dst
    $DstDir = Split-Path -Parent $Dst
    if (!(Test-Path $DstDir)) { New-Item -ItemType Directory -Force -Path $DstDir | Out-Null }
    Copy-Item $Src $Dst -Force
}

$Runner = Join-Path $Repo "python_ref\ultraballoondb_core\selftest\run_g1g2_queryable_reconstruction_index_v00j2.py"
python $Runner `
    --repo-root $Repo `
    --matrix-n $MatrixN `
    --exception-count $ExceptionCount `
    --prefix-records $PrefixRecords `
    --query-samples $QuerySamples

if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00J2_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_G1G2_QUERYABLE_RECONSTRUCTION_INDEX_V00J2_SCRIPT"
