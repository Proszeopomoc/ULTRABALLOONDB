param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$MatrixN = 1024,
  [int]$ExceptionCount = 8,
  [int]$PrefixRecords = 10000,
  [int]$PatchCount = 4,
  [int]$QuerySamples = 8
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00J3 G1G2 MUTATION DELTA PATCH ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "MATRIX_N=$MatrixN"
Write-Host "EXCEPTION_COUNT=$ExceptionCount"
Write-Host "PREFIX_RECORDS=$PrefixRecords"
Write-Host "PATCH_COUNT=$PatchCount"
Write-Host "QUERY_SAMPLES=$QuerySamples"

$Targets = @(
  @{ Src="python_ref\ultraballoondb_core\g1g2_delta_patch.py"; Dst="python_ref\ultraballoondb_core\g1g2_delta_patch.py" },
  @{ Src="python_ref\ultraballoondb_core\selftest\run_g1g2_mutation_delta_patch_v00j3.py"; Dst="python_ref\ultraballoondb_core\selftest\run_g1g2_mutation_delta_patch_v00j3.py" },
  @{ Src="docs\V00J3_G1G2_MUTATION_DELTA_PATCH.md"; Dst="docs\V00J3_G1G2_MUTATION_DELTA_PATCH.md" },
  @{ Src="scripts\windows\RUN_G1G2_MUTATION_DELTA_PATCH_V00J3.ps1"; Dst="scripts\windows\RUN_G1G2_MUTATION_DELTA_PATCH_V00J3.ps1" }
)

foreach ($T in $Targets) {
  $src = Join-Path $PackageRoot $T.Src
  $dst = Join-Path $RepoRoot $T.Dst
  $dstDir = Split-Path -Parent $dst
  New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
  Copy-Item -Force $src $dst
}

$Selftest = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_mutation_delta_patch_v00j3.py"
python $Selftest `
  --repo-root $RepoRoot `
  --matrix-n $MatrixN `
  --exception-count $ExceptionCount `
  --prefix-records $PrefixRecords `
  --patch-count $PatchCount `
  --query-samples $QuerySamples

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00J3_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_RUN_G1G2_MUTATION_DELTA_PATCH_V00J3_SCRIPT"
