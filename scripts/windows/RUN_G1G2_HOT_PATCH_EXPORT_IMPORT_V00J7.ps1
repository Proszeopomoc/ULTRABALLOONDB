param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$MatrixN = 512,
  [int]$PrefixRecords = 10000,
  [int]$BaseExceptions = 8,
  [int]$PatchCount = 32,
  [int]$QuerySamples = 8
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path $RepoRoot).Path
Write-Host "=== ULTRABALLOONDB V00J7 G1G2 HOT PATCH EXPORT IMPORT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "MATRIX_N=$MatrixN"
Write-Host "PREFIX_RECORDS=$PrefixRecords"
Write-Host "BASE_EXCEPTIONS=$BaseExceptions"
Write-Host "PATCH_COUNT=$PatchCount"
Write-Host "QUERY_SAMPLES=$QuerySamples"

$GuardPath = Join-Path $RepoRoot "docs\CORE_ALIGNMENT_GUARD.md"
if (-not (Test-Path $GuardPath)) {
  throw "NO_GO_V00J7_CORE_ALIGNMENT_GUARD_MISSING: $GuardPath"
}

$DependencyPath = Join-Path $RepoRoot "python_ref\ultraballoondb_core\g1g2_delta_patch.py"
if (-not (Test-Path $DependencyPath)) {
  throw "NO_GO_V00J7_DEPENDENCY_MISSING: V00J3 g1g2_delta_patch.py is required"
}

Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00J7_G1G2_HOT_PATCH_EXPORT_IMPORT"
Write-Host "ROLE=SUPPORT"
Write-Host "TOUCHES_CORE_LAYERS=L0,L4,L7"
Write-Host "USES_AUXILIARY_LAYERS=C1,C2,C3,C4,C5"
Write-Host "MUST_NOT_REPLACE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION"
Write-Host "RUNTIME_IMPACT=BOUNDED_IN_MEMORY_HOT_PATCH_ONLY"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

$Files = @(
  @{Src="python_ref\ultraballoondb_core\g1g2_hot_patch_xfer.py"; Dst="python_ref\ultraballoondb_core\g1g2_hot_patch_xfer.py"},
  @{Src="python_ref\ultraballoondb_core\selftest\run_g1g2_hot_patch_export_import_v00j7.py"; Dst="python_ref\ultraballoondb_core\selftest\run_g1g2_hot_patch_export_import_v00j7.py"},
  @{Src="docs\V00J7_G1G2_HOT_PATCH_EXPORT_IMPORT.md"; Dst="docs\V00J7_G1G2_HOT_PATCH_EXPORT_IMPORT.md"},
  @{Src="docs\alignment\V00J7_G1G2_HOT_PATCH_EXPORT_IMPORT.json"; Dst="docs\alignment\V00J7_G1G2_HOT_PATCH_EXPORT_IMPORT.json"},
  @{Src="scripts\windows\RUN_G1G2_HOT_PATCH_EXPORT_IMPORT_V00J7.ps1"; Dst="scripts\windows\RUN_G1G2_HOT_PATCH_EXPORT_IMPORT_V00J7.ps1"}
)

foreach ($f in $Files) {
  $src = Join-Path $PackageRoot $f.Src
  if (-not (Test-Path $src)) { throw "NO_GO_V00J7_PACKAGE_FILE_MISSING: $src" }
  $dst = Join-Path $RepoRoot $f.Dst
  $dstDir = Split-Path -Parent $dst
  New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
  Copy-Item $src $dst -Force
}

python (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_hot_patch_export_import_v00j7.py") `
  --repo-root $RepoRoot `
  --matrix-n $MatrixN `
  --prefix-records $PrefixRecords `
  --base-exceptions $BaseExceptions `
  --patch-count $PatchCount `
  --query-samples $QuerySamples

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00J7_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_ULTRABALLOONDB_V00J7_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_G1G2_HOT_PATCH_EXPORT_IMPORT_V00J7_SCRIPT"
