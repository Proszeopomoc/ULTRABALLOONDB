param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$MatrixN = 512,
  [int]$PrefixRecords = 10000,
  [int]$BaseExceptions = 8,
  [int]$PatchEvents = 512,
  [int]$WorkingSet = 64,
  [int]$QuerySamples = 8
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path $RepoRoot).Path
Write-Host "=== ULTRABALLOONDB V00J6 G1G2 PATCH CHAIN COMPACTION ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "MATRIX_N=$MatrixN"
Write-Host "PREFIX_RECORDS=$PrefixRecords"
Write-Host "BASE_EXCEPTIONS=$BaseExceptions"
Write-Host "PATCH_EVENTS=$PatchEvents"
Write-Host "WORKING_SET=$WorkingSet"
Write-Host "QUERY_SAMPLES=$QuerySamples"

$GuardPath = Join-Path $RepoRoot "docs\CORE_ALIGNMENT_GUARD.md"
if (-not (Test-Path $GuardPath)) {
  throw "NO_GO_V00J6_CORE_ALIGNMENT_GUARD_MISSING: $GuardPath"
}

$DependencyPath = Join-Path $RepoRoot "python_ref\ultraballoondb_core\g1g2_delta_patch.py"
if (-not (Test-Path $DependencyPath)) {
  throw "NO_GO_V00J6_DEPENDENCY_MISSING: V00J3 g1g2_delta_patch.py is required"
}

Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00J6_G1G2_PATCH_CHAIN_COMPACTION"
Write-Host "ROLE=SUPPORT"
Write-Host "TOUCHES_CORE_LAYERS=L0,L4,L6"
Write-Host "USES_AUXILIARY_LAYERS=C1,C2,C3,C4,C5"
Write-Host "MUST_NOT_REPLACE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION"
Write-Host "RUNTIME_IMPACT=OFFLINE_COMPACTION_ONLY"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

$Files = @(
  @{Src="python_ref\ultraballoondb_core\g1g2_patch_chain_compaction.py"; Dst="python_ref\ultraballoondb_core\g1g2_patch_chain_compaction.py"},
  @{Src="python_ref\ultraballoondb_core\selftest\run_g1g2_patch_chain_compaction_v00j6.py"; Dst="python_ref\ultraballoondb_core\selftest\run_g1g2_patch_chain_compaction_v00j6.py"},
  @{Src="docs\V00J6_G1G2_PATCH_CHAIN_COMPACTION.md"; Dst="docs\V00J6_G1G2_PATCH_CHAIN_COMPACTION.md"},
  @{Src="docs\alignment\V00J6_G1G2_PATCH_CHAIN_COMPACTION.json"; Dst="docs\alignment\V00J6_G1G2_PATCH_CHAIN_COMPACTION.json"},
  @{Src="scripts\windows\RUN_G1G2_PATCH_CHAIN_COMPACTION_V00J6.ps1"; Dst="scripts\windows\RUN_G1G2_PATCH_CHAIN_COMPACTION_V00J6.ps1"}
)

foreach ($f in $Files) {
  $src = Join-Path $PackageRoot $f.Src
  $dst = Join-Path $RepoRoot $f.Dst
  $dstDir = Split-Path -Parent $dst
  New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
  Copy-Item $src $dst -Force
}

python (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_patch_chain_compaction_v00j6.py") `
  --repo-root $RepoRoot `
  --matrix-n $MatrixN `
  --prefix-records $PrefixRecords `
  --base-exceptions $BaseExceptions `
  --patch-events $PatchEvents `
  --working-set $WorkingSet `
  --query-samples $QuerySamples

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00J6_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_ULTRABALLOONDB_V00J6_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_G1G2_PATCH_CHAIN_COMPACTION_V00J6_SCRIPT"
