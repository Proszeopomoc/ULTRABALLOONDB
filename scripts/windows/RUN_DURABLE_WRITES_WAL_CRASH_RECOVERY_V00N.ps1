param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$EventCount = 10000,
  [int]$CheckpointRecords = 4,
  [int]$ReplayRecords = 4,
  [int]$QueryTopK = 64
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00N DURABLE WRITES WAL CRASH RECOVERY ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "CHECKPOINT_RECORDS=$CheckpointRecords"
Write-Host "REPLAY_RECORDS=$ReplayRecords"
Write-Host "QUERY_TOP_K=$QueryTopK"

$GuardPath = Join-Path $RepoRoot "docs\CORE_ALIGNMENT_GUARD.md"
if (-not (Test-Path $GuardPath)) { throw "NO_GO_V00N_CORE_ALIGNMENT_GUARD_MISSING: $GuardPath" }

$Dependencies = @(
  "python_ref\ultraballoondb_core\types.py",
  "python_ref\ultraballoondb_core\wave.py",
  "python_ref\ultraballoondb_core\hot_snapshot.py",
  "python_ref\ultraballoondb_core\hot_wave_subgraph_binding.py",
  "python_ref\ultraballoondb_core\unified_runtime.py"
)
foreach ($rel in $Dependencies) {
  $dep = Join-Path $RepoRoot $rel
  if (-not (Test-Path $dep)) { throw "NO_GO_V00N_DEPENDENCY_MISSING: $dep" }
}

Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY"
Write-Host "ROLE=CORE"
Write-Host "TOUCHES_CORE_LAYERS=L0,L1,L2,L3,L4"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION"
Write-Host "RUNTIME_IMPACT=DURABLE_SINGLE_WRITER_WAL_RECOVERY_REFERENCE"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$Files = @(
  @{Src="python_ref\ultraballoondb_core\durable_runtime.py"; Dst="python_ref\ultraballoondb_core\durable_runtime.py"},
  @{Src="python_ref\ultraballoondb_core\selftest\run_durable_writes_wal_crash_recovery_v00n.py"; Dst="python_ref\ultraballoondb_core\selftest\run_durable_writes_wal_crash_recovery_v00n.py"},
  @{Src="docs\V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY.md"; Dst="docs\V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY.md"},
  @{Src="docs\alignment\V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY.json"; Dst="docs\alignment\V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY.json"},
  @{Src="scripts\windows\RUN_DURABLE_WRITES_WAL_CRASH_RECOVERY_V00N.ps1"; Dst="scripts\windows\RUN_DURABLE_WRITES_WAL_CRASH_RECOVERY_V00N.ps1"}
)
foreach ($f in $Files) {
  $src = Join-Path $PackageRoot $f.Src
  if (-not (Test-Path $src)) { throw "NO_GO_V00N_PACKAGE_FILE_MISSING: $src" }
  $dst = Join-Path $RepoRoot $f.Dst
  New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
  Copy-Item $src $dst -Force
}

python (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_durable_writes_wal_crash_recovery_v00n.py") `
  --repo-root $RepoRoot `
  --event-count $EventCount `
  --checkpoint-records $CheckpointRecords `
  --replay-records $ReplayRecords `
  --query-top-k $QueryTopK

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00N_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_ULTRABALLOONDB_V00N_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_DURABLE_WRITES_WAL_CRASH_RECOVERY_V00N_SCRIPT"
