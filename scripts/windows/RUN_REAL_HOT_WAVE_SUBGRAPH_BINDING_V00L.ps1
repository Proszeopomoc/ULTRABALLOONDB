param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$EventCount = 10000,
  [int]$SeedQueries = 16,
  [int]$TopKPerSeed = 8,
  [int]$MaxSteps = 2,
  [double]$EnergyThreshold = 0.10
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00L REAL HOT WAVE SUBGRAPH BINDING ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "SEED_QUERIES=$SeedQueries"
Write-Host "TOP_K_PER_SEED=$TopKPerSeed"
Write-Host "MAX_STEPS=$MaxSteps"
Write-Host "ENERGY_THRESHOLD=$EnergyThreshold"

$GuardPath = Join-Path $RepoRoot "docs\CORE_ALIGNMENT_GUARD.md"
if (-not (Test-Path $GuardPath)) { throw "NO_GO_V00L_CORE_ALIGNMENT_GUARD_MISSING: $GuardPath" }

$Dependencies = @(
  "python_ref\ultraballoondb_core\types.py",
  "python_ref\ultraballoondb_core\wave.py",
  "python_ref\ultraballoondb_core\hot_snapshot.py",
  "python_ref\ultraballoondb_core\floating_subgraph.py"
)
foreach ($rel in $Dependencies) {
  $dep = Join-Path $RepoRoot $rel
  if (-not (Test-Path $dep)) { throw "NO_GO_V00L_DEPENDENCY_MISSING: $dep" }
}

Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING"
Write-Host "ROLE=CORE"
Write-Host "TOUCHES_CORE_LAYERS=L1,L2,L3,L4,L7"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION"
Write-Host "RUNTIME_IMPACT=REFERENCE_CORE_BINDING"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$Files = @(
  @{Src="python_ref\ultraballoondb_core\hot_wave_subgraph_binding.py"; Dst="python_ref\ultraballoondb_core\hot_wave_subgraph_binding.py"},
  @{Src="python_ref\ultraballoondb_core\selftest\run_real_hot_wave_subgraph_binding_v00l.py"; Dst="python_ref\ultraballoondb_core\selftest\run_real_hot_wave_subgraph_binding_v00l.py"},
  @{Src="docs\V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING.md"; Dst="docs\V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING.md"},
  @{Src="docs\alignment\V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING.json"; Dst="docs\alignment\V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING.json"},
  @{Src="scripts\windows\RUN_REAL_HOT_WAVE_SUBGRAPH_BINDING_V00L.ps1"; Dst="scripts\windows\RUN_REAL_HOT_WAVE_SUBGRAPH_BINDING_V00L.ps1"}
)
foreach ($f in $Files) {
  $src = Join-Path $PackageRoot $f.Src
  if (-not (Test-Path $src)) { throw "NO_GO_V00L_PACKAGE_FILE_MISSING: $src" }
  $dst = Join-Path $RepoRoot $f.Dst
  New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
  Copy-Item $src $dst -Force
}

python (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_real_hot_wave_subgraph_binding_v00l.py") `
  --repo-root $RepoRoot `
  --event-count $EventCount `
  --seed-queries $SeedQueries `
  --top-k-per-seed $TopKPerSeed `
  --max-steps $MaxSteps `
  --energy-threshold $EnergyThreshold

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00L_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_ULTRABALLOONDB_V00L_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_REAL_HOT_WAVE_SUBGRAPH_BINDING_V00L_SCRIPT"
