param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$EventCount = 100000,
  [int]$SeedQueries = 16,
  [int]$TopK = 64,
  [int]$MaxSteps = 2,
  [double]$EnergyThreshold = 0.10
)
$ErrorActionPreference = "Stop"
Write-Host "=== ULTRABALLOONDB V00P1 CSR MMAP CORE HOTPATH BINDING ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "SEED_QUERIES=$SeedQueries"
Write-Host "TOP_K=$TopK"
Write-Host "MAX_STEPS=$MaxSteps"
Write-Host "ENERGY_THRESHOLD=$EnergyThreshold"
Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00P1_CSR_MMAP_CORE_HOTPATH_BINDING"
Write-Host "ROLE=CORE"
Write-Host "TOUCHES_CORE_LAYERS=L1,L2,L3,L4,L7"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION"
Write-Host "RUNTIME_IMPACT=CORE_HOTPATH_LAYOUT_BINDING"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "docs\alignment") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "scripts\windows") | Out-Null

Copy-Item (Join-Path $PackageRoot "python_ref\ultraballoondb_core\csr_mmap_hotpath.py") (Join-Path $RepoRoot "python_ref\ultraballoondb_core\csr_mmap_hotpath.py") -Force
Copy-Item (Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_csr_mmap_core_hotpath_binding_v00p1.py") (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_csr_mmap_core_hotpath_binding_v00p1.py") -Force
Copy-Item (Join-Path $PackageRoot "docs\V00P1_CSR_MMAP_CORE_HOTPATH_BINDING.md") (Join-Path $RepoRoot "docs\V00P1_CSR_MMAP_CORE_HOTPATH_BINDING.md") -Force
Copy-Item (Join-Path $PackageRoot "docs\alignment\V00P1_CSR_MMAP_CORE_HOTPATH_BINDING.json") (Join-Path $RepoRoot "docs\alignment\V00P1_CSR_MMAP_CORE_HOTPATH_BINDING.json") -Force
Copy-Item $MyInvocation.MyCommand.Path (Join-Path $RepoRoot "scripts\windows\RUN_CSR_MMAP_CORE_HOTPATH_BINDING_V00P1.ps1") -Force

$py = "python"
& $py (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_csr_mmap_core_hotpath_binding_v00p1.py") `
  --repo-root $RepoRoot `
  --event-count $EventCount `
  --seed-queries $SeedQueries `
  --top-k $TopK `
  --max-steps $MaxSteps `
  --energy-threshold $EnergyThreshold

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "PASS_ULTRABALLOONDB_V00P1_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_CSR_MMAP_CORE_HOTPATH_BINDING_V00P1_SCRIPT"
