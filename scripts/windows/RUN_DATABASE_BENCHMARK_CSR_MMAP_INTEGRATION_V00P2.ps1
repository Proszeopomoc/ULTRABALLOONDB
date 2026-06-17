param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$Scales = "10000,100000,1000000,10000000",
  [int]$QuerySamples = 32,
  [int]$QueryTopK = 64,
  [int]$MaxSteps = 2,
  [double]$EnergyThreshold = 0.10,
  [int]$TimeoutMinutesPerScale = 360,
  [switch]$RetainDatabases
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

Write-Host "=== ULTRABALLOONDB V00P2 DATABASE BENCHMARK CSR MMAP INTEGRATION ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "SCALES=$Scales"
Write-Host "QUERY_SAMPLES=$QuerySamples"
Write-Host "QUERY_TOP_K=$QueryTopK"
Write-Host "MAX_STEPS=$MaxSteps"
Write-Host "ENERGY_THRESHOLD=$EnergyThreshold"
Write-Host "TIMEOUT_MINUTES_PER_SCALE=$TimeoutMinutesPerScale"
Write-Host "RETAIN_DATABASES=$RetainDatabases"

$destCore = Join-Path $RepoRoot "python_ref\ultraballoondb_core"
$destSelf = Join-Path $destCore "selftest"
$destDocs = Join-Path $RepoRoot "docs"
$destAlign = Join-Path $destDocs "alignment"
$destScripts = Join-Path $RepoRoot "scripts\windows"
New-Item -ItemType Directory -Force -Path $destCore,$destSelf,$destDocs,$destAlign,$destScripts | Out-Null

Copy-Item (Join-Path $PackageRoot "python_ref\ultraballoondb_core\benchmark_suite_csr_mmap.py") (Join-Path $destCore "benchmark_suite_csr_mmap.py") -Force
Copy-Item (Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_database_benchmark_csr_mmap_integration_v00p2.py") (Join-Path $destSelf "run_database_benchmark_csr_mmap_integration_v00p2.py") -Force
Copy-Item (Join-Path $PackageRoot "docs\V00P2_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION.md") (Join-Path $destDocs "V00P2_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION.md") -Force
Copy-Item (Join-Path $PackageRoot "docs\alignment\V00P2_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION.json") (Join-Path $destAlign "V00P2_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION.json") -Force
Copy-Item $MyInvocation.MyCommand.Path (Join-Path $destScripts "RUN_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION_V00P2.ps1") -Force

$argsList = @(
  (Join-Path $destSelf "run_database_benchmark_csr_mmap_integration_v00p2.py"),
  "--repo-root", $RepoRoot,
  "--scales", $Scales,
  "--query-samples", $QuerySamples,
  "--query-top-k", $QueryTopK,
  "--max-steps", $MaxSteps,
  "--energy-threshold", $EnergyThreshold,
  "--timeout-minutes-per-scale", $TimeoutMinutesPerScale
)
if ($RetainDatabases) { $argsList += "--retain-databases" }

python @argsList
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "PASS_RUN_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION_V00P2_SCRIPT"
