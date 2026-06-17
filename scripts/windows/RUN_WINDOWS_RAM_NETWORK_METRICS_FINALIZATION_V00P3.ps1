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

Write-Host "=== ULTRABALLOONDB V00P3 WINDOWS RAM AND NETWORK METRICS FINALIZATION ==="
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

$sourceCore = Join-Path $PackageRoot "python_ref\ultraballoondb_core\benchmark_suite_csr_mmap.py"
$targetCore = Join-Path $destCore "benchmark_suite_csr_mmap.py"
if (Test-Path $targetCore) {
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $backupDir = Join-Path $RepoRoot "audit\v00p3_install_backup\$stamp"
  New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
  Copy-Item $targetCore (Join-Path $backupDir "benchmark_suite_csr_mmap.py.before_v00p3") -Force
  Write-Host "BACKUP=$backupDir"
}

Copy-Item $sourceCore $targetCore -Force
Copy-Item (Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_windows_ram_network_metrics_finalization_v00p3.py") (Join-Path $destSelf "run_windows_ram_network_metrics_finalization_v00p3.py") -Force
Copy-Item (Join-Path $PackageRoot "docs\V00P3_WINDOWS_RAM_AND_NETWORK_METRICS_FINALIZATION.md") (Join-Path $destDocs "V00P3_WINDOWS_RAM_AND_NETWORK_METRICS_FINALIZATION.md") -Force
Copy-Item (Join-Path $PackageRoot "docs\alignment\V00P3_WINDOWS_RAM_AND_NETWORK_METRICS_FINALIZATION.json") (Join-Path $destAlign "V00P3_WINDOWS_RAM_AND_NETWORK_METRICS_FINALIZATION.json") -Force
Copy-Item $MyInvocation.MyCommand.Path (Join-Path $destScripts "RUN_WINDOWS_RAM_NETWORK_METRICS_FINALIZATION_V00P3.ps1") -Force

$argsList = @(
  (Join-Path $destSelf "run_windows_ram_network_metrics_finalization_v00p3.py"),
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
Write-Host "PASS_RUN_WINDOWS_RAM_NETWORK_METRICS_FINALIZATION_V00P3_SCRIPT"
