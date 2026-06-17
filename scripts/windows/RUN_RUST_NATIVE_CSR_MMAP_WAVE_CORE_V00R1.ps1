param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$EventCount = 1000000,
  [int]$QuerySamples = 5000,
  [int]$TopK = 64,
  [int]$MaxSteps = 2,
  [double]$EnergyThreshold = 0.10,
  [double]$MinQuerySpeedup = 1.25,
  [int]$TimeoutSeconds = 1800
)
$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00R1 RUST NATIVE CSR MMAP WAVE CORE CANDIDATE ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "QUERY_SAMPLES=$QuerySamples"
Write-Host "TOP_K=$TopK"
Write-Host "MAX_STEPS=$MaxSteps"
Write-Host "ENERGY_THRESHOLD=$EnergyThreshold"
Write-Host "MIN_QUERY_SPEEDUP=$MinQuerySpeedup"
Write-Host "TIMEOUT_SECONDS=$TimeoutSeconds"
Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE"
Write-Host "ROLE=EXPERIMENT"
Write-Host "TOUCHES_CORE_LAYERS=L1,L2,L3,L7"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION,L7_FLOATING_SUBGRAPH"
Write-Host "RUNTIME_IMPACT=SHADOW_PARITY_AND_BENCHMARK_ONLY"
Write-Host "ACTIVE_RUNTIME_REPLACEMENT=FALSE"
Write-Host "THIRD_PARTY_RUST_CRATES=0"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

function Copy-SafeFile {
  param([Parameter(Mandatory=$true)][string]$Source, [Parameter(Mandatory=$true)][string]$Destination)
  $src = [System.IO.Path]::GetFullPath($Source)
  $dst = [System.IO.Path]::GetFullPath($Destination)
  if ($src -ieq $dst) {
    return
  }
  $parent = Split-Path -Parent $dst
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  Copy-Item -LiteralPath $src -Destination $dst -Force
}

$files = @(
  "rust_native\ultraballoondb_rust_core\Cargo.toml",
  "rust_native\ultraballoondb_rust_core\Cargo.lock",
  "rust_native\ultraballoondb_rust_core\rust-toolchain.toml",
  "rust_native\ultraballoondb_rust_core\src\main.rs",
  "python_ref\ultraballoondb_core\selftest\run_rust_native_csr_mmap_wave_core_v00r1.py",
  "docs\V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE.md",
  "docs\alignment\V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE.json",
  "scripts\linux\RUN_RUST_NATIVE_CSR_MMAP_WAVE_CORE_V00R1.sh"
)
foreach ($relative in $files) {
  Copy-SafeFile (Join-Path $PackageRoot $relative) (Join-Path $RepoRoot $relative)
}
Copy-SafeFile $MyInvocation.MyCommand.Path (Join-Path $RepoRoot "scripts\windows\RUN_RUST_NATIVE_CSR_MMAP_WAVE_CORE_V00R1.ps1")

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
  Write-Host "NO_GO_ULTRABALLOONDB_V00R1_CARGO_NOT_FOUND"
  Write-Host "INSTALL_COMMAND=winget install --exact --id Rustlang.Rustup"
  Write-Host "AFTER_INSTALL=Open a new PowerShell and run: rustup default stable"
  exit 3
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
  throw "Python command not found."
}

& $python.Source (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_rust_native_csr_mmap_wave_core_v00r1.py") `
  --repo-root $RepoRoot `
  --event-count $EventCount `
  --query-samples $QuerySamples `
  --top-k $TopK `
  --max-steps $MaxSteps `
  --energy-threshold $EnergyThreshold `
  --min-query-speedup $MinQuerySpeedup `
  --timeout-seconds $TimeoutSeconds

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "PASS_ULTRABALLOONDB_V00R1_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_RUST_NATIVE_CSR_MMAP_WAVE_CORE_V00R1_SCRIPT"
