param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [int]$CoreEventCount = 10000,
    [int]$QuerySamples = 1000,
    [int]$TopK = 64,
    [int]$MaxSteps = 2,
    [double]$EnergyThreshold = 0.10,
    [int]$TimeoutSeconds = 1800
)

$ErrorActionPreference = "Stop"
$PackageRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00R2 RUST NATIVE RUNTIME BINDING ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "CORE_EVENT_COUNT=$CoreEventCount"
Write-Host "QUERY_SAMPLES=$QuerySamples"
Write-Host "TOP_K=$TopK"
Write-Host "MAX_STEPS=$MaxSteps"
Write-Host "ENERGY_THRESHOLD=$EnergyThreshold"
Write-Host "TIMEOUT_SECONDS=$TimeoutSeconds"
Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00R2_RUST_NATIVE_RUNTIME_BINDING"
Write-Host "ROLE=CORE"
Write-Host "TOUCHES_CORE_LAYERS=L1,L2,L3,L7"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L0,L1,L2,L3,L4,L5,L6,L7,WAL,API,CLI,HTTP"
Write-Host "RUNTIME_IMPACT=OPT_IN_ACTIVE_RUST_QUERY_BINDING_WITH_SAFE_FALLBACK"
Write-Host "ACTIVE_FULL_RUNTIME_REPLACEMENT=FALSE"
Write-Host "ROADMAP_STATUS=ALIGNED"

function Install-File([string]$RelativePath) {
    $Source = (Resolve-Path (Join-Path $PackageRoot $RelativePath)).Path
    $Destination = Join-Path $RepoRoot $RelativePath
    $Parent = Split-Path $Destination -Parent
    New-Item $Parent -ItemType Directory -Force | Out-Null
    $DestinationFull = [System.IO.Path]::GetFullPath($Destination)
    if ($Source -ieq $DestinationFull) {
        return
    }
    Copy-Item $Source $Destination -Force
}

$Files = @(
    "rust_native\ultraballoondb_rust_core\Cargo.toml",
    "rust_native\ultraballoondb_rust_core\Cargo.lock",
    "rust_native\ultraballoondb_rust_core\rust-toolchain.toml",
    "rust_native\ultraballoondb_rust_core\src\main.rs",
    "python_ref\ultraballoondb_core\rust_runtime_binding.py",
    "python_ref\ultraballoondb_core\selftest\run_rust_native_runtime_binding_v00r2.py",
    "scripts\windows\RUN_RUST_NATIVE_RUNTIME_BINDING_V00R2.ps1",
    "scripts\linux\RUN_RUST_NATIVE_RUNTIME_BINDING_V00R2.sh",
    "docs\V00R2_RUST_NATIVE_RUNTIME_BINDING.md",
    "docs\alignment\V00R2_RUST_NATIVE_RUNTIME_BINDING.json"
)
foreach ($File in $Files) { Install-File $File }

$GitIgnore = Join-Path $RepoRoot ".gitignore"
$IgnoreRule = "rust_native/**/target/"
if (-not (Test-Path $GitIgnore)) {
    Set-Content $GitIgnore "$IgnoreRule`n" -Encoding UTF8
} elseif (-not (@(Get-Content $GitIgnore | Where-Object { $_.Trim() -eq $IgnoreRule }).Count -gt 0)) {
    Add-Content $GitIgnore "`n$IgnoreRule" -Encoding UTF8
}

$Cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $Cargo) {
    Write-Host "NO_GO_ULTRABALLOONDB_V00R2_CARGO_NOT_FOUND"
    exit 3
}
$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    Write-Host "NO_GO_ULTRABALLOONDB_V00R2_PYTHON_NOT_FOUND"
    exit 3
}

& $Python.Source `
  (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_rust_native_runtime_binding_v00r2.py") `
  --repo-root $RepoRoot `
  --core-event-count $CoreEventCount `
  --query-samples $QuerySamples `
  --top-k $TopK `
  --max-steps $MaxSteps `
  --energy-threshold $EnergyThreshold `
  --timeout-seconds $TimeoutSeconds

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "PASS_ULTRABALLOONDB_V00R2_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_RUST_NATIVE_RUNTIME_BINDING_V00R2_SCRIPT"
