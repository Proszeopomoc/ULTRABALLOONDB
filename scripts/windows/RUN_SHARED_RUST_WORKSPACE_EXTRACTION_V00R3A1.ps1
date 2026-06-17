param(
    [Parameter(Mandatory=$true)]
    [string]$RepoRoot,

    [int]$EventCount = 100000,
    [int]$CoreEventCount = 1000,
    [int]$QuerySamples = 100,
    [int]$TopK = 64,
    [int]$MaxSteps = 2,
    [double]$EnergyThreshold = 0.10,
    [int]$TimeoutSeconds = 1800
)

$ErrorActionPreference = "Stop"
$PackageRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00R3A1 SHARED RUST WORKSPACE EXTRACTION ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "CORE_EVENT_COUNT=$CoreEventCount"
Write-Host "QUERY_SAMPLES=$QuerySamples"
Write-Host "TOP_K=$TopK"
Write-Host "MAX_STEPS=$MaxSteps"
Write-Host "ENERGY_THRESHOLD=$EnergyThreshold"
Write-Host "TIMEOUT_SECONDS=$TimeoutSeconds"
Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION"
Write-Host "ROLE=CORE"
Write-Host "TOUCHES_CORE_LAYERS=L1,L2,L3,L7"
Write-Host "MUST_PRESERVE=V00R1_PARITY,V00R2_ACTIVE_QUERY_BINDING,L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION,L7_FLOATING_SUBGRAPH"
Write-Host "RUNTIME_IMPACT=STRUCTURAL_REFACTOR_WITHOUT_SEMANTIC_CHANGE"
Write-Host "ACTIVE_FULL_RUNTIME_REPLACEMENT=FALSE"
Write-Host "ROADMAP_STATUS=ALIGNED"

$OldMain = Join-Path $RepoRoot "rust_native\ultraballoondb_rust_core\src\main.rs"
$ExpectedOldMainSha = "C52B5C53336F8CFA19440562538E2AD9B70B14A15EAFC71F1C6EF0439E9E4E39"

if (-not (Test-Path $OldMain)) {
    throw "Missing verified V00R2 source: $OldMain"
}

$ActualOldMainSha = (Get-FileHash $OldMain -Algorithm SHA256).Hash
$KnownPartialR01MainSha = "864EA80857EFDDC69D0CA658A89DE051AB7499FCC005A63AB509BF267210C7FB"

if ($ActualOldMainSha -eq $ExpectedOldMainSha) {
    Write-Host "SOURCE_STATE=VERIFIED_V00R2_PRE_EXTRACTION"
}
elseif ($ActualOldMainSha -eq $KnownPartialR01MainSha) {
    Write-Host "SOURCE_STATE=KNOWN_PARTIAL_V00R3A1_R01_AFTER_FMT_CHECK_FAILURE"
}
else {
    throw "NO_GO_SOURCE_DRIFT: expected verified V00R2 main.rs $ExpectedOldMainSha or known partial R01 main.rs $KnownPartialR01MainSha, got $ActualOldMainSha"
}

$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Backup = Join-Path $RepoRoot "audit\v00r3a1_install_backup\$Stamp"
New-Item $Backup -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $RepoRoot "rust_native") (Join-Path $Backup "rust_native") -Recurse -Force
Write-Host "BACKUP=$Backup"

# Install the workspace and shared-core extraction.
Copy-Item (Join-Path $PackageRoot "rust_native\Cargo.toml") (Join-Path $RepoRoot "rust_native\Cargo.toml") -Force
Copy-Item (Join-Path $PackageRoot "rust_native\Cargo.lock") (Join-Path $RepoRoot "rust_native\Cargo.lock") -Force
Copy-Item (Join-Path $PackageRoot "rust_native\rust-toolchain.toml") (Join-Path $RepoRoot "rust_native\rust-toolchain.toml") -Force

New-Item (Join-Path $RepoRoot "rust_native\.cargo") -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $PackageRoot "rust_native\.cargo\config.toml") (Join-Path $RepoRoot "rust_native\.cargo\config.toml") -Force

New-Item (Join-Path $RepoRoot "rust_native\ultraballoondb-core\src") -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $PackageRoot "rust_native\ultraballoondb-core\Cargo.toml") (Join-Path $RepoRoot "rust_native\ultraballoondb-core\Cargo.toml") -Force
Copy-Item (Join-Path $PackageRoot "rust_native\ultraballoondb-core\src\lib.rs") (Join-Path $RepoRoot "rust_native\ultraballoondb-core\src\lib.rs") -Force

Copy-Item (Join-Path $PackageRoot "rust_native\ultraballoondb_rust_core\Cargo.toml") (Join-Path $RepoRoot "rust_native\ultraballoondb_rust_core\Cargo.toml") -Force
Copy-Item (Join-Path $PackageRoot "rust_native\ultraballoondb_rust_core\src\main.rs") (Join-Path $RepoRoot "rust_native\ultraballoondb_rust_core\src\main.rs") -Force

# A workspace has one canonical lock/toolchain at its root.
Remove-Item (Join-Path $RepoRoot "rust_native\ultraballoondb_rust_core\Cargo.lock") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $RepoRoot "rust_native\ultraballoondb_rust_core\rust-toolchain.toml") -Force -ErrorAction SilentlyContinue

$TestTarget = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_shared_rust_workspace_extraction_v00r3a1.py"
$DocTarget = Join-Path $RepoRoot "docs\V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION.md"
$AlignTarget = Join-Path $RepoRoot "docs\alignment\V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION.json"
$LinuxTarget = Join-Path $RepoRoot "scripts\linux\RUN_SHARED_RUST_WORKSPACE_EXTRACTION_V00R3A1.sh"

New-Item (Split-Path $TestTarget) -ItemType Directory -Force | Out-Null
New-Item (Split-Path $DocTarget) -ItemType Directory -Force | Out-Null
New-Item (Split-Path $AlignTarget) -ItemType Directory -Force | Out-Null
New-Item (Split-Path $LinuxTarget) -ItemType Directory -Force | Out-Null

Copy-Item (Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_shared_rust_workspace_extraction_v00r3a1.py") $TestTarget -Force
Copy-Item (Join-Path $PackageRoot "docs\V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION.md") $DocTarget -Force
Copy-Item (Join-Path $PackageRoot "docs\alignment\V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION.json") $AlignTarget -Force
Copy-Item (Join-Path $PackageRoot "scripts\linux\RUN_SHARED_RUST_WORKSPACE_EXTRACTION_V00R3A1.sh") $LinuxTarget -Force

# R01 correctly failed closed because the extracted library had not yet been
# normalized by rustfmt. R02 performs the deterministic formatter step first,
# then the selftest verifies `cargo fmt --check`.
Push-Location (Join-Path $RepoRoot "rust_native")
try {
    cargo fmt --all
    if ($LASTEXITCODE -ne 0) {
        throw "cargo fmt --all failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
Write-Host "PASS_ULTRABALLOONDB_V00R3A1_RUSTFMT_NORMALIZATION"

python $TestTarget `
  --repo-root $RepoRoot `
  --event-count $EventCount `
  --core-event-count $CoreEventCount `
  --query-samples $QuerySamples `
  --top-k $TopK `
  --max-steps $MaxSteps `
  --energy-threshold $EnergyThreshold `
  --timeout-seconds $TimeoutSeconds

if ($LASTEXITCODE -ne 0) {
    throw "V00R3A1 validation failed with exit code $LASTEXITCODE. Backup: $Backup"
}

Write-Host "PASS_ULTRABALLOONDB_V00R3A1_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_SHARED_RUST_WORKSPACE_EXTRACTION_V00R3A1_SCRIPT"
