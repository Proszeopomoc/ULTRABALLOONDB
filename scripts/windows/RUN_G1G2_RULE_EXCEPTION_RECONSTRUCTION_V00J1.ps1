param(
    [string]$RepoRoot = "C:\UltraBalloonDB",
    [int]$MatrixN = 1024,
    [int]$ExceptionCount = 8,
    [int]$PrefixRecords = 10000,
    [int]$RandomBytes = 65536
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00J1 G1G2 RULE EXCEPTION RECONSTRUCTION ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "MATRIX_N=$MatrixN"
Write-Host "EXCEPTION_COUNT=$ExceptionCount"
Write-Host "PREFIX_RECORDS=$PrefixRecords"
Write-Host "RANDOM_BYTES=$RandomBytes"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

if (!(Test-Path $RepoRoot)) {
    throw "NO_GO_REPO_ROOT_NOT_FOUND: $RepoRoot"
}

$Targets = @(
    "python_ref\ultraballoondb_core",
    "python_ref\ultraballoondb_core\selftest",
    "docs",
    "scripts\windows"
)
foreach ($t in $Targets) {
    New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot $t) | Out-Null
}

Copy-Item -Force (Join-Path $PackageRoot "python_ref\ultraballoondb_core\g1g2_reconstruction.py") (Join-Path $RepoRoot "python_ref\ultraballoondb_core\g1g2_reconstruction.py")
Copy-Item -Force (Join-Path $PackageRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_rule_exception_reconstruction_v00j1.py") (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_rule_exception_reconstruction_v00j1.py")
Copy-Item -Force (Join-Path $PackageRoot "docs\V00J1_G1G2_RULE_EXCEPTION_RECONSTRUCTION_CORE.md") (Join-Path $RepoRoot "docs\V00J1_G1G2_RULE_EXCEPTION_RECONSTRUCTION_CORE.md")
Copy-Item -Force (Join-Path $PackageRoot "scripts\windows\RUN_G1G2_RULE_EXCEPTION_RECONSTRUCTION_V00J1.ps1") (Join-Path $RepoRoot "scripts\windows\RUN_G1G2_RULE_EXCEPTION_RECONSTRUCTION_V00J1.ps1")

$Runner = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_rule_exception_reconstruction_v00j1.py"

& python $Runner `
    --repo-root $RepoRoot `
    --matrix-n $MatrixN `
    --exception-count $ExceptionCount `
    --prefix-records $PrefixRecords `
    --random-bytes $RandomBytes

if ($LASTEXITCODE -ne 0) {
    throw "NO_GO_V00J1_SELFTEST_FAILED: exit=$LASTEXITCODE"
}

Write-Host "PASS_RUN_G1G2_RULE_EXCEPTION_RECONSTRUCTION_V00J1_SCRIPT"
