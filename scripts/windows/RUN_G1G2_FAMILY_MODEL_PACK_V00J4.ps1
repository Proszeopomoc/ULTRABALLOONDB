param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$FamilyFiles = 8,
  [int]$RecordsPerFile = 5000,
  [int]$ExceptionsPerFile = 3,
  [int]$QuerySamples = 8
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00J4 G1G2 FAMILY MODEL PACK ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "FAMILY_FILES=$FamilyFiles"
Write-Host "RECORDS_PER_FILE=$RecordsPerFile"
Write-Host "EXCEPTIONS_PER_FILE=$ExceptionsPerFile"
Write-Host "QUERY_SAMPLES=$QuerySamples"

$Targets = @(
  @{ Src="python_ref\ultraballoondb_core\g1g2_family_pack.py"; Dst="python_ref\ultraballoondb_core\g1g2_family_pack.py" },
  @{ Src="python_ref\ultraballoondb_core\selftest\run_g1g2_family_model_pack_v00j4.py"; Dst="python_ref\ultraballoondb_core\selftest\run_g1g2_family_model_pack_v00j4.py" },
  @{ Src="docs\V00J4_G1G2_FAMILY_MODEL_PACK.md"; Dst="docs\V00J4_G1G2_FAMILY_MODEL_PACK.md" },
  @{ Src="scripts\windows\RUN_G1G2_FAMILY_MODEL_PACK_V00J4.ps1"; Dst="scripts\windows\RUN_G1G2_FAMILY_MODEL_PACK_V00J4.ps1" }
)

foreach ($T in $Targets) {
  $src = Join-Path $PackageRoot $T.Src
  $dst = Join-Path $RepoRoot $T.Dst
  $dstDir = Split-Path -Parent $dst
  New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
  Copy-Item -Force $src $dst
}

$Selftest = Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_family_model_pack_v00j4.py"
python $Selftest `
  --repo-root $RepoRoot `
  --family-files $FamilyFiles `
  --records-per-file $RecordsPerFile `
  --exceptions-per-file $ExceptionsPerFile `
  --query-samples $QuerySamples

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00J4_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_RUN_G1G2_FAMILY_MODEL_PACK_V00J4_SCRIPT"
