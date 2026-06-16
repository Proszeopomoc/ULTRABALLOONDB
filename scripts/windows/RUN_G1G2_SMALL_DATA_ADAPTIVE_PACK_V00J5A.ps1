param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$InputFolder = "",
  [int]$MaxFiles = 64,
  [int]$MaxBytesPerFile = 1048576,
  [int]$QuerySamples = 8,
  [int]$MaxDictionaryTokens = 512
)

$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00J5A G1G2 SMALL DATA ADAPTIVE PACK ==="
Write-Host "REPO_ROOT=$RepoRoot"
if ($InputFolder -eq "") {
  $InputFolder = Join-Path $RepoRoot "docs"
}
Write-Host "INPUT_FOLDER=$InputFolder"
Write-Host "MAX_FILES=$MaxFiles"
Write-Host "MAX_BYTES_PER_FILE=$MaxBytesPerFile"
Write-Host "QUERY_SAMPLES=$QuerySamples"
Write-Host "MAX_DICTIONARY_TOKENS=$MaxDictionaryTokens"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

$Files = @(
  @{Src="python_ref\ultraballoondb_core\g1g2_small_adaptive_pack.py"; Dst="python_ref\ultraballoondb_core\g1g2_small_adaptive_pack.py"},
  @{Src="python_ref\ultraballoondb_core\selftest\run_g1g2_small_data_adaptive_pack_v00j5a.py"; Dst="python_ref\ultraballoondb_core\selftest\run_g1g2_small_data_adaptive_pack_v00j5a.py"},
  @{Src="docs\V00J5A_G1G2_SMALL_DATA_ADAPTIVE_PACK.md"; Dst="docs\V00J5A_G1G2_SMALL_DATA_ADAPTIVE_PACK.md"},
  @{Src="scripts\windows\RUN_G1G2_SMALL_DATA_ADAPTIVE_PACK_V00J5A.ps1"; Dst="scripts\windows\RUN_G1G2_SMALL_DATA_ADAPTIVE_PACK_V00J5A.ps1"}
)

foreach ($f in $Files) {
  $src = Join-Path $PackageRoot $f.Src
  $dst = Join-Path $RepoRoot $f.Dst
  $dstDir = Split-Path -Parent $dst
  New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
  Copy-Item $src $dst -Force
}

python (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_g1g2_small_data_adaptive_pack_v00j5a.py") `
  --repo-root $RepoRoot `
  --input-folder $InputFolder `
  --max-files $MaxFiles `
  --max-bytes-per-file $MaxBytesPerFile `
  --query-samples $QuerySamples `
  --max-dictionary-tokens $MaxDictionaryTokens

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00J5A_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_RUN_G1G2_SMALL_DATA_ADAPTIVE_PACK_V00J5A_SCRIPT"
