param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$EventCount = 10000,
  [int]$QueryTopK = 64
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path $RepoRoot).Path

Write-Host "=== ULTRABALLOONDB V00O STABLE DATABASE API CLI TRANSPORT ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "QUERY_TOP_K=$QueryTopK"

$GuardPath = Join-Path $RepoRoot "docs\CORE_ALIGNMENT_GUARD.md"
if (-not (Test-Path $GuardPath)) { throw "NO_GO_V00O_CORE_ALIGNMENT_GUARD_MISSING: $GuardPath" }

$Dependencies = @(
  "python_ref\ultraballoondb_core\types.py",
  "python_ref\ultraballoondb_core\wave.py",
  "python_ref\ultraballoondb_core\unified_runtime.py",
  "python_ref\ultraballoondb_core\durable_runtime.py"
)
foreach ($rel in $Dependencies) {
  $dep = Join-Path $RepoRoot $rel
  if (-not (Test-Path $dep)) { throw "NO_GO_V00O_DEPENDENCY_MISSING: $dep" }
}

Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00O_STABLE_DATABASE_API_CLI_TRANSPORT"
Write-Host "ROLE=CORE"
Write-Host "TOUCHES_CORE_LAYERS=L0,L1,L2,L3,L4,L5,L6,L7"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION"
Write-Host "RUNTIME_IMPACT=STABLE_API_CLI_HTTP_REFERENCE"
Write-Host "ROADMAP_STATUS=ALIGNED"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$Files = @(
  @{Src="python_ref\ultraballoondb_core\database_api.py"; Dst="python_ref\ultraballoondb_core\database_api.py"},
  @{Src="python_ref\ultraballoondb_core\cli.py"; Dst="python_ref\ultraballoondb_core\cli.py"},
  @{Src="python_ref\ultraballoondb_core\http_transport.py"; Dst="python_ref\ultraballoondb_core\http_transport.py"},
  @{Src="python_ref\ultraballoondb_core\selftest\run_stable_database_api_cli_transport_v00o.py"; Dst="python_ref\ultraballoondb_core\selftest\run_stable_database_api_cli_transport_v00o.py"},
  @{Src="docs\V00O_STABLE_DATABASE_API_CLI_TRANSPORT.md"; Dst="docs\V00O_STABLE_DATABASE_API_CLI_TRANSPORT.md"},
  @{Src="docs\alignment\V00O_STABLE_DATABASE_API_CLI_TRANSPORT.json"; Dst="docs\alignment\V00O_STABLE_DATABASE_API_CLI_TRANSPORT.json"},
  @{Src="scripts\windows\RUN_STABLE_DATABASE_API_CLI_TRANSPORT_V00O.ps1"; Dst="scripts\windows\RUN_STABLE_DATABASE_API_CLI_TRANSPORT_V00O.ps1"}
)
foreach ($f in $Files) {
  $src = Join-Path $PackageRoot $f.Src
  if (-not (Test-Path $src)) { throw "NO_GO_V00O_PACKAGE_FILE_MISSING: $src" }
  $dst = Join-Path $RepoRoot $f.Dst
  New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
  Copy-Item $src $dst -Force
}

$env:PYTHONPATH = (Join-Path $RepoRoot "python_ref") + [IO.Path]::PathSeparator + $env:PYTHONPATH
python (Join-Path $RepoRoot "python_ref\ultraballoondb_core\selftest\run_stable_database_api_cli_transport_v00o.py") `
  --repo-root $RepoRoot `
  --event-count $EventCount `
  --query-top-k $QueryTopK

if ($LASTEXITCODE -ne 0) { throw "NO_GO_V00O_SELFTEST_FAILED: exit=$LASTEXITCODE" }

Write-Host "PASS_ULTRABALLOONDB_V00O_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_STABLE_DATABASE_API_CLI_TRANSPORT_V00O_SCRIPT"
