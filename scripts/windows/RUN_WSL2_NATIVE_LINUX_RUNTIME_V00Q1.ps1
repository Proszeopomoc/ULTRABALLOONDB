param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$Distro = "",
  [int]$EventCount = 100000,
  [int]$CoreEventCount = 1000,
  [int]$TimeoutSeconds = 600
)
$ErrorActionPreference = "Stop"

Write-Host "=== ULTRABALLOONDB V00Q1 WSL2 NATIVE LINUX RUNTIME VALIDATION ==="
Write-Host "REPO_ROOT=$RepoRoot"
Write-Host "DISTRO=$Distro"
Write-Host "EVENT_COUNT=$EventCount"
Write-Host "CORE_EVENT_COUNT=$CoreEventCount"
Write-Host "TIMEOUT_SECONDS=$TimeoutSeconds"
Write-Host "ALIGNMENT_CHECK"
Write-Host "MILESTONE=V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION"
Write-Host "ROLE=SUPPORT"
Write-Host "TOUCHES_CORE_LAYERS=NONE"
Write-Host "USES_AUXILIARY_LAYERS=NONE"
Write-Host "MUST_PRESERVE=L0,L1,L2,L3,L4,L5,L6,L7"
Write-Host "RUNTIME_IMPACT=CROSS_PLATFORM_VALIDATION_ONLY"
Write-Host "ROADMAP_STATUS=ALIGNED"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "WSL is not installed or wsl.exe is not available."
}
if (-not (Test-Path $RepoRoot)) {
  throw "Repo root missing: $RepoRoot"
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

function Copy-IfDifferentPath([string]$Source, [string]$Destination) {
  $src = [System.IO.Path]::GetFullPath($Source)
  $dst = [System.IO.Path]::GetFullPath($Destination)
  if ($src -ieq $dst) { return }
  $parent = Split-Path -Parent $dst
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  Copy-Item $src $dst -Force
}

function Convert-ToWslPath([string]$WindowsPath) {
  $full = [System.IO.Path]::GetFullPath($WindowsPath)
  if ($full.Length -lt 3 -or $full[1] -ne ':') {
    throw "Only drive-letter Windows paths are supported: $full"
  }
  $drive = $full.Substring(0,1).ToLowerInvariant()
  $rest = $full.Substring(2).Replace('\','/')
  return "/mnt/$drive$rest"
}

$QScriptRel = "python_ref\ultraballoondb_core\selftest\run_wsl2_native_linux_runtime_validation_v00q1.py"
$LinuxRunnerRel = "scripts\linux\RUN_WSL2_NATIVE_LINUX_RUNTIME_V00Q1.sh"
$WindowsRunnerRel = "scripts\windows\RUN_WSL2_NATIVE_LINUX_RUNTIME_V00Q1.ps1"
$DocRel = "docs\V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION.md"
$AlignmentRel = "docs\alignment\V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION.json"

Copy-IfDifferentPath (Join-Path $PackageRoot $QScriptRel) (Join-Path $RepoRoot $QScriptRel)
Copy-IfDifferentPath (Join-Path $PackageRoot $LinuxRunnerRel) (Join-Path $RepoRoot $LinuxRunnerRel)
Copy-IfDifferentPath $MyInvocation.MyCommand.Path (Join-Path $RepoRoot $WindowsRunnerRel)
Copy-IfDifferentPath (Join-Path $PackageRoot $DocRel) (Join-Path $RepoRoot $DocRel)
Copy-IfDifferentPath (Join-Path $PackageRoot $AlignmentRel) (Join-Path $RepoRoot $AlignmentRel)

$WslArgs = @()
if (-not [string]::IsNullOrWhiteSpace($Distro)) {
  $WslArgs += @("-d", $Distro)
}

Write-Host "=== WSL INVENTORY ==="
& wsl.exe -l -v
if ($LASTEXITCODE -ne 0) { throw "wsl.exe -l -v failed" }

$Kernel = (& wsl.exe @WslArgs -- uname -r 2>$null | Out-String).Trim()
$IsWsl2Kernel = $Kernel -match "(?i)WSL2|microsoft-standard"
Write-Host "WSL_KERNEL=$Kernel"
Write-Host "WSL2_KERNEL_DETECTED=$IsWsl2Kernel"
if (-not $IsWsl2Kernel) {
  throw "WSL2 kernel was not detected. Upgrade the selected distro to WSL2 before this validation."
}

$PythonVersion = (& wsl.exe @WslArgs -- python3 --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
  throw "python3 is missing in the selected WSL distro."
}
Write-Host "WSL_PYTHON=$PythonVersion"

$RunId = Get-Date -Format "RUN_yyyyMMdd_HHmmss"
$RunDir = Join-Path $RepoRoot "audit\v00q1_wsl2_native_linux_runtime_validation\$RunId"
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$Archive = Join-Path $RunDir "tracked_source.tar"
$WindowsFixture = Join-Path $RunDir "windows_fixture"
$WindowsManifest = Join-Path $RunDir "windows_fixture_manifest.json"
$LinuxFixture = Join-Path $RunDir "linux_fixture_from_wsl"
$LinuxManifest = Join-Path $RunDir "linux_fixture_manifest.json"
$LinuxReport = Join-Path $RunDir "wsl2_native_linux_runtime_report.json"
$WindowsVerifyReport = Join-Path $RunDir "linux_to_windows_fixture_verification.json"
$FinalReport = Join-Path $RunDir "v00q1_wsl2_native_linux_runtime_validation_report.json"

Push-Location $RepoRoot
try {
  & git archive --format=tar --output="$Archive" HEAD
  if ($LASTEXITCODE -ne 0) { throw "git archive failed" }
} finally {
  Pop-Location
}

$Py = "python"
$QScript = Join-Path $RepoRoot $QScriptRel
& $Py $QScript create-fixture `
  --layout-dir $WindowsFixture `
  --manifest-path $WindowsManifest `
  --event-count $EventCount
if ($LASTEXITCODE -ne 0) { throw "Windows fixture creation failed" }

$ArchiveWsl = Convert-ToWslPath $Archive
$QScriptWsl = Convert-ToWslPath $QScript
$WindowsFixtureWsl = Convert-ToWslPath $WindowsFixture
$WindowsManifestWsl = Convert-ToWslPath $WindowsManifest
$RunDirWsl = Convert-ToWslPath $RunDir
$LinuxRunnerWsl = Convert-ToWslPath (Join-Path $RepoRoot $LinuxRunnerRel)

$BashArgs = @(
  @($WslArgs),
  "--", "bash", $LinuxRunnerWsl,
  "--archive", $ArchiveWsl,
  "--q-script", $QScriptWsl,
  "--windows-fixture", $WindowsFixtureWsl,
  "--windows-manifest", $WindowsManifestWsl,
  "--windows-evidence-dir", $RunDirWsl,
  "--run-id", $RunId,
  "--event-count", "$EventCount",
  "--core-event-count", "$CoreEventCount",
  "--timeout-seconds", "$TimeoutSeconds"
)
$FlatBashArgs = @()
foreach ($part in $BashArgs) {
  if ($part -is [System.Array]) { $FlatBashArgs += $part } else { $FlatBashArgs += $part }
}
& wsl.exe @FlatBashArgs
if ($LASTEXITCODE -ne 0) { throw "WSL2 native Linux validation failed" }

if (-not (Test-Path $LinuxFixture) -or -not (Test-Path $LinuxManifest) -or -not (Test-Path $LinuxReport)) {
  throw "WSL evidence files were not copied back to Windows."
}

& $Py $QScript verify-fixture `
  --layout-dir $LinuxFixture `
  --manifest-path $LinuxManifest `
  --report-path $WindowsVerifyReport
$LinuxToWindowsOk = $LASTEXITCODE -eq 0
if (-not $LinuxToWindowsOk) { throw "Linux-to-Windows CSR fixture verification failed" }

$LinuxDoc = Get-Content $LinuxReport -Raw | ConvertFrom-Json
$WindowsVerifyDoc = Get-Content $WindowsVerifyReport -Raw | ConvertFrom-Json
$ArchiveHash = (Get-FileHash $Archive -Algorithm SHA256).Hash
$LinuxReportHash = (Get-FileHash $LinuxReport -Algorithm SHA256).Hash
$WindowsFixtureHash = (Get-FileHash $WindowsManifest -Algorithm SHA256).Hash
$LinuxFixtureHash = (Get-FileHash $LinuxManifest -Algorithm SHA256).Hash

$Checks = [ordered]@{
  wsl2_kernel_detected = [bool]$IsWsl2Kernel
  linux_suite_passed = ($LinuxDoc.status -eq "PASS_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_RUNTIME")
  windows_to_linux_binary_compatible = [bool]$LinuxDoc.checks.windows_to_linux_csr_binary_compatible
  linux_to_windows_binary_compatible = [bool]$WindowsVerifyDoc.ok
  native_linux_filesystem = [bool]$LinuxDoc.checks.native_linux_filesystem
  l0_l7_runtime_passed = [bool]$LinuxDoc.existing_selftests.v00m_unified_l0_l7.pass
  wal_recovery_passed = [bool]$LinuxDoc.existing_selftests.v00n_wal_recovery.pass
  api_cli_http_passed = [bool]$LinuxDoc.existing_selftests.v00o_api_cli_http.pass
  csr_mmap_passed = [bool]$LinuxDoc.existing_selftests.v00p1_csr_mmap.pass
}
$AllPass = -not ($Checks.Values -contains $false)

$Final = [ordered]@{
  version = "V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION"
  status = $(if ($AllPass) { "PASS_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_AND_CROSS_OS_BINARY_COMPATIBILITY" } else { "NO_GO_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION" })
  timestamp = (Get-Date).ToString("o")
  repo_root = $RepoRoot
  head_commit = (& git -C $RepoRoot rev-parse HEAD | Out-String).Trim()
  wsl_kernel = $Kernel
  wsl_python = $PythonVersion
  event_count = $EventCount
  core_event_count = $CoreEventCount
  alignment = [ordered]@{
    role = "SUPPORT"
    touches_core_layers = @()
    uses_auxiliary_layers = @()
    must_preserve = @("L0","L1","L2","L3","L4","L5","L6","L7")
    runtime_impact = "CROSS_PLATFORM_VALIDATION_ONLY"
    roadmap_status = "ALIGNED"
  }
  checks = $Checks
  evidence = [ordered]@{
    tracked_source_tar_sha256 = $ArchiveHash
    windows_fixture_manifest_sha256 = $WindowsFixtureHash
    linux_fixture_manifest_sha256 = $LinuxFixtureHash
    linux_report_sha256 = $LinuxReportHash
    linux_report = $LinuxReport
    windows_verification = $WindowsVerifyReport
  }
  claims = [ordered]@{
    wsl2_native_linux_runtime = $AllPass
    independent_linux_distribution = $false
    macos_native_runtime = $false
    windows_emulator_required_inside_wsl = $false
  }
}
$Final | ConvertTo-Json -Depth 10 | Set-Content $FinalReport -Encoding UTF8

if (-not $AllPass) {
  Write-Host "NO_GO_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION"
  Write-Host "REPORT=$FinalReport"
  exit 2
}

Write-Host "PASS_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_AND_CROSS_OS_BINARY_COMPATIBILITY"
Write-Host "REPORT=$FinalReport"
Write-Host "WSL_REPORT=$LinuxReport"
Write-Host "PASS_ULTRABALLOONDB_V00Q1_ALIGNMENT_CHECK"
Write-Host "PASS_RUN_WSL2_NATIVE_LINUX_RUNTIME_V00Q1_SCRIPT"
