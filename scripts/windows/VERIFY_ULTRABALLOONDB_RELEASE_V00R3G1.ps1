param(
    [Parameter(Mandatory=$true)][string]$ReleaseZip,
    [switch]$Dynamic
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Verifier = Join-Path $RepoRoot "tools\release\verify_release_bundle_v00r3g1.py"
if (-not (Test-Path -LiteralPath $Verifier)) { throw "FAIL_RELEASE_VERIFIER_NOT_FOUND" }
$argsList = @($Verifier, "--release-zip", $ReleaseZip)
if ($Dynamic) { $argsList += "--dynamic" }
& python @argsList
if ($LASTEXITCODE -ne 0) { throw "FAIL_RELEASE_VERIFICATION" }
