#Requires -Version 5.1
param(
  [string]$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..")),
  [switch]$Clean = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-MsBuildPath {
  $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
    if ($LASTEXITCODE -eq 0 -and $installPath) {
      $candidate = Join-Path $installPath "MSBuild\Current\Bin\MSBuild.exe"
      if (Test-Path $candidate) { return $candidate }
    }
  }

  throw "Could not find MSBuild.exe. Install Visual Studio (with MSBuild) or ensure msbuild.exe is on PATH."
}

$msbuild = Get-MsBuildPath
Write-Host "Using MSBuild: $msbuild"

$examplesRoot = Join-Path $RepoRoot "src\examples"
if (-not (Test-Path $examplesRoot)) {
  throw "Examples folder not found: $examplesRoot"
}

$projects = Get-ChildItem -Path (Join-Path $examplesRoot "*\*.vcxproj") -File | Sort-Object FullName
if (-not $projects -or $projects.Count -eq 0) {
  throw "No vcxproj files found under: $examplesRoot\*\*.vcxproj"
}

$configurations = @("Debug", "Release")
$platforms = @("Win32", "x64")

$runtimes = @(
  @{ Name = "MD"; Value = "MultiThreadedDLL" },
  @{ Name = "MDd"; Value = "MultiThreadedDebugDLL" },
  @{ Name = "MT"; Value = "MultiThreaded" },
  @{ Name = "MTd"; Value = "MultiThreadedDebug" }
)

function Invoke-Build([string]$proj, [string]$cfg, [string]$plat, [hashtable]$rt) {
  $projName = [IO.Path]::GetFileNameWithoutExtension($proj)
  $rtName = $rt.Name
  $rtVal = $rt.Value

  if (-not (Test-Path $proj)) {
    Write-Host "FAILED: Project file missing on disk: $proj" -ForegroundColor Red
    exit 1
  }

  $targets = if ($Clean) { "Clean;Build" } else { "Build" }

  # IMPORTANT: Do NOT quote $proj. Pass it as a raw argument.
  $args = @(
    $proj,
    "/t:$targets",
    "/m",
    "/nologo",
    "/v:m",
    "/p:Configuration=$cfg",
    "/p:Platform=$plat",
    "/p:RuntimeLibrary=$rtVal"
  )

  Write-Host ""
  Write-Host "=== Building: $projName | $cfg | $plat | $rtName ($rtVal) ==="
  Write-Host "Project: $proj"

  # Stream output to console AND keep it for failure reporting
  $output = & $msbuild @args 2>&1 | Tee-Object -Variable buildOutput

  if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "FAILED: $projName | $cfg | $plat | $rtName ($rtVal)" -ForegroundColor Red
    Write-Host "MSBuild exit code: $LASTEXITCODE" -ForegroundColor Red
    Write-Host ""
    # Output already streamed, but echo again for clarity if VSCode folds prior output
    $buildOutput | ForEach-Object { Write-Host $_ }
    exit 1
  }
}

foreach ($p in $projects) {
  foreach ($cfg in $configurations) {
    foreach ($plat in $platforms) {
      foreach ($rt in $runtimes) {
        Invoke-Build -proj $p.FullName -cfg $cfg -plat $plat -rt $rt
      }
    }
  }
}

Write-Host ""
Write-Host "SUCCESS: All projects built for all configurations/platforms/runtime libraries." -ForegroundColor Green
exit 0
