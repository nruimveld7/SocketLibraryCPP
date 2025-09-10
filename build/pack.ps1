param(
  [switch]$Expand
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# (Optional) richer diagnostics if anything slips through:
trap {
  Write-Host "`n--- Unhandled error details -------------------" -ForegroundColor Red
  $_ | Format-List * -Force
  Write-Host "-----------------------------------------------`n" -ForegroundColor Red
  break
}

# ---------------------------
# Paths (scripts live in build\)
# ---------------------------
# Robust script dir (avoid PSCommandPath; avoid -LiteralPath with -Parent)
$scriptDir = if ($PSScriptRoot) {
  $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
  Split-Path -Path $MyInvocation.MyCommand.Path -Parent
} else {
  throw "Cannot determine script directory. Run this as a .ps1 file."
}

$buildDir = $scriptDir
$repoRoot = Split-Path -Path $buildDir -Parent

# Hard-coded locations
$Solution = Join-Path $repoRoot 'SocketLibraryCPP.sln'
$Nuspec   = Join-Path $buildDir 'SocketLibraryCPP.nuspec'

# Output goes to build\
$outputDir = $buildDir

Write-Host "Repo root: $repoRoot" -ForegroundColor Cyan
Write-Host "Build dir: $buildDir" -ForegroundColor Cyan
Set-Location $repoRoot

# ---------------------------
# Tool discovery (MSBuild/NuGet)
# ---------------------------
function Find-MSBuild {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $path = & $vswhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null |
            Select-Object -First 1
    if ($path -and (Test-Path $path)) { return $path }
  }
  $cmd = Get-Command msbuild -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

function Find-NuGet {
  # Prefer repo copy if present: repo\pkg\nuget.exe
  $repoNuGet = Join-Path $repoRoot 'pkg\nuget.exe'
  if (Test-Path $repoNuGet) { return $repoNuGet }
  $cmd = Get-Command nuget -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

$MSBuildExe = Find-MSBuild
if (-not $MSBuildExe) {
  throw @"
MSBuild not found.

Install one of:
  - Visual Studio 2019/2022 with MSBuild workload
  - or 'Build Tools for Visual Studio' (includes MSBuild)

Tip: msbuild often isn't on PATH; we auto-detect via vswhere when available.
"@
}
Write-Host "MSBuild: $MSBuildExe" -ForegroundColor Green

$NuGetExe = Find-NuGet
if (-not $NuGetExe) {
  throw @"
nuget.exe not found.

Options:
  - Place nuget.exe at: $($repoRoot)\pkg\nuget.exe
  - or install NuGet CLI and ensure it's on PATH
"@
}
Write-Host "NuGet:   $NuGetExe" -ForegroundColor Green

# ---------------------------
# Always build (Win32/x64 × Debug/Release)
# ---------------------------
$matrix = @(
  @{ Platform='x86'; Configuration='Debug'   }
  @{ Platform='x86'; Configuration='Release' }
  @{ Platform='x64'  ; Configuration='Debug'   }
  @{ Platform='x64'  ; Configuration='Release' }
)

foreach ($m in $matrix) {
  Write-Host "Building $($m.Platform) / $($m.Configuration)..." -ForegroundColor Yellow
  & $MSBuildExe $Solution /m /p:Platform=$($m.Platform) /p:Configuration=$($m.Configuration) | Out-Host
}

# ---------------------------
# Pack (nuspec is the source of truth)
# ---------------------------
# Ensure output dir exists
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Clean ALL existing .nupkg in the output dir first
Get-ChildItem -Path $outputDir -Filter *.nupkg -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

# Do not pass -Version; allow nuspec to decide
Write-Host "Packing via nuspec..." -ForegroundColor Cyan
& $NuGetExe pack $Nuspec -BasePath $repoRoot -NoDefaultExcludes -Verbosity detailed -OutputDirectory $outputDir | Out-Host

# ---------------------------
# Find newest .nupkg and derive identity from filename
# ---------------------------
$pkgFile = Get-ChildItem -Path $outputDir -Filter *.nupkg |
           Sort-Object LastWriteTimeUtc -Descending |
           Select-Object -First 1

if (-not $pkgFile) { throw "No .nupkg found in $outputDir after packing." }

# Filename without extension, e.g. "My.Package.Id.1.0.3-beta.1"
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($pkgFile.Name)

# Split on the LAST dot: left = Id (can contain dots), right = Version (can contain '-' for prerelease)
$lastDot = $baseName.LastIndexOf('.')
if ($lastDot -lt 1) { throw "Unexpected package filename format: '$($pkgFile.Name)'" }

$id      = $baseName.Substring(0, $lastDot)
$version = $baseName.Substring($lastDot + 1)

# Build the canonical name NuGet uses
$finalName = '{0}.{1}.nupkg' -f $id, $version
$finalPath = Join-Path $outputDir $finalName

# If NuGet already produced the canonical name, no rename needed
if ($pkgFile.FullName -ne $finalPath) {
  Move-Item -LiteralPath $pkgFile.FullName -Destination $finalPath -Force
}

Write-Host "Created: $finalPath" -ForegroundColor Green

# ---------------------------
# Optional: expand to _pkgview (under build\)
# ---------------------------
if ($Expand) {
  $viewDir = Join-Path $buildDir '_pkgview'
  $zipPath = "$finalPath.zip"
  if (Test-Path $viewDir) { Remove-Item $viewDir -Recurse -Force }
  if (Test-Path $zipPath)  { Remove-Item $zipPath  -Force }

  Copy-Item $finalPath $zipPath
  Expand-Archive -Path $zipPath -DestinationPath $viewDir -Force
  Remove-Item $zipPath -Force

  Write-Host "_pkgview tree:" -ForegroundColor Cyan
  if (Get-Command tree -ErrorAction SilentlyContinue) {
    tree $viewDir
  } else {
    Get-ChildItem $viewDir -Recurse | Format-Table FullName
  }
}

Write-Host "Done." -ForegroundColor Green
