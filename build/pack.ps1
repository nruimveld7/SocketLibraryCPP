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

# Find the newly produced nupkg (latest write)
$pkgFile = Get-ChildItem -Path $outputDir -Filter *.nupkg |
           Sort-Object LastWriteTimeUtc -Descending |
           Select-Object -First 1

if (-not $pkgFile) { throw "No .nupkg found in $outputDir after packing." }

# ---------------------------
# Read identity from embedded nuspec and normalize name
# ---------------------------
function Get-PackageIdentityFromNupkg {
  param([Parameter(Mandatory)][string]$Path)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $fs  = [System.IO.File]::OpenRead($Path)
  try {
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read, $false)
    $entry = $zip.Entries | Where-Object { $_.FullName -like '*.nuspec' } | Select-Object -First 1
    if (-not $entry) { throw "Embedded .nuspec not found in package $Path" }
    $sr = New-Object System.IO.StreamReader($entry.Open())
    try {
      [xml]$xml = $sr.ReadToEnd()
    } finally {
      $sr.Dispose()
    }
    [pscustomobject]@{
      Id      = $xml.package.metadata.id
      Version = $xml.package.metadata.version  # already normalized by nuget (e.g., 1.0 -> 1.0.0)
    }
  } finally {
    $zip.Dispose()
    $fs.Dispose()
  }
}

$identity = Get-PackageIdentityFromNupkg -Path $pkgFile.FullName
if (-not $identity.Id -or -not $identity.Version) {
  throw "Could not read Id/Version from $($pkgFile.FullName)"
}

$finalName = '{0}.{1}.nupkg' -f $identity.Id, $identity.Version
$finalPath = Join-Path $outputDir $finalName

# Rename if NuGet's filename differs (e.g., normalization or prerelease)
if ($pkgFile.FullName -ne $finalPath) {
  Move-Item -LiteralPath $pkgFile.FullName -Destination $finalPath -Force
} else {
  # Keep the same object path if already correct
  $finalPath = $pkgFile.FullName
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
