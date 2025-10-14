# repoRoot\build\scripts\PackageNuGet.ps1
# Package the NuGet .nupkg using existing built outputs. No building here.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -- Resolve paths relative to this script (works from any CWD) --
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$BuildDir  = Split-Path -Parent $ScriptDir
$RepoRoot  = Split-Path -Parent $BuildDir
$LogsDir   = Join-Path $BuildDir 'logs'
$AssetsDir = Join-Path $BuildDir 'assets'
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

$ProjPath  = Join-Path $RepoRoot 'src\SocketLibraryCPP\SocketLibraryCPP.vcxproj'
$Nuspec    = Join-Path $AssetsDir 'SocketLibraryCPP.nuspec'
$OutDir    = $BuildDir
$LibStage  = Join-Path $RepoRoot 'lib\SocketLibraryCPP'

if (-not (Test-Path -LiteralPath $ProjPath)) { throw "Project not found: $ProjPath" }
if (-not (Test-Path -LiteralPath $Nuspec))  { throw "Nuspec not found:  $Nuspec" }

# -- Find nuget.exe (prefer PATH, then common repo locations) --
function Get-NuGetExe {
  $cmd = Get-Command nuget.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidates = @(
    (Join-Path $BuildDir 'nuget.exe'),
    (Join-Path $RepoRoot 'nuget.exe'),
    (Join-Path $RepoRoot '.nuget\nuget.exe')
  )
  foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
  return $null
}

$NuGetExe = Get-NuGetExe
if (-not $NuGetExe) {
  throw @"
nuget.exe not found.

Place it at one of:
  - $($BuildDir)\nuget.exe
  - $($RepoRoot)\nuget.exe
  - $($RepoRoot)\.nuget\nuget.exe
or install NuGet CLI and ensure it's on PATH.
"@
}

# -- Discover Configuration|Platform pairs from the vcxproj (namespace-safe) --
[xml]$xml = Get-Content -LiteralPath $ProjPath
$pcNodes = $xml.SelectNodes("//*[local-name()='ItemGroup' and @Label='ProjectConfigurations']/*[local-name()='ProjectConfiguration']")
if (-not $pcNodes -or $pcNodes.Count -eq 0) { throw "No ProjectConfiguration nodes found in $ProjPath" }

$pairsRaw = foreach ($n in $pcNodes) {
  $include = $n.GetAttribute('Include')  # e.g., "Debug|Win32"
  if (-not $include) { continue }
  $cp = $include -split '\|'
  if ($cp.Count -ne 2) { continue }
  [pscustomobject]@{ Configuration = $cp[0]; Platform = $cp[1] }
}
$pairs = $pairsRaw | Sort-Object Platform, Configuration -Unique

# -- Single run log setup --
$RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunLog   = Join-Path $LogsDir ("PackNuGet_{0}.log" -f $RunStamp)

"======================================================================" | Out-File -FilePath $RunLog -Encoding UTF8
"PackNuGet run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"           | Out-File -FilePath $RunLog -Append
"RepoRoot : $RepoRoot"                                                 | Out-File -FilePath $RunLog -Append
"BuildDir : $BuildDir"                                                 | Out-File -FilePath $RunLog -Append
"AssetsDir : $AssetsDir"                                               | Out-File -FilePath $RunLog -Append
"Nuspec  : $Nuspec"                                                    | Out-File -FilePath $RunLog -Append
"nuget   : $NuGetExe"                                                  | Out-File -FilePath $RunLog -Append
$pairList = ($pairs | ForEach-Object { "$($_.Configuration)|$($_.Platform)" }) -join ', '
"Pairs   : $pairList"                                                  | Out-File -FilePath $RunLog -Append
"======================================================================" | Out-File -FilePath $RunLog -Append

# -- Staging sanity check (robust to 0/1/many files) --
$sep = '─' * 70
Write-Host "`n$sep`nStaging check (looking under $LibStage)`n$sep"
@("Staging root: $LibStage", "") | Out-File -FilePath $RunLog -Append

function Get-ArrayCount($x) { ($x | Measure-Object).Count }  # safe count

if (Test-Path -LiteralPath $LibStage) {
  foreach ($p in $pairs) {
    $expectDir = Join-Path $LibStage (Join-Path $p.Platform $p.Configuration)
    $libs = @()
    if (Test-Path -LiteralPath $expectDir) {
      # force to array; match .lib or .a
      $libs = @(Get-ChildItem -LiteralPath $expectDir -File -Include *.lib,*.a -ErrorAction SilentlyContinue)
    }
    $libCount = Get-ArrayCount $libs
    $msg  = if ($libCount -gt 0) { "OK   $($p.Configuration)|$($p.Platform)  -> $expectDir  ($libCount lib file(s))" }
            else                  { "MISS $($p.Configuration)|$($p.Platform)  -> $expectDir  (no lib files found)" }
    Write-Host $msg
    $msg | Out-File -FilePath $RunLog -Append
  }
} else {
  Write-Host "Staging root not found; skipping per-pair check."
  "Staging root not found; skipping per-pair check." | Out-File -FilePath $RunLog -Append
}

# -- Pack via nuspec (nuspec = source of truth) --
Write-Host "`n$sep`nPacking via nuspec`n$sep"
@("", $sep, "BEGIN PACK", "Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')", $sep, "") | Out-File -FilePath $RunLog -Append

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

& $NuGetExe pack $Nuspec -BasePath $RepoRoot -NoDefaultExcludes -Verbosity detailed -OutputDirectory $OutDir `
  *>&1 | Tee-Object -FilePath $RunLog -Append

if ($LASTEXITCODE) {
  @("", "RESULT: FAILED (pack)", "End: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')", $sep) | Out-File -FilePath $RunLog -Append
  throw "nuget pack failed. See log: $RunLog"
}

@("", "RESULT: SUCCESS (pack)", "End: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')", $sep) | Out-File -FilePath $RunLog -Append

$pkgFile = Get-ChildItem -LiteralPath $OutDir -Filter *.nupkg | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if (-not $pkgFile) { throw "No .nupkg found in $OutDir after packing." }

Write-Host "`nCreated: $($pkgFile.FullName)"
"Created: $($pkgFile.FullName)" | Out-File -FilePath $RunLog -Append

Write-Host "`nDone. Log: $RunLog"
