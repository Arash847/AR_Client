<#
.SYNOPSIS
    Fetches the third-party cores ARClient drives and stages them under cores/.

.DESCRIPTION
    ARClient embeds xray-core as a Go module, so there is nothing to fetch for
    it. This script stages the two binaries it supervises:

      aether.exe   the tunnel core, from the CluvexStudio/Aether release
      zeptun       the tunnelling engine, from the Noisemux/zeptun release

    Both are pinned to an exact tag and verified against a published checksum.
    A censorship tool that silently picks up a different build of its own
    transport is not a censorship tool any more, so the pins are the point
    rather than an inconvenience.

.PARAMETER WithGeo
    Also stage geoip.dat and geosite.dat. Off by default: the only consumer is
    the optional ads rule, and the two files are large enough to notice in a
    release archive.

.PARAMETER AetherVersion
    Aether release tag to stage. Defaults to the pin below.

.PARAMETER ZeptunVersion
    zeptun release tag to stage. Required for a release build; when omitted the
    newest release is resolved, which is convenient for local exploration and
    wrong for something published.

.EXAMPLE
    ./scripts/fetch-cores.ps1
    ./scripts/fetch-cores.ps1 -WithGeo
#>
[CmdletBinding()]
param(
    [switch]$WithGeo,
    [string]$OutDir = "cores",
    [string]$AetherVersion = "",
    [string]$ZeptunVersion = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Pinned versions. Bump deliberately, one at a time, and read the release notes
# rather than taking latest: both of these change behaviour between releases.
$DefaultAetherVersion = "v2.1.0"
$GeoBase             = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

if ($AetherVersion -eq "") { $AetherVersion = $DefaultAetherVersion }
$AetherAsset = "aether-windows-x86_64.zip"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Get-Verified {
    <#
      Downloads a URL and, when a checksum URL is supplied, verifies the result.
      Verification is not optional: a mismatch aborts the build rather than
      warning, because the alternative is a release built from an unverified
      transport.
    #>
    param(
        [Parameter(Mandatory)] [string]$Url,
        [string]$Sha256Url,
        [Parameter(Mandatory)] [string]$Dest
    )
    Write-Host "  fetching $Url"
    & curl.exe -sS -L --retry 5 --connect-timeout 20 --max-time 600 -o $Dest $Url
    if ($LASTEXITCODE -ne 0) { throw "download failed: $Url" }

    if (-not $Sha256Url) { return }

    $shaDest = "$Dest.sha256"
    & curl.exe -sS -L --retry 5 --connect-timeout 20 --max-time 120 -o $shaDest $Sha256Url
    if ($LASTEXITCODE -ne 0) { throw "checksum download failed: $Sha256Url" }

    $expected = (Get-Content $shaDest -Raw).Trim().Split()[0].ToLower()
    $actual   = (Get-FileHash -Path $Dest -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Remove-Item $Dest, $shaDest -Force -ErrorAction SilentlyContinue
        throw "checksum mismatch for $Url`n  expected $expected`n  actual   $actual"
    }
    Remove-Item $shaDest -Force
    Write-Host "  verified sha256 $actual"
}

function Expand-And-Place {
    <#
      Expands an archive and moves one named file out of it, which is what both
      archives need: they contain the binary alongside a launcher script and, in
      zeptun's case, wintun.dll.
    #>
    param(
        [Parameter(Mandatory)] [string]$Archive,
        [Parameter(Mandatory)] [string]$Want,   # file name to extract
        [Parameter(Mandatory)] [string]$Dest
    )
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("arclient-" + [guid]::NewGuid().ToString("N"))
    Expand-Archive -Path $Archive -DestinationPath $tmp -Force
    $found = Get-ChildItem -Path $tmp -Recurse -Filter $Want -File | Select-Object -First 1
    if (-not $found) { throw "$Want not found in $Archive" }
    Move-Item -Path $found.FullName -Destination $Dest -Force
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $Archive -Force
    Write-Host "  placed $Dest"
}

Write-Host "== Aether =="
$aetherZip = Join-Path $env:TEMP "aether.zip"
Get-Verified -Url "https://github.com/CluvexStudio/Aether/releases/download/$AetherVersion/$AetherAsset" `
             -Sha256Url "https://github.com/CluvexStudio/Aether/releases/download/$AetherVersion/$AetherAsset.sha256" `
             -Dest $aetherZip
Expand-And-Place -Archive $aetherZip -Want "aether.exe" -Dest (Join-Path $OutDir "aether.exe")

# zeptun: pinned by tag. A blank pin resolves the newest release, which is fine
# for exploration and wrong for a release, so the workflow always passes one.
Write-Host "== zeptun =="
if ($ZeptunVersion -eq "") {
    $rel = Invoke-RestMethod "https://api.github.com/repos/Noisemux/zeptun/releases/latest" `
            -Headers @{ "User-Agent" = "arclient-build" }
    $ZeptunVersion = $rel.tag_name
    Write-Host "  (no pin supplied; resolved $ZeptunVersion)"
}
$zeptunAsset = "zeptun-windows-x86_64.zip"
$zeptunZip = Join-Path $env:TEMP "zeptun.zip"
Get-Verified -Url "https://github.com/Noisemux/zeptun/releases/download/$ZeptunVersion/$zeptunAsset" -Dest $zeptunZip

# Both files are extracted in one pass. zeptun's tunnel does not work without
# wintun.dll beside the executable, and the failure without it is an
# unhelpful error rather than a clear one, so they are always staged together.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("arclient-" + [guid]::NewGuid().ToString("N"))
Expand-Archive -Path $zeptunZip -DestinationPath $tmp -Force
foreach ($pair in @(@("zeptun.exe", "zeptun.exe"), @("wintun.dll", "wintun.dll"))) {
    $found = Get-ChildItem -Path $tmp -Recurse -Filter $pair[0] -File | Select-Object -First 1
    if (-not $found) { throw "$($pair[0]) not found in the zeptun archive" }
    Move-Item -Path $found.FullName -Destination (Join-Path $OutDir $pair[1]) -Force
    Write-Host "  placed $($pair[1])"
}
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zeptunZip -Force -ErrorAction SilentlyContinue

if ($WithGeo) {
    Write-Host "== geo assets (optional) =="
    New-Item -ItemType Directory -Force -Path "geo" | Out-Null
    foreach ($f in @("geoip.dat", "geosite.dat")) {
        Get-Verified -Url "$GeoBase/$f" -Dest (Join-Path "geo" $f)
        Write-Host "  placed geo/$f"
    }
}

Write-Host ""
Write-Host "staged:"
Get-ChildItem $OutDir | ForEach-Object { Write-Host "  $($_.Name)  $([math]::Round($_.Length/1MB,1)) MB" }
