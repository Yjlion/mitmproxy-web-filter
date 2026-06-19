<#
.SYNOPSIS
    Download and (re)populate the shared site categories from the IPFire squidguard blocklist.
    PowerShell port of scripts/update_categories.sh. Safe to run repeatedly (e.g. from Task Scheduler).

.PARAMETER Url
    Override the source URL (default: IPFire squidguard.tar.gz).

.PARAMETER Keep
    Comma-separated category whitelist (default: all).

.PARAMETER Quiet
    Suppress progress output.

.EXAMPLE
    scripts\update_categories.ps1
    scripts\update_categories.ps1 -Keep "porn,gambling,ads" -Quiet
#>
param(
    [string]$Url  = "https://dbl.ipfire.org/lists/squidguard.tar.gz",
    [string]$Keep = "",
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    if (-not $Quiet) { Write-Host $Message }
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

# Resolve repo root (parent of the scripts/ directory).
$ScriptDir = $PSScriptRoot
$Root      = Split-Path $ScriptDir -Parent
$Dest      = Join-Path $Root "categories"

# Work in a temp directory; clean up on exit.
$Tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $Tmp | Out-Null

try {
    $Archive = Join-Path $Tmp "list.tar.gz"

    Write-Log "[categories] downloading $Url"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing

    Write-Log "[categories] extracting"
    # tar.exe ships with Windows 10+ (bsdtar). Extract into $Tmp.
    & tar -xzf $Archive -C $Tmp
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed (exit $LASTEXITCODE)" }

    # Find the directory that holds per-category subdirectories.
    # Prefer a "blacklists" subdir; fall back to the first dir containing */domains.
    $Src = $null
    $BlacklistsCandidate = Join-Path $Tmp "blacklists"
    if (Test-Path $BlacklistsCandidate) {
        $hasDomains = Get-ChildItem -Path $BlacklistsCandidate -Recurse -Filter "domains" -ErrorAction SilentlyContinue |
                      Where-Object { $_.Directory.Parent.FullName -eq $BlacklistsCandidate }
        if ($hasDomains) { $Src = $BlacklistsCandidate }
    }
    if (-not $Src) {
        foreach ($dir in Get-ChildItem -Path $Tmp -Directory) {
            $domainFiles = Get-ChildItem -Path $dir.FullName -Recurse -Filter "domains" -ErrorAction SilentlyContinue
            if ($domainFiles) { $Src = $dir.FullName; break }
        }
    }
    if (-not $Src) { throw "[categories] no */domains found in archive" }

    # Build into a staging directory, then swap in.
    $Stage = Join-Path $Tmp "stage"
    New-Item -ItemType Directory -Path $Stage | Out-Null

    $Updated   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $IndexItems = [System.Collections.Generic.List[string]]::new()

    # Parse $Keep into a set (empty = all categories).
    $KeepSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Keep.Trim()) {
        foreach ($k in $Keep.Split(',')) {
            $trimmed = $k.Trim()
            if ($trimmed) { [void]$KeepSet.Add($trimmed) }
        }
    }

    foreach ($CatDir in Get-ChildItem -Path $Src -Directory) {
        $Name        = $CatDir.Name
        $DomainsFile = Join-Path $CatDir.FullName "domains"

        if (-not (Test-Path $DomainsFile)) { continue }
        if ($KeepSet.Count -gt 0 -and -not $KeepSet.Contains($Name)) { continue }

        $StageDir = Join-Path $Stage $Name
        New-Item -ItemType Directory -Path $StageDir | Out-Null

        # Read, strip comments/blank lines, lowercase, strip \r, dedupe, sort.
        $Lines = [System.IO.File]::ReadAllLines($DomainsFile) |
                 Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } |
                 ForEach-Object { $_.Trim().ToLowerInvariant().TrimEnd("`r") } |
                 Where-Object { $_ -ne '' } |
                 Sort-Object -Unique

        $OutPath = Join-Path $StageDir "domains"
        Write-Utf8NoBom -Path $OutPath -Content ($Lines -join "`n")

        $Count = $Lines.Count
        $IndexItems.Add("{`"name`":`"$Name`",`"count`":$Count,`"updated`":`"$Updated`"}")
        Write-Log ("[categories] {0,-12} {1,8} domains" -f $Name, $Count)
    }

    if ($IndexItems.Count -eq 0) { throw "[categories] nothing populated" }

    # Build index.json (UTF-8 no BOM).
    $CatsJson  = $IndexItems -join ","
    $IndexJson = "{`n  `"source`": `"$Url`",`n  `"updated`": `"$Updated`",`n  `"categories`": [$CatsJson]`n}`n"
    Write-Utf8NoBom -Path (Join-Path $Stage "index.json") -Content $IndexJson

    # Swap: move new category dirs + index.json into $Dest (replace existing).
    if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Path $Dest | Out-Null }

    foreach ($StageSubDir in Get-ChildItem -Path $Stage -Directory) {
        $TargetDir = Join-Path $Dest $StageSubDir.Name
        if (Test-Path $TargetDir) { Remove-Item -Recurse -Force $TargetDir }
        Move-Item -Path $StageSubDir.FullName -Destination $TargetDir
    }
    $StagedIndex  = Join-Path $Stage "index.json"
    $DestIndex    = Join-Path $Dest "index.json"
    if (Test-Path $DestIndex) { Remove-Item -Force $DestIndex }
    Move-Item -Path $StagedIndex -Destination $DestIndex

    Write-Log "[categories] done -> $Dest"

} finally {
    if (Test-Path $Tmp) { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
}
