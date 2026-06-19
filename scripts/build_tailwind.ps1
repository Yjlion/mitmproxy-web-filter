# build_tailwind.ps1 — Regenerate management/ui/tailwind.css using the Tailwind v3 standalone binary.
# Run from the repo root. Idempotent: skips re-download if the binary is already cached.

param()
$ErrorActionPreference = "Stop"

$version = "v3.4.17"
$binPath = "$env:TEMP\tailwindcss-v3.exe"
$url     = "https://github.com/tailwindlabs/tailwindcss/releases/download/$version/tailwindcss-windows-x64.exe"

if (-not (Test-Path $binPath)) {
    Write-Host "Downloading Tailwind CSS standalone binary $version ..."
    Invoke-WebRequest -Uri $url -OutFile $binPath -UseBasicParsing
    Write-Host "Download complete."
} else {
    Write-Host "Tailwind binary already cached at $binPath"
}

Write-Host "Building management/ui/tailwind.css ..."
& $binPath `
    -c management/ui/tailwind.config.js `
    -i management/ui/tailwind.input.css `
    -o management/ui/tailwind.css `
    --minify

if ($LASTEXITCODE -ne 0) {
    Write-Error "Tailwind build failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

$size = (Get-Item "management/ui/tailwind.css").Length
Write-Host "Done. management/ui/tailwind.css regenerated ($size bytes)."
