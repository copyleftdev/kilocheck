param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$Target
)

$ErrorActionPreference = "Stop"
$name = "kilo-$Tag-$Target"
$archive = "$name.zip"
$binary = "target/$Target/release/kilo.exe"
$stage = Join-Path $env:RUNNER_TEMP $name

if (-not (Test-Path $binary -PathType Leaf)) {
    throw "release binary is missing: $binary"
}

New-Item -ItemType Directory -Force -Path "dist", $stage | Out-Null
Copy-Item $binary, "LICENSE", "README.md" -Destination $stage
Compress-Archive -Path $stage -DestinationPath "dist/$archive" -Force
$hash = (Get-FileHash "dist/$archive" -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $archive" | Set-Content "dist/$archive.sha256" -Encoding ascii
