# Install (or update) the jkbase CLI on Windows from its GitHub Releases.
#
#   irm https://jkbase.app/install.ps1 | iex
#
# Env: JKBASE_VERSION (e.g. 0.2.0), JKBASE_INSTALL_DIR (default: %LOCALAPPDATA%\jkbase\bin).
# Verifies the archive against the release's SHA256SUMS. Afterwards `jkbase upgrade` updates in place.
$ErrorActionPreference = 'Stop'
$repo = 'joeleaver/jkbase'
$dir = if ($env:JKBASE_INSTALL_DIR) { $env:JKBASE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'jkbase\bin' }

if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    throw 'jkbase-install: only x86_64 Windows builds are published'
}
$asset = 'jkbase-x86_64-pc-windows-msvc.tar.gz'
if ($env:JKBASE_VERSION) {
    $v = $env:JKBASE_VERSION.TrimStart('v')
    if ($v -notmatch '^\d+\.\d+\.\d+$') { throw 'jkbase-install: JKBASE_VERSION must look like 0.2.0' }
    $base = "https://github.com/$repo/releases/download/cli-v$v"
} else {
    $base = "https://github.com/$repo/releases/latest/download"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("jkbase-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "jkbase-install: downloading $asset"
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile "$tmp\$asset"
    $want = (Get-Content "$tmp\SHA256SUMS" | ForEach-Object {
        $f = $_ -split '\s+'; if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq $asset) { $f[0] }
    }) | Select-Object -First 1
    if (-not $want) { throw "jkbase-install: SHA256SUMS has no entry for $asset" }
    $got = (Get-FileHash -Algorithm SHA256 "$tmp\$asset").Hash
    if ($got -ne $want.ToUpper()) { throw "jkbase-install: checksum mismatch for $asset" }

    tar -xzf "$tmp\$asset" -C $tmp jkbase.exe
    & "$tmp\jkbase.exe" --version | Out-Null

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $dest = Join-Path $dir 'jkbase.exe'
    if (Test-Path $dest) { Move-Item -Force $dest "$dest.old" }
    Move-Item -Force "$tmp\jkbase.exe" $dest
    Write-Host "jkbase-install: installed $(& $dest --version) to $dest"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $dir)) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
        Write-Host "jkbase-install: added $dir to your user PATH (open a new terminal)"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
