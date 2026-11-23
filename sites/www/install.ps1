# Install (or update) the jkbase CLI on Windows from its GitHub Releases.
#
#   irm https://jkbase.app/install.ps1 | iex
#
# Env: JKBASE_VERSION (e.g. 0.2.0), JKBASE_INSTALL_DIR (default: %LOCALAPPDATA%\jkbase\bin).
# Verifies the archive against the release's SHA256SUMS. Afterwards `jkbase upgrade` updates in place.
# Wrapped in a script block so nothing (variables, ErrorActionPreference) leaks into the caller's
# session under `iex`.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # PS 5.1's progress bar makes downloads crawl
    # Windows PowerShell 5.1 may default to TLS 1.0/1.1, which GitHub refuses.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'joeleaver/jkbase'
    $dir = if ($env:JKBASE_INSTALL_DIR) { $env:JKBASE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'jkbase\bin' }

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'jkbase-install: only 64-bit Windows is supported'
    }
    # One x86_64 build; Windows 11 on ARM64 runs it under emulation.
    $asset = 'jkbase-x86_64-pc-windows-msvc.tar.gz'
    if ($env:JKBASE_VERSION) {
        $v = $env:JKBASE_VERSION.TrimStart('v')
        if ($v -notmatch '^\d+\.\d+\.\d+$') { throw 'jkbase-install: JKBASE_VERSION must look like 0.2.0' }
        $base = "https://github.com/$repo/releases/download/cli-v$v"
    } else {
        $base = "https://github.com/$repo/releases/latest/download"
    }
    if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
        throw 'jkbase-install: needs tar.exe (built into Windows 10 1803 and later)'
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("jkbase-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "jkbase-install: downloading $asset"
        Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
        Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile "$tmp\$asset"
        $want = (Get-Content "$tmp\SHA256SUMS" | ForEach-Object {
            $f = $_.Trim() -split '\s+'; if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq $asset) { $f[0] }
        }) | Select-Object -First 1
        if (-not $want) { throw "jkbase-install: SHA256SUMS has no entry for $asset" }
        $got = (Get-FileHash -Algorithm SHA256 "$tmp\$asset").Hash
        if ($got -ne $want.ToUpperInvariant()) { throw "jkbase-install: checksum mismatch for $asset" }

        # Native commands don't throw on failure under PS 5.1: check exit codes explicitly.
        tar -xzf "$tmp\$asset" -C $tmp jkbase.exe
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$tmp\jkbase.exe")) { throw 'jkbase-install: could not extract jkbase.exe' }
        & "$tmp\jkbase.exe" --version | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "jkbase-install: the downloaded binary doesn't run here" }

        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dest = Join-Path $dir 'jkbase.exe'
        $old = "$dest.old"
        Remove-Item -Force $old -ErrorAction SilentlyContinue
        $hadOld = Test-Path $dest
        if ($hadOld) { Move-Item -Force $dest $old }
        try {
            Move-Item -Force "$tmp\jkbase.exe" $dest
        } catch {
            if ($hadOld) { Move-Item -Force $old $dest }  # never leave the user without jkbase.exe
            throw
        }
        Write-Host "jkbase-install: installed $(& $dest --version) to $dest"

        # Edit the user PATH via the registry WITHOUT expanding it, so %VAR% entries survive
        # (Environment.GetEnvironmentVariable returns the expanded string and SetEnvironmentVariable
        # would write it back as plain REG_SZ).
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        try {
            $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if (-not (($userPath -split ';') -contains $dir)) {
                $new = if ($userPath) { "$userPath;$dir" } else { $dir }
                $key.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                # Tell running shells/Explorer; a no-op set does the broadcast.
                [Environment]::SetEnvironmentVariable('JKBASE_PATH_REFRESH', $null, 'User')
                Write-Host "jkbase-install: added $dir to your user PATH (open a new terminal)"
            }
        } finally {
            $key.Close()
        }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
