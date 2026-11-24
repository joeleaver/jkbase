# Install (or update) the jkbase CLI on Windows from its GitHub Releases.
#
#   irm https://jkbase.app/install.ps1 | iex
#
# Env: JKBASE_VERSION (e.g. 0.2.0), JKBASE_INSTALL_DIR (default: %LOCALAPPDATA%\jkbase\bin).
# Before installing, verifies the release's SHA256SUMS.sig (an SSH signature by a jkbase release key,
# checked with Windows' built-in `ssh-keygen -Y verify`), then the archive against those signed
# SHA256SUMS. The version they're signed for must be the one asked for, or (for the latest) no
# older than what jkbase.app advertises, so an old signed release can't pass as current. Any
# failure stops the install. Afterwards `jkbase upgrade` updates in place.
# Wrapped in a script block so nothing (variables, ErrorActionPreference) leaks into the caller's
# session under `iex`.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # PS 5.1's progress bar makes downloads crawl
    # Windows PowerShell 5.1 may default to TLS 1.0/1.1, which GitHub refuses.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'joeleaver/jkbase'
    $cliInfo = 'https://api.jkbase.app/cli'
    # Release-signing keys, ssh-keygen allowed_signers format. MUST equal
    # crates/jkbase-cli/release-keys/allowed_signers (jkbase-cli's tests fail if they drift).
    # Rotation: docs/cli-release-signing.md.
    $allowedSigners = @'
jkbase-release namespaces="jkbase-cli-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIltN+xCwUnnTEwHjfpSXksIoOKqAq/mvXsuR79EMiG5 jkbase-cli-release-primary
jkbase-release namespaces="jkbase-cli-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXxp2r84eJ1MlJHvBoyE9/FMFR9U71zYXqP63fpcBW0 jkbase-cli-release-standby
'@
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
    $sshKeygen = Get-Command ssh-keygen -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $sshKeygen) {
        throw ('jkbase-install: needs ssh-keygen.exe (OpenSSH Client) to verify the release signature. ' +
            'Install it from Settings > System > Optional features > OpenSSH Client, or run (as admin) ' +
            "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -- then re-run")
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("jkbase-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "jkbase-install: downloading $asset"
        Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
        try {
            Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS.sig" -OutFile "$tmp\SHA256SUMS.sig"
        } catch {
            throw 'jkbase-install: the release has no SHA256SUMS.sig (signed releases start at 0.2.1)'
        }
        # Verify before reading a line of SHA256SUMS: everything below trusts only these signed
        # bytes. ssh-keygen reads the message on stdin; feed it the file's raw bytes (a PowerShell
        # pipe would re-encode them).
        [IO.File]::WriteAllText("$tmp\allowed_signers", ($allowedSigners -replace "`r", '') + "`n")
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $sshKeygen.Source
        $psi.Arguments = "-Y verify -f `"$tmp\allowed_signers`" -I jkbase-release -n jkbase-cli-release -s `"$tmp\SHA256SUMS.sig`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [Diagnostics.Process]::Start($psi)
        $errTask = $p.StandardError.ReadToEndAsync()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $sums = [IO.File]::ReadAllBytes("$tmp\SHA256SUMS")
        # An ssh-keygen without -Y exits before reading stdin; the exit code below reports that.
        try { $p.StandardInput.BaseStream.Write($sums, 0, $sums.Length); $p.StandardInput.Close() } catch { }
        $p.WaitForExit()
        $why = ($outTask.Result + $errTask.Result).Trim()
        if ($p.ExitCode -ne 0) {
            if ($why -match 'unknown option|illegal option|usage:') {
                throw ('jkbase-install: your ssh-keygen is too old to verify signatures (needs OpenSSH 8.1+). ' +
                    'Update it with: winget install Microsoft.OpenSSH.Preview -- or put Git for Windows ssh-keygen first on PATH')
            }
            throw "jkbase-install: release signature verification FAILED - not installing ($why)"
        }
        $signed = (Get-Content "$tmp\SHA256SUMS" | ForEach-Object {
            $f = $_.Trim() -split '\s+'; if ($f.Count -eq 3 -and $f[0] -eq '#' -and $f[1] -eq 'jkbase-cli') { $f[2] }
        }) | Select-Object -First 1
        if ($signed -notmatch '^\d+\.\d+\.\d+$') { throw 'jkbase-install: the signed SHA256SUMS names no jkbase-cli version - not installing' }
        if ($env:JKBASE_VERSION) {
            if ($signed -ne $v) { throw "jkbase-install: asked for $v but the release is signed as $signed - not installing" }
        } else {
            # Rollback guard, from a second origin: the release host can't make an old (genuinely
            # signed) build look current unless jkbase.app agrees.
            try { Invoke-WebRequest -UseBasicParsing $cliInfo -OutFile "$tmp\cli" } catch {
                throw "jkbase-install: can't reach $cliInfo to confirm the latest version"
            }
            $latest = (Get-Content -Raw "$tmp\cli" | ConvertFrom-Json).latest
            if ($latest -notmatch '^\d+\.\d+\.\d+$') { throw "jkbase-install: unexpected answer from $cliInfo" }
            if ([version]$signed -lt [version]$latest) {
                throw "jkbase-install: the release is $signed but $latest is current - refusing an old release"
            }
        }
        Write-Host "jkbase-install: release signature OK (jkbase $signed)"
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
        $got = & "$tmp\jkbase.exe" --version
        if ($LASTEXITCODE -ne 0) { throw "jkbase-install: the downloaded binary doesn't run here" }
        if ("$got".Trim() -ne "jkbase $signed") { throw "jkbase-install: the downloaded binary reports '$got', expected jkbase $signed" }

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
