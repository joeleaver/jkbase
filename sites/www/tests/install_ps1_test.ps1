# Tests install.ps1's release verification end to end on Windows against a local fake release:
# Invoke-WebRequest is shadowed by a function serving files from a directory, the release is
# signed with throwaway keys made here, and install.ps1's embedded $allowedSigners is swapped for
# those keys (the real block is pinned to release-keys/allowed_signers by jkbase-cli's tests).
# Needs ssh-keygen (Windows OpenSSH Client) and a real jkbase.exe to package.
#
#   pwsh sites/www/tests/install_ps1_test.ps1 -Exe target\x86_64-pc-windows-msvc\release\jkbase.exe
param([Parameter(Mandatory = $true)][string]$Exe)
$ErrorActionPreference = 'Stop'

$script = Get-Content -Raw (Join-Path $PSScriptRoot '..\install.ps1')
$work = Join-Path ([IO.Path]::GetTempPath()) ("jkbase-ps1-test-" + [Guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
$asset = 'jkbase-x86_64-pc-windows-msvc.tar.gz'
$fails = 0

function Keygen([string]$cmdline) {
    # cmd.exe for the empty -N "" and the stdin redirect: PowerShell's native-argument passing
    # differs between versions on exactly those.
    cmd /c "ssh-keygen $cmdline < NUL"
    if ($LASTEXITCODE -ne 0) { throw "ssh-keygen $cmdline failed" }
}
foreach ($k in 'primary', 'standby', 'rogue') { Keygen "-q -t ed25519 -N `"`" -C $k -f `"$work\$k`"" }
function Signer($k) { "jkbase-release namespaces=`"jkbase-cli-release`" " + (Get-Content -Raw "$work\$k.pub").Trim() }

# install.ps1 with its key block replaced by $keys.
function ScriptWith([string]$keys) {
    $open = "`$allowedSigners = @'"
    $i = $script.IndexOf($open)
    $j = $script.IndexOf("'@", $i)
    if ($i -lt 0 -or $j -lt 0) { throw 'could not find $allowedSigners block' }
    $body = if ($keys) { "`n$keys`n" } else { "`n" }
    [ScriptBlock]::Create($script.Substring(0, $i + $open.Length) + $body + $script.Substring($j))
}
$trusted = ScriptWith ((Signer 'primary') + "`n" + (Signer 'standby'))
$noKeys = ScriptWith ''

# Shadows the cmdlet for the script under test: copies $FakeRelease\<last URL segment>, or fails.
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [Parameter(Position = 0)][string]$Uri, [string]$OutFile)
    $src = Join-Path $global:FakeRelease ($Uri -split '/')[-1]
    if (-not (Test-Path $src)) { throw "404 $Uri" }
    Copy-Item $src $OutFile
}

function MakeRelease([string]$dir, [string]$key, [string]$ns = 'jkbase-cli-release', [switch]$Extra) {
    $stage = "$dir\stage"
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item $Exe "$stage\jkbase.exe"
    $files = @('jkbase.exe')
    if ($Extra) { Set-Content "$stage\EXTRA" 'different archive'; $files += 'EXTRA' }
    tar -C $stage -czf "$dir\$asset" @files
    if ($LASTEXITCODE -ne 0) { throw 'tar failed' }
    Remove-Item -Recurse -Force $stage
    $h = (Get-FileHash -Algorithm SHA256 "$dir\$asset").Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$dir\SHA256SUMS", "$h  $asset`n")
    Remove-Item -Force "$dir\SHA256SUMS.sig" -ErrorAction SilentlyContinue
    Keygen "-q -Y sign -f `"$work\$key`" -n $ns `"$dir\SHA256SUMS`""
}

function Run([string]$name, [string]$expect, [string]$rel, $sb = $trusted, [string]$path = $env:PATH, [string]$want = '') {
    $dir = "$work\dest-$name"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Set-Content "$dir\jkbase.exe" 'old'
    $global:FakeRelease = $rel
    $env:JKBASE_INSTALL_DIR = $dir
    $savedPath = $env:PATH
    $env:PATH = $path
    try { $out = (& $sb *>&1 | Out-String); $got = 'ok' }
    catch { $out = $_.Exception.Message; $got = 'fail' }
    finally { $env:PATH = $savedPath }
    $problem = $null
    if ($got -ne $expect) { $problem = "expected $expect, got $got" }
    elseif ($expect -eq 'ok') {
        $v = & "$dir\jkbase.exe" --version
        if ($v -notmatch '^jkbase \d') { $problem = "new binary not installed ($v)" }
        elseif ($out -notmatch 'release signature OK') { $problem = 'no signature OK line' }
    } elseif ((Get-Content -Raw "$dir\jkbase.exe").Trim() -ne 'old') {
        $problem = 'a failed install replaced the existing binary'
    }
    if (-not $problem -and $want -and $out -notmatch [regex]::Escape($want)) { $problem = "output lacks '$want'" }
    if ($problem) { Write-Host "FAIL $name`: $problem`n    $out"; $script:fails++ } else { Write-Host "ok   $name" }
}

try {
    $r = "$work\rel-good"; MakeRelease $r 'primary'
    Run 'good' 'ok' $r

    $r = "$work\rel-standby"; MakeRelease $r 'standby'
    Run 'signed-by-standby-key' 'ok' $r

    $r = "$work\rel-nosig"; MakeRelease $r 'primary'; Remove-Item "$r\SHA256SUMS.sig"
    Run 'missing-signature' 'fail' $r -want 'no SHA256SUMS.sig'

    $r = "$work\rel-rogue"; MakeRelease $r 'rogue'
    Run 'untrusted-key' 'fail' $r -want 'signature verification FAILED'

    $r = "$work\rel-ns"; MakeRelease $r 'primary' 'file'
    Run 'wrong-namespace' 'fail' $r -want 'signature verification FAILED'

    # Archive swapped and SHA256SUMS rewritten to match, old signature kept.
    $r = "$work\rel-swap"; MakeRelease $r 'primary'
    $sig = [IO.File]::ReadAllBytes("$r\SHA256SUMS.sig"); $before = Get-Content -Raw "$r\SHA256SUMS"
    MakeRelease $r 'rogue' -Extra; [IO.File]::WriteAllBytes("$r\SHA256SUMS.sig", $sig)
    if ((Get-Content -Raw "$r\SHA256SUMS") -eq $before) { throw 'test setup: SHA256SUMS unchanged' }
    Run 'tampered-sums' 'fail' $r -want 'signature verification FAILED'

    # Archive swapped, signed SHA256SUMS left alone: the checksum catches it.
    $r = "$work\rel-archive"; MakeRelease $r 'primary'
    New-Item -ItemType Directory "$r\x" | Out-Null; Set-Content "$r\x\jkbase.exe" 'evil'
    tar -C "$r\x" -czf "$r\$asset" jkbase.exe
    Run 'tampered-archive' 'fail' $r -want 'checksum mismatch'

    Run 'no-trusted-keys' 'fail' "$work\rel-good" $noKeys -want 'signature verification FAILED'

    # System32 has tar.exe but not ssh-keygen (that lives in System32\OpenSSH).
    $sys = [Environment]::SystemDirectory
    if (Test-Path "$sys\ssh-keygen.exe") { throw "test setup: ssh-keygen in $sys" }
    Run 'no-ssh-keygen' 'fail' "$work\rel-good" $trusted "$sys;$PSHOME" -want 'needs ssh-keygen'
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
if ($fails -ne 0) { Write-Host "$fails install.ps1 test(s) failed"; exit 1 }
Write-Host 'all install.ps1 tests passed'
