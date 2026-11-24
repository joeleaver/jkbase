#!/bin/sh
# Install (or update) the jkbase CLI from its GitHub Releases.
#
#   curl -fsSL https://jkbase.app/install.sh | sh
#
# Env:
#   JKBASE_VERSION      install this version (e.g. 0.2.0) instead of the latest
#   JKBASE_INSTALL_DIR  where to put `jkbase` (default: ~/.local/bin)
#
# Before installing, verifies the release's SHA256SUMS.sig (an SSH signature by a jkbase release
# key, checked with `ssh-keygen -Y verify`), then the archive against those signed SHA256SUMS. The
# version they're signed for must be the one asked for, or (for the latest) no older than what
# jkbase.app advertises, so an old signed release can't be passed off as current. Any failure
# stops the install. Once installed, `jkbase upgrade` updates in place.
set -eu

REPO="joeleaver/jkbase"
CLI_INFO="https://api.jkbase.app/cli"
# Release-signing keys, ssh-keygen allowed_signers format. MUST equal
# crates/jkbase-cli/release-keys/allowed_signers (jkbase-cli's tests fail if they drift).
# Rotation: docs/cli-release-signing.md.
ALLOWED_SIGNERS='
jkbase-release namespaces="jkbase-cli-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIltN+xCwUnnTEwHjfpSXksIoOKqAq/mvXsuR79EMiG5 jkbase-cli-release-primary
jkbase-release namespaces="jkbase-cli-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXxp2r84eJ1MlJHvBoyE9/FMFR9U71zYXqP63fpcBW0 jkbase-cli-release-standby
'
DIR="${JKBASE_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'jkbase-install: %s\n' "$*"; }
die() { printf 'jkbase-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "needs '$1'"; }
# ver_ge A B: dotted version A >= B.
ver_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, "."); split(b, y, ".")
        for (i = 1; i <= 3; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 }
        exit 0 }'
}
isver() { case "$1" in "" | *[!0-9.]* | *..* | .* | *.) return 1 ;; *.*.*.*) return 1 ;; *.*.*) return 0 ;; *) return 1 ;; esac; }

need uname; need tar; need mkdir; need mktemp; need awk; need sed
command -v ssh-keygen >/dev/null 2>&1 || die "needs ssh-keygen (OpenSSH 8.1+) to verify the release \
signature — install it (Debian/Ubuntu: apt-get install openssh-client; Alpine: apk add openssh-keygen; \
Fedora: dnf install openssh) and re-run"
if command -v curl >/dev/null 2>&1; then
    get() { curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    # busybox wget (Alpine's default) has no --https-only; every URL here is https:// anyway.
    if wget --help 2>&1 | grep -q -- --https-only; then
        get() { wget -q --https-only "$1" -O "$2"; }
    else
        get() { wget -q "$1" -O "$2"; }
    fi
else
    die "needs curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
    sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "needs sha256sum or shasum"
fi

case "$(uname -s)" in
    Linux) os=unknown-linux-musl ;;
    Darwin) os=apple-darwin ;;
    *) die "unsupported OS $(uname -s) — on Windows use: irm https://jkbase.app/install.ps1 | iex" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "unsupported CPU $(uname -m)" ;;
esac
# An x86_64 shell under Rosetta still gets the native arm64 build.
if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] \
    && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    arch=aarch64
fi
target="$arch-$os"
asset="jkbase-$target.tar.gz"

if [ -n "${JKBASE_VERSION:-}" ]; then
    v="${JKBASE_VERSION#v}"
    case "$v" in *[!0-9.]* | "") die "JKBASE_VERSION must look like 0.2.0" ;; esac
    base="https://github.com/$REPO/releases/download/cli-v$v"
else
    base="https://github.com/$REPO/releases/latest/download"
fi

tmp="$(mktemp -d)"
staged=""
trap 'rm -rf "$tmp"; [ -z "$staged" ] || rm -f "$staged"' EXIT
trap 'exit 130' INT TERM

say "downloading $asset"
get "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "no release found at $base"
get "$base/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" || die "the release has no SHA256SUMS.sig (signed releases start at 0.2.1)"
# Verify before reading a line of SHA256SUMS: everything below trusts only these signed bytes.
printf '%s\n' "$ALLOWED_SIGNERS" >"$tmp/allowed_signers"
if ! out="$(ssh-keygen -Y verify -f "$tmp/allowed_signers" -I jkbase-release -n jkbase-cli-release \
    -s "$tmp/SHA256SUMS.sig" <"$tmp/SHA256SUMS" 2>&1)"; then
    case "$out" in
        *"unknown option"* | *"illegal option"* | *"usage:"*)
            die "your ssh-keygen is too old to verify signatures (needs OpenSSH 8.1+)" ;;
    esac
    die "release signature verification FAILED — not installing ($out)"
fi
signed="$(awk '$1 == "#" && $2 == "jkbase-cli" { print $3; exit }' "$tmp/SHA256SUMS")"
isver "$signed" || die "the signed SHA256SUMS names no jkbase-cli version — not installing"
if [ -n "${JKBASE_VERSION:-}" ]; then
    [ "$signed" = "$v" ] || die "asked for $v but the release is signed as $signed — not installing"
else
    # Rollback guard, from a second origin: the release host can't make an old (genuinely
    # signed) build look current unless jkbase.app agrees.
    get "$CLI_INFO" "$tmp/cli" || die "can't reach $CLI_INFO to confirm the latest version"
    latest="$(sed -n 's/.*"latest"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\1/p' "$tmp/cli")"
    isver "$latest" || die "unexpected answer from $CLI_INFO"
    ver_ge "$signed" "$latest" || die "the release is $signed but $latest is current — refusing an old release"
fi
say "release signature OK (jkbase $signed)"
get "$base/$asset" "$tmp/$asset" || die "no $target build in that release"
want="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no entry for $asset"
[ "$(sha "$tmp/$asset")" = "$want" ] || die "checksum mismatch for $asset"

tar -xzf "$tmp/$asset" -C "$tmp" jkbase
[ -f "$tmp/jkbase" ] || die "archive has no jkbase binary"

# Stage beside the destination, then rename: same filesystem, so the swap is atomic and an
# interrupted install never leaves a missing or truncated jkbase. (Also sidesteps a noexec /tmp
# for the run check below.)
mkdir -p "$DIR"
staged="$(mktemp "$DIR/.jkbase.XXXXXX")"
cp "$tmp/jkbase" "$staged"
chmod 755 "$staged"
got="$("$staged" --version 2>/dev/null)" || die "the downloaded binary doesn't run here"
[ "$got" = "jkbase $signed" ] || die "the downloaded binary reports '$got', expected jkbase $signed"
mv -f "$staged" "$DIR/jkbase"
staged=""
say "installed $("$DIR/jkbase" --version) to $DIR/jkbase"

case ":$PATH:" in
    *":$DIR:"*) ;;
    *) say "add $DIR to your PATH, e.g.: echo 'export PATH=\"$DIR:\$PATH\"' >> ~/.profile" ;;
esac
other="$(command -v jkbase 2>/dev/null || true)"
if [ -n "$other" ] && [ "$other" != "$DIR/jkbase" ]; then
    say "note: another jkbase at $other comes first on your PATH — remove it (e.g. cargo uninstall jkbase-cli)"
fi
