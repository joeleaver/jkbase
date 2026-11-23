#!/bin/sh
# Install (or update) the jkbase CLI from its GitHub Releases.
#
#   curl -fsSL https://jkbase.app/install.sh | sh
#
# Env:
#   JKBASE_VERSION      install this version (e.g. 0.2.0) instead of the latest
#   JKBASE_INSTALL_DIR  where to put `jkbase` (default: ~/.local/bin)
#
# Verifies the archive against the release's SHA256SUMS before installing. Once installed,
# `jkbase upgrade` updates in place.
set -eu

REPO="joeleaver/jkbase"
DIR="${JKBASE_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'jkbase-install: %s\n' "$*"; }
die() { printf 'jkbase-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "needs '$1'"; }

need uname; need tar; need mkdir; need mktemp
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
"$staged" --version >/dev/null 2>&1 || die "the downloaded binary doesn't run here"
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
