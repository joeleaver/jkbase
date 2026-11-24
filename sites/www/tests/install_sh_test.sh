#!/bin/sh
# Tests install.sh's release verification end to end against a local fake release: a stub `curl`
# (or `wget`) on PATH serves files from a directory, the release is signed with throwaway keys
# made here, and a copy of install.sh has its embedded ALLOWED_SIGNERS swapped for those keys (the
# real block is pinned to release-keys/allowed_signers by jkbase-cli's tests). Needs ssh-keygen
# (OpenSSH 8.1+).
#
#   sh sites/www/tests/install_sh_test.sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0

case "$(uname -s)" in Linux) os=unknown-linux-musl ;; Darwin) os=apple-darwin ;; esac
case "$(uname -m)" in x86_64 | amd64) arch=x86_64 ;; aarch64 | arm64) arch=aarch64 ;; esac
if [ "$os" = apple-darwin ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    arch=aarch64
fi
asset="jkbase-$arch-$os.tar.gz"

# Keys: primary + standby (both trusted), and one nobody trusts.
for k in primary standby rogue; do
    ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$work/$k" </dev/null
done
signer() { printf 'jkbase-release namespaces="jkbase-cli-release" %s\n' "$(cat "$work/$1.pub")"; }

# install.sh with its key block replaced by the given allowed_signers lines.
script_with() { # <out> <lines>
    # Keys via the environment: BSD awk rejects a newline in a -v value.
    KEYS="$2" awk '
        $0 == "ALLOWED_SIGNERS='\''" { print; if (ENVIRON["KEYS"] != "") print ENVIRON["KEYS"]; skip = 1; next }
        skip && $0 == "'\''" { skip = 0 }
        !skip { print }
    ' "$script" >"$1"
    grep -q "^ALLOWED_SIGNERS='" "$1" || { echo "could not find ALLOWED_SIGNERS block" >&2; exit 1; }
}
trusted="$(signer primary)
$(signer standby)"
script_with "$work/install.sh" "$trusted"
script_with "$work/install-nokeys.sh" ""

# Stubs serve $RELEASE/<last URL segment> (so .../cli is the /cli answer), or fail like -f does.
mkdir -p "$work/bin" "$work/wgetbin"
cat >"$work/bin/curl" <<'EOF'
#!/bin/sh
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in -o) out="$2"; shift ;; https://*) url="$1" ;; esac
    shift
done
f="$RELEASE/${url##*/}"
[ -f "$f" ] || exit 22
cp "$f" "$out"
EOF
cat >"$work/wgetbin/wget" <<'EOF'
#!/bin/sh
[ "$1" = --help ] && { echo "  --https-only"; exit 0; }
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in -O) out="$2"; shift ;; https://*) url="$1" ;; esac
    shift
done
f="$RELEASE/${url##*/}"
[ -f "$f" ] || exit 8
cp "$f" "$out"
EOF
chmod +x "$work/bin/curl" "$work/wgetbin/wget"

# A release: archive with a stub binary reporting <binver>, SHA256SUMS naming <version> (or no
# version line if it's "-"), signed by <key> under <namespace>; plus the /cli answer <latest>.
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
make_release() { # <dir> <key> [namespace] [version] [binver] [latest]
    ver="${4:-9.9.9}"
    mkdir -p "$1/stage"
    printf '#!/bin/sh\necho "jkbase %s"\n' "${5:-$ver}" >"$1/stage/jkbase"
    chmod +x "$1/stage/jkbase"
    tar -C "$1/stage" -czf "$1/$asset" jkbase
    rm -rf "$1/stage"
    { [ "$ver" = - ] || printf '# jkbase-cli %s\n' "$ver"; printf '%s  %s\n' "$(sha "$1/$asset")" "$asset"; } >"$1/SHA256SUMS"
    printf '{"latest":"%s","minimum":"0.1.0"}\n' "${6:-9.9.9}" >"$1/cli"
    rm -f "$1/SHA256SUMS.sig" # -Y sign would prompt to overwrite
    ssh-keygen -q -Y sign -f "$work/$2" -n "${3:-jkbase-cli-release}" "$1/SHA256SUMS" </dev/null
}

# run <name> <expect: ok|fail> <release dir> [script] [PATH] [JKBASE_VERSION] — fresh install
# dir holding an old jkbase; a failure must leave that old binary untouched.
run() {
    name="$1"; expect="$2"; rel="$3"; s="${4:-$work/install.sh}"; p="${5:-$work/bin:$PATH}"; pin="${6:-}"
    dir="$work/dest-$name"
    mkdir -p "$dir"
    printf 'old\n' >"$dir/jkbase"
    if RELEASE="$rel" JKBASE_INSTALL_DIR="$dir" JKBASE_VERSION="$pin" PATH="$p" sh "$s" >"$work/out-$name" 2>&1 </dev/null
    then got=ok; else got=fail; fi
    if [ "$got" != "$expect" ]; then
        echo "FAIL $name: expected $expect, got $got"; sed 's/^/    /' "$work/out-$name"; fails=$((fails + 1)); return
    fi
    if [ "$expect" = ok ]; then
        "$dir/jkbase" --version | grep -q "^jkbase [0-9]" \
            || { echo "FAIL $name: new binary not installed"; fails=$((fails + 1)); return; }
        grep -q "release signature OK" "$work/out-$name" \
            || { echo "FAIL $name: no signature OK line"; fails=$((fails + 1)); return; }
    elif [ "$(cat "$dir/jkbase")" != old ]; then
        echo "FAIL $name: a failed install replaced the existing binary"; fails=$((fails + 1)); return
    fi
    echo "ok   $name"
}
expect_output() { # <name> <substring>
    grep -q -- "$2" "$work/out-$1" || { echo "FAIL $1: output lacks '$2'"; sed 's/^/    /' "$work/out-$1"; fails=$((fails + 1)); }
}
# A PATH holding only the tools install.sh uses, plus the given extra dirs' contents.
farm() { # <dir> <include ssh-keygen: yes|no> [extra bin dir...]
    d="$1"; kg="$2"; shift 2
    mkdir -p "$d"
    for t in sh uname tar mkdir mktemp awk cut rm cp chmod mv cat grep sed gzip sha256sum shasum sysctl; do
        p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$d/$t"
    done
    [ "$kg" = no ] || ln -sf "$(command -v ssh-keygen)" "$d/ssh-keygen"
    for x in "$@"; do for f in "$x"/*; do ln -sf "$f" "$d/${f##*/}"; done; done
}

r="$work/rel-good"; make_release "$r" primary
run good ok "$r"
run pinned-version ok "$r" "" "" 9.9.9

r="$work/rel-standby"; make_release "$r" standby
run signed-by-standby-key ok "$r"

# Released but jkbase.app not redeployed yet: newer than advertised is fine.
r="$work/rel-ahead"; make_release "$r" primary "" 9.9.10 "" 9.9.9
run newer-than-advertised ok "$r"

r="$work/rel-nosig"; make_release "$r" primary; rm "$r/SHA256SUMS.sig"
run missing-signature fail "$r"; expect_output missing-signature "no SHA256SUMS.sig"

r="$work/rel-rogue"; make_release "$r" rogue
run untrusted-key fail "$r"; expect_output untrusted-key "signature verification FAILED"

r="$work/rel-ns"; make_release "$r" primary file
run wrong-namespace fail "$r"; expect_output wrong-namespace "signature verification FAILED"

# Attacker swaps the archive and rewrites SHA256SUMS to match, keeping the old signature.
r="$work/rel-swap"; make_release "$r" primary
sig="$(cat "$r/SHA256SUMS.sig")"; before="$(cat "$r/SHA256SUMS")"
make_release "$r" rogue jkbase-cli-release 6.6.6; printf '%s\n' "$sig" >"$r/SHA256SUMS.sig"
[ "$(cat "$r/SHA256SUMS")" != "$before" ] || { echo "test setup: SHA256SUMS unchanged" >&2; exit 1; }
run tampered-sums fail "$r"; expect_output tampered-sums "signature verification FAILED"

# Archive swapped, SHA256SUMS (signed) left alone: the checksum catches it.
r="$work/rel-archive"; make_release "$r" primary
mkdir "$r/x"; printf 'evil\n' >"$r/x/jkbase"; tar -C "$r/x" -czf "$r/$asset" jkbase
run tampered-archive fail "$r"; expect_output tampered-archive "checksum mismatch"

# Rollback: an old, genuinely signed release served as the latest / as a pinned newer version.
r="$work/rel-old"; make_release "$r" primary "" 1.0.0 "" 9.9.9
run rollback-latest fail "$r"; expect_output rollback-latest "refusing an old release"
run rollback-pinned fail "$r" "" "" 9.9.9; expect_output rollback-pinned "signed as 1.0.0"

r="$work/rel-nover"; make_release "$r" primary "" -
run no-version-line fail "$r"; expect_output no-version-line "names no jkbase-cli version"

r="$work/rel-binver"; make_release "$r" primary "" 9.9.9 9.9.8
run binary-version-mismatch fail "$r"; expect_output binary-version-mismatch "expected jkbase 9.9.9"

r="$work/rel-noapi"; make_release "$r" primary; rm "$r/cli"
run cli-info-unreachable fail "$r"; expect_output cli-info-unreachable "can't reach"

r="$work/rel-good"
run no-trusted-keys fail "$r" "$work/install-nokeys.sh"; expect_output no-trusted-keys "signature verification FAILED"

farm "$work/nokeygen" no "$work/bin"
run no-ssh-keygen fail "$r" "$work/install.sh" "$work/nokeygen"; expect_output no-ssh-keygen "needs ssh-keygen"

# OpenSSH < 8.1: no -Y.
mkdir -p "$work/oldkg"
printf '#!/bin/sh\necho "unknown option -- Y" >&2\necho "usage: ssh-keygen [-q] [-b bits]" >&2\nexit 1\n' >"$work/oldkg/ssh-keygen"
chmod +x "$work/oldkg/ssh-keygen"
farm "$work/oldpath" no "$work/bin" "$work/oldkg"
run old-ssh-keygen fail "$r" "$work/install.sh" "$work/oldpath"; expect_output old-ssh-keygen "too old"

# No curl: the wget path (busybox-style environments).
farm "$work/wgetpath" yes "$work/wgetbin"
run wget-download ok "$r" "$work/install.sh" "$work/wgetpath"

if [ "$fails" -ne 0 ]; then echo "$fails install.sh test(s) failed"; exit 1; fi
echo "all install.sh tests passed"
