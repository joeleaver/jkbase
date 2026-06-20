#!/usr/bin/env bash
# Assemble a build-VM toolchain ext4 from an apko Wolfi image (WS2).
#
# apko gives us a reproducible glibc rootfs (an OCI/docker-archive tar). We then
# inject the bits apko can't: the static musl jkbuild-init as /sbin/init (the
# in-VM lifecycle), the baked bun binary, busybox applet symlinks the lifecycle
# shells out to, and the mountpoint dirs (the root boots read-only, so they must
# pre-exist). Finally mkfs.ext4 -d into the image — userspace, no mount (P0-3),
# matching tools/build-toolchain.sh / build_image.rs.
#
# Usage: tools/build-image.sh [--config images/apko/build-bun.apko.yaml] [--out PATH]
#
# INJECT_BUN=1 (default) bakes the bun binary at /opt/bun/bin/bun (bun toolchain).
# Set INJECT_BUN=0 for toolchains that carry their own runtime — e.g. the dockerfile
# escape-hatch image, whose buildah-built image IS the runtime:
#   INJECT_BUN=0 CONFIG=images/apko/build-dockerfile.apko.yaml \
#     OUT=.firecracker/toolchains/dockerfile.ext4 tools/build-image.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-$REPO_ROOT/images/apko/build-bun.apko.yaml}"
OUT="${OUT:-$REPO_ROOT/.firecracker/toolchains/bun.ext4}"
WORK="${WORK:-$REPO_ROOT/.firecracker/work/image-$(basename "${OUT%.ext4}")}"
BUN_BIN="${BUN_BIN:-$REPO_ROOT/.firecracker/assets/bun}"
INIT_BIN="${INIT_BIN:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/jkbuild-init}"
INJECT_BUN="${INJECT_BUN:-1}"
# INJECT_RUST_WASIP2=1 bakes a pinned official Rust toolchain (with the wasm32-wasip2
# target std) at /opt/rust for the function toolchain. RUST_TOOLCHAIN_DIR points at a
# self-contained rustup toolchain dir (bin/ + lib/rustlib/{host,wasm32-wasip2}); the
# default is the repo-pinned toolchain rustup materialized on this host. See the
# build-function.apko.yaml header for why this is injected, not an apko package.
INJECT_RUST_WASIP2="${INJECT_RUST_WASIP2:-0}"
RUST_TOOLCHAIN_DIR="${RUST_TOOLCHAIN_DIR:-}"
# INJECT_JS=1 bakes the JS componentizer (jco + componentize-js + esbuild) into
# /opt/js-tools and generates the wasi:http WIT (at the engine's exact version) at
# /opt/jkbuild/wit/function.wit, for the function toolchain's JS/TS path.
INJECT_JS="${INJECT_JS:-0}"
export PATH="$HOME/.local/bin:$PATH"

command -v apko >/dev/null || {
    echo "apko not found — run tools/install-image-tools.sh" >&2
    exit 1
}
if [ "$INJECT_BUN" = "1" ] && [ ! -f "$BUN_BIN" ]; then
    echo "bun binary missing at $BUN_BIN — run tools/install-image-tools.sh" >&2
    exit 1
fi
# Always (re)build jkbuild-init — it's the in-VM lifecycle, and baking a stale one ships
# an old detect/build contract (a silent, confusing footgun). cargo is incremental, so
# this is ~free when unchanged. Allow opt-out only when a caller pre-built it deliberately.
if [ "${SKIP_INIT_BUILD:-0}" != "1" ]; then
    echo "[build-image] building jkbuild-init (musl-static, incremental)"
    (cd "$REPO_ROOT" && cargo build -p jkbuild --bin jkbuild-init \
        --target x86_64-unknown-linux-musl --release) \
        || { echo "[build-image] ERROR: jkbuild-init build failed" >&2; exit 1; }
fi
[ -f "$INIT_BIN" ] || { echo "[build-image] ERROR: jkbuild-init missing at $INIT_BIN" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/stage"
STAGE="$WORK/stage"

echo "[build-image] apko build $CONFIG"
# Use the committed lockfile when present so the package set is reproducible
# (the Wolfi repo is rolling; an unlocked build drifts). Regenerate with:
#   apko lock "$CONFIG" --arch x86_64 --output "${CONFIG%.yaml}.lock.json"
LOCK="${CONFIG%.yaml}.lock.json"
lock_arg=()
[ -f "$LOCK" ] && lock_arg=(--lockfile "$LOCK")
apko build "$CONFIG" jkbase-toolchain:latest "$WORK/oci.tar" --arch x86_64 "${lock_arg[@]}" >/dev/null

echo "[build-image] extracting rootfs layers"
# docker-archive: manifest.json lists ordered layer tarballs; apply in order.
layers="$(tar xf "$WORK/oci.tar" -O manifest.json | python3 -c \
    'import json,sys; print("\n".join(json.load(sys.stdin)[0]["Layers"]))')"
[ -n "$layers" ] || {
    echo "no layers in apko manifest" >&2
    exit 1
}
for layer in $layers; do
    # Skip device nodes (mknod needs root; jkbuild-init mounts devtmpfs at boot)
    # and skip same-owner so non-root extraction doesn't fail on chown.
    tar xf "$WORK/oci.tar" -O "$layer" |
        tar xz -C "$STAGE" --no-same-owner --exclude='dev/*' --exclude='./dev/*'
done

echo "[build-image] injecting jkbuild-init, mountpoints, busybox applets$([ "$INJECT_BUN" = "1" ] && echo ", bun")"
install -Dm0755 "$INIT_BIN" "$STAGE/sbin/init"
if [ "$INJECT_BUN" = "1" ]; then
    install -Dm0755 "$BUN_BIN" "$STAGE/opt/bun/bin/bun"
fi
# The RO root can't mkdir at boot — pre-create everything the lifecycle mounts.
mkdir -p "$STAGE"/{scratch,src,out,cache,newroot,work,proc,sys,dev,tmp,run,var,bin,sbin}
# Ensure the applets jkbuild-init shells out to resolve to busybox.
bb=""
for cand in usr/bin/busybox bin/busybox usr/sbin/busybox; do
    [ -x "$STAGE/$cand" ] && bb="/$cand" && break
done
if [ -n "$bb" ]; then
    for applet in sh mount umount cp nc reboot sync mkdir cat sed; do
        if [ ! -e "$STAGE/bin/$applet" ]; then ln -sf "$bb" "$STAGE/bin/$applet"; fi
    done
else
    echo "[build-image] WARN: busybox not found in image; lifecycle shell-outs may fail" >&2
fi

# Inject a pinned official Rust toolchain WITH the wasm32-wasip2 target std at
# /opt/rust (the function toolchain). Wolfi packages only the host std, and the
# wasip2 std must be built by the SAME rustc, so we bake the official self-contained
# toolchain (its binaries target an old glibc, so they run on Wolfi's newer glibc).
if [ "$INJECT_RUST_WASIP2" = "1" ]; then
    src="$RUST_TOOLCHAIN_DIR"
    if [ -z "$src" ]; then
        # Default: the repo-pinned toolchain rustup materialized for this host.
        chan="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$REPO_ROOT/rust-toolchain.toml" | head -1)"
        host="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
        src="${RUSTUP_HOME:-$HOME/.rustup}/toolchains/${chan}-${host}"
    fi
    if [ ! -x "$src/bin/cargo" ] || [ ! -x "$src/bin/rustc" ]; then
        echo "[build-image] ERROR: rust toolchain not found at $src (set RUST_TOOLCHAIN_DIR, or run: rustup toolchain install <chan> && rustup target add wasm32-wasip2)" >&2
        exit 1
    fi
    if [ ! -d "$src/lib/rustlib/wasm32-wasip2" ]; then
        echo "[build-image] ERROR: wasm32-wasip2 std missing in $src — run: rustup target add wasm32-wasip2" >&2
        exit 1
    fi
    echo "[build-image] injecting Rust toolchain + wasm32-wasip2 std from $src → /opt/rust"
    mkdir -p "$STAGE/opt/rust"
    # Copy the self-contained toolchain (real binaries, not rustup proxies). rustc
    # resolves its sysroot relative to its own path, so /opt/rust is self-sufficient.
    cp -a "$src/." "$STAGE/opt/rust/"
    mkdir -p "$STAGE/usr/local/bin"
    for tool in cargo rustc rustdoc; do
        [ -e "$STAGE/opt/rust/bin/$tool" ] && ln -sf /opt/rust/bin/"$tool" "$STAGE/usr/local/bin/$tool"
    done
fi

# Inject the JS componentizer (jco + componentize-js + esbuild) at /opt/js-tools and
# generate the wasi:http WIT the JS builder targets. The StarlingMonkey engine ships
# inside componentize-js, so no separate engine download. node_modules is portable JS +
# the linux-x64 esbuild binary (this host's arch == the VM's), so a host npm install
# into the stage is correct for the guest.
if [ "$INJECT_JS" = "1" ]; then
    command -v node >/dev/null && command -v npm >/dev/null || {
        echo "[build-image] ERROR: node + npm required on the host for INJECT_JS" >&2
        exit 1
    }
    command -v wasm-tools >/dev/null || {
        echo "[build-image] ERROR: wasm-tools required on the host for INJECT_JS (WIT gen)" >&2
        exit 1
    }
    echo "[build-image] injecting JS componentizer (jco + componentize-js + esbuild) → /opt/js-tools"
    jsdir="$STAGE/opt/js-tools"
    mkdir -p "$jsdir"
    ( cd "$jsdir" && npm install --no-audit --no-fund --silent \
        @bytecodealliance/jco @bytecodealliance/componentize-js esbuild ) \
        || { echo "[build-image] ERROR: npm install of JS componentizer failed" >&2; exit 1; }
    # /bin/sh wrappers on the build PATH (avoid #!/usr/bin/env node shebang assumptions).
    mkdir -p "$STAGE/usr/local/bin"
    cat > "$STAGE/usr/local/bin/jco" <<'SH'
#!/bin/sh
exec node /opt/js-tools/node_modules/@bytecodealliance/jco/src/jco.js "$@"
SH
    # esbuild's bin/esbuild is the NATIVE binary (its postinstall installs the platform
    # binary there), so exec it directly — it is not a node script.
    cat > "$STAGE/usr/local/bin/esbuild" <<'SH'
#!/bin/sh
exec /opt/js-tools/node_modules/esbuild/bin/esbuild "$@"
SH
    chmod 0755 "$STAGE/usr/local/bin/jco" "$STAGE/usr/local/bin/esbuild"

    # Generate /opt/jkbuild/wit/function.wit from the bundled StarlingMonkey engine, at
    # its EXACT wasi:http version (so a componentize-js engine bump can't skew it). The
    # `fn` world exports incoming-handler; the awk slice keeps the wasi:* dep packages.
    engine="$jsdir/node_modules/@bytecodealliance/componentize-js/lib/starlingmonkey_embedding.wasm"
    [ -f "$engine" ] || { echo "[build-image] ERROR: StarlingMonkey engine missing at $engine" >&2; exit 1; }
    ver="$(wasm-tools component wit "$engine" | grep -oE 'export wasi:http/incoming-handler@0\.2\.[0-9]+' | grep -oE '0\.2\.[0-9]+' | head -1)"
    [ -n "$ver" ] || { echo "[build-image] ERROR: could not read wasi:http version from the engine" >&2; exit 1; }
    echo "[build-image] generating /opt/jkbuild/wit/function.wit (wasi:http@$ver)"
    mkdir -p "$STAGE/opt/jkbuild/wit"
    {
        echo "package local:fn;"
        echo "world fn {"
        # Import wasi:cli/environment so the JS env-shim can read project secrets.
        echo "  import wasi:cli/environment@$ver;"
        echo "  export wasi:http/incoming-handler@$ver;"
        echo "}"
        wasm-tools component wit "$engine" | awk '/^package wasi:/{p=1} /^package local:/{p=0} p'
    } > "$STAGE/opt/jkbuild/wit/function.wit"

    # Env shim the JS builder prepends so a function reads project secrets via the
    # standard `process.env`. The getter calls getEnvironment() lazily — at REQUEST time,
    # not at wizer pre-init (which would snapshot the empty build-time env). Pinned to the
    # engine's exact wasi:cli version.
    mkdir -p "$STAGE/opt/jkbuild/js"
    cat > "$STAGE/opt/jkbuild/js/env-shim.js" <<SHIM
import { getEnvironment } from 'wasi:cli/environment@$ver';
globalThis.process ??= {};
Object.defineProperty(globalThis.process, 'env', {
  configurable: true,
  get() { return Object.fromEntries(getEnvironment()); },
});
SHIM
fi

# Build-mirror CA (optional). When BUILD_CA_CERT points at the shared CA cert, bake it
# into THIS build toolchain's trust store so the build tools accept the mirror's
# TLS-terminated registry connections: append to the public bundle (cargo/git/bun via
# the system store) AND drop the standalone PEM at the path node/bun read via
# NODE_EXTRA_CA_CERTS. Set BUILD_CA_CERT only for the language toolchains (bun/node/
# rust); the dockerfile toolchain uses the allow-any proxy (never MITM'd) so it needs
# no CA. This step is in build-image.sh ONLY — runtime images are built by
# tools/build-base-layer.sh, which has no CA step, so the CA can never leak into a
# runtime trust store (invariant I-3).
if [ -n "${BUILD_CA_CERT:-}" ]; then
    if [ ! -f "$BUILD_CA_CERT" ]; then
        echo "[build-image] BUILD_CA_CERT set but $BUILD_CA_CERT not found" >&2
        exit 1
    fi
    echo "[build-image] injecting build-mirror CA from $BUILD_CA_CERT"
    install -Dm0644 "$BUILD_CA_CERT" "$STAGE/etc/ssl/certs/jkbase-build-ca.crt"
    bundle="$STAGE/etc/ssl/certs/ca-certificates.crt"
    if [ -f "$bundle" ]; then
        printf '\n' >> "$bundle"
        cat "$BUILD_CA_CERT" >> "$bundle"
    else
        # Refuse to ship a CA-required toolchain whose system store can't trust the
        # mirror — otherwise cargo/git/bun silently fail every registry TLS at runtime.
        echo "[build-image] ERROR: $bundle absent; cannot bake mirror CA into the system store" >&2
        exit 1
    fi
fi

echo "[build-image] mkfs.ext4 -d (no mount)"
# Wolfi ships /etc/shadow et al. mode 0000; rootless `mkfs.ext4 -d` can't read
# them. Grant owner read so the userspace populate succeeds — runtime perms are
# irrelevant for a platform-built build toolchain (the guest runs as root).
chmod -R u+rwX "$STAGE"
content_kib="$(du -sk "$STAGE" | cut -f1)"
size_kib=$((content_kib + content_kib / 2 + 65536)) # +50% metadata slack +64MiB headroom
rm -f "$OUT"
mkdir -p "$(dirname "$OUT")"
truncate -s "${size_kib}K" "$OUT"
mkfs.ext4 -F -q -O ^has_journal -d "$STAGE" "$OUT"
chmod 0444 "$OUT"
echo "[build-image] done: $OUT ($(du -h "$OUT" | cut -f1)); init=/sbin/init=jkbuild-init$([ "$INJECT_BUN" = "1" ] && echo ", /opt/bun/bin/bun present")"
