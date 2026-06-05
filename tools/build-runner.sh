#!/bin/sh
# jkbase build-runner — the guest init (PID 1) baked into build-VM *toolchain*
# images as /sbin/init. ONE build VM builds ONE target (per-target model; see
# design §12). It runs untrusted tenant build logic; the host-side jail
# (jkbase-orch::build_vm + jailer) is the security boundary, not this script.
#
# Drive contract (set by jkbase-orch::build_vm::configure_and_wait):
#   /dev/vda  toolchain rootfs   (RO root, this image)
#   /dev/vdb  scratch            (RW, throwaway; empty ext4 from stage_rw_prealloc)
#   /dev/vdc  source snapshot    (RO ext4, this target's source subdir)
#   /dev/vdd  output             (RW, empty ext4; host reads it back out-of-band)
#   /dev/vde  cache              (RW, optional, per-project)
#
# CoW overlay: the build runs chroot'd into an overlay of scratch-over-toolchain,
# so it sees a WRITABLE rootfs (cargo/npm/pip write all over /) while the
# toolchain image stays read-only and shared across builds — all writes land on
# the throwaway scratch upper.
#
# Network model (fetch-then-seal, design §9). When the host attaches a NIC it
# passes `jkbase.proxy=<url>` on the kernel cmdline. Then the build is TWO-PHASE:
#   FETCH   — `build.sh fetch`  runs with HTTP(S)_PROXY set (network up via the
#             allowlist egress proxy); on completion we print FETCH-COMPLETE.
#   SEAL    — the HOST tears the TAP down (host-enforced; we just observe eth0's
#             carrier drop — we have no API to bring it back).
#   COMPILE — `build.sh compile` runs with the network gone.
# With no `jkbase.proxy=` (offline build) we run `build.sh` once, unchanged.
#
# Contract: write artifacts + a `status` file (the build exit code) + a
# `build.log` to the output drive, then `reboot -f` — on x86 that is what makes
# the firecracker process exit (poweroff does NOT; see the FAQ).

set +e

mount -t proc     proc     /proc 2>/dev/null
mount -t sysfs    sysfs    /sys  2>/dev/null
mount -t devtmpfs devtmpfs /dev  2>/dev/null
mount -t tmpfs    tmpfs    /tmp  2>/dev/null

mkdir -p /scratch /src /out /cache
mount               /dev/vdb /scratch 2>/dev/null || echo "[build-runner] WARN: no scratch drive"
mount -t ext4 -o ro /dev/vdc /src     2>/dev/null || echo "[build-runner] WARN: no source drive"
mount               /dev/vdd /out     2>/dev/null || echo "[build-runner] WARN: no output drive"
mount               /dev/vde /cache   2>/dev/null   # optional

# Egress proxy URL from the kernel cmdline (empty = offline build).
PROXY=$(sed -n 's/.*jkbase\.proxy=\([^ ]*\).*/\1/p' /proc/cmdline 2>/dev/null)

run_phase() {
    # $1 = root prefix ("" = current root, "/newroot" = overlay)
    # $2 = phase arg passed to build.sh ("" | "fetch" | "compile")
    # $3 = proxy URL to export (empty = none)
    root="${1:-/}"
    phase="$2"
    penv=""
    if [ -n "$3" ]; then
        penv="http_proxy=$3 https_proxy=$3 HTTP_PROXY=$3 HTTPS_PROXY=$3"
    fi
    if [ -f /src/build.sh ]; then
        chroot "$root" /bin/sh -c \
            "cd /work 2>/dev/null; SRC=/src OUT=/out CACHE=/cache $penv sh /src/build.sh $phase >>/out/build.log 2>&1"
        return $?
    fi
    echo "no /src/build.sh found" >>/out/build.log
    return 127
}

# Block until the host has sealed the network (deleted the TAP), or a timeout, by
# probing the proxy endpoint until it is unreachable. The host owns the TAP, so
# this is observation only — we cannot bring the network back.
wait_for_seal() {
    seal_host=$(echo "$PROXY" | sed 's|^[a-z]*://||; s|/.*||; s|:.*||')
    seal_port=$(echo "$PROXY" | sed 's|^[a-z]*://[^:/]*:||; s|/.*||')
    [ -z "$seal_port" ] && seal_port=80
    i=0
    while [ "$i" -lt 30 ]; do
        if ! nc -w 1 "$seal_host" "$seal_port" </dev/null >/dev/null 2>&1; then
            echo "[seal] network sealed (proxy $seal_host:$seal_port unreachable); compiling offline"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo "[seal] WARN: proxy still reachable after wait; compiling anyway"
}

# Run the build under root prefix $1, one-shot (offline) or two-phase (networked).
do_build() {
    root="$1"
    if [ -n "$PROXY" ]; then
        echo "[build-runner] networked build via proxy $PROXY (fetch-then-seal)"
        run_phase "$root" fetch "$PROXY"
        rc=$?
        echo "[seal] FETCH-COMPLETE"
        if [ "$rc" -ne 0 ]; then
            return "$rc"
        fi
        wait_for_seal
        run_phase "$root" compile ""
        return $?
    fi
    run_phase "$root" "" ""
    return $?
}

RC=127
mkdir -p /scratch/upper /scratch/work /scratch/workspace /newroot
if mount -t overlay overlay \
        -o lowerdir=/,upperdir=/scratch/upper,workdir=/scratch/work /newroot 2>/out/overlay.err; then
    # Make the IO drives + virtual filesystems visible inside the writable root.
    mkdir -p /newroot/src /newroot/out /newroot/cache /newroot/work /newroot/proc /newroot/dev /newroot/tmp
    mount -o bind /src             /newroot/src   2>/dev/null
    mount -o bind /out             /newroot/out   2>/dev/null
    mount -o bind /cache           /newroot/cache 2>/dev/null
    mount -o bind /scratch/workspace /newroot/work 2>/dev/null
    mount -t proc proc             /newroot/proc  2>/dev/null
    mount -o bind /dev             /newroot/dev   2>/dev/null
    mount -t tmpfs tmpfs           /newroot/tmp   2>/dev/null
    echo "[build-runner] CoW overlay active; building in a writable rootfs"
    do_build /newroot
    RC=$?
    sync
    umount /newroot/tmp /newroot/proc /newroot/dev /newroot/src /newroot/out /newroot/cache /newroot/work 2>/dev/null
    umount /newroot 2>/dev/null
else
    echo "[build-runner] WARN: overlay unavailable; building without a writable rootfs"
    mount -o bind /scratch /work 2>/dev/null || mkdir -p /work
    do_build ""
    RC=$?
fi

echo "$RC" >/out/status
echo "[build-runner] build exit=$RC; artifacts written to output drive"

sync
umount /out 2>/dev/null
reboot -f
