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
# Contract: run the source's build, write artifacts + a `status` file (the build
# exit code) + a `build.log` to the output drive, then `reboot -f` — on x86 that
# is what makes the firecracker process exit (poweroff does NOT; see the FAQ).

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

run_build() {
    # $1 = root prefix ("" = current root, "/newroot" = overlay). Build env points
    # at the bind-mounted IO drives; cwd is the build workspace.
    if [ -f /src/build.sh ]; then
        chroot "${1:-/}" /bin/sh -c \
            'cd /work 2>/dev/null; SRC=/src OUT=/out CACHE=/cache sh /src/build.sh >/out/build.log 2>&1'
        return $?
    fi
    echo "no /src/build.sh found" >/out/build.log
    return 127
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
    run_build /newroot
    RC=$?
    sync
    umount /newroot/tmp /newroot/proc /newroot/dev /newroot/src /newroot/out /newroot/cache /newroot/work 2>/dev/null
    umount /newroot 2>/dev/null
else
    echo "[build-runner] WARN: overlay unavailable; building without a writable rootfs"
    mount -o bind /scratch /work 2>/dev/null || mkdir -p /work
    run_build ""
    RC=$?
fi

echo "$RC" >/out/status
echo "[build-runner] build exit=$RC; artifacts written to output drive"

sync
umount /out 2>/dev/null
reboot -f
