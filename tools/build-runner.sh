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
# Contract: run the source's build, write artifacts + a `status` file (the build
# exit code) + a `build.log` to the output drive, then `reboot -f` — on x86 that
# is what makes the firecracker process exit (poweroff does NOT; see the FAQ).

set +e

mount -t proc     proc     /proc    2>/dev/null
mount -t sysfs    sysfs    /sys     2>/dev/null
mount -t devtmpfs devtmpfs /dev     2>/dev/null
mount -t tmpfs    tmpfs    /tmp     2>/dev/null

mkdir -p /scratch /src /out /cache
mount               /dev/vdb /scratch 2>/dev/null || echo "[build-runner] WARN: no scratch drive"
mount -t ext4 -o ro /dev/vdc /src     2>/dev/null || echo "[build-runner] WARN: no source drive"
mount               /dev/vdd /out     2>/dev/null || echo "[build-runner] WARN: no output drive"
mount               /dev/vde /cache   2>/dev/null   # optional

echo "[build-runner] drives mounted; starting build"

RC=127
if [ -f /src/build.sh ]; then
    # TODO(build): replace build.sh with CNB lifecycle (servers) / per-language
    # wasm toolchain (functions); and run inside a CoW overlay of scratch over
    # the toolchain root so the build sees a writable rootfs.
    ( cd /scratch && SRC=/src OUT=/out CACHE=/cache sh /src/build.sh >/out/build.log 2>&1 )
    RC=$?
else
    echo "no /src/build.sh found" >/out/build.log
fi

echo "$RC" >/out/status
echo "[build-runner] build exit=$RC; artifacts written to output drive"

sync
umount /out 2>/dev/null
reboot -f
