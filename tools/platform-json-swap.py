#!/usr/bin/env python3
"""Surgically replace ONE `runtimes.<key>` entry of a layer store's platform.json.

  platform-json-swap.py [--backup] <store>/platform.json <runtime-key> <entry.json>

The companion of `ONLY=rhypedb tools/build-base-layer.sh` (local bake) and
tools/ship-rhypedb-layer.sh (host ship). platform.json is what every NEW deploy plans its
layers from, so a swap must never:
  - point at a blob that isn't in the store, or whose bytes don't match its content address
    (every deploy of that runtime would then fail its host sha256 re-verify);
  - touch any other entry (a drifted base/runtime digest re-plans every tenant onto blobs
    that may not exist on that host).
Both are checked BEFORE the write; the write is tmp+fsync+rename in the store dir, keeping
the original's mode/owner. Re-running with the entry already in place is a no-op.
"""
import copy
import hashlib
import json
import os
import re
import sys
import time

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def die(msg):
    print(f"[platform-json-swap] {msg}", file=sys.stderr)
    sys.exit(1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_entry(entry, store):
    for k in ("name", "role", "media", "digest", "file", "size", "fs_verity", "verity"):
        if k not in entry:
            die(f"entry missing '{k}'")
    digest = entry["digest"]
    if not (isinstance(digest, str) and digest.startswith("sha256:") and HEX64.match(digest[7:])):
        die(f"entry digest not sha256:<64-hex>: {digest!r}")
    hexd = digest[7:]
    if entry["file"] != f"sha256-{hexd}.erofs":
        die(f"entry file {entry['file']!r} doesn't match its digest")
    v = entry["verity"]
    if not (isinstance(v, dict) and HEX64.match(str(v.get("root_hash", "")))
            and HEX64.match(str(v.get("salt", ""))) and isinstance(v.get("data_size"), int)):
        die(f"entry verity params malformed: {v!r}")
    blob = os.path.join(store, entry["file"])
    if not os.path.isfile(blob):
        die(f"blob {blob} not in the store — install it before swapping the manifest")
    if os.path.getsize(blob) != entry["size"]:
        die(f"blob {blob} size {os.path.getsize(blob)} != entry size {entry['size']}")
    got = sha256_file(blob)
    if got != hexd:
        die(f"blob {blob} sha256 {got} != its content address {hexd}")


def main():
    args = sys.argv[1:]
    backup = "--backup" in args
    args = [a for a in args if a != "--backup"]
    if len(args) != 3:
        die("usage: platform-json-swap.py [--backup] <platform.json> <runtime-key> <entry.json>")
    manifest, key, entry_path = args
    store = os.path.dirname(os.path.abspath(manifest))

    with open(manifest) as f:
        raw = f.read()
    current = json.loads(raw)
    with open(entry_path) as f:
        entry = json.load(f)
    if not isinstance(current.get("runtimes"), dict):
        die(f"{manifest} has no runtimes table")
    validate_entry(entry, store)

    old = current["runtimes"].get(key)
    if old == entry:
        print(f"[platform-json-swap] runtimes.{key} already {entry['digest']} — unchanged")
        return

    updated = copy.deepcopy(current)
    updated["runtimes"][key] = entry
    # Everything but runtimes.<key> must be byte-for-byte the same data.
    strip = lambda d: {**d, "runtimes": {k: v for k, v in d["runtimes"].items() if k != key}}
    assert strip(updated) == strip(current), "swap touched more than runtimes." + key

    st = os.stat(manifest)
    if backup:
        bak = f"{manifest}.pre-{key}-{time.strftime('%Y%m%d%H%M%S')}"
        with open(bak, "w") as f:
            f.write(raw)
        os.chmod(bak, st.st_mode & 0o777)
        if os.geteuid() == 0:
            os.chown(bak, st.st_uid, st.st_gid)
        print(f"[platform-json-swap] backup: {bak}")

    tmp = f"{manifest}.swap.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(updated, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, st.st_mode & 0o777)
    if os.geteuid() == 0:
        os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, manifest)
    dfd = os.open(store, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    print(f"[platform-json-swap] runtimes.{key}: {old['digest'] if old else '(absent)'} -> {entry['digest']}")


if __name__ == "__main__":
    main()
