#!/usr/bin/env bash
# Add (or remove) loopback source-address aliases so `l4-load --bind-ips` can give every virtual
# participant its OWN address.
#
# Why this exists: the plane's per-source egress bucket is keyed on the destination IP of the
# reply — i.e. one bucket per client address. K participants sharing one source address share ONE
# 1 MiB/s bucket instead of getting K of them, which turns a healthy run into fake catastrophic
# loss. A conference has K distinct client addresses; the harness must too.
#
#   sudo ./setup-source-ips.sh add 24        # 127.0.1.1 .. 127.0.1.24
#   sudo ./setup-source-ips.sh del 24
#   ./setup-source-ips.sh list 24            # comma list for --bind-ips (no privileges needed)
#
# NOTE ON /24s: these aliases all sit in one /24, so they still share the per-/24 backstop
# (8 MiB/s by default). That is fine for isolating the PER-SOURCE cap, and it is exactly the
# wrong setup for isolating the per-project one. To separate those effects, put the aliases on a
# dummy interface across several /24s (10.90.0.x, 10.90.1.x, …) and pass those instead.
set -euo pipefail

CMD="${1:-}"
COUNT="${2:-24}"
BASE="${BASE:-127.0.1}"
DEV="${DEV:-lo}"

usage() { echo "usage: $0 {add|del|list} [count]  (BASE=$BASE DEV=$DEV)" >&2; exit 2; }
[ -n "$CMD" ] || usage
case "$COUNT" in ''|*[!0-9]*) usage ;; esac
[ "$COUNT" -ge 1 ] && [ "$COUNT" -le 250 ] || { echo "count must be 1..250" >&2; exit 2; }

# BASE/DEV are overridable because a run against a REMOTE plane needs real routable sources —
# loopback aliases cannot be the source for an off-box destination (connect(2) → EINVAL). But an
# unvalidated override silently adds up to 250 addresses to a production NIC, so anything outside
# the loopback default has to be acknowledged. CONFIRM=1 for non-interactive use.
case "$BASE" in
  127.*) ;;
  *)
    if [ "${CONFIRM:-0}" != "1" ] && [ "$CMD" != "list" ]; then
      cat >&2 <<EOF
!! BASE=$BASE DEV=$DEV is NOT loopback: this ${CMD}s up to $COUNT real addresses on a real
   interface, and they persist until you run '$0 del $COUNT' or reboot.

   Intended for a remote-plane run, where real sources are required. If that is what you
   want, re-run with CONFIRM=1:

       sudo CONFIRM=1 BASE=$BASE DEV=$DEV $0 $CMD $COUNT
EOF
      exit 2
    fi
    ;;
esac
# A bad DEV would otherwise be swallowed by the `|| true` on each add.
if [ "$CMD" != "list" ] && ! ip link show dev "$DEV" >/dev/null 2>&1; then
  echo "no such interface: DEV=$DEV" >&2; exit 2
fi

case "$CMD" in
  add)
    for i in $(seq 1 "$COUNT"); do
      ip addr add "${BASE}.${i}/32" dev "$DEV" 2>/dev/null || true
    done
    echo "added ${COUNT} aliases on ${DEV}: ${BASE}.1 .. ${BASE}.${COUNT}"
    ;;
  del)
    for i in $(seq 1 "$COUNT"); do
      ip addr del "${BASE}.${i}/32" dev "$DEV" 2>/dev/null || true
    done
    echo "removed ${COUNT} aliases on ${DEV}"
    ;;
  list)
    out=""
    for i in $(seq 1 "$COUNT"); do
      out="${out}${out:+,}${BASE}.${i}"
    done
    echo "$out"
    ;;
  *) usage ;;
esac
