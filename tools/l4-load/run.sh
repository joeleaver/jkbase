#!/usr/bin/env bash
# A/B driver for the L4 load harness: run the SAME offered load with and without the plane in the
# path, so the delta is attributable rather than merely observed.
#
#   ./run.sh baseline                 # sim on this box, generator straight at it — no plane
#   ./run.sh plane <host> <port>      # through the deployed plane (see `jkbase l4 ls`)
#   ./run.sh both <host> <port>       # baseline, then plane, then the comparison
#
# Env: PARTICIPANTS (10) DURATION (60) WARMUP (5) VIDEO_KBPS (1500) AUDIO_KBPS (40)
#      VISIBLE (0 = every camera) AUDIO_STREAMS (3) SPEAKER_KBPS (0) IPS (auto)
#
# At 20+ participants cap BOTH fan-outs and price the tiles as a simulcast low layer. Real SFUs
# forward only the loudest ~3 audio streams and send thumbnails at ~180kbps; leaving either at
# "everyone at full rate" measures a workload no conference product generates.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/target/release"
PARTICIPANTS="${PARTICIPANTS:-10}"
DURATION="${DURATION:-60}"
WARMUP="${WARMUP:-5}"
VIDEO_KBPS="${VIDEO_KBPS:-1500}"
AUDIO_KBPS="${AUDIO_KBPS:-40}"
VISIBLE="${VISIBLE:-0}"
AUDIO_STREAMS="${AUDIO_STREAMS:-3}"
SPEAKER_KBPS="${SPEAKER_KBPS:-0}"
OUT="${OUT:-$HERE/results}"

build() {
  echo "── building ────────────────────────────────────────────────"
  cargo build --manifest-path "$HERE/Cargo.toml" --release
}

# Source aliases matter only when the plane is in the path (it is the plane that keys egress on
# the destination IP). The baseline is unaffected either way, so the same list is used for both
# runs — an A/B whose two halves differ in more than one variable proves nothing.
#
# $1 (optional) = the target host. Loopback aliases CANNOT be used as the source for an off-box
# destination: Linux refuses to route a 127.x source off the loopback interface and connect(2)
# returns EINVAL, which used to abort the documented remote run at participant 0. So they are only
# offered when the target is itself loopback; for a remote target the caller must supply real
# addresses via IPS= (see setup-source-ips.sh with BASE/DEV set to a routable subnet + NIC).
ips() {
  if [ -n "${IPS:-}" ]; then echo "$IPS"; return; fi
  local target_host="${1:-}"
  case "$target_host" in
    ''|localhost|127.*|::1|'[::1]') ;;   # loopback target: aliases are usable
    *) echo ""; return ;;                # remote target: loopback aliases would EINVAL
  esac
  if ip addr show dev lo 2>/dev/null | grep -q '127\.0\.1\.1/32'; then
    "$HERE/setup-source-ips.sh" list "$PARTICIPANTS"
  else
    echo ""
  fi
}

# Only meaningful when the plane is in the path — it is the plane that keys egress on the
# destination address.
warn_shared_ip() {
  local target_host="${1:-}"
  if [ -n "$(ips "$target_host")" ]; then return; fi
  case "$target_host" in
    ''|localhost|127.*|::1|'[::1]')
      cat >&2 <<'EOF'
!! No source-IP aliases found. All participants will share one address, so they share ONE
   per-source egress bucket instead of getting one each — the plane run will look far worse
   than reality. Fix with:  sudo ./setup-source-ips.sh add <participants>
EOF
      ;;
    *)
      cat >&2 <<EOF
!! Remote target ($target_host) with no source IPs, so all $PARTICIPANTS participants will share
   ONE per-source egress bucket instead of getting one each. The run will look far worse than
   reality and the reporter will refuse to draw a verdict from it.

   Loopback aliases CANNOT be used here — Linux will not route a 127.x source off-box, so
   connect(2) fails with EINVAL. You need real addresses on a routable interface:

       sudo BASE=<your-subnet-prefix> DEV=<your-nic> ./setup-source-ips.sh add $PARTICIPANTS
       IPS="\$(BASE=<prefix> ./setup-source-ips.sh list $PARTICIPANTS)" $0 $*

   Or set IPS=a,b,c directly. Proceeding anyway — the result is not a conference measurement.
EOF
      ;;
  esac
}

run_load() {
  local label="$1" target="$2"
  local extra=()
  local ip_list
  # Pass the destination host so loopback aliases are never offered for a remote target.
  ip_list="$(ips "${target%%:*}")"
  [ -n "$ip_list" ] && extra+=(--bind-ips "$ip_list")
  # The ceiling diagnosis describes the plane; applying it to the control run would invent
  # findings that run cannot support.
  [ "$label" = "baseline" ] && extra+=(--baseline)

  mkdir -p "$OUT"
  echo
  echo "── $label → $target ────────────────────────────────────────"
  "$BIN/l4-load" \
    --target "$target" \
    --participants "$PARTICIPANTS" \
    --duration "$DURATION" \
    --warmup "$WARMUP" \
    --video-kbps "$VIDEO_KBPS" \
    --audio-kbps "$AUDIO_KBPS" \
    --visible-streams "$VISIBLE" \
    --audio-streams "$AUDIO_STREAMS" \
    --speaker-kbps "$SPEAKER_KBPS" \
    --json \
    "${extra[@]}" | tee "$OUT/$label.txt"
}

baseline() {
  # Sim bound to a real address so the generator can reach it without the plane. This is the ONLY
  # context in which the simulator may leave loopback; a deployed run keeps the default.
  "$BIN/l4-sfu-sim" --bind 127.0.0.1 --port 9300 --http-port 8081 --report-secs 5 &
  local sim=$!
  trap 'kill '"$sim"' 2>/dev/null || true' EXIT
  sleep 0.5
  run_load baseline "127.0.0.1:9300"
  kill "$sim" 2>/dev/null || true
  trap - EXIT
}

compare() {
  local a="$OUT/baseline.txt" b="$OUT/plane.txt"
  [ -f "$a" ] && [ -f "$b" ] || return 0
  echo
  echo "── baseline vs plane ───────────────────────────────────────"
  for f in "$a" "$b"; do
    local json
    json="$(grep -o '{.*}' "$f" | tail -1)"
    [ -n "$json" ] && echo "$(basename "$f" .txt): $json"
  done
  echo
  echo "The plane's cost is the delta in delivered_pct, worst_loss_pct and rtt_p95_ns."
  echo "A plane run that trips a ceiling is a CONFIG finding; one that loses packets with no"
  echo "ceiling signature is a PUMP finding. They have different fixes — don't conflate them."
}

case "${1:-both}" in
  baseline) build; baseline ;;
  plane)
    [ $# -ge 3 ] || { echo "usage: $0 plane <host> <port>" >&2; exit 2; }
    build; warn_shared_ip "$2"; run_load plane "$2:$3" ;;
  both)
    [ $# -ge 3 ] || { echo "usage: $0 both <host> <port>" >&2; exit 2; }
    build; warn_shared_ip "$2"; baseline; run_load plane "$2:$3"; compare ;;
  *) echo "usage: $0 {baseline|plane|both} [host port]" >&2; exit 2 ;;
esac
