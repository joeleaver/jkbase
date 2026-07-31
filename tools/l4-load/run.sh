#!/usr/bin/env bash
# A/B driver for the L4 load harness: run the SAME offered load with and without the plane in the
# path, so the delta is attributable rather than merely observed.
#
#   ./run.sh baseline                 # sim on this box, generator straight at it — no plane
#   ./run.sh plane <host> <port>      # through the deployed plane (see `jkbase l4 ls`)
#   ./run.sh both <host> <port>       # baseline, then plane, then the comparison
#
# Env: PARTICIPANTS (10) DURATION (60) WARMUP (5) VIDEO_KBPS (1500) AUDIO_KBPS (40) IPS (auto)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/target/release"
PARTICIPANTS="${PARTICIPANTS:-10}"
DURATION="${DURATION:-60}"
WARMUP="${WARMUP:-5}"
VIDEO_KBPS="${VIDEO_KBPS:-1500}"
AUDIO_KBPS="${AUDIO_KBPS:-40}"
OUT="${OUT:-$HERE/results}"

build() {
  echo "── building ────────────────────────────────────────────────"
  cargo build --manifest-path "$HERE/Cargo.toml" --release
}

# Source aliases matter only when the plane is in the path (it is the plane that keys egress on
# the destination IP). The baseline is unaffected either way, so the same list is used for both
# runs — an A/B whose two halves differ in more than one variable proves nothing.
ips() {
  if [ -n "${IPS:-}" ]; then echo "$IPS"; return; fi
  if ip addr show dev lo 2>/dev/null | grep -q '127\.0\.1\.1/32'; then
    "$HERE/setup-source-ips.sh" list "$PARTICIPANTS"
  else
    echo ""
  fi
}

# Only meaningful when the plane is in the path — it is the plane that keys egress on the
# destination address.
warn_shared_ip() {
  if [ -z "$(ips)" ]; then
    cat >&2 <<'EOF'
!! No source-IP aliases found. All participants will share one address, so they share ONE
   per-source egress bucket instead of getting one each — the plane run will look far worse
   than reality. Fix with:  sudo ./setup-source-ips.sh add <participants>
EOF
  fi
}

run_load() {
  local label="$1" target="$2"
  local extra=()
  local ip_list
  ip_list="$(ips)"
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
    build; warn_shared_ip; run_load plane "$2:$3" ;;
  both)
    [ $# -ge 3 ] || { echo "usage: $0 both <host> <port>" >&2; exit 2; }
    build; warn_shared_ip; baseline; run_load plane "$2:$3"; compare ;;
  *) echo "usage: $0 {baseline|plane|both} [host port]" >&2; exit 2 ;;
esac
