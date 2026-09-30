#!/usr/bin/env bash
# Live ACME DNS-01 issuance e2e for tenant wildcard domains (docs/wildcard-domains.md):
# Pebble (a real ACME CA, validating DNS-01 against our nameserver) + BIND (RFC2136 target,
# authoritative for the platform zone `jk.test` AND a tenant zone `tenant.test` whose
# `_acme-challenge.play` CNAMEs into the platform's delegation zone). Runs the ignored
# `wildcard_issuance_e2e` test against them. Needs docker; nothing leaves the box.
#
#   tools/wildcard-issuance-e2e.sh            # run, then tear down
#   KEEP=1 tools/wildcard-issuance-e2e.sh     # leave the containers up for poking
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:2.7.0}"
BIND_IMAGE="${BIND_IMAGE:-internetsystemsconsortium/bind9:9.20}"
DNS_PORT="${DNS_PORT:-15353}"
NAME="jkbase-wc-e2e-$$"
WORK="$(mktemp -d)"

cleanup() {
  if [[ -z "${KEEP:-}" ]]; then
    docker rm -f "$NAME-bind" "$NAME-pebble" >/dev/null 2>&1 || true
    rm -rf "$WORK"
  else
    echo "KEEP=1: containers $NAME-{bind,pebble} and $WORK left in place"
  fi
}
trap cleanup EXIT

TSIG_SECRET="$(head -c 32 /dev/urandom | base64)"
mkdir -p "$WORK/bind" "$WORK/certs"

cat >"$WORK/bind/named.conf" <<EOF
key "jkbase-e2e" { algorithm hmac-sha256; secret "$TSIG_SECRET"; };
options {
  directory "/var/cache/bind";
  listen-on port $DNS_PORT { 127.0.0.1; };
  listen-on-v6 { none; };
  # Recursive for localhost so the CNAME from tenant.test is chased into jk.test, as Let's
  # Encrypt's recursive resolvers do. Authoritative-only BIND answers the bare CNAME and the
  # DNS-01 check fails. Forward nothing: only the two local zones exist.
  recursion yes;
  allow-recursion { 127.0.0.1; };
  forwarders { };
  dnssec-validation no;
};
zone "jk.test" { type primary; file "/etc/bind/jk.test.zone"; allow-update { key "jkbase-e2e"; }; };
zone "tenant.test" { type primary; file "/etc/bind/tenant.test.zone"; };
EOF

soa() {
  cat <<EOF
\$TTL 60
@ IN SOA ns.jk.test. ops.jk.test. ( 1 60 60 600 60 )
@ IN NS ns.jk.test.
EOF
}
{ soa; echo "ns IN A 127.0.0.1"; } >"$WORK/bind/jk.test.zone"
{
  soa
  echo "_acme-challenge.play IN CNAME e2elabel01._acme-delegation.jk.test."
  # nodelegate.tenant.test deliberately has NO _acme-challenge CNAME.
} >"$WORK/bind/tenant.test.zone"
chmod -R a+rwX "$WORK"

echo "==> starting BIND on 127.0.0.1:$DNS_PORT"
docker run -d --name "$NAME-bind" --network host \
  -v "$WORK/bind:/etc/bind" "$BIND_IMAGE" \
  -g -c /etc/bind/named.conf -u bind >/dev/null

echo "==> starting Pebble (DNS-01 validated against 127.0.0.1:$DNS_PORT)"
docker run -d --name "$NAME-pebble" --network host \
  -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
  "$PEBBLE_IMAGE" -config /test/config/pebble-config.json -dnsserver "127.0.0.1:$DNS_PORT" >/dev/null
docker cp "$NAME-pebble:/test/certs/pebble.minica.pem" "$WORK/pebble-root.pem" >/dev/null

for _ in $(seq 1 30); do
  if curl -fsS --cacert "$WORK/pebble-root.pem" https://localhost:14000/dir >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS --cacert "$WORK/pebble-root.pem" https://localhost:14000/dir >/dev/null

export JK_E2E_DNS="127.0.0.1:$DNS_PORT"
export JK_E2E_TSIG_SECRET="$TSIG_SECRET"
export JK_E2E_ACME_DIR="https://localhost:14000/dir"
export JK_E2E_ACME_ROOT="$WORK/pebble-root.pem"
export JK_E2E_CERT_DIR="$WORK/certs"

echo "==> running the issuance e2e"
(cd "$ROOT" && cargo test -p jkbase-proxy --test wildcard_issuance_e2e -- --ignored --nocapture)

echo "==> issued tenant wildcard:"
openssl x509 -in "$WORK/certs/wildcard/play.tenant.test/fullchain.pem" -noout -subject -ext subjectAltName -dates
