#!/usr/bin/env bash
# Start an OpenBao dev server with the KMIP listener enabled, in the
# background. Logs go to $POC_DIR/bao.log and the pid to $POC_DIR/bao.pid.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

"$here/gen-certs.sh" >/dev/null
mkdir -p "$POC_DIR"

cat >"$POC_DIR/server.hcl" <<HCL
kmip {
  address            = "$KMIP_BIND"
  tls_cert_file      = "$POC_DIR/certs/server.pem"
  tls_key_file       = "$POC_DIR/certs/server.key"
  tls_client_ca_file = "$POC_DIR/certs/ca.pem"
  auth_path          = "auth/cert/login"
  auth_role          = "$KMIP_ROLE"
  mount_path         = "$KMIP_MOUNT/"
  log_messages       = ${KMIP_LOG_MESSAGES:-false}
}
HCL

if [[ -f "$POC_DIR/bao.pid" ]] && kill -0 "$(cat "$POC_DIR/bao.pid")" 2>/dev/null; then
  echo "server already running (pid $(cat "$POC_DIR/bao.pid"))"
  exit 0
fi

nohup "$BAO" server -dev -dev-root-token-id="$BAO_TOKEN" \
  -dev-listen-address="${BAO_ADDR#http://}" \
  -config="$POC_DIR/server.hcl" >"$POC_DIR/bao.log" 2>&1 &
echo $! >"$POC_DIR/bao.pid"

# Wait for the API and the KMIP port.
for _ in $(seq 1 60); do
  if "$BAO" status >/dev/null 2>&1 && (exec 3<>"/dev/tcp/127.0.0.1/$KMIP_PORT") 2>/dev/null; then
    echo "OpenBao is up (pid $(cat "$POC_DIR/bao.pid")), KMIP listening on $KMIP_BIND"
    exit 0
  fi
  sleep 0.5
done
echo "server did not become ready; see $POC_DIR/bao.log" >&2
tail -20 "$POC_DIR/bao.log" >&2
exit 1
