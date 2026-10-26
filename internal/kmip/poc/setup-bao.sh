#!/usr/bin/env bash
# Configure OpenBao for KMIP: enable the cert auth method, mount the kmip
# secrets engine, and create a policy and a cert auth role that trusts the
# PoC CA for the configured client common names.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

"$BAO" auth enable cert >/dev/null 2>&1 || true
"$BAO" secrets enable -path="$KMIP_MOUNT" kmip >/dev/null 2>&1 || true

# What a KMIP client may do. Each KMIP operation is its own path, so a
# narrower policy can allow, say, only encrypt and decrypt.
"$BAO" policy write kmip-client - >/dev/null <<POLICY
path "$KMIP_MOUNT/*" {
  capabilities = ["create", "read", "update", "list"]
}
POLICY

"$BAO" write "auth/cert/certs/$KMIP_ROLE" \
  certificate=@"$POC_DIR/certs/ca.pem" \
  allowed_common_names="$KMIP_CLIENTS" \
  token_policies=kmip-client >/dev/null

echo "configured: auth/cert/certs/$KMIP_ROLE (clients: $KMIP_CLIENTS), mount $KMIP_MOUNT/"
