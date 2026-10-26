#!/usr/bin/env bash
# Copy the certificates to a directory the containers can read. The database
# images run as unprivileged users that cannot read the 0600 private keys, so
# the copies are world-readable. This is for the local PoC only.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

"$here/gen-certs.sh" >/dev/null
rm -rf "$POC_DIR/certs-docker"
mkdir -p "$POC_DIR/certs-docker"
cp "$POC_DIR"/certs/*.pem "$POC_DIR"/certs/client-*.key "$POC_DIR/certs-docker/"
chmod 755 "$POC_DIR/certs-docker"
chmod 644 "$POC_DIR"/certs-docker/*
