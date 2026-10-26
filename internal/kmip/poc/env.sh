#!/usr/bin/env bash
# Shared settings for the KMIP proof-of-concept scripts. Source this file;
# override any variable in your environment first.

POC_DIR="${POC_DIR:-$PWD/kmip-poc-run}"   # where certificates, config, logs and the pid file go
BAO="${BAO:-bao}"                          # path to the bao binary built from this branch

# The OpenBao API (the dev server's address) and root token.
export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
export BAO_TOKEN="${BAO_TOKEN:-root}"

# Where the KMIP listener binds, and the extra host names or IPs clients will
# use to reach it. Containers on Docker Desktop reach the host as
# host.docker.internal, so it is always included in the server certificate.
KMIP_BIND="${KMIP_BIND:-0.0.0.0:5696}"
KMIP_PORT="${KMIP_BIND##*:}"
KMIP_HOSTS="${KMIP_HOSTS:-localhost,127.0.0.1,host.docker.internal}"

# Client identities. Each common name becomes a separate OpenBao entity, and
# objects are only visible to the entity that created them.
KMIP_CLIENTS="${KMIP_CLIENTS:-pykmip,mongod,mysqld,alice,bob}"

# The cert auth role and kmip mount the listener uses.
KMIP_ROLE="${KMIP_ROLE:-kmip-clients}"
KMIP_MOUNT="${KMIP_MOUNT:-kmip}"

# Log every KMIP request and response (as XML) to the server log. Debugging
# only: the log then contains key material.
KMIP_LOG_MESSAGES="${KMIP_LOG_MESSAGES:-false}"
