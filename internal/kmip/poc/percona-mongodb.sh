#!/usr/bin/env bash
# Run Percona Server for MongoDB with its master key held in OpenBao over
# KMIP, then prove it works.
#
#   ./percona-mongodb.sh up      start mongod with --enableEncryption
#   ./percona-mongodb.sh verify  write data and inspect the key in OpenBao
#   ./percona-mongodb.sh logs
#   ./percona-mongodb.sh down
#
# Needs: docker, the OpenBao server from start-server.sh + setup-bao.sh, and
# the PyKMIP virtualenv for the inspection step.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

IMAGE="${PSMDB_IMAGE:-percona/percona-server-mongodb:7.0}"
NAME="${PSMDB_NAME:-psmdb-kmip}"
VOLUME="${NAME}-data"

case "${1:-up}" in
  up)
    "$here/docker-certs.sh"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true   # encryption can only be enabled on an empty data directory
    docker run -d --name "$NAME" \
      --add-host=host.docker.internal:host-gateway \
      -v "$POC_DIR/certs-docker:/certs:ro" \
      -v "$VOLUME:/data/db" \
      -p "${PSMDB_PORT:-27017}:27017" \
      "$IMAGE" mongod --bind_ip_all --enableEncryption \
        --kmipServerName host.docker.internal \
        --kmipPort "$KMIP_PORT" \
        --kmipServerCAFile /certs/ca.pem \
        --kmipClientCertificateFile /certs/client-mongod-combined.pem
    echo "waiting for mongod..."
    for _ in $(seq 1 60); do
      if docker exec "$NAME" mongosh --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; then
        echo "mongod is up with encryption at rest; its master key is in OpenBao"
        exit 0
      fi
      sleep 1
    done
    echo "mongod did not start; last log lines:" >&2
    docker logs --tail 40 "$NAME" >&2
    exit 1
    ;;
  verify)
    echo "== encryption status reported by mongod"
    docker exec "$NAME" mongosh --quiet --eval '
      db.getSiblingDB("poc").docs.insertOne({hello: "kmip", at: new Date()});
      printjson(db.serverStatus().encryptionAtRest);
      print("documents:", db.getSiblingDB("poc").docs.countDocuments());'
    echo
    echo "== objects mongod created in OpenBao (as identity: mongod)"
    "${PYTHON:-python3}" "$here/inspect_objects.py" mongod
    ;;
  logs) docker logs --tail "${2:-80}" "$NAME" ;;
  down) docker rm -f "$NAME" >/dev/null 2>&1 || true; docker volume rm "$VOLUME" >/dev/null 2>&1 || true; echo "removed $NAME" ;;
  *) echo "usage: $0 up|verify|logs|down" >&2; exit 2 ;;
esac
