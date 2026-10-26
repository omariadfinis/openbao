#!/usr/bin/env bash
# Run Percona Server for MySQL with the keyring_kmip component pointed at
# OpenBao, then prove it works.
#
#   ./percona-mysql.sh up      start mysqld with component_keyring_kmip
#   ./percona-mysql.sh verify  create an encrypted table and inspect the keys
#   ./percona-mysql.sh logs
#   ./percona-mysql.sh down
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

IMAGE="${PSMYSQL_IMAGE:-percona/percona-server:8.4}"
NAME="${PSMYSQL_NAME:-psmysql-kmip}"
VOLUME="${NAME}-data"
ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-root}"

# Where the image keeps the mysqld binary and its plugins. These are the
# locations in the Percona images; adjust if a newer image moves them.
MYSQLD_DIR="${PSMYSQL_MYSQLD_DIR:-/usr/sbin}"
PLUGIN_DIR="${PSMYSQL_PLUGIN_DIR:-/usr/lib64/mysql/plugin}"

mysql_exec() { docker exec "$NAME" mysql -uroot -p"$ROOT_PASSWORD" "$@"; }

case "${1:-up}" in
  up)
    "$here/docker-certs.sh"
    mkdir -p "$POC_DIR/mysql"

    # The component must be loaded early, so it is named in a manifest next to
    # the mysqld binary rather than installed with INSTALL COMPONENT.
    cat >"$POC_DIR/mysql/mysqld.my" <<JSON
{
  "read_local_manifest": false,
  "components": "file://component_keyring_kmip"
}
JSON
    cat >"$POC_DIR/mysql/component_keyring_kmip.cnf" <<JSON
{
  "server_addr": "host.docker.internal",
  "server_port": "$KMIP_PORT",
  "client_ca": "/certs/client-mysqld.pem",
  "client_key": "/certs/client-mysqld.key",
  "server_ca": "/certs/ca.pem"
}
JSON
    chmod 644 "$POC_DIR"/mysql/*

    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
      --add-host=host.docker.internal:host-gateway \
      -e MYSQL_ROOT_PASSWORD="$ROOT_PASSWORD" \
      -v "$POC_DIR/certs-docker:/certs:ro" \
      -v "$POC_DIR/mysql/mysqld.my:$MYSQLD_DIR/mysqld.my:ro" \
      -v "$POC_DIR/mysql/component_keyring_kmip.cnf:$PLUGIN_DIR/component_keyring_kmip.cnf:ro" \
      -v "$VOLUME:/var/lib/mysql" \
      -p "${PSMYSQL_PORT:-3306}:3306" \
      "$IMAGE"
    echo "waiting for mysqld..."
    for _ in $(seq 1 90); do
      if mysql_exec -e 'SELECT 1' >/dev/null 2>&1; then
        echo "mysqld is up"
        mysql_exec -e 'SELECT * FROM performance_schema.keyring_component_status'
        exit 0
      fi
      sleep 2
    done
    echo "mysqld did not start; last log lines:" >&2
    docker logs --tail 60 "$NAME" >&2
    exit 1
    ;;
  verify)
    echo "== keyring component status"
    mysql_exec -e 'SELECT * FROM performance_schema.keyring_component_status'
    echo "== create an encrypted table, rotate the master key, store a user key"
    mysql_exec -e "
      CREATE DATABASE IF NOT EXISTS poc;
      DROP TABLE IF EXISTS poc.secrets;
      CREATE TABLE poc.secrets (id INT PRIMARY KEY, note VARCHAR(64)) ENCRYPTION='Y';
      INSERT INTO poc.secrets VALUES (1, 'encrypted with a key from OpenBao');
      SELECT * FROM poc.secrets;
      SHOW CREATE TABLE poc.secrets\\G
      ALTER INSTANCE ROTATE INNODB MASTER KEY;"
    echo
    echo "== objects mysqld created in OpenBao (as identity: mysqld)"
    "${PYTHON:-python3}" "$here/inspect_objects.py" mysqld
    ;;
  logs) docker logs --tail "${2:-80}" "$NAME" ;;
  down) docker rm -f "$NAME" >/dev/null 2>&1 || true; docker volume rm "$VOLUME" >/dev/null 2>&1 || true; echo "removed $NAME" ;;
  *) echo "usage: $0 up|verify|logs|down" >&2; exit 2 ;;
esac
