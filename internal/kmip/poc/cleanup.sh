#!/usr/bin/env bash
# Stop the OpenBao dev server and remove the Percona containers and volumes.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

"$here/stop-server.sh" || true
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  for c in psmdb-kmip psmysql-kmip; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for v in psmdb-kmip-data psmysql-kmip-data; do docker volume rm "$v" >/dev/null 2>&1 || true; done
fi
echo "cleaned up (certificates and logs remain in $POC_DIR; delete it to start fresh)"
