#!/usr/bin/env bash
# Start OpenBao with the KMIP listener, configure it, and run the PyKMIP
# interoperability suite against it. Optionally run the Percona databases too.
#
#   BAO=/path/to/bao ./run-all.sh               # server + setup + PyKMIP suite
#   BAO=/path/to/bao WITH_PERCONA=1 ./run-all.sh  # ...and Percona MongoDB + MySQL (needs Docker)
#
# Build the binary first:  go build -o /tmp/bao .   (from the repository root)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"

if ! command -v "$BAO" >/dev/null 2>&1 && [[ ! -x "$BAO" ]]; then
  echo "bao binary not found: set BAO=/path/to/bao (build it with: go build -o /tmp/bao .)" >&2
  exit 1
fi

# A virtualenv with PyKMIP, created on first use.
VENV="${VENV:-$POC_DIR/venv}"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "== creating a virtualenv with PyKMIP in $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet PyKMIP
fi
export PYTHON="$VENV/bin/python"

echo "== starting OpenBao with the KMIP listener"
"$here/start-server.sh"
"$here/setup-bao.sh"

echo "== PyKMIP interoperability suite"
POC_DIR="$POC_DIR" "$PYTHON" "$here/pykmip_test.py" 2>&1 | grep -v "Config file"

if [[ -n "${WITH_PERCONA:-}" ]]; then
  echo "== Percona Server for MongoDB"
  "$here/percona-mongodb.sh" up
  "$here/percona-mongodb.sh" verify
  echo "== Percona Server for MySQL"
  "$here/percona-mysql.sh" up
  "$here/percona-mysql.sh" verify
fi

echo
echo "Done. OpenBao is still running (log: $POC_DIR/bao.log); stop everything with ./cleanup.sh"
