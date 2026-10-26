#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$here/env.sh"
if [[ -f "$POC_DIR/bao.pid" ]]; then
  kill "$(cat "$POC_DIR/bao.pid")" 2>/dev/null || true
  rm -f "$POC_DIR/bao.pid"
  echo "stopped"
fi
