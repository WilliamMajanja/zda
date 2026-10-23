#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[zda] dependency audit (stdlib only)"
if grep -RInE "import (numpy|requests|yaml|lief|pefile|scipy|pandas)" zda tests 2>/dev/null; then
  echo "[zda] ERROR: third-party import detected" >&2
  exit 1
fi

echo "[zda] compile (bytecode)"
python3 -m compileall -q zda

echo "[zda] run test suite"
python3 -m unittest discover -s tests -v

echo "[zda] build self-contained zipapp"
STAGE="/tmp/scratchpad/zda_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE" dist
cp -r zda "$STAGE/zda"
cat > "$STAGE/__main__.py" <<'PY'
import sys
from zda.cli import main
sys.exit(main(sys.argv[1:]))
PY
python3 -m zipapp "$STAGE" -o dist/zda.pyz -p "/usr/bin/env python3" --compress
chmod +x dist/zda.pyz

echo "[zda] verify artifact"
python3 dist/zda.pyz --version
echo "[zda] build complete: dist/zda.pyz"
