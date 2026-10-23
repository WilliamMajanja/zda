"""Single-file test harness: runs the ZDA stdlib-only test suite."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(ROOT / "tests"), "-v"]
raise SystemExit(subprocess.run(cmd).returncode)
