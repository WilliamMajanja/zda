"""Standalone, stdlib-only smoke harness for ZDA (no external test runner required)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import zda
from zda.registry import inspect_file, identify, list_formats


class StandaloneHarness(unittest.TestCase):
    def test_version_and_formats(self):
        self.assertTrue(zda.__version__)
        fmts = list_formats()
        self.assertGreaterEqual(len(fmts), 18)
        self.assertTrue(all(f.get("deps") == "stdlib-only" for f in fmts))

    def test_no_third_party_imports(self):
        forbidden = {"numpy", "requests", "yaml", "lief", "pefile", "scipy", "pandas"}
        for path in ROOT.rglob("*.py"):
            if "tests" in path.parts and path.name == "test_standalone.py":
                continue
            text = path.read_text(errors="replace")
            for lib in forbidden:
                self.assertNotIn(f"import {lib}", text)
                self.assertNotIn(f"from {lib}", text)

    def test_malformed_inputs_do_not_crash(self):
        d = Path(tempfile.mkdtemp())
        for fmt in (f["format"] for f in list_formats()):
            p = d / f"{fmt}.bin"
            p.write_bytes(os.urandom(128))
            try:
                inspect_file(str(p), fmt_name=fmt)
            except Exception as e:  # pragma: no cover - failure path
                self.fail(f"{fmt} crashed on malformed input: {e}")

    def test_empty_file(self):
        d = Path(tempfile.mkdtemp())
        p = d / "empty.bin"
        p.write_bytes(b"")
        env = inspect_file(str(p))
        self.assertIn("file", env)
        self.assertIn("format", env)

    def test_zipapp_runs(self):
        if not (ROOT / "dist" / "zda.pyz").exists():
            self.skipTest("dist/zda.pyz not built")
        out = subprocess.run([sys.executable, str(ROOT / "dist" / "zda.pyz"), "--version"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("zda", out.stdout)


if __name__ == "__main__":
    # Allow running as a single file without an external runner.
    result = unittest.main(exit=False, verbosity=2)
    sys.exit(0 if result.result.wasSuccessful() else 1)
