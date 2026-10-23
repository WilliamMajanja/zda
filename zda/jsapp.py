"""Static JavaScript/Electron application analysis (stdlib only)."""

import json
import os
import re
from pathlib import Path

_MAX_FILES = 4000
_MAX_BYTES = 1 << 20


def analyze(path):
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"no such path: {root}")
    if root.is_file():
        return _analyze_asar(root)
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune heavy dirs
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "dist", "build")]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.stat().st_size <= _MAX_BYTES:
                    files.append(p)
            except OSError:
                pass
            if len(files) >= _MAX_FILES:
                break
        if len(files) >= _MAX_FILES:
            break

    js_files = [p for p in files if p.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx")]
    modules = []
    imports = set()
    boundaries = set()
    electron_markers = set()
    for p in js_files[:_MAX_FILES]:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        modules.append(str(p.relative_to(root)))
        for m in re.finditer(r"(?:require|import)\s*\(?['\"]([^'\"]+)['\"]", text):
            imports.add(m.group(1))
        for marker in ("ipcMain", "ipcRenderer", "contextBridge", "BrowserWindow",
                      "remote", "shell", "webContents", "preload"):
            if marker in text:
                boundaries.add(marker)
        for marker in ("electron", "BrowserWindow", "app.whenReady"):
            if marker in text:
                electron_markers.add(marker)

    manifests = []
    for p in files:
        if p.name == "package.json":
            try:
                m = json.loads(p.read_text(errors="replace"))
                manifests.append({
                    "path": str(p.relative_to(root)),
                    "name": m.get("name"),
                    "main": m.get("main"),
                    "scripts": list((m.get("scripts") or {}).keys()),
                    "dependencies": sorted((m.get("dependencies") or {}).keys()),
                })
            except (json.JSONDecodeError, OSError):
                pass

    asars = [str(p.relative_to(root)) for p in files if p.suffix == ".asar"]

    return {
        "root": str(root),
        "file_count": len(files),
        "js_module_count": len(js_files),
        "modules_sample": modules[:50],
        "imports": sorted(imports)[:100],
        "electron_boundaries": sorted(boundaries),
        "electron_markers": sorted(electron_markers),
        "manifests": manifests,
        "asar_archives": asars,
        "limits": [
            "static text scan only; no execution",
            "node_modules, .git, dist, build pruned",
            f"capped at {_MAX_FILES} files / {_MAX_BYTES} bytes per file",
        ],
    }


def _analyze_asar(path):
    from .formats.asar import AsarFormat
    # delegate to format inspector by writing a temp? Instead parse directly.
    import struct, json
    data = path.read_bytes()
    hdr_size = struct.unpack("<I", data[:4])[0]
    off = 8 if len(data) >= 8 and data[4:8] == b"\x00\x00\x00\x00" else 4
    hdr = json.loads(data[off : off + hdr_size].decode("utf-8"))
    files = []

    def walk(node, prefix=""):
        if not isinstance(node, dict):
            return
        if "files" in node and isinstance(node["files"], dict):
            for name, child in node["files"].items():
                walk(child, prefix + "/" + name if prefix else name)
            return
        files.append(prefix)

    walk(hdr)
    return {
        "asar": str(path),
        "file_count": len(files),
        "files_sample": files[:50],
        "limits": ["static header inventory only"],
    }
