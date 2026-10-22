"""MCP stdio server: JSON-RPC 2.0, newline-delimited messages, stdlib only.

Exposes:
  initialize / shutdown (protocol basics)
  tools: zda_identify, zda_inspect, zda_list_formats
"""

import json
import sys

from . import __version__
from .registry import inspect_file, list_formats

SERVER_INFO = {"name": "zda", "version": __version__}


def _tools():
    return [
        {
            "name": "zda_identify",
            "description": "Identify a local file's format (fast, signature-based). Returns format, confidence and summary.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "absolute path of the file to identify"}},
                "required": ["path"],
            },
        },
        {
            "name": "zda_inspect",
            "description": (
                "Deeply inspect a local file in a registered format (ELF, PE, Mach-O, APK/JAR/OOXML,"
                " PDF, SQLite, GGUF, safetensors, WASM, JVM class, EVM, BEAM, Godot PCK, images,"
                " PyInstaller). Returns findings with evidence, limitations and sha256 facts."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "absolute path of the file to inspect"},
                    "format": {"type": "string", "description": "optional: force a format from zda_list_formats"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "zda_list_formats",
            "description": "List every format that zda can inspect, with descriptions and confidence.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def _result(res):
    return {"content": [{"type": "text", "text": json.dumps(res, indent=2, ensure_ascii=False)}]}


def _dispatch(method, params):
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion", "2024-11-05"),
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    if method == "tools/list":
        return {"tools": _tools()}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "zda_list_formats":
            return _result({"formats": list_formats()})
        if name in ("zda_identify", "zda_inspect"):
            path = args.get("path")
            if not path:
                return _result({"error": "missing required argument: path"})
            fmt = args.get("format")
            env = inspect_file(path, fmt_name=fmt)
            if name == "zda_identify":
                keep = {k: env.get(k) for k in ("schema", "format", "confidence", "summary", "file")}
                return _result(keep)
            return _result(env)
        return {"error": {"code": -32601, "message": f"unknown tool: {name}"}}
    if method in ("ping",):
        return {}
    return {"error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(args):
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {e}"}})
            continue
        if "id" not in msg:
            continue
        mid = msg["id"]
        try:
            res = _dispatch(msg.get("method"), msg.get("params") or {})
            if res and "error" in res:
                _send({"jsonrpc": "2.0", "id": mid, "error": res["error"]})
            else:
                _send({"jsonrpc": "2.0", "id": mid, "result": (res or {})})
        except FileNotFoundError as e:
            _send({"jsonrpc": "2.0", "id": mid, "result": _result({"error": str(e)})})
        except (ValueError, KeyError) as e:
            _send({"jsonrpc": "2.0", "id": mid, "result": _result({"error": str(e)})})
    return 0


def _send(o):
    sys.stdout.write(json.dumps(o, ensure_ascii=False) + "\n")
    sys.stdout.flush()
