"""ASAR archives: static header/file inventory, stdlib only."""

import json
import struct

from ..registry import Format, Inspection


class AsarFormat(Format):
    name = "asar"
    description = "ASAR (Electron) archives: header JSON, file inventory, sizes, integrity hashes"
    confidence = 0.9

    def match(self, buf, size):
        if len(buf) < 8:
            return 0.0
        hdr_size = struct.unpack("<I", buf[:4])[0]
        if 16 < hdr_size < (1 << 20) and size >= hdr_size + 8:
            try:
                json.loads((buf[8 : 8 + hdr_size] if buf[4:8] == b"\x00\x00\x00\x00" else buf[4 : 4 + hdr_size]).tobytes())
                return 0.95
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        # try without reserved 4 bytes
        try:
            hdr_size = struct.unpack("<I", buf[:4])[0]
            if 16 < hdr_size < (1 << 20):
                json.loads(bytes(buf[4 : 4 + hdr_size]))
                return 0.9
        except (json.JSONDecodeError, UnicodeDecodeError, struct.error):
            pass
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("file contents are not extracted; only the header inventory is read")
        with open(path, "rb") as fh:
            data = fh.read()
        # parse header
        hdr_size = struct.unpack("<I", data[:4])[0]
        off = 4
        if len(data) >= 8 and data[4:8] == b"\x00\x00\x00\x00":
            off = 8
        else:
            off = 4
        if off + hdr_size > len(data):
            ins.confidence = 0.5
            ins.summary = "ASAR header truncated"
            ins.add_finding("header", ins.summary)
            return ins
        try:
            hdr = json.loads(data[off : off + hdr_size].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            ins.confidence = 0.5
            ins.summary = f"ASAR header JSON parse failed: {e}"
            ins.add_finding("header", ins.summary)
            return ins
        files = []

        def walk(node, prefix=""):
            if not isinstance(node, dict):
                return
            if "files" in node and isinstance(node["files"], dict):
                for name, child in node["files"].items():
                    walk(child, prefix + "/" + name if prefix else name)
                return
            # leaf
            size = node.get("size")
            offset = node.get("offset")
            files.append((prefix, size, offset, node.get("integrity")))

        walk(hdr)
        ins.summary = f"ASAR archive, {len(files)} file(s)"
        ins.add_finding("header", ins.summary, evidence=f"header {hdr_size} bytes")
        for name, sz, off, integ in files[:24]:
            ins.add_finding("file", f"{name!r}: {sz} bytes at offset {off}" + (" (integrity)" if integ else ""))
        if len(files) > 24:
            ins.add_finding("files", f"... +{len(files) - 24} more")
        return ins
