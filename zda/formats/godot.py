"""Godot PCK: static header/directory inventory, stdlib only."""

import struct

from ..registry import Format, Inspection


class GodotPckFormat(Format):
    name = "godot-pck"
    description = "Godot engine PCK packs: format version, engine version, file inventory"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:4] == b"GDPC" or buf[:4] == b"CPDG":
            return 1.0
        if size > 128 and size >= 4 and buf[:4] == b"RSCC":
            return 0.5
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("file contents are not extracted; only the header and directory are read")
        with open(path, "rb") as fh:
            data = fh.read()
        magic = data[:4] if len(data) >= 4 else buf[:4]
        o = 4
        if len(data) < 24:
            ins.confidence = 0.5
            ins.summary = "truncated Godot PCK header"
            ins.add_finding("header", ins.summary, evidence=buf[:16].hex(" ") if buf else "")
            return ins
        if magic == b"CPDG":
            ins.confidence = 0.6
            ins.add_finding("magic", "reversed 'GDPC' magic — may be renamed/reordered pack")
        fmt_ver, ver_major, ver_minor, ver_patch = struct.unpack("<IIII", data[o : o + 16])
        o += 16
        flags = 0
        if fmt_ver >= 2:
            flags = struct.unpack("<I", data[o : o + 4])[0]
            o += 4
            file_base = struct.unpack("<Q", data[o : o + 8])[0] if fmt_ver >= 2 else 0
            o += 8
        file_count = struct.unpack("<I", data[o : o + 4])[0]
        o += 4
        ins.summary = (
            f"Godot PCK (format {fmt_ver}), engine {ver_major}.{ver_minor}.{ver_patch}, {file_count} file(s)"
        )
        ins.add_finding("header", ins.summary, evidence=data[:20].hex(" "))
        if flags & 1:
            ins.add_finding("encrypted", "PACK_DIR_ENCRYPTED flag set (directory is encrypted)")
            ins.add_limit("encrypted directories are not traversed")
        if flags & 2:
            ins.add_finding("relative", "PACK_RELATIVE_BASE flag set — path-base packing")
        if flags & 4:
            ins.add_finding("custom-hash", "PACK_FILE_VERSION flag set — per-file versioning dictionary used")
        n = 0
        shown = 0
        store = {0: "brotli", 1: "fastlz", 2: "deflate", 3: "gzip", 4: "zstd"}
        for i in range(min(file_count, 4096)):
            if o + 4 > len(data):
                ins.add_finding("idx-truncated", f"directory truncated at file {i}")
                break
            path_len = struct.unpack("<I", data[o : o + 4])[0]
            o += 4
            if o + path_len > len(data):
                ins.add_finding("idx-truncated", "path length overruns file")
                break
            raw = data[o : o + path_len]
            name = raw.decode("utf-8", "replace").rstrip("\x00")
            o += path_len
            enc = {}
            for k in ("offset", "size"):
                if fmt_ver >= 2:
                    v = struct.unpack("<Q", data[o : o + 8])[0]
                    o += 8
                else:
                    v = struct.unpack("<I", data[o : o + 4])[0]
                    o += 4
                enc[k] = v
            md5 = data[o : o + 16].hex()
            o += 16
            if fmt_ver >= 2 and (flags & 8):
                enc["size"] = struct.unpack("<Q", buf[o : o + 8])[0]
                o += 8
            flags2 = 0
            if fmt_ver < 2:
                flags2 = struct.unpack("<I", data[o : o + 4])[0]
                o += 4
            elif fmt_ver >= 2:
                flags2 = struct.unpack("<H", data[o : o + 2])[0]
                o += 2
            n += 1
            if shown < 14:
                shown += 1
                codec = flags2 & 0b111
                cm = ["brotli", "fastlz", "deflate", "gzip", "zstd", "?", "plain", "?"][codec]
                ins.add_finding(
                    "file",
                    f"{name!r}: {enc['size']} bytes, comp {cm}, md5 {md5[:12]}…",
                )
        if n == 0 and file_count:
            ins.add_finding("directory", "directory could not be read")
        ins.add_finding("sum", f"read {n}/{file_count} file entries (bound 4096)")
        return ins
