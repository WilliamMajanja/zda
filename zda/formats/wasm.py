"""WebAssembly: static module section/import/export/func decode to bounded WAT-ish output, stdlib only."""

import struct

from ..registry import Format, Inspection

VLT = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64", 0x40: "void"}
SEC = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
       6: "global", 7: "export", 8: "start", 9: "elem", 10: "code", 11: "data",
       12: "data-count", 13: "tag"}


class _R:
    def __init__(self, fh):
        self.fh = fh

    def u(self):
        result = 0
        shift = 0
        while True:
            b = self.fh.read(1)[0]
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7
            if shift > 35:
                raise ValueError("LEB128 too long")

    def name(self):
        n = self.u()
        if n > 65536:
            raise ValueError("name too long")
        return self.fh.read(n).decode("utf-8", "replace")


class WasmFormat(Format):
    name = "wasm"
    description = "WebAssembly modules: sections, imports, exports, function type signatures (WAT-ish)"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:4] == b"\x00asm" and len(buf) >= 8:
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("no validation is performed; bounds checks stop parsing when truncated")
        ins.add_limit("custom sections (code bodies) are not disassembled here")
        if len(buf) < 8:
            ins.confidence = 0.5
            ins.summary = "truncated WASM header"
            ins.add_finding("header", ins.summary, evidence=buf[:8].hex(" ") if buf else "")
            return ins
        version = struct.unpack("<I", buf[4:8])[0]
        ins.summary = f"WebAssembly module, version {version}, size {size}"
        ins.add_finding("header", ins.summary, evidence=buf[:8].hex(" "))
        if size > (1 << 30):
            ins.add_finding("size", "module exceeds 1 GiB; sections above 1 GiB are not parsed")
        with open(path, "rb") as fh:
            fh.seek(8)
            r = _R(fh)
            func_types, imports, exports = [], [], []
            try:
                while True:
                    b = fh.read(1)
                    if len(b) < 1:
                        break
                    sid = b[0]
                    sz = r.u()
                    start = fh.tell()
                    if sid == 1:
                        n = r.u()
                        for i in range(min(n, 1024)):
                            if r.u() != 0x60:
                                break
                            params = self._vals(r)
                            results = self._vals(r)
                            func_types.append(f"(func ({' '.join(params)}) -> ({' '.join(results)}))")
                    elif sid == 2:
                        n = r.u()
                        for i in range(min(n, 1024)):
                            mod, name = r.name(), r.name()
                            kind = r.u()
                            if kind == 0:
                                ti = r.u()
                                imports.append(f"func {ti} {mod}.{name}")
                            elif kind == 1:
                                imports.append(f"table {mod}.{name}")
                            elif kind == 2:
                                imports.append(f"memory {mod}.{name}")
                            elif kind == 3:
                                imports.append(f"global {mod}.{name}")
                            else:
                                imports.append(f"?kind{kind} {mod}.{name}")
                                break
                    elif sid == 3:
                        n = r.u()
                        for i in range(min(n, 1024)):
                            r.u()
                    elif sid == 7:
                        n = r.u()
                        for i in range(min(n, 1024)):
                            name = r.name()
                            kind = r.u()
                            idx = r.u()
                            k = {0: "func", 1: "table", 2: "memory", 3: "global"}.get(kind, kind)
                            exports.append(f"{k} {name}={idx}")
                    elif sid == 0:
                        cname = r.name()
                        ins.add_finding("custom-name", f"custom section: {cname!r}")
                    ins.add_finding("section", f"{SEC.get(sid, sid)} at 0x{start:x}, {sz} bytes")
                    if fh.tell() < start:
                        break
                    fh.seek(start + sz)
            except (ValueError, IndexError, struct.error) as e:
                ins.add_finding("parse-stopped", f"sections parsed until error: {e}")
        if func_types:
            for ft in func_types[:16]:
                ins.add_finding("type", ft)
        if imports:
            for im in imports[:16]:
                ins.add_finding("import", f"import {im} [func {im.split(' ')[0]}]")
        if func_types:
            ins.add_finding("funcs", f"{len(func_types)} function type(s) declared")
        if imports:
            ins.add_finding("imported", f"{len(imports)} import(s)")
        if exports:
            for ex in exports[:16]:
                ins.add_finding("export", f"export {ex}")
            ins.add_finding("exported", f"{len(exports)} export(s)")
        return ins

    def _vals(self, r):
        n = r.u()
        out = []
        for _ in range(min(n, 256)):
            t = r.fh.read(1)[0]
            out.append(VLT.get(t, f"?{t:#x}"))
        return out
