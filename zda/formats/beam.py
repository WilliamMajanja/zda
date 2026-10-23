"""Erlang BEAM: IFF chunk and atom inspection, stdlib only."""

import struct

from ..registry import Format, Inspection


class BeamFormat(Format):
    name = "beam"
    description = "Erlang BEAM files: IFF chunk layout, atoms, exports/imports, code header"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 12 and buf[:4] == b"FOR1" and buf[8:12] == b"BEAM":
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("structure inspection only; BEAM bytecode is not decoded to a readable form here")
        with open(path, "rb") as fh:
            data = fh.read()
        if len(buf) < 12:
            ins.confidence = 0.5
            ins.summary = "truncated BEAM header"
            ins.add_finding("header", ins.summary, evidence=buf[:12].hex(" ") if buf else "")
            return ins
        form1len = struct.unpack(">I", buf[4:8])[0]
        ins.summary = f"Erlang BEAM file, FOR1 size {form1len}, {size} bytes"
        ins.add_finding("iff", ins.summary, evidence=buf[:12].hex(" "))
        o = 12
        atoms = []
        n_exports = n_imports = 0
        while o + 8 <= len(data) and o < form1len + 8:
            tag = data[o : o + 4]
            clen = struct.unpack(">I", data[o + 4 : o + 8])[0]
            body = data[o + 8 : o + 8 + clen]
            if tag == b"AtU8":
                atoms = self._atu8(body)
                ins.add_finding("atoms", f"{len(atoms)} atom(s)", evidence=", ".join(atoms[:12]) + ("…" if len(atoms) > 12 else ""))
            elif tag == b"Code":
                if len(body) >= 16:
                    maxver, v, opcode_max, hdrsz, i_count = struct.unpack(">IIIII", body[:20])
                    ins.add_finding("code", f"code chunk: maximum version {maxver}, instruction count {i_count}")
            elif tag == b"ExpT":
                n_exports = struct.unpack(">I", body[:4])[0] if len(body) >= 4 else 0
                ins.add_finding("exports", f"{n_exports} exported function(s)")
            elif tag == b"ImpT":
                n_imports = struct.unpack(">I", body[:4])[0] if len(body) >= 4 else 0
                ins.add_finding("imports", f"{n_imports} imported functions(s)")
            elif tag == b"Dbgi":
                ins.add_finding("debug", "Dbgi chunk present (debug info / abstract code included)")
            elif tag == b"CInf":
                ins.add_finding("compile-info", "compile-info chunk present (compiler version, options)")
            else:
                ins.add_finding("chunk", f"{tag.decode('latin-1')!r}: {clen} bytes")
            o += 8 + clen + (clen & 1)
        if o < form1len + 8:
            ins.add_finding("iff-truncated", f"chunk walk ended before the FOR1 size: {o} < {form1len + 8}")
        if atoms:
            others = [a for a in atoms if len(a) < 60][:30]
            nameshint = [a for a in others if a[0].isupper()][:10]
            if nameshint:
                ins.add_finding("atom-hint", "module-like atom(s): " + ", ".join(nameshint))
        return ins

    def _atu8(self, body):
        if len(body) < 4:
            return []
        n = struct.unpack(">I", body[:4])[0]
        o, out = 4, []
        for i in range(min(n, 4096)):
            if o + 2 > len(body):
                break
            ln = struct.unpack(">H", body[o : o + 2])[0]
            o += 2
            if o + ln > len(body):
                break
            out.append(body[o : o + ln].decode("utf-8", "replace"))
            o += ln
        return out
