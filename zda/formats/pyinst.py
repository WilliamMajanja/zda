"""PyInstaller: bounded CArchive cookie/TOC scan, stdlib only."""

import struct

from ..registry import Format, Inspection


COOKIE = b"MEI\014\013\012\013\016"


class PyInstallerFormat(Format):
    name = "pyinstaller"
    description = "PyInstaller executables: CArchive cookie, TOC members, python version marker"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 24 and buf[:4] == b"\x7fELF":
            return 0.2
        if buf[:2] in (b"MZ", b"\xcf\xfa") and size >= 4096:
            return 0.3
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("bounded TOC walk; member bodies are only length-accounted, not extracted")
        with open(path, "rb") as fh:
            data = fh.read()
        cookie_off = self._find_cookie(data)
        if cookie_off is None:
            ins.confidence = 0.25
            ind = "no PyInstaller cookie in the tail; not a PyInstaller executable (or a stripped/onefile-without-cookie layout)"
            ins.summary = ind
            ins.add_finding("pyinstaller", ind)
            return ins
        try:
            pkg_len, toc_off, toc_len, pyver = struct.unpack(
                "!IIII", data[cookie_off + 8 : cookie_off + 24]
            )
            pylib = data[cookie_off + 24 : cookie_off + 88].split(b"\x00")[0].decode("latin-1")
        except struct.error:
            ins.add_finding("cookie-error", "cookie located but too close to EOF to parse")
            return ins
        version = pylib.split(".so")[0] if pylib else ""
        ins.summary = (
            f"PyInstaller archive, python runtime {version or pylib or 'unknown'}"
            f" (pyvers {pyver}), package size 0x{pkg_len:x}, TOC {toc_len} bytes"
        )
        ins.add_finding("cookie", ins.summary, evidence=f"cookie {data[cookie_off:cookie_off + 8].hex(' ')} at end-0x{size - cookie_off}")
        archive_base = cookie_off + 88 - pkg_len
        if archive_base < 0:
            ins.add_finding("size-check", f"package length 0x{pkg_len:x} does not fit before the cookie — truncated archive")
            return ins
        toc_base = archive_base + toc_off
        members = self._toc(data, toc_base, toc_len)
        for name, compressed, sz in members[:24]:
            ins.add_finding("member", f"{name!r}: {sz} bytes raw, {'deflate' if compressed else 'stored'}")
        if members:
            ins.add_finding("members", f"... and {max(0, len(members) - 24)} more" if len(members) > 24 else f"{len(members)} member(s) total")
        vsn = [m for m in members if m[0].lower().endswith((".pyz",))]
        if vsn:
            ins.add_finding("pyz", f"PYZ dependency archive present: {vsn[0][0]}")
        pythons = [m for m in members if "python" in m[0].lower()]
        if pythons:
            ins.add_finding("runtime-lib", f"python shared runtime: {pythons[0][0]}")
        self._pycode(ins, data)
        return ins

    def _find_cookie(self, data):
        tail = data[-(256 * 1024):] if len(data) > 256 * 1024 else data
        idx = tail.find(COOKIE)
        while idx != -1 and tail.find(COOKIE, idx + 1) != -1:
            nxt = tail.find(COOKIE, idx + 1)
            idx = nxt
        if idx == -1:
            return None
        return len(data) - len(tail) + idx

    def _toc(self, data, base, length):
        out = []
        if base < 0 or length <= 0 or base + length > len(data):
            return out
        blob = data[base : base + length]
        o = 0
        while o + 18 <= len(blob):
            esz = struct.unpack("!i", blob[o : o + 4])[0]
            off, clen, uclen, flag = struct.unpack("!IIIB", blob[o + 4 : o + 17])
            o += 17
            e = o
            if o + esz - 18 > len(blob) or esz < 17:
                break
            nameend = blob.find(b"\x00", o)
            if nameend < 0:
                break
            name = blob[o : nameend].decode("utf-8", "replace")
            o = o + (esz - 18)
            out.append((name, bool(flag), uclen))
        return out

    def _pycode(self, ins, data):
        # find embedded .pyc magic 2-byte version markers for f-strings etc (bounded)
        hits = []
        for magic, label in [
            (b"\x6f\x0d\x0d\x0a", "3.14"),
            (b"\xcb\x0d\x0d\x0a", "3.13"),
            (b"\xca\x0d\x0d\x0a", "3.12"),
            (b"\xcb\x0d\x0d\x0a", "3.13"),
        ]:
            if magic in data[-256 * 1024 :]:
                hits.append(label)
        if hits:
            ins.add_finding("pyc", f"embedded .pyc magic version marker(s): {', '.join(sorted(set(hits)))}")
