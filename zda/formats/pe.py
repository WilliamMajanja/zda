"""PE: static COFF/Optional-header/section/import inspection, stdlib only."""

import datetime

from ..registry import Format, Inspection, _u16le, _u32le, hexdump

MAG10B, MAG20B = 0x10B, 0x20B
SUBSYS = {1: "native", 2: "windows-gui", 3: "windows-console", 9: "wince", 10: "efi", 14: "xbox"}
MACHINE = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "aarch64", 0x200: "IA-64"}


class PeFormat(Format):
    name = "pe"
    description = "PE/COFF executables (Windows .exe/.dll/.sys): header, sections, imports, Authenticode presence"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 0x40 and buf[:2] == b"MZ":
            return 1.0
        if buf[:4] == b"VZ\0\0":
            return 0.9
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("static inspection; no execution, no virtual translation; imports are read via the import table only")
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < 0x40:
            ins.confidence = 0.5
            ins.summary = "too short to be a PE (missing DOS header)"
            ins.add_finding("header", ins.summary, evidence=buf[:16].hex(" ") if buf else "")
            return ins
        e_lfanew = _u32le(data, 0x3C)
        if e_lfanew + 4 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            ins.confidence = 0.6
            ins.summary = "DOS MZ header found, but no PE\\0\\0 signature at e_lfanew"
            ins.add_finding("dos-header", "MZ signature; not a modern PE (or e_lfanew points elsewhere)",
                            evidence=hexdump(buf[:4]))
            return ins
        coff = e_lfanew + 4
        nsec, timestamp = _u16le(data, coff + 2), _u32le(data, coff + 4)
        opt_size = _u16le(data, coff + 16)
        mach = MACHINE.get(_u16le(data, coff), f"machine 0x{_u16le(data, coff):04x}")
        opt = coff + 20
        magic = _u16le(data, opt)
        bits = 64 if magic == MAG20B else (32 if magic == MAG10B else None)
        ts = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
        ins.summary = f"PE {bits or '?'}-bit {mach}, {nsec} section(s), subsystem {SUBSYS.get(_u16le(data, opt + (68 if bits == 64 else 68)), 'unknown')}, built {ts:%Y-%m-%d %H:%M}"
        ins.add_finding("header", ins.summary, evidence=hexdump(data[coff:coff + 8]))
        ins.add_finding("timestamp", f"linker timestamp: {ts.isoformat()}", evidence=str(timestamp))
        subsys_off = opt + 68 if bits == 64 else opt + 68
        if bits:
            subsys = SUBSYS.get(_u16le(data, subsys_off))
            if subsys:
                ins.add_finding("subsystem", f"{subsys}")
        section_table = coff + 20 + opt_size
        secs = []
        for i in range(nsec):
            base = section_table + i * 40
            if base + 40 > len(data):
                break
            name = data[base : base + 8].split(b"\x00")[0].decode("latin-1")
            vsize, vaddr, rawsize, rawoff = (
                _u32le(data, base + 8), _u32le(data, base + 12),
                _u32le(data, base + 16), _u32le(data, base + 20),
            )
            chars = _u32le(data, base + 36)
            flags = [n for n, b in [("code", 0x20), ("idata", 0x40), ("udata", 0x80), ("W", 0x80000000), ("X", 0x20000000), ("discarded", 0x2000000)] if chars & b]
            secs.append((name, vsize, rawsize))
            ins.add_finding(
                "section",
                f"{name!r}: vsize 0x{vsize:x}, raw 0x{rawsize:x} at 0x{rawoff:x}, flags [{','.join(flags) or '-'}]",
            )
        rwx = [n for n, v, r in secs if v & 0x20000000]
        if rwx:
            ins.add_finding("rwx-section", f"writable executable sections: {', '.join(rwx)}")
        nimp = self._imports(ins, data, opt, bits, coff, opt_size, section_table, nsec)
        if not nimp and b"MT" in data[:1024]:
            ins.add_finding("runtime", "possible MinGW/MSVC runtime hints absent — likely a .NET/managed or packed image")
        self._dotnet(ins, data, opt, bits)
        self._clr_metadata(ins, data, opt, bits, section_table, nsec)
        self._authenticode(ins, data, opt, bits)
        self._toolchain(ins, data)
        self._strings(ins, data)
        return ins

    def _dir(self, data, opt, bits, idx):
        base = opt + (108 if bits == 64 else 92) + idx * 8
        if base + 8 > len(data):
            return None
        return _u32le(data, base), _u32le(data, base + 4)

    def _rva(self, secs, r):
        for name, vsize, vaddr, rawsize, rawoff in secs:
            if vaddr <= r < vaddr + max(vsize, rawsize):
                return rawoff + (r - vaddr)
        return None

    def _imports(self, ins, data, opt, bits, coff, opt_size, section_table, nsec):
        secs = []
        for i in range(nsec):
            base = section_table + i * 40
            if base + 40 > len(data):
                break
            secs.append((
                data[base:base + 8].split(b"\x00")[0].decode("latin-1"),
                _u32le(data, base + 8), _u32le(data, base + 12),
                _u32le(data, base + 16), _u32le(data, base + 20),
            ))
        d = self._dir(data, opt, bits, 1)
        if not d:
            return 0
        rva, sz = d
        if not rva:
            return 0
        fo = self._rva(secs, rva)
        if fo is None:
            return 0
        dlls, count = [], 0
        step = 8 if bits == 64 else 4
        i = 0
        while i < 8192:
            base = fo + i * 20
            if base + 20 > len(data):
                break
            name_rva = _u32le(data, base + 12)
            if not name_rva:
                break
            no = self._rva(secs, name_rva)
            if no is None or no + 64 > len(data):
                break
            name = data[no : no + 64].split(b"\x00")[0].decode("latin-1")
            iat_rva = _u32le(data, base + 16)
            n_imp = 0
            j = 0
            while True:
                p = self._rva(secs, iat_rva + j * step)
                if p is None or p + step > len(data):
                    break
                v = int.from_bytes(data[p : p + step], "little")
                if v == 0:
                    break
                tbl = v & 0xFFF00000 if bits == 32 else v
                if bits == 32 and v & 0x80000000:
                    n_imp += 1
                else:
                    n_imp += 1
                j += 1
                if j > 4096:
                    break
            dlls.append(f"{name} ({n_imp} imports)")
            count += n_imp
            i += 1
        if dlls:
            ins.add_finding("imports", f"{len(dlls)} DLL dependencies, {count} imported symbol slots",
                            evidence=", ".join(dlls[:10]))
        return len(dlls)

    def _dotnet(self, ins, data, opt, bits):
        if bits is None:
            return
        d = self._dir(data, opt, bits, 14)
        if d and d[0]:
            ins.add_finding("dotnet", "CLR data directory present — .NET assembly (managed code), use `zda inspect` metadata limits")

    def _authenticode(self, ins, data, opt, bits):
        if bits is None:
            return
        d = self._dir(data, opt, bits, 4)
        if d and d[0]:
            off, sz = d
            fo = None
            header = data[off : off + 4]
            ins.add_finding(
                "authenticode",
                f"WIN_CERTIFICATE table present ({sz} bytes)",
                evidence=f"w\\)certificate magic: {header.hex(' ')}",
            )
        else:
            ins.add_finding("authenticode", "not signed (empty certificate data directory)")

    def _clr_metadata(self, ins, data, opt, bits, section_table, nsec):
        if bits is None:
            return
        d = self._dir(data, opt, bits, 14)
        if not (d and d[0]):
            return
        secs = []
        for i in range(nsec):
            base = section_table + i * 40
            if base + 40 > len(data):
                break
            secs.append((
                data[base:base + 8].split(b"\x00")[0].decode("latin-1"),
                _u32le(data, base + 8), _u32le(data, base + 12),
                _u32le(data, base + 16), _u32le(data, base + 20),
            ))
        fo = self._rva(secs, d[0])
        if fo is None or fo + 16 > len(data):
            return
        meta_rva = _u32le(data, fo + 8)
        meta_size = _u32le(data, fo + 12)
        mo = self._rva(secs, meta_rva)
        if mo is None or mo + 20 > len(data) or data[mo:mo + 4] != b"BSJB":
            ins.add_finding("dotnet-meta", "CLR data directory present but metadata root not found")
            return
        verlen = _u32le(data, mo + 16)
        if verlen > 256 or mo + 20 + verlen > len(data):
            verlen = min(verlen, 256)
        version = data[mo + 20 : mo + 20 + verlen].split(b"\x00")[0].decode("latin-1", "replace")
        ins.add_finding("dotnet-meta", f"CLR metadata version: {version!r}")
        off = mo + 20 + ((verlen + 3) // 4) * 4
        if off + 4 > len(data):
            return
        nstreams = _u16le(data, off + 2)
        o = off + 4
        streams = []
        for _ in range(min(nstreams, 16)):
            if o + 8 > len(data):
                break
            soff = _u32le(data, o)
            ssz = _u32le(data, o + 4)
            o += 8
            name = data[o:o + 32].split(b"\x00")[0].decode("latin-1", "replace")
            o += ((len(name) + 1 + 3) // 4) * 4
            streams.append(f"{name}({ssz})")
        if streams:
            ins.add_finding("dotnet-streams", f"{len(streams)} metadata stream(s): {', '.join(streams)}")

    def _toolchain(self, ins, data):
        low = data[: min(len(data), 1 << 20)].lower()
        for needle, label in ((b"go1.", "Go"), (b"rustc", "Rust"), (b"gcc", "GCC")):
            if needle in low:
                ins.add_finding("toolchain", f"{label} toolchain marker present")

    def _strings(self, ins, data):
        names = [b"Microsoft", b"MFC", b"MSVCRT", b"KERNEL32", b"mscoree.dll"]
        for n in names:
            if n.lower() in data[:65536].lower():
                ins.add_finding("vendor-hint", f"embedded string: {n.decode()}")
        ins.add_limit("vendor hints are heuristic string matches and can be faked")


def section_bounded(data):
    return None
