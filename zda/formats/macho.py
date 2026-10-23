"""Mach-O: static header/load-command/section inspection for thin and fat images, stdlib only."""

import struct

from ..registry import Format, Inspection, hexdump
from .elf import _u16le, _u32le, _u64le

MH_MAGIC, MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF
MH_CIGAM, MH_CIGAM_64 = 0xCEFAEDFE, 0xCFFAEDFE
FAT_MAGIC, FAT_CIGAM = 0xCAFEBABE, 0xBEBAFECA
LC_SEGMENT_64, LC_UUID, LC_UNIXTHREAD = 0x19, 0x1B, 0x5
LC_LOAD_DYLIB, LC_ID_DYLIB, LC_MIN_VERSION = 0xC, 0xD, 0x25


class MachOFormat(Format):
    name = "mach-o"
    description = "Mach-O binaries (macOS/iOS): header, load commands, dylibs, UUID, architecture list"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 16:
            m = int.from_bytes(buf[:4], "little")
            if m in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64):
                return 1.0
            if int.from_bytes(buf[:4], "big") == FAT_MAGIC:
                # fat magic (0xCAFEBABE) collides with JVM class files; a fat
                # image must have a small nfat_arch count and plausible arches
                nfat = int.from_bytes(buf[4:8], "big")
                if 1 <= nfat <= 16 and len(buf) >= 8 + 20 * min(nfat, 4):
                    return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("static inspection only; no jailbreak/device checks, no symbolication")
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < 32 or len(buf) < 4:
            ins.confidence = 0.5
            ins.summary = "truncated Mach-O header"
            ins.add_finding("header", ins.summary, evidence=buf[:16].hex(" ") if buf else "")
            return ins
        magic = int.from_bytes(buf[:4], "little")
        if magic in (FAT_MAGIC, FAT_CIGAM):
            return self._fat(ins, data)
        order = "<" if magic in (MH_MAGIC, MH_MAGIC_64) else ">"
        return self._thin(ins, data, order)

    def _thin(self, ins, data, order):
        if len(data) < 32:
            ins.confidence = 0.5
            ins.summary = "truncated Mach-O thin header"
            return ins
        cputype, cpusub = struct.unpack(f"{order}II", data[4:12])
        filetype = struct.unpack(f"{order}I", data[12:16])[0]
        ncmds = struct.unpack(f"{order}I", data[16:20])[0]
        magic = int.from_bytes(data[:4], "little")
        bits = 64 if magic in (MH_MAGIC_64, MH_CIGAM_64) else 32
        types = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 5: "core"}
        kind = types.get(filetype, str(filetype))
        ins.summary = f"Mach-O {bits}-bit {kind}, cputype {cputype}, {ncmds} load command(s)"
        ins.add_finding("header", ins.summary, evidence=hexdump(data[:16]))
        o = 32 if bits == 64 else 28
        dylibs, uuid = [], None
        for _ in range(min(ncmds, 4096)):
            if o + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack(f"{order}II", data[o : o + 8])
            if cmdsize <= 0:
                break
            if cmd == LC_UUID and cmdsize >= 24:
                uuid = data[o + 8 : o + 24].hex()
            elif cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB):
                nf = struct.unpack(f"{order}I", data[o : o + 12][0:4])[0]
                dylib_off = struct.unpack(f"{order}I", data[o + 8 : o + 12])[0]
                name = data[o + dylib_off : o + cmdsize].split(b"\x00")[0].decode("latin-1")
                dylibs.append(name)
            elif cmd == LC_SEGMENT_64 and cmdsize >= 72:
                segname = data[o + 8 : o + 24].split(b"\x00")[0].decode("latin-1")
                nsects = struct.unpack(f"{order}I", data[o + 64 : o + 68])[0]
                ins.add_finding("segment", f"LC_SEGMENT_64 {segname!r}, {nsects} section(s), cmdsize {cmdsize}")
            elif cmd == LC_UNIXTHREAD:
                ins.add_finding("entry", "LC_UNIXTHREAD present (entry thread state)")
            o += cmdsize
        if uuid:
            ins.add_finding("uuid", f"LC_UUID: {uuid}")
        if dylibs:
            ins.add_finding("dylibs", f"{len(dylibs)} linked library/libraries",
                            evidence=", ".join(dylibs[:8]))
        low = data[: min(len(data), 1 << 20)].lower()
        if b"go buildinf" in low or b"go1." in low:
            ins.add_finding("toolchain", "Go build detected")
        if b"rustc" in low:
            ins.add_finding("toolchain", "Rust toolchain marker present")
        return ins

    def _fat(self, ins, data):
        if len(data) < 8:
            ins.confidence = 0.5
            ins.summary = "truncated Mach-O fat header"
            return ins
        nfat = struct.unpack(">I", data[4:8])[0]
        archs = []
        o = 8
        for i in range(min(nfat, 32)):
            if o + 20 > len(data):
                break
            cputype, cpusub, off, sz, align = struct.unpack(">IIIII", data[o : o + 20])
            archs.append((cputype, off, sz))
            ins.add_finding("fat-arch", f"cputype {cputype}: offset 0x{off:x}, size 0x{sz:x}, align {2**align}")
            o += 20
        ins.summary = f"Mach-O fat binary with {len(archs)} architecture(s)"
        return ins
