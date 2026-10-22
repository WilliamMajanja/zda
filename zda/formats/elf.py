"""ELF: static header/section/segment/symbol/note inspection, stdlib only."""

from ..registry import Format, Inspection, _u16le, _u32le, _u64le, hexdump

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOBITS = 1, 2, 3, 6, 8
PT_LOAD, PT_NOTE, PT_INTERP = 1, 4, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552

ETYPE = {1: "REL", 2: "EXEC (non-PIE)", 3: "DYN (PIE/shared)", 4: "CORE"}
MACHINES = {
    3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "aarch64", 243: "RISC-V",
}
STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
NOTE_TYPES = {3: "NT_GNU_BUILD_ID", 4: "NT_GNU_ABI_TAG", 1: "NT_PRSTATUS"}

def note_type_name(t):
    return NOTE_TYPES.get(t, f"type {t}")


class ElfFormat(Format):
    name = "elf"
    description = "ELF executables/objects: header, sections, segments, symbols, notes, mitigations"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 6 and buf[:4] == b"\x7fELF" and buf[4] in (1, 2) and buf[5] in (1, 2):
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("static inspection only; no pseudocode, assembly or decompilation")
        ins.add_limit("symbol and note tables are read but cross-references are not resolved")
        with open(path, "rb") as fh:
            data = fh.read()

        is64 = buf[4] == 2
        isle = buf[5] == 1
        e_type = _u16le(buf, 16)
        e_machine = _u16le(buf, 18)
        type_ = ETYPE.get(e_type, str(e_type))
        machine = MACHINES.get(e_machine, f"machine {e_machine}")
        bits = 64 if is64 else 32
        order = "LE" if isle else "BE"
        ins.summary = f"ELF {bits}-bit {order} {type_}, {machine}"
        ins.add_finding("header", ins.summary, evidence=hexdump(buf[:16]))

        entry = _u64le(buf, 24) if is64 else _u32le(buf, 24)
        ins.add_finding("entry-point", f"e_entry = 0x{entry:x}")

        shoff = _u64le(buf, 40) if is64 else _u32le(buf, 32)
        shnum = _u16le(buf, 60) if is64 else _u16le(buf, 48)
        shentsize = _u16le(buf, 58) if is64 else _u16le(buf, 46)
        sections = parse_sections(data, shoff, shnum, shentsize, is64)
        if sections:
            named = ", ".join(s["name"] or f"[{s['index']}]" for s in sections[:10])
            extra = f", … +{len(sections) - 10} more" if len(sections) > 10 else ""
            ins.add_finding("sections", f"{len(sections)} section table entries; notable: {named}{extra}",
                            evidence=sections[0].get("evidence"))
        else:
            ins.add_finding("sections", "no section header table (stripped or nosey binary)")

        phoff = _u64le(buf, 32) if is64 else _u32le(buf, 28)
        phnum = _u16le(buf, 56) if is64 else _u16le(buf, 44)
        phentsize = _u16le(buf, 54) if is64 else _u16le(buf, 42)
        segs = parse_segments(data, phoff, phnum, phentsize, is64)
        if segs:
            ins.add_finding("segments", f"{len(segs)} program-header segment(s)")
            for seg in segs[:12]:
                if seg["type"] == PT_LOAD:
                    fl = seg["flags"]
                    rwx = ("R" if fl & 4 else "-") + ("W" if fl & 2 else "-") + ("X" if fl & 1 else "-")
                    ins.add_finding("segment", f"loadable: vaddr-off 0x{seg['off']:x}, filesz 0x{seg['filesz']:x}, perms {rwx}")
            for seg in segs:
                if seg["type"] == PT_INTERP:
                    blob = data[seg["off"] : seg["off"] + seg["filesz"]].split(b"\x00")[0]
                    ins.add_finding("interpreter", f"PT_INTERP: {blob.decode('latin-1')}")

        self._mitigations(ins, data, segs, e_type)
        self._notes(ins, data, segs)
        self._imports(ins, data, sections)
        self._embedded_strings(ins, data)
        return ins

    def _mitigations(self, ins, data, segs, e_type):
        nx, relro = None, None
        for seg in segs:
            if seg["type"] == PT_GNU_STACK:
                nx = not (seg["flags"] & 1)
            elif seg["type"] == PT_GNU_RELRO:
                relro = True
        pie = e_type == 3
        canary = b"__stack_chk_fail" in data
        findings = [
            ("NX (non-executable stack)",
             "yes" if nx else ("missing" if nx is None else "no")),
            ("RELRO",
             "yes" if relro else "not present"),
            ("PIE",
             "yes" if pie else "no"),
            ("stack canary (__stack_chk_fail)",
             "yes" if canary else "no"),
        ]
        for name, verdict in findings:
            ins.add_finding("mitigation", f"{name}: {verdict}")
        gaps = [n for (n, v) in findings if v in ("missing", "no", "not present")]
        if gaps:
            ins.add_finding("mitigation-gap", f"may need hardening: {', '.join(gaps)}")

    def _notes(self, ins, data, segs):
        n = 0
        for seg in segs:
            if seg["type"] != PT_NOTE:
                continue
            blob = data[seg["off"] : seg["off"] + seg["filesz"]]
            o = 0
            while o + 12 <= len(blob):
                namesz, descsz, ntype = (
                    int.from_bytes(blob[o : o + 4], "little"),
                    int.from_bytes(blob[o + 4 : o + 8], "little"),
                    int.from_bytes(blob[o + 8 : o + 12], "little"),
                )
                o += 12
                if namesz > 256 or descsz > 1024 * 1024:
                    ins.add_finding("note", "note descriptors skipped (size bound exceeded)")
                    break
                name = blob[o : o + namesz].split(b"\x00")[0]
                desc_off = o + ((namesz + 3) // 4) * 4
                desc = blob[desc_off : desc_off + descsz]
                if name == b"GNU" and ntype == 3:
                    ins.add_finding("elf-note", f"NT_GNU_BUILD_ID: {desc.hex(' ')}", evidence=f"name=GNU type={ntype}")
                elif name == b"GNU":
                    ins.add_finding("elf-note", f"GNU note type {ntype}, desc {desc.hex(' ') if desc else '(empty)'}")
                else:
                    ins.add_finding("elf-note", f"vendor {name.decode('latin-1') or '(blank)'}: {note_type_name(ntype)}")
                o = desc_off + ((descsz + 3) // 4) * 4
                n += 1
        if n == 0:
            ins.add_finding("elf-note", "no PT_NOTE segments (no build-id) — binary may be packed or stripped of notes")

    def _imports(self, ins, data, sections):
        for sec in sections:
            if sec["type"] == SHT_DYNAMIC:
                ins.add_finding(
                    "dynamic",
                    "SHT_DYNAMIC section present — linked against shared libraries",
                )
                break
        if b"libc.so" in data or b"libc.dylib" in data:
            ins.add_finding("library", "references the platform libc — dynamically linked")
        if b"libc.so.6" in data:
            ins.add_finding("library", "references glibc 2.x (libc.so.6)")

    def _embedded_strings(self, ins, data):
        found_strings = 0
        s, last = [], None
        for b in data[:262144]:
            if 32 <= b < 127:
                s.append(b)
            else:
                if len(s) >= 8:
                    found_strings += 1
                    if last is None:
                        last = (bytes(s).decode("latin-1"), found_strings)
                s = []
        if found_strings:
            ins.add_finding(
                "strings",
                f"≥{found_strings} printable ASCII strings ≥8 chars in the first 256 KiB",
                evidence=f"first: {last[0][:80]!r}" if last else None,
            )
            ins.add_limit("string scan is bounded to the first 256 KiB")


def parse_sections(data, shoff, shnum, shentsize, is64):
    out = []
    if not shoff or shoff + 1 > len(data):
        return out
    e = shentsize or (64 if is64 else 40)
    name_idx = _u16le(data, 0x3E)
    strtab = None
    raw = []
    for i in range(shnum):
        base = shoff + i * e
        if base + e > len(data):
            return raw
        if is64:
            name_off, type_, off, size = (
                _u32le(data, base), _u32le(data, base + 4),
                _u64le(data, base + 24), _u64le(data, base + 32),
            )
        else:
            name_off, type_, off, size = (
                _u32le(data, base), _u32le(data, base + 4),
                _u32le(data, base + 16), _u32le(data, base + 20),
            )
        raw.append({"index": i, "nameoff": name_off, "type": type_, "off": off, "size": size})
    if name_idx < len(raw):
        st = raw[name_idx]
        strtab = data[st["off"] : st["off"] + st["size"]]
    def lookup(noff):
        if strtab is None or noff >= len(strtab):
            return ""
        return strtab[noff:].split(b"\x00")[0].decode("latin-1")
    for s in raw:
        s2 = dict(s)
        s2["name"] = lookup(s["nameoff"])
        out.append(s2)
    return out


def parse_segments(data, phoff, phnum, phentsize, is64):
    out = []
    if not phoff:
        return out
    e = phentsize or (56 if is64 else 32)
    for i in range(phnum):
        base = phoff + i * e
        if base + e > len(data):
            break
        p_type = _u32le(data, base)
        if is64:
            p_flags = _u32le(data, base + 4)
            p_off, p_filesz = _u64le(data, base + 8), _u64le(data, base + 32)
        else:
            p_flags = _u32le(data, base + 24)
            p_off, p_filesz = _u32le(data, base + 4), _u32le(data, base + 16)
        out.append({"type": p_type, "flags": p_flags, "off": p_off, "filesz": p_filesz})
    return out
