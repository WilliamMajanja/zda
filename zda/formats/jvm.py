"""JVM: static .class file header inspection, stdlib only."""

import struct

from ..registry import Format, Inspection

ACC = {0x1: "public", 0x10: "final", 0x20: "super", 0x400: "abstract", 0x800: "synthetic", 0x1000: "annotation"}


def _java_of(major):
    if major < 45:
        return f"pre-1.1 ({major})"
    if major <= 48:
        return {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4"}.get(major, f"{major}")
    return str(major - 44)


class JvmFormat(Format):
    name = "jvm-class"
    description = "Java/JVM .class files: version, access flags, this/super class, fields, methods"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:4] == b"\xca\xfe\xba\xbe" and len(buf) >= 10:
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("constant-pool entries and member descriptors are not fully decoded; bytecode is not disassembled")
        with open(path, "rb") as fh:
            data = fh.read()
        minor, major = struct.unpack(">HH", data[4:8])
        java = _java_of(major)
        count = struct.unpack(">H", data[8:10])[0]
        ins.summary = f"JVM class file, JDK {java} (class-version {major}.{minor})"
        ins.add_finding("header", ins.summary, evidence=data[:10].hex(" "))
        o = 10
        utf8s, class_by_slot = {}, {}
        n_utf8, n_classes = 0, 0
        for slot in range(1, max(min(count, 65535), 1)):
            if o >= len(data):
                ins.add_finding("truncated", "constant pool truncated")
                break
            tag = data[o]
            o += 1
            if tag == 1:
                n = struct.unpack(">H", data[o : o + 2])[0] if o + 2 <= len(data) else 0
                o += 2
                if o + n <= len(data):
                    utf8s[slot] = data[o : o + n].decode("utf-8", "replace")
                o += n
                n_utf8 += 1
            elif tag in (7,):
                idx = struct.unpack(">H", data[o : o + 2])[0]
                class_by_slot[slot] = idx
                o += 2
                n_classes += 1
            elif tag in (8, 16, 19, 20):
                o += 2
            elif tag in (3, 4):
                o += 4
            elif tag in (5, 6):
                o += 8
                slot += 1
            elif tag in (9, 10, 11, 12, 17, 18):
                o += 4
            elif tag == 15:
                o += 3
            else:
                ins.add_finding("pool", f"unknown constant-pool tag {tag} at slot {slot}")
                break

        def cls_name(class_slot):
            ref = class_by_slot.get(class_slot)
            if ref is None:
                return f"<class#{class_slot}>"
            return utf8s.get(ref, f"<utf8#{ref}>")

        if o + 8 <= len(data):
            acc = struct.unpack(">H", data[o : o + 2])[0]
            flags = [v for k, v in ACC.items() if k & acc]
            this_idx = struct.unpack(">H", data[o + 2 : o + 4])[0]
            super_idx = struct.unpack(">H", data[o + 4 : o + 6])[0]
            ins.add_finding("flags", f"access: {', '.join(flags) or 'package-private'}")
            ins.add_finding("this-class", cls_name(this_idx))
            if super_idx:
                ins.add_finding("super-class", cls_name(super_idx))
            o += 6
            if o + 2 <= len(data):
                n_ifaces = struct.unpack(">H", data[o : o + 2])[0]
                o += 2 + 2 * min(n_ifaces, 64)
                if n_ifaces:
                    ins.add_finding("interfaces", f"{n_ifaces} interface(s) implemented")
            if o + 4 <= len(data):
                n_fields = struct.unpack(">H", data[o : o + 2])[0]
                n_methods = struct.unpack(">H", data[o + 2 : o + 4])[0]
                ins.add_finding("members", f"{n_fields} field(s), {n_methods} method(s)")
        ins.add_finding(
            "pool",
            f"constant pool: {count - 1} slots, {n_utf8} utf8, {n_classes} class-refs",
        )
        return ins
