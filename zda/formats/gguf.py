"""GGUF: static header/metadata/tensor-declaration inspection, stdlib only."""

import struct

from ..registry import Format, Inspection

GGUF_MAGIC = b"GGUF"
FTYPES = {
    0: "u8", 1: "i8", 2: "u16", 3: "i16", 4: "u32", 5: "i32", 6: "f32",
    7: "bool", 8: "string", 9: "array", 10: "u64", 11: "i64", 12: "f64",
}
SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
GGML_DTYPE = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 8: "I64",
    24: "Q8_0", 30: "Q2_K", 31: "Q3_K", 32: "Q4_K", 33: "Q5_K",
    34: "Q6_K", 35: "Q8_K", 36: "BF16",
}
ALIGNMENT = 32
MAX_KVS = 1024
MAX_TENSORS = 4096
MAX_STR = 4096
MAX_ARRAY = 4 * 1024 * 1024


class _Eof(Exception):
    pass


class _Cur:
    def __init__(self, fh):
        self.fh = fh
        self.o = 0

    def take(self, n):
        self.fh.seek(self.o)
        b = self.fh.read(n)
        if len(b) < n:
            raise _Eof
        self.o += n
        return b

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def u32s(self, n):
        return struct.unpack(f"<{min(n, 32)}I", self.take(4 * min(n, 32)))

    def u64s(self, n):
        return struct.unpack(f"<{min(n, 32)}Q", self.take(8 * min(n, 32)))

    def string(self):
        n = self.u64()
        if n > MAX_STR:
            raise ValueError(f"string length {n} exceeds bound")
        return self.take(n).decode("utf-8", "replace")

    def align(self):
        self.o = (self.o + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT


class GgufFormat(Format):
    name = "gguf"
    description = "GGUF model files: magic/version, tensor declarations, key-value metadata"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:4] == GGUF_MAGIC and len(buf) >= 8 and 1 <= buf[4] <= 8:
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("weights are never read or verified; only header declarations are walked")
        ins.add_limit("metadata arrays longer than the bound are skipped, not enumerated")
        with open(path, "rb") as fh:
            version, ntensors, nkvs = struct.unpack("<IQQ", buf[4:24])
            ins.summary = f"GGUF v{version}, {ntensors} tensor(s), {nkvs} metadata kv(s)"
            ins.add_finding("header", ins.summary, evidence=buf[:24].hex(" "))
            c = _Cur(fh)
            c.o = 24
            try:
                for i in range(min(nkvs, MAX_KVS)):
                    key = c.string()
                    vtype = c.u32()
                    shown = self._kv_value(c, vtype)
                    ins.add_finding("metadata", f"{key} = {shown}")
                if nkvs > MAX_KVS:
                    ins.add_finding("metadata", f"... kv list bound-reached at {MAX_KVS}")
            except (_Eof, ValueError, struct.error) as e:
                ins.add_finding("metadata-truncated", f"header parse stopped early: {e}")
            # tensor list starts after the metadata; the file cursor may be off due
            # to skipped arrays, so do not try to walk tensors unless all kvs parsed
            try:
                for t in self._tensors(c, ntensors):
                    ins.add_finding(
                        "tensor",
                        f"{t['name']!r}: {t['n_dims']}-d shape {t['shape']}, type {t['dtype']}",
                    )
            except (_Eof, ValueError, struct.error) as e:
                ins.add_finding("tensors-partial", f"tensor list parse stopped early: {e}")
        return ins

    def _kv_value(self, c, vtype):
        if vtype == 8:
            return f"{c.string()!r} (string)"
        if vtype == 9:
            atype = c.u32()
            count = c.u64()
            if atype == 8:
                n = count if count <= 32 else 32
                vals = [c.string() for _ in range(n)]
                self._skip_strings(c, count - n)
                return f"array of {count}: [{', '.join(repr(v) for v in vals[:4])}, …]"
            if atype in SIZES:
                c.o += SIZES[atype] * count if count <= MAX_ARRAY else MAX_ARRAY
                return f"array of {count} {FTYPES[atype]}"
            return f"array of {count} of unknown type {atype}"
        if vtype in SIZES:
            b = c.take(SIZES[vtype])
            val = int.from_bytes(b, "little")
            if vtype == 7:
                return f"bool({bool(val)})"
            return f"{val} ({FTYPES[vtype]})"
        return f"<unhandled value type {vtype}>"

    def _skip_strings(self, c, n):
        for _ in range(min(max(n, 0), 1024)):
            ln = c.u64()
            c.o += min(ln, MAX_STR)

    def _tensors(self, c, ntensors):
        out = []
        for i in range(min(ntensors, MAX_TENSORS)):
            name_start = c.o
            n_dims = c.u32()
            name_len = c.u32()
            if name_len > 512:
                raise ValueError(f"tensor name length {name_len} too large")
            name = c.take(name_len).decode("utf-8", "replace")
            dims = c.u64s(min(n_dims, 16)) if n_dims else ()
            if n_dims > 16:
                raise ValueError(f"tensor dim count {n_dims} unsupported here")
            dtype = c.u32()
            offset = c.u64()
            c.o = name_start + (8 + name_len + 8 * n_dims + 12)
            c.align()
            out.append({
                "name": name,
                "n_dims": n_dims,
                "shape": list(dims[:4]),
                "dtype": GGML_DTYPE.get(dtype, str(dtype)),
            })
        return out
