"""safetensors: header JSON, tensor declarations, stdlib only."""

import json
import struct

from ..registry import Format, Inspection


class SafetensorsFormat(Format):
    name = "safetensors"
    description = "safetensors model files: header JSON, tensor dtypes/shapes, byte offset accounting"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 9:
            n = struct.unpack("<Q", buf[:8])[0]
            if 0 < n < 1 << 28 and buf[8:9] == b"{":
                return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("weights are never read or verified; only declarations from the header JSON are parsed")
        with open(path, "rb") as fh:
            n = struct.unpack("<Q", fh.read(8))[0]
            if n > 8 * 1024 * 1024:
                ins.add_finding("header-error", f"header JSON of {n} bytes exceeds the 8 MiB bound")
                ins.confidence = 0.5
                return ins
            blob = fh.read(n)
            try:
                hdr = json.loads(blob.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                ins.add_finding("header-error", f"header JSON decode failed: {e}")
                return ins
        meta = hdr.pop("__metadata__", None)
        tensors = sorted(hdr.items())
        dtypes = sorted({v["dtype"] for _, v in tensors})
        ins.summary = f"safetensors, {len(tensors)} tensor(s), dtypes: {', '.join(dtypes)}, header {n} bytes"
        ins.add_finding("header", ins.summary, evidence=f"{n}-byte header JSON at offset 8")
        if meta:
            ins.add_finding("metadata", f"__metadata__: " + json.dumps(meta)[:160])
        elements = 0
        byte_elems = 0
        for name, t in tensors[:64]:
            shape = t.get("shape", [])
            n_el: int = 1
            for s in shape:
                n_el *= s
            elements += n_el
            byte_elems += n_el * _dtype_size(t.get("dtype"))
            ins.add_finding(
                "tensor",
                f"{name!r}: {t.get('dtype', '?')} {shape}",
                evidence=f"data_offsets {t.get('data_offsets')}",
            )
        if len(tensors) > 64:
            ins.add_finding("tensor", f"... +{len(tensors) - 64} more tensor declarations")
        if tensors:
            ins.add_finding(
                "declared",
                f"declared total {elements} element(s), ~{byte_elems} bytes of tensor data (dtype-sized sums)",
            )
            ins.add_finding(
                "coverage",
                f"file size {size}, header+ {byte_elems} covers {min(100, int(byte_elems / max(1, size) * 100))}% of file",
            )
        return ins


def _dtype_size(dt):
    return {
        "BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1,
        "U16": 2, "I16": 2, "F16": 2, "BF16": 2,
        "U32": 4, "I32": 4, "F32": 4,
        "U64": 8, "I64": 8, "F64": 8,
    }.get(str(dt), 4)
