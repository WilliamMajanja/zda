"""Inspector registry, envelopes and shared helpers."""

import hashlib
import os
import sys
from pathlib import Path

SCHEMA = "zda.v1"

_READ_SIZE = 65536


class Inspection:
    """Mutable envelope dict wrapper with helper builders."""

    def __init__(self, fmt, confidence=1.0):
        self.format = fmt
        self.confidence = confidence
        self.summary = ""
        self.findings = []
        self.limits = []

    def add_finding(self, kind, detail, evidence=None, **extra):
        f = {"kind": kind, "detail": detail}
        if evidence is not None:
            f["evidence"] = evidence
        if extra:
            f.update(extra)
        self.findings.append(f)
        return f

    def add_limit(self, text):
        self.limits.append(text)

    def envelope(self, path):
        return {
            "schema": SCHEMA,
            "file": file_facts(path),
            "format": self.format,
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
            "findings": self.findings,
            "limits": self.limits,
        }


def file_facts(path):
    facts = {"path": str(path), "size": os.path.getsize(path)}
    try:
        import stat
        st = os.stat(path)
        facts["mode"] = stat.filemode(st.st_mode)
    except Exception:
        pass
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    facts["sha256"] = h.hexdigest()
    return facts


def err_envelope(path, message):
    return {
        "schema": SCHEMA,
        "file": path,
        "error": message,
    }


class Format:
    """A file format inspector.

    match must consume `buf` (first _READ_SIZE bytes of the file) plus the
    file size and return a confidence in (0, 1], or 0 if it cannot own the
    file. inspect reads the file and returns an Inspection.
    """

    name = ""
    description = ""
    confidence = 1.0
    deps = "stdlib-only"

    def match(self, buf, size):  # pragma: no cover - overridden
        return 0.0

    def inspect(self, path, buf, size):  # pragma: no cover - overridden
        raise NotImplementedError


def identify(path):
    """Return the best-matching (Format, confidence, buf) for a file."""
    apath = Path(path)
    if not apath.is_file():
        raise FileNotFoundError(f"no such file: {apath}")
    with open(apath, "rb") as fh:
        buf = fh.read(_READ_SIZE)
    size = os.path.getsize(apath)
    best, score = None, 0.0
    for cls in REGISTRY:
        fmt = cls()
        try:
            s = float(fmt.match(buf, size))
        except Exception:
            s = 0.0
        if s > score:
            best, score = fmt, s
    return best, score, buf, size


def inspect_file(path, fmt_name=None):
    """Inspect a file; results include evidence and limitations."""
    apath = Path(path)
    best, score, buf, size = identify(apath)
    chosen = best
    if fmt_name is not None:
        fmt_name = fmt_name.lower()
        for cls in REGISTRY:
            f = cls()
            if f.name == fmt_name:
                chosen = f
                break
        else:
            raise ValueError(f"unknown format: {fmt_name!r}; run `zda list-formats`")
    if chosen is None:
        ins = Inspection("unknown", 0.5 + score / 2)
        ins.summary = "unrecognized file (no format owned it with confidence)"
        ins.add_finding(
            "unknown-format",
            "file did not match any registered format signature",
            evidence=f"first bytes: {buf[:16].hex(' ')}",
        )
        ins.add_limit("identification is signature-based; packed/obfuscated files may evade it")
        return ins.envelope(apath)
    ins = chosen.inspect(apath, buf, size)
    if not ins.summary:
        ins.summary = f"{chosen.name} file, no summary available"
    return ins.envelope(apath)


def list_formats():
    entries = [
        {
            "format": cls.name,
            "description": cls.description,
            "confidence": round(float(cls.confidence), 2),
            "deps": cls.deps,
        }
        for cls in REGISTRY
        if cls.name
    ]
    return sorted(entries, key=lambda d: d["format"])


def _u16le(b, o):
    return b[o] | (b[o + 1] << 8)


def _u16be(b, o):
    return (b[o] << 8) | b[o + 1]


def _u32le(b, o):
    return int.from_bytes(b[o : o + 4], "little")

def _u32be(b, o):
    return int.from_bytes(b[o : o + 4], "big")


def _u64le(b, o):
    return int.from_bytes(b[o : o + 8], "little")


def hexdump(b, n=16):
    b = b[:n].hex(" ")
    return b


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def ellipsize(s, n=120):
    return s if len(s) <= n else s[: n - 1] + "…"
