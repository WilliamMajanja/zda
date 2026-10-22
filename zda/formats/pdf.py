"""PDF: static header/structure inspection, stdlib only."""

import re

from ..registry import Format, Inspection


class PdfFormat(Format):
    name = "pdf"
    description = "PDF documents: version, page count, encryption, linearization, producer"
    confidence = 0.95

    def match(self, buf, size):
        if len(buf) >= 5 and buf[:5] == b"%PDF-":
            return 0.99
        if b"%PDF-" in buf[:1024]:
            return 0.9
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("static scan; page count is a structural count and may double-count object streams")
        ins.add_limit("JS/launch actions are detected by keyword only, not sandbo xed")
        with open(path, "rb") as fh:
            data = fh.read()
        end_nl = data.find(b"\n", 5, 12)
        version = (data[5 : end_nl] if end_nl > 0 else b"").decode("latin-1", "replace").strip() or "unknown"
        trailer_xref = data.rfind(b"startxref")
        eof = data.rfind(b"%%EOF")
        pagemode = re.findall(rb"/Type\s*/Page(?![a-zA-Z])", data)
        ins.summary = f"PDF {version}, {len(pagemode)} page object(s), {size} bytes"
        ins.add_finding("header", ins.summary, evidence=data[:16].decode("latin-1", "replace"))
        if data.rfind(b"linearized") >= 0:
            ins.add_finding("linearized", "linearized (fast-web-view) header present")
        if trailer_xref >= 0 and eof >= 0:
            ins.add_finding("trailer", "startxref + %%EOF trailer present (normal termination)")
        else:
            ins.add_finding("trailer", "missing startxref/%%EOF — file may be truncated or repaired")
        if b"/Encrypt" in data:
            ins.add_finding("encryption", "/Encrypt dictionary present — encrypted document")
        js = b"/JavaScript" in data or b"/JS" in data
        if js:
            ins.add_finding("javascript", "JavaScript action referenced (/JavaScript or /JS)")
        launch = b"/Launch" in data or b"/EmbeddedFile" in data
        if launch:
            ins.add_finding("embedded", "/Launch or /EmbeddedFile present")
        for m in re.finditer(rb"/Producer\s*\((.{0,80}?)\)", data):
            ins.add_finding("producer", f"Producer: {m.group(1).decode('latin-1', 'replace')!r}")
            break
        for m in re.finditer(rb"/Title\s*\((.{0,80}?)\)", data):
            ins.add_finding("title", f"Title: {m.group(1).decode('latin-1', 'replace')!r}")
            break
        ins.add_finding("page-objects", f"{len(pagemode)} bare /Type /Page object reference(s) (see limits)")
        return ins
