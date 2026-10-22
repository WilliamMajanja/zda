"""ZIP-based formats: apk/jar/ooxml/epub/odf/war/zip inventory, stdlib only."""

import zipfile

from ..registry import Format, Inspection


def ooxml_kind(zf):
    names = zf.namelist()
    if any(n.startswith("word/") for n in names):
        return "docx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    if any(n.startswith("xl/") for n in names):
        return "xlsx"
    if any(n.startswith("visio/") for n in names):
        return "vsdx"
    return "ooxml"


def media_kind(zf):
    try:
        with zf.open("mimetype") as fh:
            blob = fh.read(64)
    except KeyError:
        return "media"
    if b"epub" in blob:
        return "epub"
    if b"opendocument.spreadsheet" in blob:
        return "ods"
    if b"opendocument.text" in blob:
        return "odt"
    if b"opendocument.presentation" in blob:
        return "odp"
    return "media"


COMPRESSION = {0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma"}


class ZipFormat(Format):
    name = "zip"
    description = "ZIP containers: apk, jar, docx/xlsx/pptx, epub/odf, war, plain zip; inventory + metadata"
    confidence = 0.95

    def match(self, buf, size):
        if buf[:4] == b"PK\x03\x04":
            return 0.98
        if buf[:4] == b"PK\x05\x06":
            return 0.95
        return 0.0

    def _kind(self, zf):
        names = set(zf.namelist())
        if "AndroidManifest.xml" in names:
            return "apk"
        if "[Content_Types].xml" in names:
            return ooxml_kind(zf)
        if "mimetype" in names:
            return media_kind(zf)
        if "META-INF/MANIFEST.MF" in names or any(n.endswith(".class") for n in names):
            return "jar"
        if any(n.startswith("WEB-INF/") for n in names):
            return "war"
        return "zip"

    def _confidence_for(self, kind):
        return {
            "apk": 1.0, "jar": 1.0, "docx": 1.0, "xlsx": 1.0, "pptx": 1.0,
            "epub": 1.0, "odt": 1.0, "ods": 1.0, "odp": 1.0, "war": 0.95, "zip": 0.9,
        }.get(kind, 0.9)

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("inventory only; no bytecode decompilation, no manifest decryption, no on-disk extraction")
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            kind = self._kind(zf)
            total_uncomp = sum(zi.file_size for zi in zf.infolist())
            methods = sorted({zi.compress_type for zi in zf.infolist()})
            ins.add_finding("inventory", f"{len(names)} entry/entries, {total_uncomp} bytes uncompressed total")
            ins.confidence = self._confidence_for(kind)
            ins.format = kind
            ins.add_finding("container", f"subtype: {kind}")
            if kind == "apk":
                self._apk(ins, names)
            elif kind == "jar":
                self._jar(ins, zf, names)
            elif kind in ("docx", "xlsx", "pptx", "vsdx"):
                self._ooxml(ins, names, kind)
            for zi in zf.infolist()[:14]:
                if zi.comment:
                    ins.add_finding(
                        "entry-comment",
                        f"{zi.filename!r}: {zi.comment.decode('latin-1')[:60]!r}",
                    )
            ins.add_finding(
                "compression",
                "methods used: " + ", ".join(f"'{c}'=={COMPRESSION.get(c, c)}" for c in methods),
            )
            if any(zi.flag_bits & 0x1 for zi in zf.infolist()):
                ins.add_finding("encryption", "encrypted entries flagged — password-protected archive")
        return ins

    def _apk(self, ins, names):
        dexn = sorted(n for n in names if n.endswith(".dex"))
        if dexn:
            ins.add_finding("dex", f"{len(dexn)} dalvik-executable shard(s): {', '.join(dexn[:6])}")
        if "META-INF/MANIFEST.MF" in names:
            ins.add_finding("v1-manifest", "META-INF/MANIFEST.MF present (v1 jar signature)")
        if any(n.endswith((".RSA", ".DSA", ".EC")) for n in names if n.startswith("META-INF/")):
            ins.add_finding("apksig-v1", "X.509 signature blocks present in META-INF (v1 signing scheme)")
        if "resources.arsc" in names:
            ins.add_finding("resources", "resources.arsc present (compiled resource table)")
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and len(n.split("/")) > 2})
        if abis:
            ins.add_finding("native-libs", f"native ABI folders: {', '.join(abis)}")

    def _jar(self, ins, zf, names):
        classes = [n for n in names if n.endswith(".class")]
        ins.add_finding("classes", f"{len(classes)} java-class file(s)")
        try:
            with zf.open("META-INF/MANIFEST.MF") as fh:
                blob = fh.read(2048).decode("latin-1", "ignore")
        except KeyError:
            return
        for attr in ("Main-Class", "Implementation-Version", "Manifest-Version", "Multi-Release",
                     "Premain-Class", "Automatic-Module-Name", "Bukkit-Main"):
            for line in blob.splitlines():
                if line.lower().startswith((attr.lower() + ":", attr.lower() + " :")):
                    ins.add_finding("manifest", line.strip())
                    break

    def _ooxml(self, ins, names, kind):
        parts = [n for n in names if n.startswith(("word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"))]
        if parts:
            ins.add_finding("content", f"document part(s): {', '.join(parts[:5])}")
        if any("vbaProject" in n for n in names):
            ins.add_finding("macro", "VBA project (vbaProject.bin) present")
        if any(n.startswith("word/externalTarget") or n.endswith(".baseline") for n in names):
            ins.add_finding("external", "external relationships present in document package")
