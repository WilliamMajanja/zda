"""Images: PNG/JPEG/GIF/WebP/BMP static metadata, stdlib only."""

import struct

from ..registry import Format, Inspection


class PngFormat(Format):
    name = "png"
    description = "PNG images: IHDR dimensions/color type, chunk inventory, text and tonal metadata"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:8] == b"\x89PNG\r\n\x1a\n":
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("pixel data is not decoded; metadata chunks and dimensions only")
        with open(path, "rb") as fh:
            data = fh.read()
        if not (len(data) >= 33):
            return self._trunc(ins, buf)
        w, h = struct.unpack(">II", data[16:24])
        bd, ct, _comp, _fil, interlace = data[24], data[25], data[26], data[27], data[28]
        ctnames = {0: "grayscale", 2: "rgb", 3: "palette", 4: "gray+alpha", 6: "rgba"}
        col = ctnames.get(ct, f"type-{ct}")
        ins.summary = f"PNG {w}x{h}, {col}, bit-depth {bd}, {'interlaced' if interlace else 'progressive-free'}"
        ins.summary = f"PNG {w}x{h}, {col}, bit-depth {bd}{', interlaced' if interlace else ''}"
        ins.add_finding("ihdr", ins.summary, evidence=buf[:8].hex(" "))
        chunks = []
        o = 8
        n = 0
        while o + 8 <= len(data) and n < 256:
            ln, tag = struct.unpack(">I", data[o : o + 4]), data[o + 4 : o + 8]
            ln = ln[0]
            tag_s = tag.decode("latin-1")
            chunks.append((tag_s, ln))
            o += 12 + ln
            n += 1
            if o + 8 > len(data):
                break
        crit = [c for c, _ in chunks if c[0].isupper()]  # noqa: F841  (kept for JSON consumers)
        ins.add_finding("chunks", f"{n} chunk(s): " + ", ".join(f"{c}({ln})" for c, ln in chunks[:12]))
        for tag, ln in chunks:
            if tag in ("iTXt", "tEXt", "zTXt"):
                ins.add_finding("text", f"{tag} chunk present ({ln} bytes)")
            elif tag == "sRGB" or tag == "iCCP":
                ins.add_finding("color", f"{tag} chunk present")
            elif tag == "eXIf":
                ins.add_finding("metadata", "eXIf chunk present")
        return ins

    def _trunc(self, ins, buf):
        ins.confidence = 0.7
        ins.summary = "PNG magic found but the file is too short to contain IHDR"
        ins.add_finding("header", ins.summary, evidence=buf[:8].hex(" "))
        return ins


class JpegFormat(Format):
    name = "jpeg"
    description = "JPEG images: SOF dimensions, marker inventory, JFIF/Exif and quantization presence"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:2] == b"\xff\xd8" and buf[2:3] == b"\xff":
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("pixel data is not decoded; markers and header fields only")
        with open(path, "rb") as fh:
            data = fh.read()
        o = 2
        sof = None
        markers = []
        while o + 4 <= len(data):
            if data[o] != 0xFF:
                break
            m = data[o + 1]
            if m == 0xD8:
                o += 2
                continue
            if m in (0x01, 0xD0) or 0xD0 <= m <= 0xD7:
                o += 2
                continue
            ln = struct.unpack(">H", data[o + 2 : o + 4])[0]
            if o + 2 + ln > len(data):
                ins.add_finding("markers", "stream truncated")
                break
            markers.append((m, ln, o))
            if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                sof = (m, ln, o)
            o += 2 + ln
            if m == 0xDA:
                break
        jfif = b"JFIF" in data[:32]
        exif = b"Exif" in data[:32]
        if sof:
            bits = data[sof[2] + 5]
            h = struct.unpack(">H", data[sof[2] + 6 : sof[2] + 8])[0]
            w = struct.unpack(">H", data[sof[2] + 8 : sof[2] + 10])[0]
            ncomp = data[sof[2] + 10]
        else:
            bits = h = w = ncomp = 0
        if w and h:
            ins.summary = f"JPEG {w}x{h}, {ncomp} component(s), {bits}-bit samples"
        else:
            ins.summary = "JPEG (no SOF parsed; may be truncated)"
        ins.add_finding("header", ins.summary, evidence=data[:4].hex(" "))
        if jfif:
            ins.add_finding("jfif", "APP0/JFIF header present")
        if exif:
            ins.add_finding("exif", "EXIF header present")
        if len(markers) >= 2:
            ins.add_finding("markers", f"first {len(markers)} marker(s): " + ", ".join(f"0x{m:02x}({ln}B)" for m, ln, _ in markers[:8]))
        if sof:
            ins.add_finding("sof", f"SOF marker 0x{sof[0]:02x} at offset 0x{sof[2]:x}")
        return ins


class GifFormat(Format):
    name = "gif"
    description = "GIF images: header, dimensions, color table, frames, metadata blocks"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:6] in (b"GIF87a", b"GIF89a"):
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("frame pixels are not decoded; header and block types only")
        with open(path, "rb") as fh:
            data = fh.read()
        version = data[3:6].decode()
        w, h, flags = struct.unpack("<HHB", data[6:11])
        gct = (flags >> 7) & 1
        ncolors = 2 ** ((flags & 7) + 1) if gct else 0
        if gct:
            ins.summary = f"GIF {w}x{h}, {version}, {ncolors}-color global table"
        else:
            ins.summary = f"GIF {w}x{h}, {version}"
        ins.add_finding("header", ins.summary, evidence=data[:6].hex(" "))
        o = 13 + (3 * ncolors if gct else 0)
        nframes = 0
        has_gce = has_ct = has_text = has_app = False
        netscape = False
        while o < len(data):
            block = data[o]
            if block == 0x21:
                sub = data[o + 1] if o + 2 <= len(data) else 0
                if sub == 0xFF:
                    has_app = True
                    if data[o : o + 11] == b"\x21\xff\x0bNETSCAPE":
                        netscape = True
                elif sub == 0xFE:
                    has_text = True
                elif sub == 0xF9:
                    has_gce = True
                elif sub == 0x01:
                    has_ct = True
                # skip sub-blocks
                o += 2
                while o < len(data) and data[o] != 0:
                    o += 1 + data[o]
                o += 1
            elif block == 0x2C:
                nframes += 1
                lf = data[o + 9] if o + 10 <= len(data) else 0
                if lf & 0x80:
                    local_ct = 2 ** ((lf & 7) + 1) * 3
                else:
                    local_ct = 0
                o += 10 + local_ct
                while o < len(data) and data[o] != 0:
                    o += 1 + data[o]
                o += 1
            elif block == 0x3B:
                break
            else:
                o += 1
        ins.add_finding("frames", f"{nframes} frame(s)")
        if has_app:
            ins.add_finding("app-ext", "application extension present" + (" (Netscape animation)" if netscape else ""))
        if has_gce:
            ins.add_finding("gce", "graphic-control extension(s) present (delays/transparency)")
        if has_ct:
            ins.add_finding("comment", "comment extension(s) present")
        if size > 0 and nframes > 1:
            ins.add_finding("animated", f"multiple frames ({nframes}) — animated GIF")
        return ins


class WebPFormat(Format):
    name = "webp"
    description = "WebP images: VP8/VP8L-frame, dimensions, metadata markers"
    confidence = 1.0

    def match(self, buf, size):
        if len(buf) >= 12 and buf[:4] == b"RIFF" and buf[8:12] == b"WEBP":
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("pixel data is not decoded; container headers only")
        with open(path, "rb") as fh:
            data = fh.read()
        riff_size = struct.unpack("<I", data[4:8])[0]
        chunk = data[12:16]
        w = h = 0
        codec = ""
        if chunk == b"VP8 ":
            w, h = struct.unpack("<HH", data[26:30])
            w &= 0x3FFF
            h &= 0x3FFF
            codec = "lossy VP8"
        elif chunk == b"VP8L":
            bits = struct.unpack("<I", data[21:25])[0]
            w = (bits & 0x3FFF) + 1
            h = ((bits >> 14) & 0x3FFF) + 1
            codec = "lossless VP8L"
        elif chunk == b"VP8X":
            w = 1 + int.from_bytes(data[24:27], "little")
            h = 1 + int.from_bytes(data[27:30], "little")
            codec = "extended VP8X"
        ins.summary = f"WebP {codec}, {w}x{h}" if w else f"WebP {codec}"
        ins.add_finding("header", ins.summary, evidence=data[:16].hex(" "))
        if b"EXIF" in data[:64]:
            ins.add_finding("exif", "EXIF chunk present")
        if b"XMP " in data[:96]:
            ins.add_finding("xmp", "XMP metadata chunk present")
        if data[:4] == b"RIFF" and riff_size + 8 != size:
            ins.add_finding("riff-size", f"RIFF size 0x{riff_size:x} + 8 != file size {size} (truncation or padding)")
        return ins
