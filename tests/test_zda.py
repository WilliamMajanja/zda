"""ZDA unit tests; fixtures are generated on the fly with stdlib-only code."""

import io
import json
import os
import sqlite3
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import zda  # noqa: E402
from zda.registry import inspect_file, identify, list_formats  # noqa: E402

HERE = Path(tempfile.gettempdir()) / "zda_fixtures"
HERE.mkdir(exist_ok=True)


def _write(name, data):
    p = HERE / name
    p.write_bytes(data)
    return str(p)


class ElfFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import subprocess
        src = HERE / "hello.c"
        src.write_text("int main(void){return 0;}\n")
        cls.path = HERE / "hello.elf"
        subprocess.run(["gcc", "-fno-plt", "-o", str(cls.path), str(src),
                        "-Wl,-z,relro,-z,now"], check=True)

    def test_identified(self):
        e = inspect_file(str(self.path))
        self.assertEqual(e["format"], "elf")
        self.assertGreater(e["confidence"], 0.9)
        self.assertTrue(any(f["kind"] == "mitigation" for f in e["findings"]))
        self.assertTrue(any(f["kind"] == "sections" for f in e["findings"]))

    def test_mitigations(self):
        e = inspect_file(str(self.path))
        got = {f["detail"] for f in e["findings"] if f["kind"] == "mitigation"}
        self.assertTrue(any("NX" in g and "yes" in g for g in got))
        self.assertTrue(any("canary" in g for g in got))
        self.assertTrue(any("PIE" in g for g in got))


class PeFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
        pe = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 2, 99, 0, 0, 240, 22)
        opt = struct.pack("<HBBIIIIIIIIII", 0x10B, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        opt += struct.pack("<IIIII", 0, 0, 0, 0, 0)  # data dirs (5 of 16; rest zeros)
        opt += b"\x00" * 92
        opt += b"MSVCRT.dll\0"
        sec = b".text".ljust(8, b"\x00")
        sec += struct.pack("<IIII", 0x10, 0x1000, 0x10, 0x400)
        sec += struct.pack("<II", 0, 0x60000020)
        sec += b"\x00" * 12
        blob = dos + pe + opt + sec + b"A" * 16
        cls.path = _write("stub.exe", blob)

    def test_identified(self):
        e = inspect_file(str(self.path))
        self.assertIn("PE", e["summary"])
        self.assertEqual(e["format"], "pe")
        self.assertTrue(any("MZ" in json.dumps(f) or "header" in f["kind"] for f in e["findings"]))


class ZipFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.example.Main\n")
            zf.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe" + b"\x00" * 8)
            zf.writestr("res.txt", b"hi")
        cls.jar = _write("app.jar", buf.getvalue())

    def test_jar_identified(self):
        e = inspect_file(self.jar)
        self.assertEqual(e["format"], "jar")
        self.assertTrue(any(f["kind"] == "manifest" and "Main-Class" in f["detail"] for f in e["findings"]))
        self.assertTrue(any(f["kind"] == "classes" and "1 java-class" in f["detail"] for f in e["findings"]))


class SqliteFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = HERE / "t.db"
        if p.exists():
            p.unlink()
        con = sqlite3.connect(str(p))
        con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        con.execute("INSERT INTO users (name) VALUES ('ada'), ('grace')")
        con.execute("CREATE INDEX idx_u ON users(name)")
        con.commit()
        con.close()
        cls.path = str(p)

    def test_schema(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "sqlite")
        self.assertTrue(any("users" in f["detail"] and "row" in f["detail"].lower() for f in e["findings"]))
        self.assertTrue(any("index" in f["detail"].lower() for f in e["findings"]))


class GgufFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        buf = io.BytesIO()
        buf.write(b"GGUF")
        buf.write(struct.pack("<IQQ", 3, 2, 3))
        def key(s):
            b = s.encode()
            buf.write(struct.pack("<Q", len(b)))
            buf.write(b)
        def kvs_string(s, val):
            key(s)
            buf.write(struct.pack("<I", 8))
            vb = val.encode()
            buf.write(struct.pack("<Q", len(vb)))
            buf.write(vb)
        def kvs_u32(s, val):
            key(s)
            buf.write(struct.pack("<I", 4))
            buf.write(struct.pack("<I", val))
        kvs_string("general.architecture", "llama")
        kvs_u32("llama.block_count", 32)
        kvs_string("tokenizer.model", "every-model-makes-it")
        offs = [0]
        def tensor(name, dims, dtype):
            nb = name.encode()
            buf.write(struct.pack("<II", len(dims), len(nb)))
            buf.write(nb)
            buf.write(struct.pack(f"<{len(dims)}Q", *dims))
            buf.write(struct.pack("<IQ", dtype, offs[0]))
            buf.write(b"\x00" * ((-buf.tell()) % 32))
            offs[0] += 8
        tensor("blk.0.attn_q.weight", (2^10, 2^20), 30)
        tensor("blk.1.attn_k.weight", (32,), 1)
        data = buf.getvalue()
        cls.path = _write("m.gguf", data)

    def test_header_and_tensors(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "gguf")
        self.assertIn("2 tensor(s)", e["summary"])
        det = [f["detail"] for f in e["findings"] if f["kind"] == "metadata"]
        self.assertTrue(any("general.architecture" in d for d in det))
        ts = [f["detail"] for f in e["findings"] if f["kind"] == "tensor"]
        self.assertTrue(any("blk.1.attn_k.weight" in t for t in ts))


class SafetensorsFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from json import dumps
        hdr = {
            "w1": {"dtype": "F32", "shape": [4, 8], "data_offsets": [0, 128]},
            "w2": {"dtype": "BF16", "shape": [4, 8], "data_offsets": [128, 192]},
        }
        blob = dumps(hdr).encode()
        data = struct.pack("<Q", len(blob)) + blob + b"\x00" * 192
        cls.path = _write("m.safetensors", data)

    def test_declarations(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "safetensors")
        det = [f["detail"] for f in e["findings"] if f["kind"] == "tensor"]
        self.assertEqual(len(det), 2)
        self.assertTrue(any("F32" in d for d in det))
        self.assertTrue(any("declared total" in f["detail"] for f in e["findings"] if f["kind"] == "declared"))


class WasmFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def leb(n):
            out = bytearray()
            while True:
                b = n & 0x7F
                n >>= 7
                if n:
                    out.append(b | 0x80)
                else:
                    out.append(b)
                    return bytes(out)
        def section(i, payload):
            return bytes([i]) + leb(len(payload)) + payload
        define = leb(1) + bytes([0x60]) + leb(1) + bytes([0x7F]) + leb(1) + bytes([0x7F])
        functions = leb(1) + leb(0)
        imps = leb(1) + leb(3) + b"env" + leb(3) + b"mem" + bytes([2, 0, 1])
        exps = leb(1) + leb(4) + b"echo" + bytes([0, 0])
        blob = b"\x00asm\x01\0\0\0" + section(1, define) + section(3, functions) + section(2, imps) + section(7, exps)
        cls.path = _write("m.wasm", blob)

    def test_sections(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "wasm")
        secs = " ".join(f["detail"] for f in e["findings"] if f["kind"] == "section")
        self.assertIn("type", secs)
        self.assertIn("export", secs)
        self.assertTrue(any("echo" in f["detail"] for f in e["findings"]))
        self.assertTrue(any("mem" in f["detail"] for f in e["findings"]))


class PdfFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        body = b"""1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R >> endobj
4 0 obj << /Producer (fcicfg-gfda) >> endobj
"""
        data = b"%PDF-1.7\n" + body + b"xref\n0 5\nstartxref\n%%EOF\n"
        cls.path = _write("doc.pdf", data)

    def test_pages(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "pdf")
        self.assertIn("PDF 1.7", e["summary"])
        self.assertTrue(any("1 page object" in f["detail"] for f in e["findings"]))
        self.assertTrue(any("startxref" in f["detail"] for f in e["findings"]))


class JvmFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pool = bytearray()

        def u8(slot_bytes):
            pool.append(1)
            pool.extend(struct.pack(">H", len(slot_bytes)))
            pool.extend(slot_bytes)

        def dcls(utf8_idx):
            pool.append(7)
            pool.extend(struct.pack(">H", utf8_idx))

        u8(b"com/example/Main")
        dcls(1)
        u8(b"java/lang/Object")
        dcls(3)
        u8(b"Code")
        u8(b"()Ljava/lang/String;")
        data = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 7)
        data += bytes(pool)
        data += struct.pack(">HHHH", 0x21, 2, 4, 0)
        data += struct.pack(">HH", 0, 1)
        cls.path = _write("Main.class", data)

    def test_names(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "jvm-class")
        txt = json.dumps(e)
        self.assertIn("com/example/Main", txt)
        self.assertIn("java/lang/Object", txt)
        self.assertIn("0 field(s), 1 method(s)", txt)


class EvmFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # dispatcher: PUSH4 sel; EQ; PUSH1 0x60; MUL; CALLDATASIZE; JUMPI via push/shl
        code = bytes.fromhex("63AABBCCDD14") + bytes([0x14])
        code += bytes.fromhex("6050")
        code += bytes.fromhex("6000") + bytes.fromhex("52")
        code += bytes.fromhex("6020") + bytes.fromhex("54")
        code += bytes.fromhex("6000808080") + bytes.fromhex("5a") + bytes.fromhex("f1")
        code += bytes.fromhex("5b") + bytes.fromhex("60ff") + bytes.fromhex("77") + b"\xff" * 7  # PUSH27
        # raw landing stub
        code += bytes.fromhex("00")
        cls.path = _write("c.hex", code.hex().encode())

    def test_selectors(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "evm")
        det = [f["detail"] for f in e["findings"] if f["kind"] == "selectors"]
        self.assertTrue(det and "0xaabbccdd" in det[0])


class BeamFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        atoms = [b"test_mod", b"main", b"other"]
        at = struct.pack(">I", len(atoms)) + b"".join(
            struct.pack(">H", len(a)) + a for a in atoms
        )
        pad = b"\x00" * ((-len(at)) % 2)
        chunks = b"AtU8" + struct.pack(">I", len(at) + len(pad)) + at + pad
        chunks += b"ExpT" + struct.pack(">I", 4) + struct.pack(">I", 1)
        chunks += b"ImpT" + struct.pack(">I", 4) + struct.pack(">I", 2)
        body = chunks
        data = b"FOR1" + struct.pack(">I", len(body)) + b"BEAM" + body
        cls.path = _write("m.beam", data)

    def test_atoms_and_exports(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "beam")
        det = json.dumps(e)
        self.assertIn("test_mod", det)
        self.assertIn("1 exported", det)


class PckFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = [("res://dir/file.txt", 16, 1), ("res://other.png", 0, 0)]
        blob = b"GDPC"
        blob += struct.pack("<IIII", 2, 4, 2, 3)
        blob += struct.pack("<I", 0)
        blob += struct.pack("<Q", 0)
        blob += struct.pack("<I", len(files))
        for name, sz, codec in files:
            nb = name.encode()
            pad = (-len(nb)) % 4
            padded = nb + b"\x00" * (pad if pad else 4) if len(nb) % 4 == 0 else nb + b"\x00" * pad
            if len(nb) % 4 == 0:
                padded = nb + b"\x00\x00\x00\x00"
            blob += struct.pack("<I", len(padded))
            blob += padded
            blob += struct.pack("<QQ", 2048, sz)
            blob += bytes(range(16))
            blob += struct.pack("<H", codec | 0x0)
        cls.path = _write("project.pck", blob)

    def test_inventory(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "godot-pck")
        self.assertIn("2 file(s)", e["summary"])
        det = [f["detail"] for f in e["findings"] if f["kind"] == "file"]
        self.assertEqual(len(det), 2)
        self.assertTrue(any("fastlz" in d or "deflate" in d for d in det))


class PngFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ihdr = struct.pack(">IIBBBBB", 640, 480, 8, 6, 0, 0, 0)
        import zlib
        def chunk(tag, body):
            c = tag + body
            return struct.pack(">I", len(body)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        blob = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Software\x00zda-test")
        cls.path = _write("img.png", blob)

    def test_png(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "png")
        self.assertIn("640x480", e["summary"])
        self.assertTrue(any("tEXt" in f["detail"] for f in e["findings"]))


class GifFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        head = b"GIF89a" + struct.pack("<HHB", 100, 80, 0xF0) + b"\x00" * (3 * 256)
        img_desc = b"\x2c" + struct.pack("<HHHHB", 0, 0, 100, 80, 0)
        lzw = b"\x02" + b"\x02" + b"\x00" + b"\x00"
        trailer = b"\x3b"
        cls.path = _write("img.gif", head + img_desc + lzw + trailer)

    def test_gif(self):
        e = inspect_file(self.path)
        self.assertEqual(e["format"], "gif")
        self.assertIn("100x80", e["summary"])
        self.assertTrue(any("frame" in f["detail"] for f in e["findings"]))


class RegistryTests(unittest.TestCase):
    def test_all_formats_listed(self):
        fmts = {f["format"] for f in list_formats()}
        expected = {"elf", "pe", "mach-o", "zip", "pdf", "sqlite", "gguf",
                    "safetensors", "wasm", "jvm-class", "evm", "beam",
                    "godot-pck", "png", "jpeg", "gif", "webp", "pyinstaller"}
        self.assertLessEqual(expected, fmts)

    def test_unknown_file(self):
        p = _write("random.bin", b"\x12\x34\x56\x78" * 64)
        e = inspect_file(p)
        self.assertEqual(e["format"], "unknown")
        self.assertIn("evidence", e["findings"][0])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            inspect_file("/nonexistent/zda/nope.bin")

    def test_bound(self):
        e = inspect_file(str(HERE / "hello.elf"))
        self.assertEqual(e["schema"], "zda.v1")
        self.assertIn("sha256", e["file"])


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = str(HERE / "hello.elf")

    def test_identify_json(self):
        import subprocess
        out = subprocess.run([sys.executable, "-m", "zda", "identify", self.elf, "--json"],
                             capture_output=True, text=True, check=True)
        o = json.loads(out.stdout)
        self.assertEqual(o["format"], "elf")

    def test_inspect_json(self):
        import subprocess
        out = subprocess.run([sys.executable, "-m", "zda", "inspect", self.elf, "--json"],
                             capture_output=True, text=True, check=True)
        o = json.loads(out.stdout)
        self.assertIn("findings", o)


class McpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = str(HERE / "hello.elf")

    def test_tools_roundtrip(self):
        from zda.mcp import _dispatch
        r = _dispatch("initialize", {"protocolVersion": "2024-11-05"})
        self.assertEqual(r["serverInfo"]["name"], "zda")
        r = _dispatch("tools/list", {})
        names = {t["name"] for t in r["tools"]}
        self.assertEqual(names, {"zda_identify", "zda_inspect", "zda_list_formats"})
        r = _dispatch("tools/call", {"name": "zda_inspect", "arguments": {"path": self.elf}})
        payload = json.loads(r["content"][0]["text"])
        self.assertEqual(payload["format"], "elf")
        r = _dispatch("tools/call", {"name": "zda_identify", "arguments": {"path": self.elf}})
        self.assertEqual(json.loads(r["content"][0]["text"])["format"], "elf")


if __name__ == "__main__":
    unittest.main()
