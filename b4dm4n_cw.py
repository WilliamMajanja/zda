#!/usr/bin/env python3
"""
b4dm4n-cw — Cipher Workbench CLI
==================================

Next-generation cryptographic workbench for The Coffee Protocol.
Up to 17 KEM aliases (1 inf1del-kyber + 15 pqcrypto-backed PQC KEMs when pqcrypto
is installed, minus the overwritten mlkem768 duplicate, plus hybrid-ecdh-kyber
and mlkem768-pure), symmetric encryption, ECDSA signing, ECDH key exchange,
covert channels, entropy analysis, interactive REPL, and more.

"brew crypto. stay paranoid. survive."

Usage:
  b4dm4n-cw <command> [options]
  b4dm4n-cw interactive
"""

import argparse
import base64
import hashlib
import math
import os
import sys
import time
import struct
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))

try:
    from rich import box
    from rich import print as rprint
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from inf1del_kyber import Inf1delKyber, _init_tables
except ImportError:
    # Keep the raw KEM CLI usable without NumPy. The standard-library backend
    # implements the same explicitly non-FIPS custom wire variant.
    from pure_mlkem import keygen as _stdlib_keygen
    from pure_mlkem import encaps as _stdlib_encaps
    from pure_mlkem import decaps as _stdlib_decaps

    class Inf1delKyber:
        @classmethod
        def keygen(cls, recipe="espresso", size=768):
            return _stdlib_keygen(size=size, recipe=recipe)

        @classmethod
        def encaps(cls, public_key, recipe="espresso", size=768):
            return _stdlib_encaps(public_key, size=size, recipe=recipe)

        @classmethod
        def decaps(cls, secret_key, ciphertext, recipe="espresso", size=768):
            return _stdlib_decaps(secret_key, ciphertext, size=size, recipe=recipe)

        @classmethod
        def hybrid_keygen(cls, ecc_seed=None, recipe="espresso", size=768):
            from server import DSA_ML_KEM
            return DSA_ML_KEM(size).hybrid_keygen(ecc_seed)

        @classmethod
        def hybrid_encapsulate(cls, hybrid_public_key, recipe="espresso", size=768):
            from server import DSA_ML_KEM
            return DSA_ML_KEM(size).hybrid_encapsulate(hybrid_public_key)

        @classmethod
        def hybrid_decapsulate(cls, hybrid_secret_key, ciphertext, recipe="espresso", size=768):
            from server import DSA_ML_KEM
            return DSA_ML_KEM(size).hybrid_decapsulate(hybrid_secret_key, ciphertext)

    def _init_tables():
        return None

_is_tty = sys.stdout.isatty()
console = Console() if HAS_RICH else None

BANNER = r"""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  ██████╗ ██████╗  █████╗ ██████╗ ███████╗███████╗███████╗███╗  ██║ ║
    ║  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██════╝████╗ ██║ ║
    ║  ██████╔╝██████╔╝███████║██████╔╝█████╗  ███████╗█████╗  ██╔██╗██║ ║
    ║  ██╔═══╝ ██╔══██╗██══██║██══██╗██══╝  ╚════██║██════╝██║╚████║ ║
    ║  ██║     ██║  ██║██║  ██║██║  ██║███████╗███████║███████╗██║ ╚███║ ║
    ║  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚══╝║
    ║                                                                      ║
    ║      C I P H E R   W O R K B E N C H   v2.0                        ║
    ║      "brew crypto. stay paranoid. survive."                         ║
    ╚═══════════════════════════════════════════════════════════════════════╝
"""

COFFEE_SNAKE = r"""
           .-..-.
          (  f   )_
         (  / \    \
        ( J |  \_   |7
        (   |    \  |
         \  |     \ |
          \  \     \|
           \  '.____.'
            \.'
             | |
             | |
              \ \
               \ \
                \ \    .--..--.
                 \ \  ( @    @ )
                  \ \  )  __  (
                   \ \ | /ff\ |
                    \ \| |   | |
                     \ | |   | |
                      \| |   | |
                       | |   | |
                        \ \ / /
                         \ \/ /
                          \  /
                           \/
"""

def _out(msg, style=None):
    if HAS_RICH and console:
        if style:
            console.print(msg, style=style)
        else:
            console.print(msg)
        sys.stdout.flush()
    else:
        s = str(msg)
        try:
            import re
            s = re.sub(r'[0-9a-fA-F]{32,}', '[REDACTED]', s)
        except Exception:
            pass
        try:
            import logging as _logging
            _logging.getLogger('b4dm4n_cw').info(s)
        except Exception:
            pass
        return


def _panel(content, title="", style="bold cyan"):
    if HAS_RICH:
        console.print(Panel(content, title=title, style=style, box=box.DOUBLE))
        sys.stdout.flush()
    else:
        print(f"=== {title} ===")
        print(content)
        print("=" * 60)


def _table(title, rows, headers=None, style="cyan"):
    if HAS_RICH:
        t = Table(title=title, box=box.ROUNDED, style=style, show_lines=True)
        if headers:
            for h in headers:
                t.add_column(h, overflow="fold")
        for row in rows:
            t.add_row(*[str(c) for c in row])
        console.print(t)
        sys.stdout.flush()
    else:
        print(f"\n--- {title} ---")
        if headers:
            print(" | ".join(headers))
            print("-" * (len(headers) * 20))
        for row in rows:
            print(" | ".join(str(c) for c in row))


def _hexdump(data, width=16, prefix="  "):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def _entropy(data):
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _fingerprint(data):
    h = hashlib.sha256(data).digest()
    words = [
        "espresso", "latte", "mocha", "cappuccino", "americano",
        "macchiato", "flat-white", "cold-brew", "ristretto", "affogato",
        "brevet", "doppio", "lungo", "con-panna", "marocchino",
        "vienna", "affogato", "guayoyo", "tinto", "cortado"
    ]
    parts = []
    for i in range(4):
        idx = int.from_bytes(h[i * 2:i * 2 + 2], "big") % len(words)
        parts.append(words[idx])
    tag = int.from_bytes(h[8:10], "big") % 10000
    return f"{'-'.join(parts)}-{tag}"


def _key_info(data, label="Key"):
    lines = []
    lines.append(f"  Size:      {len(data)} bytes")
    lines.append(f"  SHA-256:   {hashlib.sha256(data).hexdigest()}")
    lines.append(f"  SHA3-256:  {hashlib.sha3_256(data).hexdigest()}")
    lines.append(f"  Entropy:   {_entropy(data):.4f} bits/byte (max 8.0)")
    lines.append(f"  Fingerprint: {_fingerprint(data)}")
    lines.append(f"  Hex (first 32): {data[:32].hex()}")
    lines.append(f"  Hex (last 32):  {data[-32:].hex()}")
    return "\n".join(lines)


_KEM_REGISTRY = None


def _get_kem_registry():
    global _KEM_REGISTRY
    if _KEM_REGISTRY is not None:
        return _KEM_REGISTRY

    _KEM_REGISTRY = {
        "inf1del-kyber": {
            "class": None, "name": "1nf1D3L custom KEM (default size 768)",
            "level": "experimental; no security level claim", "pq": True, "custom": True,
            "pk": 1184, "sk": 2400, "ct": 1120, "ss": 32,
            "ops": Inf1delKyber,
        },
    }

    try:
        from providers.kem import PQC_KEM_REGISTRY, get_pqc_kem, list_pqc_kems
        # Populate the lazy ML-KEM-512/768/1024 provider registry before
        # enumerating algorithms (including the stdlib-only fallback).
        list_pqc_kems()
        for alg_name in PQC_KEM_REGISTRY:
            try:
                kem_provider = get_pqc_kem(alg_name)
                available = kem_provider.is_available()
                info = kem_provider.get_info()
            except Exception:
                available = False
            display = alg_name.replace("_", "-").replace("ml-kem", "ML-KEM").replace("hqc", "HQC").replace("mceliece", "McEliece")
            _KEM_REGISTRY[alg_name] = {
                "class": kem_provider if available else None,
                "name": display, "available": available,
                "pq": True, "custom": False,
            }
    except ImportError:
        try:
            from server import MLKEM768, PQC_KEM_REGISTRY, HybridKEM
            for alg_name, kem_cls in PQC_KEM_REGISTRY.items():
                try:
                    available = kem_cls.is_available()
                except Exception:
                    available = False
                display = alg_name.replace("_", "-").replace("ml-kem", "ML-KEM").replace("hqc", "HQC").replace("mceliece", "McEliece")
                _KEM_REGISTRY[alg_name] = {
                    "class": kem_cls, "name": display, "available": available,
                    "pq": True, "custom": False,
                }
            _KEM_REGISTRY["hybrid-ecdh-kyber"] = {
                "class": HybridKEM, "name": "Hybrid ECDH-P256 + ML-KEM-768",
                "pq": True, "custom": False, "hybrid": True,
            }
            _KEM_REGISTRY["mlkem768-pure"] = {
                "class": MLKEM768, "name": "ML-KEM-768 (Pure Python)",
                "pq": True, "custom": False,
            }
        except ImportError:
            pass

    return _KEM_REGISTRY


def _resolve_kem(name):
    reg = _get_kem_registry()
    name_lower = name.lower().replace("_", "-")
    if name_lower in reg:
        return name_lower, reg[name_lower]
    aliases = {
        "inf1del": "inf1del-kyber", "kyber": "inf1del-kyber",
        "1nf1del": "inf1del-kyber", "custom": "inf1del-kyber",
        "mlkem512": "ml_kem_512", "mlkem768": "ml_kem_768", "mlkem1024": "ml_kem_1024",
        "ml-kem-512": "ml_kem_512", "ml-kem-768": "ml_kem_768", "ml-kem-1024": "ml_kem_1024",
        "1nf1d3l-kem-2048": "1nf1d3l_kem_2048", "1nf1d3l-kem-4096": "1nf1d3l_kem_4096",
        "inf1del-kem-2048": "1nf1d3l_kem_2048", "inf1del-kem-4096": "1nf1d3l_kem_4096",
        "hqc128": "hqc_128", "hqc192": "hqc_192", "hqc256": "hqc_256",
        "mc3488": "mceliece348864", "mc4608": "mceliece460896",
        "mc6688": "mceliece6688128", "mc6960": "mceliece6960119",
        "mc8192": "mceliece8192128",
        "hybrid": "hybrid-ecdh-kyber", "h": "hybrid-ecdh-kyber",
    }
    if name_lower in aliases:
        return aliases[name_lower], reg[aliases[name_lower]]
    for k in reg:
        if name_lower in k:
            return k, reg[k]
    return None, None


ALL_RECIPES = ["espresso", "cappuccino", "latte", "mocha", "americano"]


class CmdHandler:
    def __init__(self, args):
        self.args = args
        self.recipe = getattr(args, "recipe", None) or "espresso"
        self.b64 = getattr(args, "b64", False)
        self.quiet = getattr(args, "quiet", False)

    def _banner(self):
        if not self.quiet:
            _out(BANNER, style="bold yellow")

    def _status(self, msg):
        _out(f"  [*] {msg}", style="dim")

    def _ok(self, msg):
        _out(f"  [+] {msg}", style="bold green")

    def _err(self, msg):
        _out(f"  [!] {msg}", style="bold red")

    def _info(self, msg):
        _out(f"  [~] {msg}", style="bold cyan")


CMD = None


def cmd_keygen(args):
    h = CmdHandler(args)
    h._banner()
    kem_name = args.algo or "inf1del-kyber"
    key, kem = _resolve_kem(kem_name)
    if not kem:
        h._err(f"Unknown algorithm: {kem_name}")
        return

    h._info(f"Generating keypair: {kem['name']} (recipe: {h.recipe})")

    if key == "inf1del-kyber":
        pk, sk = Inf1delKyber.keygen(h.recipe)
        exts = (".pk", ".sk")
    elif kem.get("hybrid"):
        pk, sk = Inf1delKyber.hybrid_keygen(recipe=h.recipe)
        exts = (".hp", ".hs")
    else:
        cls = kem["class"]
        if not getattr(cls, "is_available", lambda: True)():
            h._err(f"Algorithm {kem_name} not available (pqcrypto not installed)")
            return
        pk, sk = cls.generate_keypair()
        exts = (".pk", ".sk")

    if args.output:
        pk_path = args.output + exts[0]
        sk_path = args.output + exts[1]
        with open(pk_path, "wb") as f:
            f.write(pk)
        import tempfile
        tmpfd, tmppath = tempfile.mkstemp(prefix='.sk.', dir=os.path.dirname(sk_path) or '.', text=False)
        try:
            os.write(tmpfd, sk)
            os.close(tmpfd)
            tmpfd = -1
            os.chmod(tmppath, 0o600)
            os.replace(tmppath, sk_path)
            tmppath = None
        finally:
            if tmpfd != -1:
                try:
                    os.close(tmpfd)
                except Exception:
                    pass
            if tmppath and os.path.exists(tmppath):
                try:
                    os.unlink(tmppath)
                except Exception:
                    pass
        h._ok(f"Public key:  {pk_path} ({len(pk)} bytes)")
        h._ok(f"Secret key:  {sk_path} ({len(sk)} bytes)")
    else:
        _out(f"\n  Public Key ({len(pk)} bytes):", style="bold")
        _out(_hexdump(pk))
        _out(f"\n  Secret Key ({len(sk)} bytes):", style="bold")
        _out(_hexdump(sk))

    if h.b64:
        _out(f"\n  PK (base64): {base64.b64encode(pk).decode()}")
        _out(f"  SK (base64): {base64.b64encode(sk).decode()}")

    h._info("Key Analysis:")
    _out(_key_info(pk, "Public Key"))
    _out("")
    _out(_key_info(sk, "Secret Key"))


def cmd_encaps(args):
    h = CmdHandler(args)
    h._banner()
    kem_name = args.algo or "inf1del-kyber"
    key, kem = _resolve_kem(kem_name)
    if not kem:
        h._err(f"Unknown algorithm: {kem_name}")
        return

    with open(args.pubkey, "rb") as f:
        pk = f.read()

    h._info(f"Encapsulating: {kem['name']} ({len(pk)} bytes, recipe: {h.recipe})")

    if key == "inf1del-kyber":
        ct, ss = Inf1delKyber.encaps(pk, h.recipe)
    elif kem.get("hybrid"):
        ct, ss = Inf1delKyber.hybrid_encapsulate(pk, h.recipe)
    else:
        cls = kem["class"]
        pk_clean = pk
        if hasattr(cls, "ENCODED_PK_LEN"):
            pk_clean = pk[:cls.ENCODED_PK_LEN]
        ct, ss = cls.encapsulate(pk_clean)

    if args.output:
        with open(args.output, "wb") as f:
            f.write(ct)
        h._ok(f"Ciphertext: {args.output} ({len(ct)} bytes)")
    else:
        _out(f"\n  Ciphertext ({len(ct)} bytes):", style="bold")
        _out(_hexdump(ct))

    _out(f"\n  Shared Secret ({len(ss)} bytes):", style="bold green")
    _out(f"  {_fingerprint(ss)}")
    h._info(f"Fingerprint: {_fingerprint(ss)}")

    if h.b64:
        _out(f"\n  CT (base64):  {base64.b64encode(ct).decode()}")
        _out(f"  SS (base64):  {base64.b64encode(ss).decode()}")


def cmd_decaps(args):
    h = CmdHandler(args)
    h._banner()
    kem_name = args.algo or "inf1del-kyber"
    key, kem = _resolve_kem(kem_name)
    if not kem:
        h._err(f"Unknown algorithm: {kem_name}")
        return

    with open(args.privkey, "rb") as f:
        sk = f.read()
    with open(args.ciphertext, "rb") as f:
        ct = f.read()

    h._info(f"Decapsulating: {kem['name']} (ct: {len(ct)} bytes, recipe: {h.recipe})")

    start = time.perf_counter()
    if key == "inf1del-kyber":
        ss = Inf1delKyber.decaps(sk, ct, h.recipe)
    elif kem.get("hybrid"):
        ss = Inf1delKyber.hybrid_decapsulate(sk, ct, h.recipe)
    else:
        cls = kem["class"]
        ss = cls.decapsulate(sk, ct)
    elapsed = (time.perf_counter() - start) * 1000

    _out(f"\n  Shared Secret ({len(ss)} bytes):", style="bold green")
    _out(f"  {_fingerprint(ss)}")
    h._info(f"Fingerprint: {_fingerprint(ss)}")

    if h.b64:
        _out(f"\n  SS (base64): {base64.b64encode(ss).decode()}")


def cmd_encrypt(args):
    h = CmdHandler(args)
    h._banner()

    try:
        from server import CoffeeCipher
    except ImportError:
        h._err("CoffeeCipher not available")
        return

    cipher = CoffeeCipher()

    if args.file:
        with open(args.file, "rb") as f:
            plaintext = f.read()
        h._info(f"Encrypting file: {args.file} ({len(plaintext)} bytes)")
    else:
        plaintext = sys.stdin.buffer.read()
        h._info(f"Encrypting stdin ({len(plaintext)} bytes)")

    key = None
    if args.key:
        with open(args.key, "rb") as f:
            key = f.read()

    start = time.perf_counter()
    ct = cipher.encrypt(plaintext, base_key=key, recipe=h.recipe)
    elapsed = (time.perf_counter() - start) * 1000

    if args.output:
        with open(args.output, "wb") as f:
            f.write(ct)
        h._ok(f"Encrypted: {args.output} ({len(ct)} bytes, {elapsed:.2f} ms)")
    else:
        sys.stdout.buffer.write(ct)

    _out(f"  Ciphertext SHA-256: {hashlib.sha256(ct).hexdigest()}")
    h._info(f"Recipe: {h.recipe} | Nonce: {ct[:12].hex()} | Tag: {ct[-16:].hex()}")


def cmd_decrypt(args):
    h = CmdHandler(args)
    h._banner()

    try:
        from server import CoffeeCipher
    except ImportError:
        h._err("CoffeeCipher not available")
        return

    cipher = CoffeeCipher()

    if args.file:
        with open(args.file, "rb") as f:
            ct = f.read()
    else:
        ct = sys.stdin.buffer.read()

    h._info(f"Decrypting ({len(ct)} bytes, recipe: {h.recipe})")

    key = None
    if args.key:
        with open(args.key, "rb") as f:
            key = f.read()

    start = time.perf_counter()
    pt = cipher.decrypt(ct, base_key=key, recipe=h.recipe)
    elapsed = (time.perf_counter() - start) * 1000

    if not pt:
        h._err("Decryption failed (authentication tag mismatch or wrong key)")
        return

    if args.output:
        with open(args.output, "wb") as f:
            f.write(pt)
        h._ok(f"Decrypted: {args.output} ({len(pt)} bytes, {elapsed:.2f} ms)")
    else:
        sys.stdout.buffer.write(pt)


def cmd_hash(args):
    h = CmdHandler(args)
    h._banner()

    try:
        from server import SecureHash
    except ImportError:
        h._err("SecureHash not available")
        return

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
        h._info(f"Hashing file: {args.file} ({len(data)} bytes)")
    elif args.string:
        data = args.string.encode()
        h._info(f"Hashing string ({len(data)} bytes)")
    else:
        data = sys.stdin.buffer.read()
        h._info(f"Hashing stdin ({len(data)} bytes)")

    algos = args.algorithms.split(",") if args.algorithms else ["sha256", "sha3_256"]
    rows = []
    for algo in algos:
        algo = algo.strip().lower()
        start = time.perf_counter()
        try:
            h_val = SecureHash.hash(data, algo)
            if isinstance(h_val, bytes):
                h_val = h_val.hex()
            else:
                h_val = str(h_val)
        except Exception:
            h_name = algo.replace("sha3_", "sha3-") if "sha3" in algo else algo
            try:
                h_val = hashlib.new(h_name, data).hexdigest()
            except Exception:
                h_val = hashlib.sha256(data).hexdigest()
        elapsed = (time.perf_counter() - start) * 1000
        rows.append((algo.upper(), h_val, f"{elapsed:.3f}ms"))

    _table("Hash Results", rows, headers=["Algorithm", "Digest", "Time"])

    if args.domain:
        dh = SecureHash.domain_hash(args.domain, data)
        _out(f"\n  Domain-separated ({args.domain}): {dh.hex()}")


def cmd_sign(args):
    h = CmdHandler(args)
    h._banner()

    try:
        from server import ECP256
    except ImportError:
        h._err("ECP256 not available")
        return

    seed_file = args.seed
    if not seed_file:
        h._err("Signing requires --seed <file>")
        return

    with open(seed_file, "rb") as f:
        seed = f.read()

    if args.file:
        with open(args.file, "rb") as f:
            message = f.read()
        h._info(f"Signing file: {args.file} ({len(message)} bytes)")
    elif args.string:
        message = args.string.encode()
        h._info(f"Signing string ({len(message)} bytes)")
    else:
        message = sys.stdin.buffer.read()
        h._info(f"Signing stdin ({len(message)} bytes)")

    start = time.perf_counter()
    sig = ECP256.sign(message, seed)
    elapsed = (time.perf_counter() - start) * 1000

    if args.output:
        with open(args.output, "wb") as f:
            f.write(sig)
        h._ok(f"Signature: {args.output} ({len(sig)} bytes, {elapsed:.2f} ms)")
    else:
        _out(f"\n  Signature ({len(sig)} bytes):", style="bold")
        _out(_hexdump(sig))

    if h.b64:
        _out(f"\n  Signature (base64): {base64.b64encode(sig).decode()}")


def cmd_verify(args):
    h = CmdHandler(args)
    h._banner()

    try:
        from server import ECP256
    except ImportError:
        h._err("ECP256 not available")
        return

    with open(args.signature, "rb") as f:
        sig = f.read()
    with open(args.pubkey, "rb") as f:
        pk = f.read()

    if args.file:
        with open(args.file, "rb") as f:
            message = f.read()
    else:
        message = sys.stdin.buffer.read()

    h._info(f"Verifying: sig={len(sig)} bytes, msg={len(message)} bytes")

    try:
        start = time.perf_counter()
        valid = ECP256.verify(message, sig, pk)
        elapsed = (time.perf_counter() - start) * 1000
        if valid:
            h._ok(f"VALID signature ({elapsed:.2f} ms)")
        else:
            h._err(f"INVALID signature ({elapsed:.2f} ms)")
    except Exception as e:
        h._err(f"Verification error: {e}")


def cmd_ecdh(args):
    h = CmdHandler(args)
    h._banner()

    try:
        from server import ECP256
    except ImportError:
        h._err("ECP256 not available")
        return

    if args.generate:
        h._info("Generating ECDH keypair (P-256)")
        pk, seed, _, _ = ECP256.generate_keypair()
        if args.output:
            with open(args.output + ".ecpk", "wb") as f:
                f.write(pk)
            with open(args.output + ".ecseed", "wb") as f:
                f.write(seed)
            h._ok(f"Public key: {args.output}.ecpk ({len(pk)} bytes)")
            h._ok(f"Secret seed: {args.output}.ecseed ({len(seed)} bytes)")
        else:
            _out(f"\n  Public Key ({len(pk)} bytes):", style="bold")
            _out(_hexdump(pk))
            _out(f"\n  Secret Seed ({len(seed)} bytes):", style="bold")
            _out(_hexdump(seed))
    elif args.seed and args.peer:
        with open(args.seed, "rb") as f:
            seed = f.read()
        with open(args.peer, "rb") as f:
            peer_pk = f.read()
        h._info("Performing ECDH key agreement")
        start = time.perf_counter()
        shared = ECP256.key_exchange(seed, peer_pk)
        elapsed = (time.perf_counter() - start) * 1000
        _out(f"\n  Shared Secret ({len(shared)} bytes):", style="bold green")
        _out(f"  {shared.hex()}")
        h._info(f"Fingerprint: {_fingerprint(shared)} ({elapsed:.2f} ms)")
    else:
        h._err("ECDH requires --generate or --seed + --peer")


def cmd_convert(args):
    h = CmdHandler(args)
    h._banner()

    with open(args.input, "rb") as f:
        data = f.read()

    h._info(f"Input: {args.input} ({len(data)} bytes)")

    if args.format == "hex":
        out = data.hex()
    elif args.format == "base64":
        out = base64.b64encode(data).decode()
    elif args.format == "base32":
        out = base64.b32encode(data).decode()
    elif args.format == "binary":
        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            h._ok(f"Written: {args.output}")
            return
        else:
            sys.stdout.buffer.write(data)
            return
    elif args.format == "c-array":
        out = ", ".join(f"0x{b:02x}" for b in data)
        out = "unsigned char data[] = {\n  " + out + "\n};\n// Length: " + str(len(data)) + " bytes"
    elif args.format == "python-bytes":
        out = f"data = {data!r}"
    else:
        out = data.hex()

    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        h._ok(f"Output: {args.output}")
    else:
        print(out)


def cmd_fingerprint(args):
    h = CmdHandler(args)
    h._banner()

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    elif args.hex:
        data = bytes.fromhex(args.hex)
    elif args.string:
        data = args.string.encode()
    else:
        h._err("Provide --file, --hex, or --string")
        return

    fp = _fingerprint(data)
    h._ok(f"Fingerprint: {fp}")
    h._info(f"Entropy: {_entropy(data):.4f} bits/byte")
    _out(f"  SHA-256:  {hashlib.sha256(data).hexdigest()}")
    _out(f"  SHA3-256: {hashlib.sha3_256(data).hexdigest()}")
    _out(f"  Size:     {len(data)} bytes")


def cmd_analyze(args):
    h = CmdHandler(args)
    h._banner()

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    elif args.hex:
        data = bytes.fromhex(args.hex)
    else:
        h._err("Provide --file or --hex")
        return

    h._info(f"Entropy analysis ({len(data)} bytes)")

    ent = _entropy(data)
    freq = Counter(data)

    rows = []
    for byte_val, count in freq.most_common(16):
        pct = count / len(data) * 100
        bar = "#" * int(pct * 2)
        rows.append((f"0x{byte_val:02x}", str(count), f"{pct:.2f}%", bar))

    _table("Byte Frequency (Top 16)", rows, headers=["Byte", "Count", "%", "Distribution"])

    _out(f"\n  Shannon Entropy: {ent:.4f} bits/byte (max: 8.0)")
    _out(f"  Uniqueness:      {len(freq)} / 256 unique byte values")

    chi2_expected = len(data) / 256
    chi2 = sum((count - chi2_expected) ** 2 / chi2_expected for count in freq.values())
    _out(f"  Chi-Squared:     {chi2:.2f} (expected ~256 for uniform)")

    if ent > 7.9:
        h._ok("Entropy: EXCELLENT (near-random)")
    elif ent > 7.5:
        h._info("Entropy: GOOD")
    elif ent > 6.0:
        _out("  Entropy: FAIR (may have patterns)", style="yellow")
    else:
        h._err("Entropy: LOW (likely not random)")

    if args.hist:
        _out("\n  Full Byte Distribution:", style="bold")
        for byte_val in range(256):
            count = freq.get(byte_val, 0)
            bar = "#" * int(count / len(data) * 200)
            if count > 0:
                _out(f"  {byte_val:3d}: {bar}")


def cmd_list(args):
    h = CmdHandler(args)
    h._banner()

    reg = _get_kem_registry()
    rows = []
    for key, info in reg.items():
        avail = "Yes" if info.get("available", True) else "No"
        pq = "Yes" if info.get("pq") else "No"
        custom = "Yes" if info.get("custom") else ""
        hybrid = "Yes" if info.get("hybrid") else ""
        pk = info.get("pk", "-")
        sk = info.get("sk", "-")
        ct = info.get("ct", "-")
        rows.append((key, info["name"], avail, pq, custom, hybrid, str(pk), str(sk), str(ct)))

    _table(
        "Available Algorithms",
        rows,
        headers=["ID", "Algorithm", "Available", "PQ", "Custom", "Hybrid", "PK(B)", "SK(B)", "CT(B)"],
    )

    _out(f"\n  Total: {len(reg)} algorithms", style="bold")

    _out("\n  Recipes:", style="bold cyan")
    for r in ALL_RECIPES:
        _out(f"    - {r}")


def cmd_bench(args):
    h = CmdHandler(args)
    h._banner()
    n = args.iterations

    _out(f"\n  Benchmarking (recipe: {h.recipe}, {n} iterations)...\n", style="bold")
    sys.stdout.flush()

    rows = []

    start = time.perf_counter()
    for i in range(n):
        pk, sk = Inf1delKyber.keygen(h.recipe)
    kg = (time.perf_counter() - start) / n * 1000
    rows.append(("KeyGen", f"{kg:.2f}"))
    sys.stdout.flush()

    start = time.perf_counter()
    for i in range(n):
        ct, ss = Inf1delKyber.encaps(pk, h.recipe)
    en = (time.perf_counter() - start) / n * 1000
    rows.append(("Encaps", f"{en:.2f}"))
    sys.stdout.flush()

    start = time.perf_counter()
    for i in range(n):
        ss2 = Inf1delKyber.decaps(sk, ct, h.recipe)
    de = (time.perf_counter() - start) / n * 1000
    rows.append(("Decaps", f"{de:.2f}"))
    sys.stdout.flush()

    assert ss == ss2, "Benchmark verification failed!"
    _table("1nf1D3L Kyber Performance", rows, headers=["Operation", "Time (ms)"])

    if args.all:
        _bench_all_kems(h, n)


def _bench_all_kems(h, n):
    reg = _get_kem_registry()
    rows = []

    _out("\n  [~] Benchmarking all available algorithms...\n", style="bold cyan")

    for key, info in reg.items():
        avail = info.get("available", True)
        if not avail:
            rows.append((key, info["name"], "N/A", "-", "-", "-", "-", "-"))
            continue

        try:
            cls = info.get("class")
            info.get("hybrid", False)
            is_custom = info.get("custom", False)

            if is_custom:
                start = time.perf_counter()
                for _ in range(min(n, 10)):
                    pk, sk = Inf1delKyber.keygen(h.recipe)
                kg = (time.perf_counter() - start) / min(n, 10) * 1000

                start = time.perf_counter()
                for _ in range(min(n, 10)):
                    ct, _ss = Inf1delKyber.encaps(pk, h.recipe)
                en = (time.perf_counter() - start) / min(n, 10) * 1000

                start = time.perf_counter()
                for _ in range(min(n, 10)):
                    Inf1delKyber.decaps(sk, ct, h.recipe)
                de = (time.perf_counter() - start) / min(n, 10) * 1000

                rows.append((key, info["name"], "Yes", f"{kg:.1f}", f"{en:.1f}", f"{de:.1f}", "-", "-"))
                continue

            sub_n = min(n, 5)

            start = time.perf_counter()
            for _ in range(sub_n):
                pk, sk = cls.generate_keypair()
            kg = (time.perf_counter() - start) / sub_n * 1000

            start = time.perf_counter()
            for _ in range(sub_n):
                ct, _ss = cls.encapsulate(pk)
            en = (time.perf_counter() - start) / sub_n * 1000

            start = time.perf_counter()
            for _ in range(sub_n):
                cls.decapsulate(sk, ct)
            de = (time.perf_counter() - start) / sub_n * 1000

            rows.append((key, info["name"], "Yes", f"{kg:.1f}", f"{en:.1f}", f"{de:.1f}", str(len(pk)), str(len(ct))))

        except Exception as e:
            rows.append((key, info["name"], "Err", "-", "-", "-", "-", str(e)[:20]))

    _table(
        "All KEM Benchmarks (ms)",
        rows,
        headers=["ID", "Algorithm", "OK", "KeyGen", "Encaps", "Decaps", "PK(B)", "CT(B)"],
    )


def cmd_coffee(args):
    CmdHandler(args)
    _out(BANNER, style="bold yellow")
    _out(COFFEE_SNAKE, style="yellow")


def cmd_info(args):
    h = CmdHandler(args)
    h._banner()
    _init_tables()

    _out("""
  ╔═══════════════════════════════════════════════════════════════╗
  ║         1nf1D3L KEM — Crypto Parameters                     ║
  ╠═══════════════════════════════════════════════════════════════╣
  ║  Variant:        Custom KEM; default parameter size 768     ║
  ║  Security:       Experimental; no level claim               ║
  ║  Lattice:        Module-LWE over R_q = Z_q[X]/(X^256 + 1)  ║
  ║  Modulus q:      3329 (NTT-friendly)                        ║
  ║  Dimension n:    256                                        ║
  ║  Module rank k:  3 (default; custom 8/16 also supported)    ║
  ║  Noise:          eta1=3, eta2=2 (custom parameters)         ║
  ║  Domain tag:     1NF1D3L-KYBER-V1                          ║
  ║                                                             ║
  ║  Sizes:                                                    ║
  ║    PK: 1184 bytes | SK: 2400 bytes                         ║
  ║    CT: 1120 bytes | SS: 32 bytes                           ║
  ║                                                             ║
  ║  Security Properties:                                       ║
  ║    [x] Re-encapsulation check (not a formal proof)          ║
  ║    [ ] Independently analyzed / constant-time                ║
  ║    [x] Domain separated                                     ║
  ║    [x] Recipe-bound                                         ║
  ║    [-] NOT FIPS 203 compliant (by design)                   ║
  ╚═══════════════════════════════════════════════════════════════╝""", style="cyan")


def cmd_interactive(args):
    _out(BANNER, style="bold yellow")
    _out(COFFEE_SNAKE, style="yellow")
    _out("\n  ╔═══════════════════════════════════════════════════════════════╗", style="bold cyan")
    _out("  ║        b4dm4n-cw  TUI  —  Interactive Cipher Workbench      ║", style="bold cyan")
    _out("  ║     \"brew crypto. stay paranoid. survive.\"                   ║", style="bold cyan")
    _out("  ╚═══════════════════════════════════════════════════════════════╝", style="bold cyan")
    _out("\n  Type 'help' for commands, 'quit' to exit.\n", style="dim")

    session_keys = {}
    session_recipe = "espresso"
    history = []

    while True:
        try:
            line = input(f"  b4dm4n [{session_recipe}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            _out("\n  Stay paranoid. ☕", style="bold yellow")
            break

        if not line:
            continue
        history.append(line)
        parts = line.split()
        cmd = parts[0].lower()
        rest = parts[1:]

        if cmd in ("quit", "exit", "q"):
            _out("  Stay paranoid. ☕", style="bold yellow")
            break

        elif cmd == "help":
            _out("""
  Available Commands:
    keygen [algo]               Generate keypair (default: inf1del-kyber)
    encaps <pk_file> [algo]     Encapsulate to public key
    decaps <sk_file> <ct_file>  Decapsulate ciphertext
    encrypt <file> [key_file]   AES-256-GCM encrypt
    decrypt <file> [key_file]   AES-256-GCM decrypt
    hash <file|string>          Hash (sha256, sha3_256, shake256)
    sign <file> <seed_file>     ECDSA P-256 sign
    verify <sig> <pk> <file>    ECDSA P-256 verify
    ecdh-gen                    Generate ECDH keypair
    ecdh <seed> <peer_pk>       ECDH key agreement
    bench [algo] [n]            Benchmark algorithm
    bench-all [n]               Benchmark all KEMs
    list                        List available algorithms
    analyze <file|hex>          Entropy analysis
    fingerprint <file|string>   Key fingerprint
    info                        Crypto parameters
    recipe <name>               Set recipe (espresso, latte, etc.)
    history                     Show command history
    quit                        Exit""", style="cyan")

        elif cmd == "recipe":
            if rest:
                session_recipe = rest[0]
                _out(f"  Recipe set to: {session_recipe}", style="bold green")
            else:
                _out(f"  Current recipe: {session_recipe}")
                _out(f"  Available: {', '.join(ALL_RECIPES)}")

        elif cmd == "history":
            for i, h_cmd in enumerate(history[-20:], 1):
                _out(f"  {i:3d}: {h_cmd}")

        elif cmd == "keygen":
            algo = rest[0] if rest else "inf1del-kyber"
            key_name, kem = _resolve_kem(algo)
            if not kem:
                _out(f"  Unknown algorithm: {algo}", style="red")
                continue
            _out(f"  Generating: {kem['name']}...", style="cyan")
            if key_name == "inf1del-kyber":
                pk, sk = Inf1delKyber.keygen(session_recipe)
            elif kem.get("hybrid"):
                pk, sk = Inf1delKyber.hybrid_keygen(recipe=session_recipe)
            else:
                pk, sk = kem["class"].generate_keypair()
            tag = _fingerprint(pk)
            session_keys[tag] = {"pk": pk, "sk": sk, "algo": key_name}
            _out(f"  Public key ({len(pk)} bytes): {pk[:32].hex()}...", style="green")
            _out(f"  Secret key ({len(sk)} bytes): {sk[:32].hex()}...", style="green")
            _out(f"  Tag: {tag}", style="bold yellow")
            _out("  Stored in session. Use tag to reference.")

        elif cmd == "encaps":
            if not rest:
                _out("  Usage: encaps <pk_file|tag> [algo]", style="red")
                continue
            pk_data = rest[0]
            algo = rest[1] if len(rest) > 1 else "inf1del-kyber"
            key_name, kem = _resolve_kem(algo)

            if pk_data in session_keys:
                pk = session_keys[pk_data]["pk"]
                key_name = session_keys[pk_data]["algo"]
                _, kem = _resolve_kem(key_name)
            else:
                with open(pk_data, "rb") as f:
                    pk = f.read()

            if key_name == "inf1del-kyber":
                ct, ss = Inf1delKyber.encaps(pk, session_recipe)
            elif kem.get("hybrid"):
                ct, ss = Inf1delKyber.hybrid_encapsulate(pk, session_recipe)
            else:
                ct, ss = kem["class"].encapsulate(pk)

            tag = _fingerprint(ss)
            _out(f"  Ciphertext: {ct.hex()[:64]}... ({len(ct)} bytes)", style="green")
            _out(f"  Shared Secret: {ss.hex()}", style="bold green")
            _out(f"  Fingerprint: {tag}", style="yellow")

        elif cmd == "decaps":
            if len(rest) < 2:
                _out("  Usage: decaps <sk_file> <ct_file>", style="red")
                continue
            with open(rest[0], "rb") as f:
                sk = f.read()
            with open(rest[1], "rb") as f:
                ct = f.read()
            ss = Inf1delKyber.decaps(sk, ct, session_recipe)
            _out(f"  Shared Secret: {ss.hex()}", style="bold green")

        elif cmd == "list":
            reg = _get_kem_registry()
            for k, v in reg.items():
                avail = "OK" if v.get("available", True) else "N/A"
                _out(f"  {k:24s} {v['name']:40s} [{avail}]", style="cyan" if avail == "OK" else "dim")

        elif cmd == "bench":
            algo = rest[0] if rest else "inf1del-kyber"
            n = int(rest[1]) if len(rest) > 1 else 10
            key_name, kem = _resolve_kem(algo)
            if key_name == "inf1del-kyber":
                _out(f"  Benchmarking 1nf1D3L Kyber ({n} iters)...", style="cyan")
                start = time.perf_counter()
                for _ in range(n):
                    pk, sk = Inf1delKyber.keygen(session_recipe)
                kg = (time.perf_counter() - start) / n * 1000
                start = time.perf_counter()
                for _ in range(n):
                    ct, ss = Inf1delKyber.encaps(pk, session_recipe)
                en = (time.perf_counter() - start) / n * 1000
                start = time.perf_counter()
                for _ in range(n):
                    Inf1delKyber.decaps(sk, ct, session_recipe)
                de = (time.perf_counter() - start) / n * 1000
                _out(f"  KeyGen: {kg:.2f}ms  Encaps: {en:.2f}ms  Decaps: {de:.2f}ms", style="bold green")
            elif kem:
                cls = kem.get("class")
                if cls and getattr(cls, "is_available", lambda: True)():
                    _out(f"  Benchmarking {kem['name']} ({n} iters)...", style="cyan")
                    sub_n = min(n, 20)
                    start = time.perf_counter()
                    for _ in range(sub_n):
                        pk, sk = cls.generate_keypair()
                    kg = (time.perf_counter() - start) / sub_n * 1000
                    start = time.perf_counter()
                    for _ in range(sub_n):
                        ct, ss = cls.encapsulate(pk)
                    en = (time.perf_counter() - start) / sub_n * 1000
                    start = time.perf_counter()
                    for _ in range(sub_n):
                        cls.decapsulate(sk, ct)
                    de = (time.perf_counter() - start) / sub_n * 1000
                    _out(f"  KeyGen: {kg:.2f}ms  Encaps: {en:.2f}ms  Decaps: {de:.2f}ms", style="bold green")

        elif cmd == "bench-all":
            n = int(rest[0]) if rest else 5
            reg = _get_kem_registry()
            rows = []
            for k, info in reg.items():
                avail = info.get("available", True)
                if not avail:
                    rows.append((k, "N/A", "-", "-", "-"))
                    continue
                cls = info.get("class")
                is_custom = info.get("custom", False)
                sub_n = min(n, 10)
                try:
                    if is_custom:
                        start = time.perf_counter()
                        for _ in range(sub_n):
                            pk, sk = Inf1delKyber.keygen(session_recipe)
                        kg = (time.perf_counter() - start) / sub_n * 1000
                        start = time.perf_counter()
                        for _ in range(sub_n):
                            ct, ss = Inf1delKyber.encaps(pk, session_recipe)
                        en = (time.perf_counter() - start) / sub_n * 1000
                        start = time.perf_counter()
                        for _ in range(sub_n):
                            Inf1delKyber.decaps(sk, ct, session_recipe)
                        de = (time.perf_counter() - start) / sub_n * 1000
                    else:
                        start = time.perf_counter()
                        for _ in range(sub_n):
                            pk, sk = cls.generate_keypair()
                        kg = (time.perf_counter() - start) / sub_n * 1000
                        start = time.perf_counter()
                        for _ in range(sub_n):
                            ct, ss = cls.encapsulate(pk)
                        en = (time.perf_counter() - start) / sub_n * 1000
                        start = time.perf_counter()
                        for _ in range(sub_n):
                            cls.decapsulate(sk, ct)
                        de = (time.perf_counter() - start) / sub_n * 1000
                    rows.append((k, f"{kg:.1f}", f"{en:.1f}", f"{de:.1f}", "OK"))
                except Exception as e:
                    rows.append((k, "-", "-", "-", str(e)[:16]))
            _table("All KEM Benchmarks (ms)", rows, headers=["Algorithm", "KeyGen", "Encaps", "Decaps", "Status"])

        elif cmd == "hash":
            if not rest:
                _out("  Usage: hash <file|string>", style="red")
                continue
            arg = " ".join(rest)
            if os.path.isfile(arg):
                with open(arg, "rb") as f:
                    data = f.read()
            else:
                data = arg.encode()
            try:
                from server import SecureHash
                h256 = SecureHash.hash(data, "sha256")
                h3_256 = SecureHash.hash(data, "sha3_256")
                h3_512 = SecureHash.hash(data, "sha3_512")
                _out(f"  SHA-256:  {h256}")
                _out(f"  SHA3-256: {h3_256}")
                _out(f"  SHA3-512: {h3_512}")
            except ImportError:
                _out(f"  SHA-256:  {hashlib.sha256(data).hexdigest()}")
                _out(f"  SHA3-256: {hashlib.sha3_256(data).hexdigest()}")

        elif cmd == "sign":
            if len(rest) < 2:
                _out("  Usage: sign <file> <seed_file>", style="red")
                continue
            with open(rest[0], "rb") as f:
                msg = f.read()
            with open(rest[1], "rb") as f:
                seed = f.read()
            try:
                from server import ECP256
                sig = ECP256.sign(msg, seed)
                _out(f"  Signature ({len(sig)} bytes): {sig[:32].hex()}...", style="green")
            except ImportError:
                _out("  ECP256 not available", style="red")

        elif cmd == "analyze":
            if not rest:
                _out("  Usage: analyze <file|hex>", style="red")
                continue
            arg = rest[0]
            if os.path.isfile(arg):
                with open(arg, "rb") as f:
                    data = f.read()
            else:
                data = bytes.fromhex(arg)
            ent = _entropy(data)
            freq = Counter(data)
            _out(f"  Size: {len(data)} bytes")
            _out(f"  Entropy: {ent:.4f} bits/byte (max 8.0)")
            _out(f"  Unique bytes: {len(freq)}/256")
            top5 = freq.most_common(5)
            _out(f"  Top 5: {', '.join(f'0x{b:02x}({c}x)' for b, c in top5)}")

        elif cmd == "fingerprint":
            if not rest:
                _out("  Usage: fingerprint <file|string|hex>", style="red")
                continue
            arg = " ".join(rest)
            if os.path.isfile(arg):
                with open(arg, "rb") as f:
                    data = f.read()
            else:
                data = arg.encode()
            _out(f"  Fingerprint: {_fingerprint(data)}", style="bold yellow")
            _out(f"  SHA-256: {hashlib.sha256(data).hexdigest()}")

        elif cmd == "info":
            cmd_info(args)

        else:
            _out(f"  Unknown command: {cmd}. Type 'help' for commands.", style="red")



def cmd_ascii(args):
    h = CmdHandler(args)
    h._banner()
    try:
        from PIL import Image
    except Exception:
        h._err("Pillow not installed. Install with: pip install Pillow")
        return
    infile = args.input
    try:
        img = Image.open(infile)
    except Exception as e:
        h._err(f"Failed to open image: {e}")
        return
    width = args.width or 100
    height = args.height
    img = img.convert('L')
    if height is None:
        w, h = img.size
        height = int(h * width * 0.55 / w)
    img = img.resize((width, height))
    chars = args.chars or '@%#*+=-:. '
    pixels = img.getdata()
    out = []
    for i, p in enumerate(pixels):
        if i % width == 0 and i != 0:
            out.append('\n')
        out.append(chars[int(p * (len(chars) - 1) / 255)])
    result = ''.join(out)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(result)
        h._ok(f"ASCII art written to {args.output}")
    else:
        print(result)

def main():
    _init_tables()

    parser = argparse.ArgumentParser(
        prog="b4dm4n-cw",
        description="b4dm4n-cw — Cipher Workbench for The Coffee Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  b4dm4n-cw keygen -o mykeys
  b4dm4n-cw keygen -a ml_kem_768 -o mlkem
  b4dm4n-cw encaps mykeys.pk -a inf1del-kyber -o ct.bin
  b4dm4n-cw decaps mykeys.sk ct.bin -a inf1del-kyber
  b4dm4n-cw encrypt secret.txt -o secret.enc
  b4dm4n-cw decrypt secret.enc -o secret.txt
  b4dm4n-cw hash myfile.txt -a sha256,sha3_256
  b4dm4n-cw sign msg.txt --seed myseed.bin -o sig.bin
  b4dm4n-cw verify sig.bin mykey.pk msg.txt
  b4dm4n-cw ecdh --generate -o ecdh_keys
  b4dm4n-cw ecdh --seed ecdh_keys.ecseed --peer ecdh_keys.ecpk
  b4dm4n-cw bench --all -n 50
  b4dm4n-cw list
  b4dm4n-cw analyze --file random.bin
  b4dm4n-cw fingerprint -s "hello world"
  b4dm4n-cw convert mykey.bin -f base64
  b4dm4n-cw interactive
        """,
    )
    parser.add_argument("--recipe", "-r", default="espresso", help="Coffee recipe for domain separation")
    parser.add_argument("--b64", action="store_true", help="Also output base64")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="Generate keypair")
    p.add_argument("-a", "--algo", default="inf1del-kyber", help="Algorithm (default: inf1del-kyber)")
    p.add_argument("-o", "--output", help="Output file prefix")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encaps", help="Encapsulate to a public key")
    p.add_argument("pubkey", help="Public key file")
    p.add_argument("-a", "--algo", default="inf1del-kyber", help="Algorithm")
    p.add_argument("-o", "--output", help="Output ciphertext file")
    p.set_defaults(func=cmd_encaps)

    p = sub.add_parser("decaps", help="Decapsulate with a private key")
    p.add_argument("privkey", help="Private key file")
    p.add_argument("ciphertext", help="Ciphertext file")
    p.add_argument("-a", "--algo", default="inf1del-kyber", help="Algorithm")
    p.set_defaults(func=cmd_decaps)

    p = sub.add_parser("encrypt", help="AES-256-GCM encrypt (CoffeeCipher)")
    p.add_argument("file", nargs="?", help="Input file (or stdin)")
    p.add_argument("-k", "--key", help="Key file (optional)")
    p.add_argument("-o", "--output", help="Output file")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="AES-256-GCM decrypt (CoffeeCipher)")
    p.add_argument("file", nargs="?", help="Input file (or stdin)")
    p.add_argument("-k", "--key", help="Key file (optional)")
    p.add_argument("-o", "--output", help="Output file")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("hash", help="Hash data")
    p.add_argument("file", nargs="?", help="File to hash (or stdin)")
    p.add_argument("-s", "--string", help="String to hash")
    p.add_argument("-a", "--algorithms", default="sha256,sha3_256", help="Comma-separated algorithms")
    p.add_argument("-d", "--domain", help="Domain separator")
    p.add_argument("-o", "--output", help="Output file")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("sign", help="ECDSA P-256 sign")
    p.add_argument("file", nargs="?", help="File to sign (or stdin)")
    p.add_argument("-s", "--string", help="String to sign")
    p.add_argument("--seed", required=True, help="Seed file")
    p.add_argument("-o", "--output", help="Output signature file")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="ECDSA P-256 verify")
    p.add_argument("signature", help="Signature file")
    p.add_argument("pubkey", help="Public key file")
    p.add_argument("file", nargs="?", help="File to verify (or stdin)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("ecdh", help="ECDH key agreement")
    p.add_argument("--generate", action="store_true", help="Generate ECDH keypair")
    p.add_argument("--seed", help="Our secret seed file")
    p.add_argument("--peer", help="Peer public key file")
    p.add_argument("-o", "--output", help="Output prefix")
    p.set_defaults(func=cmd_ecdh)

    p = sub.add_parser("convert", help="Convert key/data format")
    p.add_argument("input", help="Input file")
    p.add_argument("-f", "--format", default="hex", choices=["hex", "base64", "base32", "binary", "c-array", "python-bytes"], help="Output format")
    p.add_argument("-o", "--output", help="Output file")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("fingerprint", help="Generate key fingerprint")
    p.add_argument("-f", "--file", help="File to fingerprint")
    p.add_argument("--hex", help="Hex string to fingerprint")
    p.add_argument("-s", "--string", help="String to fingerprint")
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("analyze", help="Entropy analysis")
    p.add_argument("-f", "--file", help="File to analyze")
    p.add_argument("--hex", help="Hex string to analyze")
    p.add_argument("--hist", action="store_true", help="Show full histogram")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("list", help="List available algorithms and recipes")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("bench", help="Benchmark cryptographic operations")
    p.add_argument("-a", "--algo", default="inf1del-kyber", help="Algorithm to benchmark")
    p.add_argument("-n", "--iterations", type=int, default=10, help="Iterations")
    p.add_argument("--all", action="store_true", help="Benchmark all available algorithms")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("info", help="Show cryptographic parameters")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("interactive", help="Interactive cipher workbench REPL")
    p.set_defaults(func=cmd_interactive)
    p = sub.add_parser("tui", help="Terminal UI (launches interactive REPL)")
    p.set_defaults(func=cmd_interactive)

    p = sub.add_parser("coffee", help="Display Coffee Protocol art")
    p.set_defaults(func=cmd_coffee)

    p = sub.add_parser("ascii", help="Convert image to ASCII art")
    p.add_argument("input", help="Input image file")
    p.add_argument("-w", "--width", type=int, help="Output width (default: 100)")
    p.add_argument("--height", type=int, help="Output height")
    p.add_argument("-c", "--chars", help="Character set (default: @%%#*+=-:. )")
    p.add_argument("-o", "--output", help="Output file")
    p.set_defaults(func=cmd_ascii)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
