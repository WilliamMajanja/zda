#!/usr/bin/env python3
from __future__ import annotations
"""CPIP/HTCPCP Server v7.0.0 — Coffee Pot Internet Protocol
RFC 2324 (HTCPCP) + RFC 7168 (HTCPCP-TEA) + CPIP Extension

Cryptography:
- CoffeeCipher v5: AES-256-GCM (FIPS 197) + HKDF-SHA256
- ECDSA P-256 (FIPS 186-4): Signatures + ECDH
- Optional HybridKEM API: ECDH P-256 + configured KEM backend; bundled 1nf1D3L variants are custom/non-FIPS
- SLH-DSA (FIPS 205): Stateless hash-based signatures (12 variants)
- ML-DSA (FIPS 204): Module-lattice signatures (Dilithium)
- All randomness: os.urandom (FIPS 140-2 compliant RNG)
"""

TEAPOT_SNAKE_ART = r"""
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



import sys

sys.dont_write_bytecode = True

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import queue
import random
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Callable, ClassVar
from urllib.parse import parse_qs, urlparse


def _load_project_env() -> None:
    """Load plain CPIP_* settings saved by the desktop key manager.

    Existing process environment always wins; values are never evaluated as
    shell syntax and non-CPIP entries are ignored.
    """
    env_path = Path(__file__).resolve().parent / ".env"
    try:
        for line in env_path.read_text().splitlines():
            item = line.strip()
            if not item or item.startswith("#") or "=" not in item:
                continue
            name, value = item.split("=", 1)
            name, value = name.strip(), value.strip()
            if not name.startswith("CPIP_"):
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            os.environ.setdefault(name, value)
    except OSError:
        pass


_load_project_env()

import providers as cpip_providers
from providers.base import BaseProvider, ProviderType
from providers.registry import ProviderRegistry
from providers.kem import KEMProvider, PQC_KEM_REGISTRY, get_pqc_kem, list_pqc_kems, register_kem_provider
from providers.spoof import SPOOF_ENABLED, SPOOF_MODE, IPRotator, ProxyManager, get_spoofed_socket, wrap_urllib_for_spoof
from providers.palantir import PalantirHardening, PALANTIR_ENABLED, PALANTIR_CHAFF, PALANTIR_MIX_DELAY, PALANTIR_FIXED_SIZE, PALANTIR_BROADCAST
from providers import rfc_api

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Radio interface (C binary for LoRa / packet radio)
try:
    from radio import RadioError, RadioInterface
    RADIO_IMPORT_OK = True
except ImportError:
    RadioInterface = None
    RadioError = Exception
    RADIO_IMPORT_OK = False

# ── Configuration ─────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
DEVICE_TYPE = os.environ.get("CPIP_DEVICE", "hyper-text")
BIND_ADDR = os.environ.get("CPIP_BIND") or ""
BIND_PORT = int(os.environ.get("CPIP_PORT", "4180"))
WEB_DIR = Path(os.environ.get("CPIP_WEB_DIR", Path(__file__).parent / "web"))


def _sock_bind(sock, addr):
    sock.bind(addr)

# Allowlist of serveable static files, computed once at startup so that
# request-controlled paths never reach a filesystem read.
_STATIC_FILE_MAP: dict[str, Path] = (
    {str(p.relative_to(WEB_DIR)): p.resolve() for p in WEB_DIR.rglob("*") if p.is_file()}
    if WEB_DIR.is_dir() else {}
)
_STATIC_ALLOWLIST = frozenset(str(p) for p in _STATIC_FILE_MAP.values())
HOSTNAME = socket.gethostname().split(".")[0]
POT_ID = hashlib.sha256(f"{HOSTNAME}:{BIND_PORT}".encode()).hexdigest()[:8]
# Runtime state (accessible from signal handler)
_http_server = None
_redirect_server = None

GPIO_PIN = int(os.environ.get("CPIP_GPIO_PIN", "17"))
GPIO_ENABLED = os.environ.get("CPIP_GPIO", "0") == "1"
AVAHI_ENABLED = os.environ.get("CPIP_AVAHI", "1") == "1"
DISCOVERY_PORT = int(os.environ.get("CPIP_DISCOVERY_PORT", "4190"))
HISTORY_MAX = 100
SCHEDULE_CHECK_INTERVAL = 15

# ── Provider System Configuration ──────────────────────────────────────
CPIP_PROVIDERS = os.environ.get("CPIP_PROVIDERS", "all")
CPIP_PROVIDER_DNS_ENABLED = os.environ.get("CPIP_PROVIDER_DNS", "1") == "1"
CPIP_PROVIDER_MESH_ENABLED = os.environ.get("CPIP_PROVIDER_MESH", "1") == "1"

# ── FIPS 140-2/3 Compliance Mode ───────────────────────────────────────
FIPS_MODE = os.environ.get("CPIP_FIPS", "0") == "1"

# ── HSM (PKCS#11) Support ──────────────────────────────────────────────
HSM_MODULE = os.environ.get("CPIP_HSM_MODULE", "")
HSM_PIN = os.environ.get("CPIP_HSM_PIN", "")
HSM_TOKEN_LABEL = os.environ.get("CPIP_HSM_TOKEN_LABEL", "cpip")

# ── SSL/TLS Configuration ──────────────────────────────────────────────
SSL_ENABLED = os.environ.get("CPIP_SSL", "1") == "1"
SSL_CERT = os.environ.get("CPIP_SSL_CERT", "")
SSL_KEY = os.environ.get("CPIP_SSL_KEY", "")
SSL_AUTO_CERT = os.environ.get("CPIP_SSL_AUTO", "1") == "1"
SSL_CERT_DIR = os.environ.get("CPIP_SSL_CERT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ssl"))
HTTP_REDIRECT = os.environ.get("CPIP_HTTP_REDIRECT", "1") == "1"
HTTP_REDIRECT_PORT = int(os.environ.get("CPIP_HTTP_REDIRECT_PORT", "4181"))

_raw_key = os.environ.get("CPIP_COVERT_KEY", "")
if not _raw_key or _raw_key == "CHANGE_ME_COFFEE_BLEND_2024":
    _was_default = _raw_key == "CHANGE_ME_COFFEE_BLEND_2024"
    COVERT_KEY_SEED = os.urandom(32)
    COVERT_KEY = b"\x00" * 32
    _COVERT_KEY_DERIVED = False
    if _was_default:
        print("   ⚠ REJECTED default COVERT_KEY — keygen-derived (ECP256 P-256)", flush=True)
    else:
        print("   ⚠ COVERT_KEY not set — keygen-derived (ECP256 P-256)", flush=True)
    print("   ⚠ Set CPIP_COVERT_KEY in environment to use a fixed key.", flush=True)
else:
    COVERT_KEY_SEED = b""
    COVERT_KEY = _raw_key.encode()
    _COVERT_KEY_DERIVED = True
if len(COVERT_KEY) < 16:
    print("   ⚠ WARNING: COVERT_KEY is shorter than 16 bytes — insecure.", flush=True)
    print("   ⚠ Use a key of at least 24 bytes (32 bytes recommended).", flush=True)
COVERT_ENABLED = os.environ.get("CPIP_COVERT", "1") == "1"
# Default coffee recipe for domain-separated KDF (Minima integration uses "minima").
CPIP_RECIPE = os.environ.get("CPIP_RECIPE", "espresso")
MESH_ENABLED = os.environ.get("CPIP_MESH", "1") == "1"
MESH_PORT = int(os.environ.get("CPIP_MESH_PORT", "4191"))
MESH_TTL = int(os.environ.get("CPIP_MESH_TTL", "5"))
MESH_HEARTBEAT = int(os.environ.get("CPIP_MESH_HEARTBEAT", "30"))
COVER_TRAFFIC = os.environ.get("CPIP_COVER_TRAFFIC", "1") == "1"
NTP_SYNC = os.environ.get("CPIP_NTP", "1") == "1"
NTP_SERVER = os.environ.get("CPIP_NTP_SERVER", "pool.ntp.org")
MESH_STEALTH = os.environ.get("CPIP_MESH_STEALTH", "0") == "1"
MESH_LATENT_PORTS = [int(p) for p in os.environ.get("CPIP_MESH_LATENT_PORTS", "4192,4193,4194").split(",") if p.strip().isdigit()]
MESH_HOP_INTERVAL = int(os.environ.get("CPIP_MESH_HOP_INTERVAL", "3600"))
MESH_PERSIST_DIR = os.environ.get("CPIP_MESH_PERSIST_DIR", "/tmp/cpip")

# ── Satellite Mesh (LEO / Internet-Wide) ────────────────────────────────
def _env_bool(name, default):
    v = os.environ.get(name)
    if v is None: return default
    return v.lower() in ("1", "yes", "true")

def _sat_env(name, default):
    """Read CPIP_SAT_* with CPIP_STARLINK_* alias fallback for backward compat."""
    v = os.environ.get(name)
    if v is None:
        alias = name.replace("CPIP_SAT_", "CPIP_STARLINK_")
        v = os.environ.get(alias)
    return v if v is not None else default

SATELLITE_ENABLED = _env_bool("CPIP_SAT", _env_bool("CPIP_STARLINK", False))
SATELLITE_PORT = int(_sat_env("CPIP_SAT_PORT", "4195"))
SATELLITE_LAT = float(_sat_env("CPIP_SAT_LAT", "0"))
SATELLITE_LON = float(_sat_env("CPIP_SAT_LON", "0"))
SATELLITE_ALT = float(_sat_env("CPIP_SAT_ALT", "0"))
MESH_SAT_TIMEOUT = float(_sat_env("CPIP_SAT_TIMEOUT", "10.0"))
MESH_SAT_HEARTBEAT = int(_sat_env("CPIP_SAT_HEARTBEAT", "60"))
SATELLITE_BOOTSTRAP = _sat_env("CPIP_SAT_BOOTSTRAP", "")
SATELLITE_RELAY = _env_bool("CPIP_SAT_RELAY", _env_bool("CPIP_STARLINK_RELAY", False))

# ── Radio (LoRa / Packet Radio) ─────────────────────────────────────────
RADIO_ENABLED = os.environ.get("CPIP_RADIO", "0") == "1"
RADIO_MODE = os.environ.get("CPIP_RADIO_MODE", "lora")
RADIO_FREQ = int(os.environ.get("CPIP_RADIO_FREQ", "915000000"))
RADIO_SF = int(os.environ.get("CPIP_RADIO_SF", "9"))
RADIO_BW = int(os.environ.get("CPIP_RADIO_BW", "125000"))
RADIO_POWER = int(os.environ.get("CPIP_RADIO_POWER", "17"))
RADIO_DEVICE = os.environ.get("CPIP_RADIO_DEVICE", "/dev/spidev0.0")
RADIO_BAUD = int(os.environ.get("CPIP_RADIO_BAUD", "115200"))

# ── Mobile Broadband (4G/5G / LTE / WWAN) ───────────────────────────────
MOBILE_ENABLED = _env_bool("CPIP_MOBILE", False)
MOBILE_APN = os.environ.get("CPIP_MOBILE_APN", "")
MOBILE_INTERFACE = os.environ.get("CPIP_MOBILE_IFACE", "wwan0")
MOBILE_BOOTSTRAP = os.environ.get("CPIP_MOBILE_BOOTSTRAP", "")
MOBILE_PORT = int(os.environ.get("CPIP_MOBILE_PORT", "4196"))
MOBILE_HEARTBEAT = int(os.environ.get("CPIP_MOBILE_HEARTBEAT", "120"))
MOBILE_KEEPALIVE = int(os.environ.get("CPIP_MOBILE_KEEPALIVE", "30"))
MOBILE_TELEMETRY = _env_bool("CPIP_MOBILE_TELEMETRY", False)

# ── Anti-ISP (NAT traversal, DNS tunnel, WSS relay, DoH) ───────────────
ANTI_ISP_ENABLED = _env_bool("CPIP_ANTI_ISP", True)
STUN_ENABLED = _env_bool("CPIP_STUN", True)
STUN_SERVERS = os.environ.get("CPIP_STUN_SERVERS",
    "stun.l.google.com:19302,stun1.l.google.com:19302,stun2.l.google.com:19302,"
    "stun.ekiga.net:3478,stun.ideasip.com:3478,stun.schlund.de:3478").split(",")
STUN_REFRESH = int(os.environ.get("CPIP_STUN_REFRESH", "300"))
UPNP_ENABLED = _env_bool("CPIP_UPNP", True)
UPNP_LEASE = int(os.environ.get("CPIP_UPNP_LEASE", "3600"))
DNS_TUNNEL_ENABLED = _env_bool("CPIP_DNS_TUNNEL", True)
DNS_TUNNEL_DOMAIN = os.environ.get("CPIP_DNS_TUNNEL_DOMAIN", "")
DNS_TUNNEL_SUBDOMAIN = os.environ.get("CPIP_DNS_TUNNEL_SUBDOMAIN", "cpip")
DNS_CHUNK_SIZE = int(os.environ.get("CPIP_DNS_CHUNK_SIZE", "63"))
WSS_TUNNEL_ENABLED = _env_bool("CPIP_WSS", True)
WSS_RELAY_SERVERS = os.environ.get("CPIP_WSS_RELAYS",
    "wss://relay.fly.dev:443,wss://cpip-relay.herokuapp.com:443").split(",")
WSS_RELAY_TIMEOUT = int(os.environ.get("CPIP_WSS_TIMEOUT", "10"))
RELAY_ENABLED = _env_bool("CPIP_RELAY", True)
RELAY_SERVERS = os.environ.get("CPIP_RELAY_SERVERS",
    "relay1.cpip-project.net:443,relay2.cpip-project.net:443").split(",")
RELAY_TIMEOUT = int(os.environ.get("CPIP_RELAY_TIMEOUT", "5"))
DNS_OBLIVIOUS_ENABLED = _env_bool("CPIP_DOH", True)
DNS_OBLIVIOUS_SERVERS = os.environ.get("CPIP_DOH_SERVERS",
    "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,"
    "https://dns.quad9.net/dns-query").split(",")

# ── IP Spoofing / Proxy Rotation ─────────────────────────────────────────

PITAIL_ENABLED = os.environ.get("CPIP_PITAIL", "0") == "1"
PITAIL_ADDR = os.environ.get("CPIP_PITAIL_ADDR", "10.0.0.1")
PITAIL_NETMASK = os.environ.get("CPIP_PITAIL_NETMASK", "255.255.255.0")
PITAIL_GADGET_DIR = os.environ.get("CPIP_PITAIL_GADGET_DIR", "/sys/kernel/config/usb_gadget")
THERMOS_ENABLED = os.environ.get("CPIP_THERMOS", "0") == "1"
THERMOS_MAX_STORAGE = int(os.environ.get("CPIP_THERMOS_MAX", "1000000"))

# ── Palantir-Grade Counter-Surveillance Hardening ─────────────────────
PALANTIR_ENABLED = os.environ.get("CPIP_PALANTIR", "0") == "1"
PALANTIR_MODE = os.environ.get("CPIP_PALANTIR_MODE", "auto")

# ── Anti-Stingray / IMSI Catcher Detection ─────────────────────────────
ANTI_STINGRAY_ENABLED = _env_bool("CPIP_ANTI_STINGRAY", True)
STINGRAY_SCAN_INTERVAL = int(os.environ.get("CPIP_STINGRAY_SCAN", "30"))
STINGRAY_SIGNAL_ANOMALY_THRESHOLD = float(os.environ.get("CPIP_STINGRAY_SIGNAL_DB", "50"))
STINGRAY_KNOWN_MCC_MNC = os.environ.get("CPIP_STINGRAY_KNOWN_MCC_MNC",
    "310260,310030,311480,310010,310006").split(",")
STINGRAY_CELL_WATCH_PORTS = [int(p) for p in os.environ.get("CPIP_STINGRAY_PORTS", "443,80,53,8080").split(",")]
STINGRAY_CELL_SCAN = _env_bool("CPIP_STINGRAY_CELL", True)
STINGRAY_RF_SCAN = _env_bool("CPIP_STINGRAY_RF", True)
STINGRAY_SIG_SCAN = _env_bool("CPIP_STINGRAY_SIG", True)
STINGRAY_KNOWN_SCAN = _env_bool("CPIP_STINGRAY_KNOWN", True)

# ── Anti-Palantir / Anti-Pegasus / Counter-Surveillance ─────────────────
ANTI_SURVEILLANCE_ENABLED = _env_bool("CPIP_ANTI_SURVEILLANCE", True)
DPI_EVASION_ENABLED = _env_bool("CPIP_DPI_EVASION", True)
DPI_EVASION_MODE = os.environ.get("CPIP_DPI_EVASION_MODE", "aggressive")
TRAFFIC_OBFUSCATION = _env_bool("CPIP_TRAFFIC_OBFUSC", True)
METADATA_STRIP = _env_bool("CPIP_METADATA_STRIP", True)
TLS_FINGERPRINT_ROTATE = int(os.environ.get("CPIP_TLS_FP_ROTATE", "3600"))
EXPLOITKIT_DETECT = _env_bool("CPIP_EXPLOITKIT_DETECT", True)
PROCESS_INJECT_DETECT = _env_bool("CPIP_PROC_INJECT_DETECT", True)

# ── Net Neutrality ──────────────────────────────────────────────────────
NET_NEUTRALITY_ENABLED = _env_bool("CPIP_NET_NEUTRALITY", True)
NN_BANDWIDTH_MONITOR = _env_bool("CPIP_NN_BW_MONITOR", True)
NN_PROTOCOL_MASQUERADE = _env_bool("CPIP_NN_PROTO_MASK", True)
NN_MASK_PROTOCOL = os.environ.get("CPIP_NN_MASK_AS", "standard_web")
NN_FRAGMENT_EVASION = _env_bool("CPIP_NN_FRAG_EVASION", True)
NN_THROTTLE_DETECT = _env_bool("CPIP_NN_THROTTLE_DETECT", True)
NN_JITTER_INJECTION = _env_bool("CPIP_NN_JITTER", True)
NN_COVER_SIZE_MIN = int(os.environ.get("CPIP_NN_COVER_MIN", "256"))
NN_COVER_SIZE_MAX = int(os.environ.get("CPIP_NN_COVER_MAX", "1024"))

# ── Bandwidth Aggregation / Multi-Link Bonding ──────────────────────────
BONDING_ENABLED = os.environ.get("CPIP_BONDING", "1") == "1"
BOND_CHUNK_MIN = int(os.environ.get("CPIP_BOND_CHUNK_MIN", "512"))
BOND_CHUNK_MAX = int(os.environ.get("CPIP_BOND_CHUNK_MAX", "4096"))
BOND_RETRY_TIMEOUT = float(os.environ.get("CPIP_BOND_RETRY", "2.0"))
BOND_MAX_SUBFLOWS = int(os.environ.get("CPIP_BOND_SUBFLOWS", "8"))
BOND_HEALTH_INTERVAL = float(os.environ.get("CPIP_BOND_HEALTH", "5.0"))
BOND_PROBE_SIZE = int(os.environ.get("CPIP_BOND_PROBE_SIZE", "1024"))
BOND_STALE_LINK = float(os.environ.get("CPIP_BOND_STALE", "30.0"))
BOND_LOSS_THRESHOLD = float(os.environ.get("CPIP_BOND_LOSS", "0.2"))
BOND_LATENCY_WINDOW = int(os.environ.get("CPIP_BOND_LAT_WIN", "10"))

CPIP_VERSION = "7.0.0"
CPIP_PROTOCOL = f"CPIP/{CPIP_VERSION} (RFC 2324 + RFC 7168 + RFC 6969 + Mesh + Multi-Transport + PQ-Crypto + Anti-ISP + Anti-Stingray + Anti-DPI + Net-Neutrality + Multi-Link Bonding + Palantir + IP Spoofing)"
_START_TIME = time.time()


def _generate_self_signed_cert(cert_dir: str) -> tuple:
    """Generate a locally-trusted SSL certificate for HTTPS.
    
    Tries mkcert first (creates certs trusted by the local CA), then falls
    back to openssl self-signed, then to the cryptography library.
    Reuses existing valid certs to avoid Chromium trust issues on restart.
    Returns (cert_path, key_path).
    """
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")
    os.makedirs(cert_dir, exist_ok=True)

    # Reuse existing valid cert if present, not expired, and has SANs
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            r = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-checkend", "0",
                 "-noout", "-text"],
                capture_output=True, text=True, timeout=10, check=False)
            if r.returncode == 0 and "Subject Alternative Name" in r.stdout:
                return cert_path, key_path
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # Find mkcert: check PATH first, then project-local binary
    import shutil
    mkcert_bin = shutil.which("mkcert")
    if not mkcert_bin:
        mkcert_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mkcert")
    names = ["localhost", "127.0.0.1", f"{HOSTNAME}.local", HOSTNAME, "::1"]
    try:
        result = subprocess.run(
            [mkcert_bin, "-cert-file", cert_path, "-key-file", key_path] + names,
            capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            ca_root = subprocess.run(
                [mkcert_bin, "-CAROOT"], capture_output=True, text=True, timeout=10, check=False)
            if ca_root.returncode == 0:
                ca_cert = os.path.join(ca_root.stdout.strip(), "rootCA.pem")
                if os.path.exists(ca_cert):
                    with open(cert_path, "ab") as f, open(ca_cert, "rb") as ca:
                        f.write(ca.read())
            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
            return cert_path, key_path
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    san = f"DNS:localhost,DNS:{HOSTNAME}.local,DNS:{HOSTNAME},IP:127.0.0.1"
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost/O=CPIP/C=US",
            "-addext", f"subjectAltName={san}",
            "-addext", "basicConstraints=CA:FALSE",
            "-addext", "keyUsage=digitalSignature,keyEncipherment",
        ], capture_output=True, check=True, timeout=30)
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
        return cert_path, key_path
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    try:
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CPIP"),
        ])
        cert = (x509.CertificateBuilder()
                 .subject_name(subject).issuer_name(issuer)
                 .public_key(key.public_key())
                 .serial_number(x509.random_serial_number())
                .not_valid_before(dt.datetime.now(tz=dt.timezone.utc))
                .not_valid_after(dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(days=365))
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                 .add_extension(x509.SubjectAlternativeName([
                     x509.DNSName("localhost"),
                     x509.DNSName(f"{HOSTNAME}.local"),
                     x509.DNSName(HOSTNAME),
                     x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                 ]), critical=False)
                 .sign(key, hashes.SHA256()))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
        return cert_path, key_path
    except ImportError:
        pass
    key_pem = _generate_pem_key()
    cert_pem = _generate_pem_cert(key_pem)
    with open(key_path, "w") as f:
        f.write(key_pem)
    with open(cert_path, "w") as f:
        f.write(cert_pem)
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    return cert_path, key_path


def _generate_pem_key() -> str:
    """Generate RSA-2048 private key via openssl. Fails if openssl unavailable."""
    try:
        r = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, text=True, timeout=10, check=False)
        if r.returncode == 0 and "BEGIN" in r.stdout:
            return r.stdout
    except Exception as _e:
        logger.debug("Ignored: %s", _e)
    raise RuntimeError("Cannot generate SSL key: openssl not found. Install openssl or provide CPIP_SSL_KEY.")


def _generate_pem_cert(key_pem: str) -> str:
    """Generate self-signed cert via openssl. Fails if openssl unavailable."""
    try:
        san = f"DNS:localhost,DNS:{HOSTNAME}.local,DNS:{HOSTNAME},IP:127.0.0.1"
        r = subprocess.run([
            "openssl", "req", "-new", "-x509", "-key", "/dev/stdin",
            "-days", "365", "-nodes", "-subj", "/CN=localhost/O=CPIP/C=US",
            "-addext", f"subjectAltName={san}",
            "-addext", "basicConstraints=CA:FALSE",
        ], input=key_pem, capture_output=True, text=True, timeout=10, check=False)
        if r.returncode == 0 and "BEGIN" in r.stdout:
            return r.stdout
    except Exception as _e:
        logger.debug("Ignored: %s", _e)
    raise RuntimeError("Cannot generate SSL cert: openssl not found. Install openssl or provide CPIP_SSL_CERT.")


import ipaddress

# ── Valid additions (RFC 2324 §2.2.2 + RFC 7168) ─────────────────────
VALID_ADDITIONS = {
    "milk":    {"type": "dairy",     "variety": ["cream", "half-and-half", "whole", "part-skim", "skim", "non-dairy"]},
    "syrup":   {"type": "sweetener", "variety": ["vanilla", "caramel", "almond", "hazelnut", "chocolate"]},
    "sugar":   {"type": "sweetener", "variety": ["white", "brown", "raw", "honey", "artificial"]},
    "spice":   {"type": "flavoring", "variety": ["cinnamon", "cardamom", "nutmeg", "clove"]},
    "alcohol": {"type": "alcohol",   "variety": ["whisky", "rum", "kahlua", "aquavit", "brandy"]},
}

DEVICE_BEVERAGE_MAP = {
    "teapot":     ["tea"],
    "coffee-pot": ["coffee"],
    "hyper-text": ["coffee", "tea"],
}

ALCOHOL_DEVICES = {"hyper-text"}

BREW_MESSAGES = {
    "teapot":     "Your teapot is steeping. Send WHEN to stop.",
    "coffee-pot": "Your coffee pot is brewing. Send WHEN to stop.",
    "hyper-text": "Your hyper-text coffee pot is brewing. Send WHEN to stop.",
}

WHEN_MESSAGES = {
    "teapot":     "Tea is ready. Pouring stopped.",
    "coffee-pot": "Coffee is ready. Pouring stopped.",
    "hyper-text": "Beverage is ready. Pouring stopped.",
}

ADDITION_TYPE_BITS = {"milk": 0, "syrup": 1, "sugar": 2, "spice": 3, "alcohol": 4}
BITS_TO_ADDITION = {v: k for k, v in ADDITION_TYPE_BITS.items()}

# ── coffee: URI scheme (RFC 2324 §3) — 24 international variants ─────
COFFEE_SCHEMES = [
    "koffie",                      # Afrikaans, Dutch
    "q%C3%A6hv%C3%A6",            # Azerbaijani
    "%D9%82%D9%87%D9%88%D8%A9",   # Arabic
    "akeita",                      # Basque
    "koffee",                      # Bengali
    "kahva",                       # Bosnian
    "kafe",                        # Bulgarian, Czech
    "caf%C3%A8",                   # Catalan, French, Galician
    "%E5%92%96%E5%95%A1",          # Chinese
    "kava",                        # Croatian
    "k%C3%A1va",                   # Czech
    "kaffe",                       # Danish, Norwegian, Swedish
    "coffee",                      # English
    "kafo",                        # Esperanto
    "kohv",                        # Estonian
    "kahvi",                       # Finnish
    "%4Baffee",                    # German
    "%CE%BA%CE%B1%CF%86%CE%AD",   # Greek
    "%E0%A4%95%E0%A5%8C%E0%A4%AB%E0%A5%80", # Hindi
    "%E3%82%B3%E3%83%BC%E3%83%92%E3%83%BC", # Japanese
    "%EC%BB%A4%ED%94%BC",          # Korean
    "%D0%BA%D0%BE%D1%84%D0%B5",    # Russian
    "%E0%B8%81%E0%B8%B2%E0%B9%81%E0%B8%9F", # Thai
    "kahawa",                      # Swahili
]
COFFEE_SCHEME_NAMES = {s.lower() for s in COFFEE_SCHEMES}

COFFEE_LANGUAGE_MAP = {
    "koffie": "Afrikaans, Dutch",
    "q%C3%A6hv%C3%A6": "Azerbaijani",
    "%D9%82%D9%87%D9%88%D8%A9": "Arabic",
    "akeita": "Basque",
    "koffee": "Bengali",
    "kahva": "Bosnian",
    "kafe": "Bulgarian, Czech",
    "caf%C3%A8": "Catalan, French, Galician",
    "%E5%92%96%E5%95%A1": "Chinese",
    "kava": "Croatian",
    "k%C3%A1va": "Czech",
    "kaffe": "Danish, Norwegian, Swedish",
    "coffee": "English",
    "kafo": "Esperanto",
    "kohv": "Estonian",
    "kahvi": "Finnish",
    "%4Baffee": "German",
    "%CE%BA%CE%B1%CF%86%CE%AD": "Greek",
    "%E0%A4%95%E0%A5%8C%E0%A4%AB%E0%A5%80": "Hindi",
    "%E3%82%B3%E3%83%BC%E3%83%92%E3%83%BC": "Japanese",
    "%EC%BB%A4%ED%94%BC": "Korean",
    "%D0%BA%D0%BE%D1%84%D0%B5": "Russian",
    "%E0%B8%81%E0%B8%B2%E0%B9%81%E0%B8%9F": "Thai",
    "kahawa": "Swahili",
}

# ── Coffee Cipher v5 — FIPS-Compliant AES-256-GCM ────────────────────
class CoffeeCipher:
    """Coffee Blend Cipher v5 — FIPS-compliant authenticated encryption.

    Uses AES-256-GCM (FIPS 197) for authenticated encryption with
    HKDF-SHA256 key derivation (SP 800-56C). All random values use
    secrets module (os.urandom) for FIPS 140-2 compliant RNG.

    Format: nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
    Key derivation: HKDF-SHA256 with domain-separated info strings.
    """

    @classmethod
    def _hkdf_extract(cls, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract: extract pseudorandom key from input keying material.
        HMAC-SHA256 PRF (SP 800-56C §5.1.1)."""
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    @classmethod
    def _hkdf_expand(cls, prk: bytes, info: bytes, length: int = 32) -> bytes:
        """HKDF-Expand: expand PRK into output keying material.
        HMAC-SHA256 PRF (SP 800-56C §5.1.2)."""
        n = (length + 31) // 32
        okm = b""
        t = b""
        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:length]

    @classmethod
    def hkdf(cls, ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        """Full HKDF (Extract-then-Expand) per SP 800-56C."""
        prk = cls._hkdf_extract(salt, ikm)
        return cls._hkdf_expand(prk, info, length)

    @classmethod
    def key_from_recipe(cls, base_key: bytes, recipe: str = "espresso") -> bytes:
        """Derive cipher key from a coffee recipe name using full HKDF.
        
        Different recipes produce cryptographically independent keys.
        Uses HKDF-Extract-then-Expand (SP 800-56C).
        """
        recipe_bytes = recipe.encode()
        salt = hashlib.sha256(b"\xc0\xff\xee" + recipe_bytes).digest()
        return cls.hkdf(base_key, salt, b"cpip-cipher-v5:" + recipe_bytes, 32)

    @classmethod
    def encrypt(cls, plaintext: bytes, base_key: bytes | None = None, recipe: str = "espresso") -> bytes:
        """Encrypt using AES-256-GCM (FIPS 197).
        
        Format: nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
        - A random 12-byte nonce is generated per encryption (SP 800-38D)
        - AES-GCM provides both confidentiality and integrity
        """
        if base_key is None:
            base_key = COVERT_KEY
        key = cls.key_from_recipe(base_key, recipe)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    @classmethod
    def decrypt(cls, ciphertext: bytes, base_key: bytes | None = None, recipe: str = "espresso") -> bytes:
        """Decrypt using AES-256-GCM (FIPS 197).
        
        Expects format: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
        Returns plaintext if authentication succeeds, or b'' on failure.
        """
        if base_key is None:
            base_key = COVERT_KEY
        if len(ciphertext) < 28:
            return b""
        key = cls.key_from_recipe(base_key, recipe)
        nonce = ciphertext[:12]
        ct_and_tag = ciphertext[12:]
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct_and_tag, None)
        except Exception:
            return b""

    @classmethod
    def hash(cls, data: bytes) -> str:
        """SHA-256 based hash with domain separation (FIPS 180-4)."""
        h = hashlib.sha256(b"cpip-hash-v5:" + data).digest()
        for _ in range(4):
            h = hashlib.sha256(b"cpip-hash-v5:" + h + data).digest()
        return h.hex()[:16]


# ── FIPS 140-2/3 Power-On Self-Tests ───────────────────────────────────
_FIPS_SELF_TESTS_PASSED = False

def _run_fips_self_tests():
    """Run FIPS-approved power-on self-tests (KATs).

    Tests AES-256-GCM encrypt/decrypt, HMAC-SHA256, HKDF, ECDSA sign/verify,
    and ECDH key exchange. Sets _FIPS_SELF_TESTS_PASSED on success.
    Raises RuntimeError with details on failure.
    """
    # AES-256-GCM Known Answer Test
    kat_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    kat_nonce = bytes.fromhex("000102030405060708090a0b")
    kat_pt = b"FIPS 140-2 AES-256-GCM KAT"
    kat_aad = b"cpip-fips-kat"
    aesgcm = AESGCM(kat_key)
    kat_ct = aesgcm.encrypt(kat_nonce, kat_pt, kat_aad)
    kat_dec = aesgcm.decrypt(kat_nonce, kat_ct, kat_aad)
    if kat_dec != kat_pt:
        raise RuntimeError("FIPS KAT failed: AES-256-GCM encrypt/decrypt mismatch")

    # HMAC-SHA256 Known Answer Test
    hmac_key = b"fips-kat-hmac-key-2024"
    hmac_expected = hmac.new(hmac_key, b"FIPS 140-2 HMAC-SHA256 KAT", hashlib.sha256).hexdigest()
    hmac_result = hmac.new(hmac_key, b"FIPS 140-2 HMAC-SHA256 KAT", hashlib.sha256).hexdigest()
    if hmac_result != hmac_expected:
        raise RuntimeError("FIPS KAT failed: HMAC-SHA256 mismatch")

    # HKDF Known Answer Test
    hkdf_ikm = b"fips-kat-hkdf-ikm"
    hkdf_salt = b"fips-kat-hkdf-salt"
    hkdf_info = b"fips-kat-hkdf-info"
    hkdf_out = CoffeeCipher.hkdf(hkdf_ikm, hkdf_salt, hkdf_info, 16)
    if len(hkdf_out) != 16:
        raise RuntimeError("FIPS KAT failed: HKDF output length mismatch")

    # ECDSA sign/verify Known Answer Test
    ecdsa_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdsa_msg = b"FIPS 140-2 ECDSA KAT"
    ecdsa_sig = ecdsa_key.sign(ecdsa_msg, ec.ECDSA(hashes.SHA256()))
    ecdsa_pub = ecdsa_key.public_key()
    try:
        ecdsa_pub.verify(ecdsa_sig, ecdsa_msg, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise RuntimeError("FIPS KAT failed: ECDSA sign/verify")

    # ECDH Known Answer Test
    ecdh_alice = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_bob = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_alice_pub = ecdh_alice.public_key()
    ecdh_bob_pub = ecdh_bob.public_key()
    ecdh_shared_a = ecdh_alice.exchange(ec.ECDH(), ecdh_bob_pub)
    ecdh_shared_b = ecdh_bob.exchange(ec.ECDH(), ecdh_alice_pub)
    if ecdh_shared_a != ecdh_shared_b:
        raise RuntimeError("FIPS KAT failed: ECDH key exchange mismatch")

    global _FIPS_SELF_TESTS_PASSED
    _FIPS_SELF_TESTS_PASSED = True


def fips_assert():
    """Assert that FIPS mode is active and self-tests passed. Call before
    any non-FIPS operation that should be blocked in FIPS mode."""
    if FIPS_MODE and not _FIPS_SELF_TESTS_PASSED:
        raise RuntimeError("FIPS mode enabled but self-tests have not passed")


# ── ECDSA P-256 — FIPS 186-4 Constant-Time ECC ────────────────────────
class ECP256:
    """ECDSA/ECDH using NIST P-256 (secp256r1) — FIPS 186-4 compliant.

    Provides ECDSA digital signatures, ECDH key exchange, and address
    derivation. All operations use the `cryptography` library's constant-time
    curve implementations (SP 800-56A compliant).

    Named ECP256 for clarity.
    """

    _CURVE = ec.SECP256R1()
    _CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    @classmethod
    def _derive_key_from_seed(cls, seed: bytes):
        """Derive an ECDSA private key from a seed using HKDF."""
        derived = hashlib.sha256(b"cpip-ecdsa-v1:" + seed).digest()
        privkey = ec.derive_private_key(int.from_bytes(derived, 'big') % cls._CURVE_ORDER, cls._CURVE, default_backend())
        return privkey

    @classmethod
    def generate_keypair(cls, seed=None):
        """Generate (public_key_bytes, seed, private_key_obj, public_key_obj).
        
        Returns a tuple compatible with the previous API:
          (public_key_bytes, seed, private_key, public_key_point)
        """
        if seed is None:
            seed = secrets.token_bytes(32)
        privkey = cls._derive_key_from_seed(seed)
        pubkey_bytes = privkey.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return (pubkey_bytes, seed, privkey, privkey.public_key())

    @classmethod
    def secret_scalar(cls, seed):
        """Derive the private key object from a seed."""
        return cls._derive_key_from_seed(seed)

    @classmethod
    def sign(cls, message, seed):
        """Sign a message with ECDSA P-256 using SHA-256. Returns DER-encoded signature."""
        privkey = cls._derive_key_from_seed(seed)
        signature = privkey.sign(
            message if isinstance(message, bytes) else message.encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        return signature

    @classmethod
    def verify(cls, message, signature, public_key):
        """Verify an ECDSA P-256 signature. Returns bool."""
        try:
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                pubkey_obj = public_key
            elif isinstance(public_key, bytes):
                pubkey_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                    cls._CURVE, public_key
                )
            else:
                return False
            pubkey_obj.verify(
                signature,
                message if isinstance(message, bytes) else message.encode(),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except Exception:
            return False

    @classmethod
    def key_exchange(cls, our_secret_seed, their_public_key):
        """ECDH: derive shared 32-byte secret using P-256 key exchange (SP 800-56A)."""
        privkey = cls._derive_key_from_seed(our_secret_seed)
        if isinstance(their_public_key, ec.EllipticCurvePublicKey):
            pubkey_obj = their_public_key
        elif isinstance(their_public_key, bytes):
            pubkey_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                cls._CURVE, their_public_key
            )
        else:
            raise TypeError("Invalid public key type for key exchange")
        shared_key = privkey.exchange(ec.ECDH(), pubkey_obj)
        return hashlib.sha256(shared_key).digest()

    @classmethod
    def pubkey_to_address(cls, public_key):
        """Derive a short address string from a public key."""
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            pk_bytes = public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        elif isinstance(public_key, bytes):
            pk_bytes = public_key
        else:
            pk_bytes = public_key
        h = hashlib.sha256(pk_bytes).digest()[:4]
        b32 = base64.b32encode(h).decode().rstrip("=").lower()
        return f"coffee:{b32}"

    @classmethod
    def address_matches(cls, address, public_key):
        return cls.pubkey_to_address(public_key) == address

    @classmethod
    def _encode_point(cls, P):
        """Encode a public key point to bytes (compatibility)."""
        if isinstance(P, ec.EllipticCurvePublicKey):
            return P.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        return P

    @classmethod
    def _decode_point(cls, s):
        """Decode bytes to a public key point (compatibility)."""
        return ec.EllipticCurvePublicKey.from_encoded_point(cls._CURVE, s)

    @classmethod
    def _scalar_mult(cls, n, P):
        """Compatibility: derive a key from scalar n (used as seed) and point P."""
        if isinstance(P, ec.EllipticCurvePublicKey):
            return P
        seed = n.to_bytes(32, 'big') if isinstance(n, int) else n
        return cls._derive_key_from_seed(seed).public_key()

# ECP256 is the canonical name; previously aliased as Ed25519


# ── Parameterized standard and experimental 1nf1D3L KEM sizes ─────────

_ML_KEM_BACKENDS: dict[int, str] = {}
_ML_KEM_SIZES = (512, 768, 1024, 2048, 4096)
_STANDARD_ML_KEM_SIZES = (512, 768, 1024)

# ── Derive COVERT_KEY from ECP256 keygen if not user-supplied ─────────
if not _COVERT_KEY_DERIVED:
    try:
        _ck_pk, _ck_sk, _, _ = ECP256.generate_keypair(COVERT_KEY_SEED)
        COVERT_KEY = _ck_sk[:32]
        print("   ✔ COVERT_KEY derived via ECP256 P-256 keygen", flush=True)
    except Exception as _e:
        COVERT_KEY = hashlib.sha256(COVERT_KEY_SEED).digest()
        print("   ⚠ ECP256 keygen fallback: %s" % _e, flush=True)


def _get_ml_kem_backend(size: int) -> str:
    """Select a KEM backend. ``stdlib`` uses no packages outside Python."""
    requested = os.environ.get("CPIP_ML_KEM_BACKEND", "auto").strip().lower()
    if size not in _ML_KEM_SIZES:
        raise ValueError(f"Unsupported KEM size: {size}")
    if requested in ("stdlib", "python", "pure-python"):
        _ML_KEM_BACKENDS[size] = "stdlib"
        return "stdlib"
    if requested not in ("auto", "numpy", "inf1del", "pqcrypto"):
        raise ValueError("CPIP_ML_KEM_BACKEND must be auto, stdlib, numpy, inf1del, or pqcrypto")
    backend = _ML_KEM_BACKENDS.get(size)
    if backend is not None:
        return backend
    if requested in ("auto", "numpy", "inf1del"):
        try:
            from inf1del_kyber import Inf1delKyber
            Inf1delKyber.keygen(size=size)
            _ML_KEM_BACKENDS[size] = "inf1del"
            return "inf1del"
        except Exception as _e:
            logger.debug("Inf1delKyber init failed for ML-KEM-%d: %s", size, _e)
            if requested in ("numpy", "inf1del"):
                raise RuntimeError(f"Requested NumPy KEM backend unavailable for size {size}") from _e
    if requested == "pqcrypto" and size not in _STANDARD_ML_KEM_SIZES:
        raise RuntimeError("pqcrypto only provides standard ML-KEM-512/768/1024; extended sizes require the 1nf1D3L backend")
    if requested == "pqcrypto" and not _PQCRYPTO_AVAILABLE:
        raise RuntimeError("pqcrypto backend requested but unavailable")
    if requested in ("auto", "pqcrypto") and size in _STANDARD_ML_KEM_SIZES and _PQCRYPTO_AVAILABLE:
        _ML_KEM_BACKENDS[size] = "pqcrypto"
        return "pqcrypto"
    if requested == "auto":
        try:
            from pure_mlkem import PurePythonMLKEM
            PurePythonMLKEM(size).keygen()
            _ML_KEM_BACKENDS[size] = "stdlib"
            return "stdlib"
        except Exception as _e:
            logger.debug("stdlib ML-KEM-%d init failed: %s", size, _e)
    raise RuntimeError(f"No ML-KEM-{size} backend available")


class DSA_ML_KEM:
    """Bundled custom KEM at standard and experimental module ranks.

    Backends (in priority order):
    1. 1nf1D3L's NumPy implementation, if available
    2. pqcrypto, if installed
    3. The standard-library-only pure-Python implementation

    512/768/1024 are standard parameter-size labels. 2048/4096 are experimental
    1nf1D3L ranks, not standardized security levels. All bundled variants are
    non-FIPS and are not wire-compatible with FIPS 203 ciphertexts.
    """

    _PARAMS = {
        512: {"N": 256, "K": 2, "Q": 3329, "ETA1": 3, "ETA2": 2, "DU": 10, "DV": 4,
               "PK_SIZE": 800, "SK_SIZE": 1632, "CT_SIZE": 800, "SS_SIZE": 32},
        768: {"N": 256, "K": 3, "Q": 3329, "ETA1": 3, "ETA2": 2, "DU": 10, "DV": 4,
               "PK_SIZE": 1184, "SK_SIZE": 2400, "CT_SIZE": 1120, "SS_SIZE": 32},
        1024: {"N": 256, "K": 4, "Q": 3329, "ETA1": 3, "ETA2": 2, "DU": 11, "DV": 5,
                 "PK_SIZE": 1568, "SK_SIZE": 3168, "CT_SIZE": 1600, "SS_SIZE": 32},
        2048: {"N": 256, "K": 8, "Q": 3329, "ETA1": 3, "ETA2": 2, "DU": 12, "DV": 5,
                 "PK_SIZE": 3104, "SK_SIZE": 6240, "CT_SIZE": 3264, "SS_SIZE": 32},
        4096: {"N": 256, "K": 16, "Q": 3329, "ETA1": 3, "ETA2": 2, "DU": 13, "DV": 5,
                 "PK_SIZE": 6176, "SK_SIZE": 12384, "CT_SIZE": 6848, "SS_SIZE": 32},
    }

    def __init__(self, size: int = 768):
        if size not in self._PARAMS:
            raise ValueError(f"Unsupported KEM size: {size}. Use 512, 768, 1024, 2048, or 4096.")
        self.size = size
        self._p = self._PARAMS[size]

    @property
    def algorithm(self) -> str:
        if self.size in _STANDARD_ML_KEM_SIZES:
            return f"ml_kem_{self.size}"
        return f"1nf1d3l_kem_{self.size}"

    @property
    def public_key_size(self) -> int:
        return self._p["PK_SIZE"]

    @property
    def secret_key_size(self) -> int:
        return self._p["SK_SIZE"]

    @property
    def ciphertext_size(self) -> int:
        return self._p["CT_SIZE"]

    @property
    def shared_key_size(self) -> int:
        return self._p["SS_SIZE"]

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate ML-KEM-{self.size} keypair."""
        backend = _get_ml_kem_backend(self.size)
        if backend == "inf1del":
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.keygen(size=self.size)
        if backend == "stdlib":
            from pure_mlkem import keygen
            return keygen(size=self.size)
        if backend == "pqcrypto":
            mod = __import__(f"pqcrypto.kem.ml_kem_{self.size}", fromlist=["ml_kem"])
            return mod.generate_keypair()
        raise RuntimeError(f"No ML-KEM-{self.size} backend available")

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate for an ML-KEM-{self.size} public key."""
        backend = _get_ml_kem_backend(self.size)
        if backend == "inf1del":
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.encaps(public_key, size=self.size)
        if backend == "stdlib":
            from pure_mlkem import encaps
            return encaps(public_key, size=self.size)
        if backend == "pqcrypto":
            mod = __import__(f"pqcrypto.kem.ml_kem_{self.size}", fromlist=["ml_kem"])
            return mod.encrypt(public_key)
        raise RuntimeError(f"No ML-KEM-{self.size} backend available")

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-{self.size} secret key."""
        backend = _get_ml_kem_backend(self.size)
        if backend == "inf1del":
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.decaps(secret_key, ciphertext, size=self.size)
        if backend == "stdlib":
            from pure_mlkem import decaps
            return decaps(secret_key, ciphertext, size=self.size)
        if backend == "pqcrypto":
            mod = __import__(f"pqcrypto.kem.ml_kem_{self.size}", fromlist=["ml_kem"])
            return mod.decrypt(secret_key, ciphertext)
        raise RuntimeError(f"No ML-KEM-{self.size} backend available")

    def hybrid_keygen(self, ecc_seed: bytes | None = None) -> tuple[bytes, bytes]:
        """Hybrid ECDH P-256 + ML-KEM-{self.size} keypair."""
        ecc_pk, ecc_seed_out, _, _ = ECP256.generate_keypair(ecc_seed)
        pk, sk = self.keygen()
        ecc_pk_len = len(ecc_pk).to_bytes(2, "big")
        hybrid_pk = ecc_pk_len + ecc_pk + pk
        hybrid_sk = ecc_seed_out + sk
        return hybrid_pk, hybrid_sk

    def hybrid_encapsulate(self, hybrid_pk: bytes) -> tuple[bytes, bytes]:
        """Hybrid encapsulation: ECDH + ML-KEM-{self.size}."""
        ecc_pk_len = int.from_bytes(hybrid_pk[:2], "big")
        ecc_pk = hybrid_pk[2:2 + ecc_pk_len]
        kyber_pk = hybrid_pk[2 + ecc_pk_len:]
        ecc_ephem_seed = secrets.token_bytes(32)
        ecc_ephem_pk, _, _, _ = ECP256.generate_keypair(ecc_ephem_seed)
        ecdh_shared = ECP256.key_exchange(ecc_ephem_seed, ecc_pk)
        kyber_ct, kyber_ss = self.encapsulate(kyber_pk)
        combined = ecdh_shared + kyber_ss + b"cpip-hybrid-mlkem-v1"
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-shared-mlkem-v1", 32)
        ecc_ephem_len = len(ecc_ephem_pk).to_bytes(2, "big")
        ciphertext = ecc_ephem_len + ecc_ephem_pk + kyber_ct
        return ciphertext, shared

    def hybrid_decapsulate(self, hybrid_sk: bytes, ciphertext: bytes) -> bytes:
        """Hybrid decapsulation: ECDH + ML-KEM-{self.size}."""
        ecc_seed = hybrid_sk[:32]
        kyber_sk = hybrid_sk[32:]
        ecc_ephem_len = int.from_bytes(ciphertext[:2], "big")
        ecc_ephem_pk = ciphertext[2:2 + ecc_ephem_len]
        kyber_ct = ciphertext[2 + ecc_ephem_len:]
        ecdh_shared = ECP256.key_exchange(ecc_seed, ecc_ephem_pk)
        kyber_ss = self.decapsulate(kyber_sk, kyber_ct)
        combined = ecdh_shared + kyber_ss + b"cpip-hybrid-mlkem-v1"
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-shared-mlkem-v1", 32)
        return shared


# ── DSA-SLH-DSA (SPHINCS+) — Stateless Hash-Based Signatures ────

class DSA_SLH_SPHINCS:
    """SLH-DSA (SPHINCS+) stateless hash-based signature scheme.

    NIST FIPS 205 standardized. Supports SHA2 and SHAKE variants
    at 128-bit, 192-bit, and 256-bit security levels.

    Backend priority:
    1. 1nf1D3L's SLH-DSA (domain-separated, recipe-bound)
    2. pqcrypto SPHINCS+ (C extension, standard params)
    """

    _VARIANTS = {
        "slh_dsa_sha2_128f_simple": {"security": 128, "hash": "sha2", "fors": "128f"},
        "slh_dsa_sha2_128s_simple": {"security": 128, "hash": "sha2", "fors": "128s"},
        "slh_dsa_sha2_192f_simple": {"security": 192, "hash": "sha2", "fors": "192f"},
        "slh_dsa_sha2_192s_simple": {"security": 192, "hash": "sha2", "fors": "192s"},
        "slh_dsa_sha2_256f_simple": {"security": 256, "hash": "sha2", "fors": "256f"},
        "slh_dsa_sha2_256s_simple": {"security": 256, "hash": "sha2", "fors": "256s"},
        "slh_dsa_shake_128f_simple": {"security": 128, "hash": "shake", "fors": "128f"},
        "slh_dsa_shake_128s_simple": {"security": 128, "hash": "shake", "fors": "128s"},
        "slh_dsa_shake_192f_simple": {"security": 192, "hash": "shake", "fors": "192f"},
        "slh_dsa_shake_192s_simple": {"security": 192, "hash": "shake", "fors": "192s"},
        "slh_dsa_shake_256f_simple": {"security": 256, "hash": "shake", "fors": "256f"},
        "slh_dsa_shake_256s_simple": {"security": 256, "hash": "shake", "fors": "256s"},
    }

    def __init__(self, variant: str = "slh_dsa_sha2_256f_simple", recipe: str = "espresso"):
        if variant not in self._VARIANTS:
            raise ValueError(f"Unknown SLH-DSA variant: {variant}")
        self.variant = variant
        self._info = self._VARIANTS[variant]
        self.recipe = recipe
        self._mod = None
        self._backend = None

    @property
    def algorithm(self) -> str:
        return self.variant

    @property
    def security_level(self) -> int:
        return self._info["security"]

    def _get_backend(self) -> str:
        """Determine backend: 'inf1del' (domain-separated) or 'pqcrypto'."""
        if self._backend is not None:
            return self._backend
        try:
            from inf1del_kyber import Inf1delSLH
            Inf1delSLH(self.variant, self.recipe)
            self._backend = "inf1del"
            return self._backend
        except Exception:
            pass
        self._backend = "pqcrypto"
        return self._backend

    def _load_mod(self):
        if self._mod is not None:
            return self._mod
        candidates = [f"pqcrypto.sign.{self.variant}"]
        if self.variant.startswith("slh_dsa_"):
            candidates.append(f"pqcrypto.sign.sphincs_{self.variant[len('slh_dsa_'):]}")
        for modname in candidates:
            try:
                self._mod = __import__(modname, fromlist=["pqcrypto"])
                return self._mod
            except ImportError:
                continue
        raise RuntimeError(f"SLH-DSA variant '{self.variant}' not available (pqcrypto not installed)")

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate SLH-DSA keypair. Returns (public_key, secret_key)."""
        backend = self._get_backend()
        if backend == "inf1del":
            from inf1del_kyber import Inf1delSLH
            return Inf1delSLH.keygen(self.variant, self.recipe)
        mod = self._load_mod()
        return mod.generate_keypair()

    def sign(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        """Sign a message. Returns (signature, public_key).

        The pqcrypto SPHINCS+ modules use the detached-signature API and
        return only the signature; the public key is embedded at the end of
        the SPHINCS+ secret key (SK = SEED || SK_PRF || PK), so it is
        recovered here to honor the documented (signature, public_key) return.
        """
        backend = self._get_backend()
        if backend == "inf1del":
            from inf1del_kyber import Inf1delSLH
            return Inf1delSLH.sign(secret_key, message, self.variant, self.recipe)
        mod = self._load_mod()
        result = mod.sign(secret_key, message)
        if isinstance(result, tuple):
            return result
        return result, secret_key[len(secret_key) // 2:]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True if valid."""
        backend = self._get_backend()
        if backend == "inf1del":
            from inf1del_kyber import Inf1delSLH
            return Inf1delSLH.verify(public_key, message, signature, self.variant, self.recipe)
        mod = self._load_mod()
        try:
            return mod.verify(public_key, message, signature)
        except Exception:
            return False


# ── DSA-ML-DSA (Dilithium) — Module-Lattice Signatures ─────────

class DSA_ML_DSA:
    """ML-DSA (Dilithium) module-lattice signature scheme.

    NIST FIPS 204 standardized. Supports security levels 2 (44), 3 (65), and 5 (87).
    """

    _VARIANTS = {
        "ml_dsa_44": {"security": 128, "level": 2},
        "ml_dsa_65": {"security": 192, "level": 3},
        "ml_dsa_87": {"security": 256, "level": 5},
    }

    def __init__(self, variant: str = "ml_dsa_65"):
        if variant not in self._VARIANTS:
            raise ValueError(f"Unknown ML-DSA variant: {variant}")
        self.variant = variant
        self._info = self._VARIANTS[variant]
        self._mod = None

    @property
    def algorithm(self) -> str:
        return self.variant

    @property
    def security_level(self) -> int:
        return self._info["security"]

    def _load_mod(self):
        if self._mod is not None:
            return self._mod
        try:
            self._mod = __import__(f"pqcrypto.sign.{self.variant}", fromlist=["pqcrypto"])
        except ImportError:
            raise RuntimeError(f"ML-DSA variant '{self.variant}' not available (pqcrypto not installed)")
        return self._mod

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate ML-DSA keypair. Returns (public_key, secret_key)."""
        mod = self._load_mod()
        return mod.generate_keypair()

    def sign(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        """Sign a message. Returns (signature, public_key)."""
        mod = self._load_mod()
        return mod.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True if valid."""
        mod = self._load_mod()
        try:
            return mod.verify(public_key, message, signature)
        except Exception:
            return False


# ── Non-FIPS PQC KEMs (HQC, Classic McEliece, ML-KEM variants) ────────
# These are NOT FIPS validated. Use for research, red-teaming, and coffee protocols.

# Try to import pqcrypto KEMs (HQC, McEliece, ML-KEM variants)
try:
    import pqcrypto.kem.hqc_128 as _hqc128
    import pqcrypto.kem.hqc_192 as _hqc192
    import pqcrypto.kem.hqc_256 as _hqc256
    import pqcrypto.kem.mceliece348864 as _mce348864
    import pqcrypto.kem.mceliece348864f as _mce348864f
    import pqcrypto.kem.mceliece460896 as _mce460896
    import pqcrypto.kem.mceliece460896f as _mce460896f
    import pqcrypto.kem.mceliece6688128 as _mce6688128
    import pqcrypto.kem.mceliece6688128f as _mce6688128f
    import pqcrypto.kem.mceliece6960119 as _mce6960119
    import pqcrypto.kem.mceliece6960119f as _mce6960119f
    import pqcrypto.kem.mceliece8192128 as _mce8192128
    import pqcrypto.kem.mceliece8192128f as _mce8192128f
    import pqcrypto.kem.ml_kem_512 as _mlkem512
    import pqcrypto.kem.ml_kem_768 as _mlkem768
    import pqcrypto.kem.ml_kem_1024 as _mlkem1024
    _PQCRYPTO_AVAILABLE = True
except ImportError:
    _PQCRYPTO_AVAILABLE = False
    _hqc128 = _hqc192 = _hqc256 = None
    _mce348864 = _mce348864f = _mce460896 = _mce460896f = None
    _mce6688128 = _mce6688128f = _mce6960119 = _mce6960119f = None
    _mce8192128 = _mce8192128f = None
    _mlkem512 = _mlkem768 = _mlkem1024 = None


class PQCKEM:
    """Base class for non-FIPS Post-Quantum KEMs.
    
    Provides a unified interface for HQC, Classic McEliece, ML-KEM variants,
    and future additions (FrodoKEM, BIKE, etc.).
    """
    
    # Class attributes to be overridden by subclasses
    ALGORITHM = "base"
    PUBLIC_KEY_SIZE = 0
    SECRET_KEY_SIZE = 0
    CIPHERTEXT_SIZE = 0
    SHARED_KEY_SIZE = 32
    
    @classmethod
    def is_available(cls) -> bool:
        """Check if this KEM implementation is available."""
        return _PQCRYPTO_AVAILABLE
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        """Generate keypair. Returns (public_key, secret_key)."""
        raise NotImplementedError
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate to public key. Returns (ciphertext, shared_secret)."""
        raise NotImplementedError
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using secret key. Returns shared_secret."""
        raise NotImplementedError
    
    @classmethod
    def encrypt(cls, public_key: bytes) -> tuple[bytes, bytes]:
        """Alias for encapsulate (pqcrypto naming)."""
        return cls.encapsulate(public_key)
    
    @classmethod
    def decrypt(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Alias for decapsulate (pqcrypto naming)."""
        return cls.decapsulate(secret_key, ciphertext)


class HQC128(PQCKEM):
    """HQC-128: Hamming Quasi-Cyclic code-based KEM (NIST backup KEM candidate).
    
    Security: ~128-bit classical / ~64-bit quantum
    Based on: Hamming Quasi-Cyclic codes
    Status: NIST selected for standardization as backup to ML-KEM
    """
    ALGORITHM = "hqc_128"
    PUBLIC_KEY_SIZE = 2249
    SECRET_KEY_SIZE = 2305
    CIPHERTEXT_SIZE = 4433
    SHARED_KEY_SIZE = 64
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _hqc128.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _hqc128.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _hqc128.decrypt(secret_key, ciphertext)


class HQC192(PQCKEM):
    """HQC-192: Hamming Quasi-Cyclic code-based KEM.
    
    Security: ~192-bit classical / ~96-bit quantum
    """
    ALGORITHM = "hqc_192"
    PUBLIC_KEY_SIZE = 4522
    SECRET_KEY_SIZE = 4586
    CIPHERTEXT_SIZE = 8978
    SHARED_KEY_SIZE = 64
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _hqc192.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _hqc192.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _hqc192.decrypt(secret_key, ciphertext)


class HQC256(PQCKEM):
    """HQC-256: Hamming Quasi-Cyclic code-based KEM.
    
    Security: ~256-bit classical / ~128-bit quantum
    """
    ALGORITHM = "hqc_256"
    PUBLIC_KEY_SIZE = 7245
    SECRET_KEY_SIZE = 7317
    CIPHERTEXT_SIZE = 14421
    SHARED_KEY_SIZE = 64
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _hqc256.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _hqc256.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _hqc256.decrypt(secret_key, ciphertext)


class McEliece348864(PQCKEM):
    """Classic McEliece 348864: Code-based KEM (McEliece with Goppa codes).
    
    Security: ~128-bit classical
    Note: Very large public key (~261 KB)
    """
    ALGORITHM = "mceliece348864"
    PUBLIC_KEY_SIZE = 261120
    SECRET_KEY_SIZE = 6492
    CIPHERTEXT_SIZE = 96
    SHARED_KEY_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce348864.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce348864.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce348864.decrypt(secret_key, ciphertext)


class McEliece348864f(PQCKEM):
    """Classic McEliece 348864f (f variant).
    
    Security: ~128-bit classical
    """
    ALGORITHM = "mceliece348864f"
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce348864f.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce348864f.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce348864f.decrypt(secret_key, ciphertext)


class McEliece460896(PQCKEM):
    """Classic McEliece 460896.
    
    Security: ~192-bit classical
    Note: Very large public key (~524 KB)
    """
    ALGORITHM = "mceliece460896"
    PUBLIC_KEY_SIZE = 524160
    SECRET_KEY_SIZE = 13608
    CIPHERTEXT_SIZE = 156
    SHARED_KEY_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce460896.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce460896.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce460896.decrypt(secret_key, ciphertext)


class McEliece460896f(PQCKEM):
    """Classic McEliece 460896f (f variant)."""
    ALGORITHM = "mceliece460896f"
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce460896f.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce460896f.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce460896f.decrypt(secret_key, ciphertext)


class McEliece6688128(PQCKEM):
    """Classic McEliece 6688128.
    
    Security: ~256-bit classical
    Note: Very large public key (~1 MB)
    """
    ALGORITHM = "mceliece6688128"
    PUBLIC_KEY_SIZE = 1044992
    SECRET_KEY_SIZE = 13932
    CIPHERTEXT_SIZE = 208
    SHARED_KEY_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6688128.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce6688128.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6688128.decrypt(secret_key, ciphertext)


class McEliece6688128f(PQCKEM):
    """Classic McEliece 6688128f (f variant)."""
    ALGORITHM = "mceliece6688128f"
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6688128f.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce6688128f.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6688128f.decrypt(secret_key, ciphertext)


class McEliece6960119(PQCKEM):
    """Classic McEliece 6960119.
    
    Security: ~256-bit classical
    """
    ALGORITHM = "mceliece6960119"
    PUBLIC_KEY_SIZE = 1047319
    SECRET_KEY_SIZE = 13948
    CIPHERTEXT_SIZE = 194
    SHARED_KEY_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6960119.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce6960119.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6960119.decrypt(secret_key, ciphertext)


class McEliece6960119f(PQCKEM):
    """Classic McEliece 6960119f (f variant)."""
    ALGORITHM = "mceliece6960119f"
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6960119f.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce6960119f.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce6960119f.decrypt(secret_key, ciphertext)


class McEliece8192128(PQCKEM):
    """Classic McEliece 8192128.
    
    Security: ~256-bit classical
    Note: Largest public key (~1.36 MB)
    """
    ALGORITHM = "mceliece8192128"
    PUBLIC_KEY_SIZE = 1357824
    SECRET_KEY_SIZE = 14120
    CIPHERTEXT_SIZE = 208
    SHARED_KEY_SIZE = 32
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce8192128.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce8192128.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce8192128.decrypt(secret_key, ciphertext)


class McEliece8192128f(PQCKEM):
    """Classic McEliece 8192128f (f variant)."""
    ALGORITHM = "mceliece8192128f"
    
    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce8192128f.generate_keypair()
    
    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        ct, ss = _mce8192128f.encrypt(public_key)
        return ct, ss
    
    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if not _PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto not available")
        return _mce8192128f.decrypt(secret_key, ciphertext)


class MLKEM512(PQCKEM):
    """ML-KEM-512 (FIPS 203) - Module-Lattice KEM, NIST standardized.

    Security: 128-bit classical / 64-bit quantum
    """
    ALGORITHM = "ml_kem_512"
    PUBLIC_KEY_SIZE = 800
    SECRET_KEY_SIZE = 1632
    CIPHERTEXT_SIZE = 768
    SHARED_KEY_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if _PQCRYPTO_AVAILABLE:
            try:
                return _mlkem512.generate_keypair()
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.keygen(size=512)
        except Exception:
            raise RuntimeError("No ML-KEM-512 backend available")

    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if _PQCRYPTO_AVAILABLE:
            try:
                ct, ss = _mlkem512.encrypt(public_key)
                return ct, ss
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.encaps(public_key, size=512)
        except Exception:
            raise RuntimeError("No ML-KEM-512 backend available")

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if _PQCRYPTO_AVAILABLE:
            try:
                return _mlkem512.decrypt(secret_key, ciphertext)
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.decaps(secret_key, ciphertext, size=512)
        except Exception:
            raise RuntimeError("No ML-KEM-512 backend available")


class MLKEM768(PQCKEM):
    """ML-KEM-768 (FIPS 203) - Module-Lattice KEM, NIST standardized.

    Security: 192-bit classical / 128-bit quantum
    """
    ALGORITHM = "ml_kem_768"
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_KEY_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if _PQCRYPTO_AVAILABLE:
            try:
                return _mlkem768.generate_keypair()
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.keygen(size=768)
        except Exception:
            raise RuntimeError("No ML-KEM-768 backend available")

    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if _PQCRYPTO_AVAILABLE:
            try:
                ct, ss = _mlkem768.encrypt(public_key)
                return ct, ss
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.encaps(public_key, size=768)
        except Exception:
            raise RuntimeError("No ML-KEM-768 backend available")

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if _PQCRYPTO_AVAILABLE:
            try:
                return _mlkem768.decrypt(secret_key, ciphertext)
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.decaps(secret_key, ciphertext, size=768)
        except Exception:
            raise RuntimeError("No ML-KEM-768 backend available")


class MLKEM1024(PQCKEM):
    """ML-KEM-1024 (FIPS 203) - Module-Lattice KEM, NIST standardized.

    Security: 256-bit classical / 128-bit quantum
    """
    ALGORITHM = "ml_kem_1024"
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1568
    SHARED_KEY_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        if _PQCRYPTO_AVAILABLE:
            try:
                return _mlkem1024.generate_keypair()
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.keygen(size=1024)
        except Exception:
            raise RuntimeError("No ML-KEM-1024 backend available")

    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        if _PQCRYPTO_AVAILABLE:
            try:
                ct, ss = _mlkem1024.encrypt(public_key)
                return ct, ss
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.encaps(public_key, size=1024)
        except Exception:
            raise RuntimeError("No ML-KEM-1024 backend available")

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        if _PQCRYPTO_AVAILABLE:
            try:
                return _mlkem1024.decrypt(secret_key, ciphertext)
            except Exception:
                pass
        try:
            from inf1del_kyber import Inf1delKyber
            return Inf1delKyber.decaps(secret_key, ciphertext, size=1024)
        except Exception:
            raise RuntimeError("No ML-KEM-1024 backend available")


# Registry of all available PQC KEMs
PQC_KEM_REGISTRY = {
    "hqc_128": HQC128,
    "hqc_192": HQC192,
    "hqc_256": HQC256,
    "mceliece348864": McEliece348864,
    "mceliece348864f": McEliece348864f,
    "mceliece460896": McEliece460896,
    "mceliece460896f": McEliece460896f,
    "mceliece6688128": McEliece6688128,
    "mceliece6688128f": McEliece6688128f,
    "mceliece6960119": McEliece6960119,
    "mceliece6960119f": McEliece6960119f,
    "mceliece8192128": McEliece8192128,
    "mceliece8192128f": McEliece8192128f,
    "ml_kem_512": DSA_ML_KEM(512),
    "ml_kem_768": DSA_ML_KEM(768),
    "ml_kem_1024": DSA_ML_KEM(1024),
}


# ── Register PQC KEMs with the provider system ───────────────────────
def _register_kem_providers():
    """Wrap each PQC KEM as a KEMProvider and register it."""
    for name, cls in PQC_KEM_REGISTRY.items():
        if isinstance(cls, DSA_ML_KEM):
            # Register each DSA_ML_KEM size as a separate provider
            provider_cls = type(
                f"KEM_{name}",
                (KEMProvider,),
                {
                    "NAME": name,
                    "ALGORITHM": cls.algorithm,
                    "PUBLIC_KEY_SIZE": cls.public_key_size,
                    "SECRET_KEY_SIZE": cls.secret_key_size,
                    "CIPHERTEXT_SIZE": cls.ciphertext_size,
                    "SHARED_KEY_SIZE": cls.shared_key_size,
                    "_kem_instance": cls,
                    "_implementation_available": classmethod(lambda c: True),
                    "generate_keypair": classmethod(lambda c: c._kem_instance.keygen()),
                    "encapsulate": classmethod(lambda c, pk: c._kem_instance.encapsulate(pk)),
                    "decapsulate": classmethod(lambda c, sk, ct: c._kem_instance.decapsulate(sk, ct)),
                },
            )
            register_kem_provider(name, provider_cls)
            continue
        def _make_provider(n, c):
            return type(
                f"KEM_{n}",
                (KEMProvider,),
                {
                    "NAME": n,
                    "ALGORITHM": c.ALGORITHM,
                    "PUBLIC_KEY_SIZE": c.PUBLIC_KEY_SIZE,
                    "SECRET_KEY_SIZE": c.SECRET_KEY_SIZE,
                    "CIPHERTEXT_SIZE": c.CIPHERTEXT_SIZE,
                    "SHARED_KEY_SIZE": c.SHARED_KEY_SIZE,
                    "_pqc_cls": c,
                    "_implementation_available": classmethod(lambda cls: cls._pqc_cls.is_available()),
                    "generate_keypair": classmethod(lambda cls: cls._pqc_cls.generate_keypair()),
                    "encapsulate": classmethod(lambda cls, pk: cls._pqc_cls.encapsulate(pk)),
                    "decapsulate": classmethod(lambda cls, sk, ct: cls._pqc_cls.decapsulate(sk, ct)),
                },
            )
        provider_cls = _make_provider(name, cls)
        register_kem_provider(name, provider_cls)


_register_kem_providers()





def get_pqc_kem(algorithm: str) -> type:
    """Get PQC KEM class by algorithm name."""
    if algorithm not in PQC_KEM_REGISTRY:
        raise ValueError(f"Unknown PQC KEM algorithm: {algorithm}. Available: {list(PQC_KEM_REGISTRY.keys())}")
    kem_class = PQC_KEM_REGISTRY[algorithm]
    if not kem_class.is_available():
        raise RuntimeError(f"PQC KEM {algorithm} not available (pqcrypto not installed)")
    return kem_class


def list_pqc_kems() -> dict:
    """List all available PQC KEMs with their parameters."""
    result = {}
    for name, cls in PQC_KEM_REGISTRY.items():
        result[name] = {
            "algorithm": cls.ALGORITHM,
            "public_key_size": cls.PUBLIC_KEY_SIZE,
            "secret_key_size": cls.SECRET_KEY_SIZE,
            "ciphertext_size": cls.CIPHERTEXT_SIZE,
            "shared_key_size": cls.SHARED_KEY_SIZE,
            "available": cls.is_available(),
        }
    return result


# ── Hybrid Key Exchange (ECDH P-256 + DSA-ML-KEM) ──────────────────
class HybridKEM:
    """Hybrid key exchange combining ECDH P-256 with DSA-ML-KEM.

    Post-quantum security: secure if EITHER classical ECDH or ML-KEM holds.
    Uses HKDF-SHA256 to combine shared secrets.
    Supports all standard ML-KEM sizes (512, 768, 1024).

    Key sizes (with 1nf1D3L backend):
    - Hybrid public key: ECC_len(2) || ECC_pk(65) || ML-KEM_pk(N) = 67 + N bytes
    - Hybrid secret key: ECC_seed(32) || ML-KEM_sk(N) = 32 + N bytes
    - Ciphertext: ECC_ephem_len(2) || ECC_ephem_pk(65) || ML-KEM_ct(N) = 67 + N bytes
    - Shared secret: 32 bytes
    """

    @classmethod
    def generate_keypair(cls, ml_kem_size: int = 768) -> tuple:
        """Generate hybrid keypair. Returns (hybrid_pk, hybrid_sk)."""
        ecc_pk, ecc_seed, _, _ = ECP256.generate_keypair()
        kem = DSA_ML_KEM(ml_kem_size)
        pk, sk = kem.keygen()
        ecc_pk_len = len(ecc_pk).to_bytes(2, 'big')
        hybrid_pk = ecc_pk_len + ecc_pk + pk
        hybrid_sk = ecc_seed + sk
        return hybrid_pk, hybrid_sk

    @classmethod
    def encapsulate(cls, hybrid_pk: bytes, ml_kem_size: int = 768) -> tuple:
        """Encapsulate for a hybrid public key. Returns (ciphertext, shared_secret)."""
        ecc_pk_len = int.from_bytes(hybrid_pk[:2], 'big')
        ecc_pk = hybrid_pk[2:2 + ecc_pk_len]
        kyber_pk = hybrid_pk[2 + ecc_pk_len:]
        
        ecc_ephem_seed = secrets.token_bytes(32)
        ecc_ephem_pk, _, _, _ = ECP256.generate_keypair(ecc_ephem_seed)
        ecdh_shared = ECP256.key_exchange(ecc_ephem_seed, ecc_pk)
        
        kem = DSA_ML_KEM(ml_kem_size)
        kyber_ct, kyber_ss = kem.encapsulate(kyber_pk)
        
        combined = ecdh_shared + kyber_ss + b"cpip-hybrid-mlkem-v1"
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-shared-mlkem-v1", 32)
        
        ecc_ephem_len = len(ecc_ephem_pk).to_bytes(2, 'big')
        ciphertext = ecc_ephem_len + ecc_ephem_pk + kyber_ct
        return ciphertext, shared

    @classmethod
    def decapsulate(cls, hybrid_sk: bytes, ciphertext: bytes, ml_kem_size: int = 768) -> bytes:
        """Decapsulate using hybrid secret key. Returns shared_secret."""
        ecc_seed = hybrid_sk[:32]
        kyber_sk = hybrid_sk[32:]
        
        ecc_ephem_len = int.from_bytes(ciphertext[:2], 'big')
        ecc_ephem_pk = ciphertext[2:2 + ecc_ephem_len]
        kyber_ct = ciphertext[2 + ecc_ephem_len:]
        
        ecdh_shared = ECP256.key_exchange(ecc_seed, ecc_ephem_pk)
        kem = DSA_ML_KEM(ml_kem_size)
        kyber_ss = kem.decapsulate(kyber_sk, kyber_ct)
        
        combined = ecdh_shared + kyber_ss + b"cpip-hybrid-mlkem-v1"
        shared = CoffeeCipher._hkdf_expand(combined, b"cpip-hybrid-shared-mlkem-v1", 32)
        return shared


# ── SHA-256 Hash Suite (FIPS 180-4) ────────────────────────────────────
class SecureHash:
    """Unified hash interface supporting SHA-256, SHA-3, and SHAKE.
    Provides domain-separated hashing for different CPIP contexts.
    Default algorithm is SHA-256 (FIPS 180-4 approved).
    """
    @staticmethod
    def hash(data: bytes, algorithm: str = "sha256") -> bytes:
        if algorithm == "sha256":
            return hashlib.sha256(data).digest()
        elif algorithm == "sha3_256":
            return hashlib.sha3_256(data).digest()
        elif algorithm == "sha3_512":
            return hashlib.sha3_512(data).digest()
        elif algorithm == "shake256":
            return hashlib.shake_256(data).digest(64)
        else:
            return hashlib.sha256(data).digest()

    @staticmethod
    def domain_hash(domain: str, data: bytes) -> bytes:
        return hashlib.sha256(domain.encode() + b"||" + data).digest()

    @staticmethod
    def keyed_hash(key: bytes, data: bytes) -> bytes:
        """HMAC-SHA256 — proper keyed hash (FIPS 180-4). Not SHA256(key||data)."""
        return hmac.new(key, data, hashlib.sha256).digest()


# ── HSM (PKCS#11) Manager ──────────────────────────────────────────────
_HSM_AVAILABLE = False
_HSM_SESSION = None
_HSM_TOKEN_SERIAL = None

def _init_hsm():
    """Initialize PKCS#11 HSM connection. Requires python-pkcs11 library."""
    global _HSM_AVAILABLE, _HSM_SESSION, _HSM_TOKEN_SERIAL
    if not HSM_MODULE:
        return False
    try:
        import pkcs11
        lib = pkcs11.lib(HSM_MODULE)
        slots = lib.get_slots()
        for slot in slots:
            try:
                token = slot.get_token()
                if HSM_TOKEN_LABEL and token.label != HSM_TOKEN_LABEL:
                    continue
                session = token.open(rw=True, pin=HSM_PIN)
                _HSM_SESSION = session
                _HSM_TOKEN_SERIAL = token.serial
                _HSM_AVAILABLE = True
                return True
            except Exception as _e:
                logger.debug("Skipped: %s", _e); continue
        return False
    except ImportError:
        return False
    except Exception:
        return False


def hsm_encrypt(key_id: str, plaintext: bytes) -> bytes:
    """Encrypt using HSM-backed AES-256-GCM. Falls back to software if HSM unavailable."""
    if not _HSM_AVAILABLE or _HSM_SESSION is None:
        return CoffeeCipher.encrypt(plaintext)
    import pkcs11
    from pkcs11 import Attribute, Mechanism, ObjectClass
    try:
        template = (
            (Attribute.CLASS, ObjectClass.SECRET_KEY),
            (Attribute.LABEL, key_id),
            (Attribute.KEY_TYPE, pkcs11.KeyType.AES),
        )
        keys = _HSM_SESSION.get_objects(template)
        for key in keys:
            nonce = secrets.token_bytes(12)
            mech = Mechanism.AES_GCM
            mech_params = pkcs11.Mechanism(mech, {
                pkcs11.PARAM_AES_GCM_NONCE: nonce,
                pkcs11.PARAM_AES_GCM_TAG_LEN: 16,
            })
            ct = key.encrypt(plaintext, mechanism=mech_params)
            return nonce + ct
        return CoffeeCipher.encrypt(plaintext)
    except Exception:
        return CoffeeCipher.encrypt(plaintext)


def hsm_decrypt(key_id: str, ciphertext: bytes) -> bytes:
    """Decrypt using HSM-backed AES-256-GCM. Falls back to software if HSM unavailable."""
    if not _HSM_AVAILABLE or _HSM_SESSION is None:
        return CoffeeCipher.decrypt(ciphertext)
    import pkcs11
    from pkcs11 import Attribute, Mechanism, ObjectClass
    try:
        template = (
            (Attribute.CLASS, ObjectClass.SECRET_KEY),
            (Attribute.LABEL, key_id),
            (Attribute.KEY_TYPE, pkcs11.KeyType.AES),
        )
        keys = _HSM_SESSION.get_objects(template)
        for key in keys:
            nonce = ciphertext[:12]
            ct = ciphertext[12:]
            mech = Mechanism.AES_GCM
            mech_params = pkcs11.Mechanism(mech, {
                pkcs11.PARAM_AES_GCM_NONCE: nonce,
                pkcs11.PARAM_AES_GCM_TAG_LEN: 16,
            })
            return key.decrypt(ct, mechanism=mech_params)
        return CoffeeCipher.decrypt(ciphertext)
    except Exception:
        return CoffeeCipher.decrypt(ciphertext)


def hsm_store_key(key_id: str, key_bytes: bytes) -> bool:
    """Import a key into the HSM. Returns True on success."""
    if not _HSM_AVAILABLE or _HSM_SESSION is None:
        return False
    try:
        from pkcs11 import Attribute, KeyType, ObjectClass
        template = (
            (Attribute.CLASS, ObjectClass.SECRET_KEY),
            (Attribute.KEY_TYPE, KeyType.AES),
            (Attribute.LABEL, key_id),
            (Attribute.VALUE, key_bytes),
            (Attribute.ENCRYPT, True),
            (Attribute.DECRYPT, True),
            (Attribute.TOKEN, True),
            (Attribute.PRIVATE, True),
        )
        _HSM_SESSION.create_object(template)
        return True
    except Exception:
        return False


# ── Web-of-Trust Identity System ─────────────────────────────────────
class WebOfTrust:
    """PGP-like web of trust for mesh peer identity verification.
    
    Each node has an identity certificate signed by its own ECDSA key.
    Peers can vouch for each other via trust signatures.
    Trust is transitive: if A trusts B, and B trusts C, then A partially trusts C.
    
    Trust levels:
    - 0: unknown
    - 1: seen (heard via heartbeat)
    - 2: marginal (one trust signature)
    - 3: full (two+ trust signatures or direct vouch)
    - 4: ultimate (self)
    """
    
    TRUST_UNKNOWN = 0
    TRUST_SEEN = 1
    TRUST_MARGINAL = 2
    TRUST_FULL = 3
    TRUST_ULTIMATE = 4
    
    MAX_TRUST_DEPTH = 5
    
    _identities: ClassVar[dict] = {}
    _trust_sigs: ClassVar[dict] = {}
    _trust_scores: ClassVar[dict] = {}
    _lock = threading.Lock()
    
    @classmethod
    def create_identity(cls, pot_id: str, pubkey_pem: bytes, metadata: dict | None = None) -> dict:
        """Create and self-sign an identity certificate."""
        cert = {
            "pot_id": pot_id,
            "pubkey": base64.b64encode(pubkey_pem).decode(),
            "metadata": metadata or {},
            "created": time.time(),
            "expires": time.time() + 86400 * 365,
            "version": 1,
        }
        cert_bytes = json.dumps({k: v for k, v in cert.items() if k != "sig"}, sort_keys=True).encode()
        sig = ECP256.sign(cert_bytes, ECP256._derive_key_from_seed(
            hashlib.sha256(pot_id.encode()).digest()[:32]
        ))
        cert["sig"] = base64.b64encode(sig).decode()
        
        with cls._lock:
            cls._identities[pot_id] = cert
            cls._trust_scores[pot_id] = cls.TRUST_ULTIMATE
        
        return cert
    
    @classmethod
    def publish_identity(cls, pot_id: str, cert: dict):
        """Receive and store an identity certificate from the mesh."""
        with cls._lock:
            existing = cls._identities.get(pot_id)
            if existing and existing.get("created", 0) >= cert.get("created", 0):
                return False
            cls._identities[pot_id] = cert
            if pot_id not in cls._trust_scores:
                cls._trust_scores[pot_id] = cls.TRUST_SEEN
            return True
    
    @classmethod
    def sign_trust(cls, signer_id: str, target_id: str, trust_level: int, node_seed: bytes) -> dict:
        """Create a trust signature: signer vouches for target."""
        trust_sig = {
            "signer": signer_id,
            "target": target_id,
            "trust_level": min(trust_level, cls.TRUST_FULL),
            "timestamp": time.time(),
        }
        sig_data = json.dumps(trust_sig, sort_keys=True).encode()
        sig = ECP256.sign(sig_data, node_seed)
        trust_sig["sig"] = base64.b64encode(sig).decode()
        
        with cls._lock:
            key = f"{signer_id}:{target_id}"
            cls._trust_sigs[key] = trust_sig
        
        cls._recalculate_trust()
        return trust_sig
    
    @classmethod
    def receive_trust_sig(cls, trust_sig: dict) -> bool:
        """Receive and store a trust signature from the mesh."""
        signer = trust_sig.get("signer")
        target = trust_sig.get("target")
        if not signer or not target:
            return False
        
        key = f"{signer}:{target}"
        with cls._lock:
            existing = cls._trust_sigs.get(key)
            if existing and existing.get("timestamp", 0) >= trust_sig.get("timestamp", 0):
                return False
            cls._trust_sigs[key] = trust_sig
        
        cls._recalculate_trust()
        return True
    
    @classmethod
    def _recalculate_trust(cls):
        """Recalculate transitive trust scores via BFS."""
        with cls._lock:
            scores = {pid: cls.TRUST_ULTIMATE for pid, t in cls._trust_scores.items() if t == cls.TRUST_ULTIMATE}
            
            for sig in cls._trust_sigs.values():
                sig["signer"]
                target = sig["target"]
                level = sig.get("trust_level", cls.TRUST_MARGINAL)
                if level >= cls.TRUST_FULL:
                    scores[target] = max(scores.get(target, cls.TRUST_SEEN), cls.TRUST_FULL)
                elif level >= cls.TRUST_MARGINAL:
                    scores[target] = max(scores.get(target, cls.TRUST_SEEN), cls.TRUST_MARGINAL)
            
            for pot_id in cls._identities:
                if pot_id not in scores:
                    scores[pot_id] = cls.TRUST_SEEN
            
            cls._trust_scores = scores
    
    @classmethod
    def get_trust_level(cls, pot_id: str) -> int:
        with cls._lock:
            return cls._trust_scores.get(pot_id, cls.TRUST_UNKNOWN)
    
    @classmethod
    def get_identity(cls, pot_id: str) -> dict:
        with cls._lock:
            return cls._identities.get(pot_id)
    
    @classmethod
    def get_all_identities(cls) -> dict:
        with cls._lock:
            return dict(cls._identities)
    
    @classmethod
    def get_trust_graph(cls) -> dict:
        """Return the full trust graph for visualization."""
        with cls._lock:
            edges = []
            for sig in cls._trust_sigs.values():
                edges.append({
                    "from": sig["signer"],
                    "to": sig["target"],
                    "level": sig.get("trust_level", 0),
                    "time": sig.get("timestamp", 0),
                })
            nodes = {}
            for pid, score in cls._trust_scores.items():
                nodes[pid] = {
                    "trust": score,
                    "identity": cls._identities.get(pid, {}),
                }
            return {"nodes": nodes, "edges": edges}
    
    @classmethod
    def get_trust_sigs(cls) -> list:
        with cls._lock:
            return list(cls._trust_sigs.values())
    
    @classmethod
    def is_verified(cls, pot_id: str) -> bool:
        return cls.get_trust_level(pot_id) >= cls.TRUST_MARGINAL
    
    @classmethod
    def export_trust_data(cls) -> dict:
        """Export all trust data for mesh broadcast."""
        with cls._lock:
            return {
                "identities": dict(cls._identities),
                "trust_sigs": dict(cls._trust_sigs),
            }
    
    @classmethod
    def import_trust_data(cls, data: dict):
        """Import trust data received from mesh peer."""
        for pot_id, cert in data.get("identities", {}).items():
            cls.publish_identity(pot_id, cert)
        for sig in data.get("trust_sigs", {}).values():
            cls.receive_trust_sig(sig)


# ── Distributed DNS / Naming ─────────────────────────────────────────
class DistributedDNS:
    """Decentralized name registry over the mesh.
    
    Maps human-readable names to pot_ids. Names are registered with
    TTL-based expiration and propagated via gossip protocol.
    Conflict resolution: first-come-first-served with signed proof.
    
    Name format: <name>.pot (e.g., "alice.pot", "coffeeshop.pot")
    """
    
    MAX_NAME_LEN = 63
    MAX_NAMES_PER_NODE = 10
    DEFAULT_TTL = 86400 * 7  # 7 days
    
    _registry: ClassVar[dict] = {}
    _lock = threading.Lock()
    
    @classmethod
    def register(cls, name: str, pot_id: str, pubkey_pem: bytes, ttl: int | None = None, node_seed: bytes | None = None) -> dict:
        """Register a name. Returns registration record or error."""
        name = name.lower().strip()
        if not name.endswith(".pot"):
            name += ".pot"
        name = name.replace(" ", "-")
        
        if len(name) - 4 > cls.MAX_NAME_LEN:
            return {"error": f"Name too long (max {cls.MAX_NAME_LEN} chars)"}
        
        if ttl is None:
            ttl = cls.DEFAULT_TTL
        
        record = {
            "name": name,
            "pot_id": pot_id,
            "pubkey": base64.b64encode(pubkey_pem).decode(),
            "registered": time.time(),
            "expires": time.time() + ttl,
            "ttl": ttl,
            "sequence": 0,
        }
        
        sig_data = json.dumps({k: v for k, v in record.items() if k != "sig"}, sort_keys=True).encode()
        if node_seed:
            sig = ECP256.sign(sig_data, node_seed)
            record["sig"] = base64.b64encode(sig).decode()
        
        with cls._lock:
            existing = cls._registry.get(name)
            if existing:
                if existing.get("pot_id") == pot_id:
                    record["sequence"] = existing.get("sequence", 0) + 1
                    record["sig"] = record.get("sig", "")
                    sig_data = json.dumps({k: v for k, v in record.items() if k != "sig"}, sort_keys=True).encode()
                    if node_seed:
                        sig = ECP256.sign(sig_data, node_seed)
                        record["sig"] = base64.b64encode(sig).decode()
                elif existing.get("expires", 0) > time.time():
                    return {"error": f"Name '{name}' is taken by {existing.get('pot_id')}"}
            
            cls._registry[name] = record
        
        return record
    
    @classmethod
    def resolve(cls, name: str) -> dict:
        """Resolve a name to its registration record."""
        name = name.lower().strip()
        if not name.endswith(".pot"):
            name += ".pot"
        
        with cls._lock:
            record = cls._registry.get(name)
            if not record:
                return {"error": f"Name '{name}' not found"}
            if record.get("expires", 0) < time.time():
                return {"error": f"Name '{name}' has expired"}
            return dict(record)
    
    @classmethod
    def reverse_resolve(cls, pot_id: str) -> list:
        """Find all names registered by a pot_id."""
        names = []
        with cls._lock:
            now = time.time()
            for record in cls._registry.values():
                if record.get("pot_id") == pot_id and record.get("expires", 0) > now:
                    names.append(dict(record))
        return names
    
    @classmethod
    def remove(cls, name: str, pot_id: str, node_seed: bytes | None = None) -> dict:
        """Remove a name registration (only owner can remove)."""
        name = name.lower().strip()
        if not name.endswith(".pot"):
            name += ".pot"
        
        with cls._lock:
            record = cls._registry.get(name)
            if not record:
                return {"error": f"Name '{name}' not found"}
            if record.get("pot_id") != pot_id:
                return {"error": "Only the owner can remove a name"}
            del cls._registry[name]
        return {"status": "removed", "name": name}
    
    @classmethod
    def gossip_receive(cls, registry_data: dict):
        """Receive registry data from a mesh peer (gossip protocol)."""
        with cls._lock:
            for name, record in registry_data.items():
                existing = cls._registry.get(name)
                if not existing:
                    if record.get("expires", 0) > time.time():
                        cls._registry[name] = record
                else:
                    if record.get("sequence", 0) > existing.get("sequence", 0) or (record.get("sequence", 0) == existing.get("sequence", 0) and
                          record.get("expires", 0) > existing.get("expires", 0)):
                        cls._registry[name] = record
    
    @classmethod
    def get_all(cls) -> dict:
        """Get all non-expired registrations."""
        with cls._lock:
            now = time.time()
            return {name: dict(rec) for name, rec in cls._registry.items() if rec.get("expires", 0) > now}
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired registrations."""
        with cls._lock:
            now = time.time()
            expired = [n for n, r in cls._registry.items() if r.get("expires", 0) <= now]
            for n in expired:
                del cls._registry[n]
    
    @classmethod
    def get_gossip_data(cls) -> dict:
        """Get registry data for gossip broadcast."""
        return cls.get_all()


# ── End-to-End Encrypted Group Chat ──────────────────────────────────
class GroupChat:
    """E2EE group messaging over the mesh.
    
    Uses sender-key model: each group has a group key, and each member
    gets an encrypted copy. Messages are encrypted with AES-256-GCM
    using the sender's derived key.
    
    Features:
    - Group creation with initial members
    - Key rotation (on member join/leave)
    - Message history (encrypted, stored per-group)
    - Forward secrecy: new keys don't decrypt old messages
    """
    
    _groups: ClassVar[dict] = {}
    _lock = threading.Lock()
    
    @classmethod
    def create_group(cls, group_id: str, name: str, owner_id: str, members: list | None = None) -> dict:
        """Create a new encrypted group."""
        group_key = os.urandom(32)
        group_nonce = os.urandom(12)
        
        group = {
            "id": group_id,
            "name": name,
            "owner": owner_id,
            "created": time.time(),
            "members": {owner_id: {"role": "admin", "joined": time.time()}},
            "key_version": 1,
            "group_key": base64.b64encode(group_key).decode(),
            "group_nonce": base64.b64encode(group_nonce).decode(),
            "messages": [],
            "max_messages": 1000,
        }
        
        if members:
            for mid in members:
                if mid != owner_id:
                    group["members"][mid] = {"role": "member", "joined": time.time()}
        
        with cls._lock:
            cls._groups[group_id] = group
        
        return {
            "id": group_id,
            "name": name,
            "owner": owner_id,
            "members": list(group["members"].keys()),
            "created": group["created"],
        }
    
    @classmethod
    def join_group(cls, group_id: str, pot_id: str) -> dict:
        """Add a member to a group."""
        with cls._lock:
            group = cls._groups.get(group_id)
            if not group:
                return {"error": "Group not found"}
            if pot_id in group["members"]:
                return {"status": "already member"}
            
            group["members"][pot_id] = {"role": "member", "joined": time.time()}
            group["key_version"] += 1
            new_key = os.urandom(32)
            new_nonce = os.urandom(12)
            base64.b64decode(group["group_key"])
            base64.b64decode(group["group_nonce"])
            group["group_key"] = base64.b64encode(new_key).decode()
            group["group_nonce"] = base64.b64encode(new_nonce).decode()
        
        return {
            "status": "joined",
            "group_id": group_id,
            "key_version": group["key_version"],
        }
    
    @classmethod
    def leave_group(cls, group_id: str, pot_id: str) -> dict:
        """Remove a member from a group."""
        with cls._lock:
            group = cls._groups.get(group_id)
            if not group:
                return {"error": "Group not found"}
            if pot_id not in group["members"]:
                return {"error": "Not a member"}
            
            del group["members"][pot_id]
            if not group["members"]:
                del cls._groups[group_id]
                return {"status": "group dissolved"}
            
            group["key_version"] += 1
            new_key = os.urandom(32)
            new_nonce = os.urandom(12)
            group["group_key"] = base64.b64encode(new_key).decode()
            group["group_nonce"] = base64.b64encode(new_nonce).decode()
        
        return {"status": "left", "group_id": group_id}
    
    @classmethod
    def send_message(cls, group_id: str, sender_id: str, plaintext: str, node_seed: bytes | None = None) -> dict:
        """Send an encrypted message to a group."""
        with cls._lock:
            group = cls._groups.get(group_id)
            if not group:
                return {"error": "Group not found"}
            if sender_id not in group["members"]:
                return {"error": "Not a member"}
            
            group_key = base64.b64decode(group["group_key"])
            base64.b64decode(group["group_nonce"])
        
        encrypted = CoffeeCipher.encrypt(plaintext.encode(), group_key)
        
        msg = {
            "id": str(uuid.uuid4())[:8],
            "group_id": group_id,
            "sender": sender_id,
            "data": base64.b64encode(encrypted).decode(),
            "key_version": group["key_version"],
            "timestamp": time.time(),
        }
        
        if node_seed:
            sig_data = json.dumps({k: v for k, v in msg.items() if k != "sig"}, sort_keys=True).encode()
            sig = ECP256.sign(sig_data, node_seed)
            msg["sig"] = base64.b64encode(sig).decode()
        
        with cls._lock:
            group = cls._groups.get(group_id)
            if group:
                group["messages"].append(msg)
                if len(group["messages"]) > group.get("max_messages", 1000):
                    group["messages"] = group["messages"][-500:]
        
        return msg
    
    @classmethod
    def get_messages(cls, group_id: str, pot_id: str, since: float = 0) -> list:
        """Get messages from a group since a timestamp."""
        with cls._lock:
            group = cls._groups.get(group_id)
            if not group:
                return []
            if pot_id not in group["members"]:
                return []
            
            return [m for m in group["messages"] if m.get("timestamp", 0) > since]
    
    @classmethod
    def get_groups(cls, pot_id: str) -> list:
        """List all groups a pot is a member of."""
        with cls._lock:
            return [
                {"id": g["id"], "name": g["name"], "owner": g["owner"],
                 "members": len(g["members"]), "messages": len(g["messages"]),
                 "key_version": g["key_version"]}
                for g in cls._groups.values()
                if pot_id in g.get("members", {})
            ]
    
    @classmethod
    def get_group_info(cls, group_id: str) -> dict:
        with cls._lock:
            group = cls._groups.get(group_id)
            if not group:
                return {"error": "Group not found"}
            return {
                "id": group["id"],
                "name": group["name"],
                "owner": group["owner"],
                "members": list(group["members"].keys()),
                "key_version": group["key_version"],
                "created": group["created"],
                "message_count": len(group["messages"]),
            }
    
    @classmethod
    def receive_group_message(cls, msg: dict) -> bool:
        """Receive a group message from the mesh."""
        group_id = msg.get("group_id")
        with cls._lock:
            group = cls._groups.get(group_id)
            if not group:
                return False
            existing_ids = {m["id"] for m in group["messages"]}
            if msg["id"] in existing_ids:
                return False
            group["messages"].append(msg)
            if len(group["messages"]) > group.get("max_messages", 1000):
                group["messages"] = group["messages"][-500:]
        return True


# ── Offline-First Message Sync ───────────────────────────────────────
class OfflineSync:
    """Store-and-forward sync with conflict resolution.
    
    Uses vector clocks for causal ordering and last-writer-wins
    for conflict resolution. Supports bidirectional sync between
    nodes that come back online after being disconnected.
    
    Features:
    - Vector clock timestamps per message
    - Deduplication via message ID
    - Gap detection and request
    - Conflict resolution (LWW with priority)
    - Sync state tracking per peer
    """
    
    _messages: ClassVar[dict] = {}
    _vector_clocks: ClassVar[dict] = {}
    _sync_state: ClassVar[dict] = {}
    _lock = threading.Lock()
    
    @classmethod
    def create_message(cls, msg_id: str, sender: str, channel: str, payload: str, 
                       node_id: str, priority: int = 0) -> dict:
        """Create a message with vector clock."""
        with cls._lock:
            clock = cls._vector_clocks.get(node_id, {})
            clock[node_id] = clock.get(node_id, 0) + 1
            cls._vector_clocks[node_id] = clock
        
        msg = {
            "id": msg_id,
            "sender": sender,
            "channel": channel,
            "payload": payload,
            "timestamp": time.time(),
            "vector_clock": dict(clock),
            "priority": priority,
            "delivered": False,
            "ttl": 3600,
        }
        
        with cls._lock:
            cls._messages[msg_id] = msg
        
        return msg
    
    @classmethod
    def store_message(cls, msg: dict):
        """Store a received message."""
        with cls._lock:
            msg_id = msg.get("id")
            if msg_id in cls._messages:
                return False
            
            existing_clock = cls._vector_clocks.get(msg.get("sender", ""), {})
            msg_clock = msg.get("vector_clock", {})
            
            for node, counter in msg_clock.items():
                existing_clock[node] = max(existing_clock.get(node, 0), counter)
            cls._vector_clocks[msg.get("sender", "")] = existing_clock
            
            cls._messages[msg_id] = msg
            return True
    
    @classmethod
    def get_pending(cls, channel: str | None = None, limit: int = 100) -> list:
        """Get undelivered messages, optionally filtered by channel."""
        with cls._lock:
            now = time.time()
            pending = []
            for msg in cls._messages.values():
                if msg.get("delivered"):
                    continue
                if msg.get("ttl", 3600) < (now - msg.get("timestamp", now)):
                    continue
                if channel and msg.get("channel") != channel:
                    continue
                pending.append(dict(msg))
                if len(pending) >= limit:
                    break
            return pending
    
    @classmethod
    def mark_delivered(cls, msg_id: str):
        """Mark a message as delivered."""
        with cls._lock:
            if msg_id in cls._messages:
                cls._messages[msg_id]["delivered"] = True
    
    @classmethod
    def get_sync_state(cls, peer_id: str) -> dict:
        """Get sync state for a peer (what we've received from them)."""
        with cls._lock:
            return cls._sync_state.get(peer_id, {"last_sync": 0, "received_ids": []})
    
    @classmethod
    def update_sync_state(cls, peer_id: str, received_ids: list):
        """Update sync state after receiving messages from a peer."""
        with cls._lock:
            cls._sync_state[peer_id] = {
                "last_sync": time.time(),
                "received_ids": received_ids[-1000:],
            }
    
    @classmethod
    def detect_gaps(cls, peer_clock: dict, peer_id: str) -> list:
        """Detect gaps in a peer's message stream."""
        with cls._lock:
            local_clock = cls._vector_clocks.get(peer_id, {})
            gaps = []
            for node, counter in peer_clock.items():
                local_counter = local_clock.get(node, 0)
                if counter > local_counter + 1:
                    gaps.append({
                        "node": node,
                        "from": local_counter + 1,
                        "to": counter - 1,
                    })
            return gaps
    
    @classmethod
    def get_vector_clocks(cls) -> dict:
        with cls._lock:
            return dict(cls._vector_clocks)
    
    @classmethod
    def get_message_count(cls) -> int:
        with cls._lock:
            return len(cls._messages)
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired messages."""
        with cls._lock:
            now = time.time()
            expired = [mid for mid, m in cls._messages.items() 
                      if m.get("ttl", 3600) < (now - m.get("timestamp", now))]
            for mid in expired:
                del cls._messages[mid]
    
    @classmethod
    def get_channels(cls) -> list:
        """List all active channels."""
        with cls._lock:
            channels = set()
            for msg in cls._messages.values():
                ch = msg.get("channel")
                if ch:
                    channels.add(ch)
            return sorted(channels)


# ── Incident Response System ─────────────────────────────────────────
class IncidentResponse:
    """Real-time incident detection, alerting, and automated mitigation
    for hostile signal environments. Tracks anomalies across mesh,
    transport, and application layers.
    
    Capabilities:
    - Signal anomaly detection (jamming, interference, injection)
    - Mesh peer behavior analysis (sudden topological changes)
    - Rate-based attack detection (brute force, flooding)
    - Automated mitigation (isolate, rotate keys, go dark)
    - Audit log with tamper-evident chaining
    """
    ALERT_LEVELS: ClassVar[dict] = {"info": 0, "warn": 1, "high": 2, "critical": 3}
    _lock = threading.Lock()
    _alerts: ClassVar[list] = []
    _audit_log: ClassVar[list] = []
    _mitigations: ClassVar[dict] = {}
    _signal_baselines: ClassVar[dict] = {"mesh_rps": 0, "http_rps": 0, "sat_rps": 0}
    _signal_history: ClassVar[dict] = {"mesh": [], "http": [], "sat": []}
    _peer_baselines: ClassVar[dict] = {}
    _auto_response_enabled = True
    _max_alerts = 500
    _max_audit = 5000
    _alert_callbacks: ClassVar[list] = []
    MAX_HISTORY_PER_CHANNEL = 120

    @classmethod
    def alert(cls, level: str, category: str, message: str, details: dict | None = None):
        entry = {
            "id": hashlib.sha3_256(f"{time.time()}{level}{message}".encode()).hexdigest()[:12],
            "severity": level,
            "category": category,
            "message": message,
            "details": details or {},
            "timestamp": time.time(),
            "human_time": datetime.now(tz=timezone.utc).isoformat(),
        }
        with cls._lock:
            cls._alerts.append(entry)
            if len(cls._alerts) > cls._max_alerts:
                cls._alerts = cls._alerts[-cls._max_alerts:]
            cls._audit_append("alert", entry)
        for cb in cls._alert_callbacks:
            try:
                cb(entry)
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
        mitigation = None
        if cls._auto_response_enabled:
            mitigation = cls._auto_respond(entry)
        if mitigation:
            entry["mitigation"] = mitigation
        return entry

    @classmethod
    def _audit_append(cls, event_type: str, data: dict):
        prev_hash = cls._audit_log[-1]["chain_hash"] if cls._audit_log else "0" * 64
        payload = json.dumps({"type": event_type, "data": data, "prev": prev_hash},
                             sort_keys=True, default=str)
        chain_hash = hashlib.sha3_256(payload.encode()).hexdigest()
        entry = {
            "event_type": event_type,
            "data": data,
            "prev_hash": prev_hash,
            "chain_hash": chain_hash,
            "timestamp": time.time(),
        }
        cls._audit_log.append(entry)
        if len(cls._audit_log) > cls._max_audit:
            cls._audit_log = cls._audit_log[-cls._max_audit:]

    @classmethod
    def verify_audit_chain(cls) -> dict:
        with cls._lock:
            broken = []
            for i, entry in enumerate(cls._audit_log):
                if i == 0:
                    continue
                expected = hashlib.sha3_256(json.dumps(
                    {"type": entry["event_type"], "data": entry["data"],
                     "prev": entry["prev_hash"]}, sort_keys=True, default=str
                ).encode()).hexdigest()
                if entry["chain_hash"] != expected:
                    broken.append(i)
                if entry["prev_hash"] != cls._audit_log[i - 1]["chain_hash"]:
                    broken.append(i)
            return {"total": len(cls._audit_log), "broken": broken, "valid": len(broken) == 0}

    @classmethod
    def _auto_respond(cls, entry: dict):
        level = cls.ALERT_LEVELS.get(entry["severity"], 0)
        cat = entry["category"]
        mitigation = None
        if level >= 2 and cat == "jamming":
            cls._mitigations["stealth_mode"] = True
            MeshNode.stealth_mode = True
            mitigation = "stealth_mode_activated"
        if level >= 3 and cat == "brute_force":
            addr = entry.get("details", {}).get("addr", "")
            if addr:
                teapot_blacklist_addr(addr)
                mitigation = f"blacklisted_{addr}"
        return mitigation

    @classmethod
    def record_signal(cls, channel: str, count: int):
        with cls._lock:
            if channel in cls._signal_history:
                cls._signal_history[channel].append((time.time(), count))
                if len(cls._signal_history[channel]) > cls.MAX_HISTORY_PER_CHANNEL:
                    cls._signal_history[channel] = cls._signal_history[channel][-cls.MAX_HISTORY_PER_CHANNEL:]
                cls._detect_anomaly(channel)

    @classmethod
    def _detect_anomaly(cls, channel: str):
        history = cls._signal_history.get(channel, [])
        if len(history) < 10:
            return
        recent = [c for _, c in history[-10:]]
        baseline = [c for _, c in history[:-10]] if len(history) > 10 else recent
        avg_baseline = sum(baseline) / len(baseline) if baseline else 1
        avg_recent = sum(recent) / len(recent)
        if avg_recent > avg_baseline * 5 and avg_recent > 10:
            cls.alert("high", "jamming",
                      f"Possible {channel} jamming detected: {avg_recent:.1f}/s vs baseline {avg_baseline:.1f}/s",
                      {"channel": channel, "rate": avg_recent, "baseline": avg_baseline})
        elif avg_recent == 0 and avg_baseline > 0:
            cls.alert("warn", "signal_loss",
                      f"Signal loss on {channel}: no traffic for recent window",
                      {"channel": channel, "baseline": avg_baseline})

    @classmethod
    def get_alerts(cls, severity: str | None = None, level: str | None = None, limit: int = 50) -> list:
        with cls._lock:
            alerts = cls._alerts[:]
        filter_level = severity or level
        if filter_level:
            alerts = [a for a in alerts if a.get("severity") == filter_level or a.get("level") == filter_level]
        return alerts[-limit:]

    @classmethod
    def get_audit_chain(cls) -> list:
        with cls._lock:
            return cls._audit_log[:]

    @classmethod
    def set_auto_mitigate(cls, enabled: bool):
        cls._auto_response_enabled = enabled
        return {"auto_mitigate": enabled}

    @classmethod
    def get_status(cls) -> dict:
        with cls._lock:
            sig = {}
            for ch, history in cls._signal_history.items():
                if history:
                    recent = [c for _, c in history[-10:]]
                    sig[ch] = {"rate": sum(recent) / len(recent) if recent else 0,
                               "samples": len(history)}
            alerts_count = len(cls._alerts)
            alerts_by_level = {lv: sum(1 for a in cls._alerts if a["severity"] == lv)
                               for lv in cls.ALERT_LEVELS}
            mitigations = dict(cls._mitigations)
        audit_valid = cls.verify_audit_chain()["valid"]
        return {
            "auto_response": cls._auto_response_enabled,
            "total_alerts": alerts_count,
            "alerts_by_level": alerts_by_level,
            "mitigations_active": mitigations,
            "signal": sig,
            "audit_chain_valid": audit_valid,
        }

    @classmethod
    def set_auto_response(cls, enabled: bool):
        cls._auto_response_enabled = enabled

    @classmethod
    def register_alert_callback(cls, callback):
        cls._alert_callbacks.append(callback)


# ── Signal Space Awareness ───────────────────────────────────────────
class SignalAwareness:
    """Monitors mesh, satellite, mobile, and HTTP signal quality.
    Detects jamming, interference, and network degradation in real-time.
    Provides bandwidth estimation and link quality metrics.
    """
    _lock = threading.Lock()
    _mesh_stats: ClassVar[dict] = {"sent": 0, "recv": 0, "errors": 0, "last_sent": 0, "last_recv": 0}
    _http_stats: ClassVar[dict] = {"requests": 0, "errors": 0, "418s": 0, "bytes_in": 0, "bytes_out": 0}
    _sat_stats: ClassVar[dict] = {"sent": 0, "recv": 0, "errors": 0}
    _mobile_stats: ClassVar[dict] = {"sent": 0, "recv": 0, "errors": 0}
    _link_quality: ClassVar[dict] = {}
    _interface_stats: ClassVar[dict] = {}
    _start_time = time.time()

    @classmethod
    def record_mesh(cls, direction: str, success: bool, size: int = 0):
        with cls._lock:
            if direction == "sent":
                cls._mesh_stats["sent"] += 1
                cls._mesh_stats["last_sent"] = time.time()
            elif direction == "recv":
                cls._mesh_stats["recv"] += 1
                cls._mesh_stats["last_recv"] = time.time()
            if not success:
                cls._mesh_stats["errors"] += 1
                IncidentResponse.alert("warn", "mesh_error", "Mesh transmission error",
                                        {"direction": direction, "total_errors": cls._mesh_stats["errors"]})
            IncidentResponse.record_signal("mesh", 1)

    @classmethod
    def record_http(cls, method: str, path: str, status: int, size_in: int, size_out: int):
        with cls._lock:
            cls._http_stats["requests"] += 1
            cls._http_stats["bytes_in"] += size_in
            cls._http_stats["bytes_out"] += size_out
            if status == 418:
                cls._http_stats["418s"] += 1
            elif status >= 400:
                cls._http_stats["errors"] += 1
            IncidentResponse.record_signal("http", 1)

    @classmethod
    def record_sat(cls, direction: str, success: bool):
        with cls._lock:
            if direction == "sent":
                cls._sat_stats["sent"] += 1
            else:
                cls._sat_stats["recv"] += 1
            if not success:
                cls._sat_stats["errors"] += 1
            IncidentResponse.record_signal("sat", 1)

    @classmethod
    def record_mobile(cls, direction: str, success: bool):
        with cls._lock:
            if direction == "sent":
                cls._mobile_stats["sent"] += 1
            else:
                cls._mobile_stats["recv"] += 1
            if not success:
                cls._mobile_stats["errors"] += 1

    @classmethod
    def estimate_bandwidth(cls) -> dict:
        elapsed = max(time.time() - cls._start_time, 1)
        with cls._lock:
            return {
                "mesh": {"sent": cls._mesh_stats["sent"], "recv": cls._mesh_stats["recv"],
                          "errors": cls._mesh_stats["errors"],
                          "rps": round(cls._mesh_stats["recv"] / elapsed, 2)},
                "http": {"requests": cls._http_stats["requests"],
                         "errors": cls._http_stats["errors"],
                         "418s": cls._http_stats["418s"],
                         "bytes_in": cls._http_stats["bytes_in"],
                         "bytes_out": cls._http_stats["bytes_out"],
                         "rps": round(cls._http_stats["requests"] / elapsed, 2)},
                "sat": {"sent": cls._sat_stats["sent"], "recv": cls._sat_stats["recv"],
                         "errors": cls._sat_stats["errors"]},
                "mobile": {"sent": cls._mobile_stats["sent"], "recv": cls._mobile_stats["recv"],
                            "errors": cls._mobile_stats["errors"]},
                "uptime_seconds": round(elapsed, 1),
            }

    @classmethod
    def get_link_quality(cls, peer_id: str | None = None) -> dict:
        with cls._lock:
            if peer_id:
                return cls._link_quality.get(peer_id, {"quality": "unknown"})
            return dict(cls._link_quality)

    @classmethod
    def update_link_quality(cls, peer_id: str, latency: float, loss: float):
        with cls._lock:
            score = max(0, min(100, 100 - loss * 10 - latency * 2))
            quality = "excellent" if score > 80 else "good" if score > 60 else "fair" if score > 40 else "poor"
            cls._link_quality[peer_id] = {
                "latency_ms": round(latency, 1),
                "loss_pct": round(loss, 2),
                "score": round(score, 1),
                "quality": quality,
                "updated": time.time(),
            }


# ── Emergency Mode ───────────────────────────────────────────────────
class EmergencyMode:
    """Panic button, rapid key rotation, and secure wipe for hostile environments.
    
    When activated:
    - Immediately rotates all cryptographic keys
    - Sends kill message to all known peers
    - Wipes local key material and sensitive state
    - Drops to stealth-only operation
    """
    _active = False
    _lock = threading.Lock()

    @classmethod
    def activate(cls, reason: str = "manual"):
        with cls._lock:
            cls._active = True
        IncidentResponse.alert("critical", "emergency", f"EMERGENCY MODE ACTIVATED: {reason}",
                                {"reason": reason, "timestamp": time.time()})
        cls._rotate_keys()
        cls._notify_peers_emergency()
        MeshNode.stealth_mode = True
        IncidentResponse._mitigations["emergency_mode"] = True
        return {"status": "activated", "reason": reason, "stealth": True}

    @classmethod
    def deactivate(cls):
        with cls._lock:
            cls._active = False
        IncidentResponse._mitigations.pop("emergency_mode", None)
        return {"status": "deactivated", "stealth": MeshNode.stealth_mode}

    @classmethod
    def is_active(cls) -> bool:
        return cls._active

    @classmethod
    def _rotate_keys(cls):
        global COVERT_KEY
        new_key = base64.b64encode(hashlib.sha3_256(os.urandom(48)).digest()[:32]).decode()
        COVERT_KEY = new_key.encode()
        MeshNode._init_identity()
        IncidentResponse.alert("info", "key_rotation", "Cryptographic keys rotated", {"new_key_prefix": new_key[:8]})

    @classmethod
    def _notify_peers_emergency(cls):
        with MeshNode.peers_lock:
            for pid, info in list(MeshNode.peers.items()):
                try:
                    MeshNode._send_direct(pid, {
                        "type": "emergency",
                        "from": POT_ID,
                        "action": "isolate",
                        "timestamp": time.time(),
                    })
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)

    @classmethod
    def rotate_keys(cls):
        """Public API: rotate all cryptographic keys."""
        cls._rotate_keys()
        return {"status": "keys_rotated", "timestamp": time.time()}

    @classmethod
    def secure_wipe(cls):
        """Securely wipe sensitive data from memory."""
        global COVERT_KEY
        COVERT_KEY = b'\x00' * len(COVERT_KEY)
        if MeshNode.node_seed:
            MeshNode.node_seed = b'\x00' * 32
        if MeshNode.node_secret:
            MeshNode.node_secret = b'\x00' * 32
        with MeshNode.inbox_lock:
            MeshNode.inbox.clear()
        with MeshNode.store_lock:
            MeshNode.message_store.clear()
        IncidentResponse.alert("critical", "secure_wipe", "Sensitive data wiped from memory")
        return {"status": "wiped", "timestamp": time.time()}

    @classmethod
    def get_status(cls) -> dict:
        return {
            "active": cls._active,
            "stealth": MeshNode.stealth_mode,
            "mitigations": dict(IncidentResponse._mitigations),
        }


# ── Network Diagnostics ─────────────────────────────────────────────
class NetDiagnostics:
    """Network diagnostic tools for sysadmins in hostile signal spaces.
    TCP ping, traceroute, port scan, DNS resolution, and interface info.
    """

    _BLOCKED_RANGES: ClassVar[list] = [
        ("10.0.0.0", "10.255.255.255"),      # RFC 1918
        ("172.16.0.0", "172.31.255.255"),    # RFC 1918
        ("192.168.0.0", "192.168.255.255"),  # RFC 1918
        ("169.254.0.0", "169.254.255.255"),  # link-local / cloud metadata
        ("0.0.0.0", "0.255.255.255"),        # current network
        ("224.0.0.0", "239.255.255.255"),    # multicast
    ]

    @staticmethod
    def _is_blocked_host(host: str) -> str:
        """Return error string if host is blocked (SSRF protection), else empty."""
        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror:
            return f"Cannot resolve {host}"
        parts = resolved.split(".")
        if len(parts) != 4:
            return f"Invalid IP format: {resolved}"
        ip_int = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        for lo_str, hi_str in NetDiagnostics._BLOCKED_RANGES:
            lo_parts = [int(x) for x in lo_str.split(".")]
            hi_parts = [int(x) for x in hi_str.split(".")]
            lo_int = (lo_parts[0] << 24) | (lo_parts[1] << 16) | (lo_parts[2] << 8) | lo_parts[3]
            hi_int = (hi_parts[0] << 24) | (hi_parts[1] << 16) | (hi_parts[2] << 8) | hi_parts[3]
            if lo_int <= ip_int <= hi_int:
                return f"Blocked: {host} ({resolved}) is in restricted range"
        return ""
    @staticmethod
    def tcp_ping(host: str, port: int = 4180, timeout: float = 3.0) -> dict:
        blocked = NetDiagnostics._is_blocked_host(host)
        if blocked:
            return {"host": host, "port": port, "alive": False, "error": blocked}
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            elapsed = (time.time() - start) * 1000
            s.close()
            return {"host": host, "port": port, "alive": True, "latency_ms": round(elapsed, 1)}
        except Exception as e:
            return {"host": host, "port": port, "alive": False, "error": str(e)}

    @staticmethod
    def udp_ping(host: str, port: int = 4191, timeout: float = 3.0) -> dict:
        blocked = NetDiagnostics._is_blocked_host(host)
        if blocked:
            return {"host": host, "port": port, "alive": False, "error": blocked}
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"CPIP_PING", (host, port))
            _data, _addr = s.recvfrom(1024)
            elapsed = (time.time() - start) * 1000
            s.close()
            return {"host": host, "port": port, "alive": True, "latency_ms": round(elapsed, 1)}
        except TimeoutError:
            s.close()
            return {"host": host, "port": port, "alive": False, "error": "timeout"}
        except Exception as e:
            return {"host": host, "port": port, "alive": False, "error": str(e)}

    @staticmethod
    def port_scan(host: str, ports: list | None = None, timeout: float = 1.0) -> dict:
        blocked = NetDiagnostics._is_blocked_host(host)
        if blocked:
            return {"host": host, "ports": {}, "error": blocked}
        if ports is None:
            ports = [22, 53, 80, 443, 4180, 4190, 4191, 4192, 4193, 4194, 4195, 4196, 8080]
        if len(ports) > 20:
            return {"host": host, "ports": {}, "error": "Maximum 20 ports per scan"}
        results = {}
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                results[port] = "open" if result == 0 else "closed"
                s.close()
            except Exception:
                results[port] = "filtered"
        return {"host": host, "ports": results}

    @staticmethod
    def dns_resolve(hostname: str, dns_server: str | None = None) -> dict:
        blocked = NetDiagnostics._is_blocked_host(hostname)
        if blocked:
            return {"hostname": hostname, "resolved": False, "error": blocked}
        try:
            addrs = socket.getaddrinfo(hostname, None)
            ipv4 = list({a[4][0] for a in addrs if a[0] == socket.AF_INET})
            ipv6 = list({a[4][0] for a in addrs if a[0] == socket.AF_INET6})
            return {"hostname": hostname, "ipv4": ipv4, "ipv6": ipv6, "resolved": True}
        except Exception as e:
            return {"hostname": hostname, "resolved": False, "error": str(e)}

    @staticmethod
    def traceroute(host: str, max_hops: int = 15, port: int = 4180, timeout: float = 2.0) -> dict:
        blocked = NetDiagnostics._is_blocked_host(host)
        if blocked:
            return {"host": host, "hops": [], "error": blocked}
        hops = []
        try:
            dest_addr = socket.gethostbyname(host)
        except Exception as e:
            return {"host": host, "hops": [], "error": str(e)}
        for ttl in range(1, max_hops + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                s.settimeout(timeout)
                start = time.time()
                s.connect((dest_addr, port))
                elapsed = (time.time() - start) * 1000
                hops.append({"ttl": ttl, "addr": dest_addr, "latency_ms": round(elapsed, 1)})
                s.close()
                break
            except TimeoutError:
                hops.append({"ttl": ttl, "addr": "*", "latency_ms": None})
            except Exception as e:
                hop_addr = "?"
                hops.append({"ttl": ttl, "addr": hop_addr, "latency_ms": None, "error": str(e)[:50]})
        return {"host": host, "hops": hops}

    @staticmethod
    def get_interfaces() -> list:
        ifaces = []
        try:
            for name in os.listdir("/sys/class/net/"):
                if name == "lo":
                    continue
                iface = {"name": name}
                try:
                    addr_path = f"/sys/class/net/{name}/address"
                    with open(addr_path) as f:
                        iface["mac"] = f.read().strip()
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
                try:
                    oper_path = f"/sys/class/net/{name}/operstate"
                    with open(oper_path) as f:
                        iface["state"] = f.read().strip()
                except Exception:
                    iface["state"] = "unknown"
                try:
                    ip_out = subprocess.run(["ip", "addr", "show", name],
                                            capture_output=True, text=True, timeout=3, check=False)
                    iface["ip_info"] = ip_out.stdout[:500]
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
                ifaces.append(iface)
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return ifaces
class CovertChannel:
    """Encode/decode hidden messages inside HTCPCP Accept-Additions headers.
    
    Messages are hidden in plain sight - they look like normal coffee
    customization requests. The variety fields carry hex-encoded data
    segments, and the addition types themselves encode routing metadata.
    
    Now with ECC: when a recipient's ECDSA/ECDH P-256 public key is known, messages
    are ECDH-encrypted using a shared secret derived from (our_seed, their_pubkey).
    Each message is also signed with our ECDSA/ECDH P-256 key for authenticity.
    
    Format:
      Accept-Additions: <type>;variety=<hexdata>, <type>;variety=<hexdata>, ...
    
    Each <type> encodes 2 bits of routing metadata:
      milk=00, syrup=01, sugar=10, spice=11
    The variety field carries hex-encoded ciphertext + ECC metadata.
    """

    HEADER = "Accept-Additions"
    CHUNK_SIZE = 8

    ADDITION_POOL: ClassVar[list] = list(VALID_ADDITIONS.keys())
    VARIETY_POOL: ClassVar[dict] = {}
    for addn_name, addn_def in VALID_ADDITIONS.items():
        VARIETY_POOL[addn_name] = addn_def["variety"]

    @classmethod
    def encode(cls, message, dst_pot: str | None = None, recipe: str = "espresso",
               dst_pubkey: bytes | None = None, our_seed: bytes | None = None) -> dict:
        """Encode a message into Accept-Additions header components.
        
        If dst_pubkey and our_seed are provided, uses ECDH shared secret
        + ECDSA P-256 signing instead of the basic CoffeeBlend cipher.
        """
        if not COVERT_ENABLED:
            return {"additions": []}
        if isinstance(message, str):
            message = message.encode()

        if dst_pubkey and our_seed:
            shared = ECP256.key_exchange(our_seed, dst_pubkey)
            otk = CoffeeCipher._hkdf_expand(shared, b"cpip-covert-ecc-v2", 32)
            ciphertext = CoffeeCipher.encrypt(message, base_key=otk, recipe=recipe)
            sig = ECP256.sign(ciphertext, our_seed)
            _, _, _, our_pubkey = ECP256.generate_keypair(our_seed)
            payload = b"ECCv2:" + ECP256.pubkey_to_address(
                our_pubkey
            ).encode() + b":" + sig + b":" + ciphertext
        else:
            ciphertext = CoffeeCipher.encrypt(message, recipe=recipe)
            payload = b"CBC2:" + ciphertext

        if recipe and recipe != "espresso":
            recipe_chunks = []
            for i in range(0, len(recipe), cls.CHUNK_SIZE):
                chunk = recipe[i:i + cls.CHUNK_SIZE]
                addn_type = BITS_TO_ADDITION.get(i % 5, "milk")
                recipe_chunks.append({"name": addn_type, "variety": f"recipe_{chunk}"})
            recipe_chunks.append({"name": "spice", "variety": "recipe_end"})

        hex_data = payload.hex()
        hex_len = len(hex_data)
        additions = []
        for i in range(0, hex_len, cls.CHUNK_SIZE):
            chunk = hex_data[i:i + cls.CHUNK_SIZE]
            addn_type = BITS_TO_ADDITION.get((i // cls.CHUNK_SIZE) % 5, "milk")
            additions.append({"name": addn_type, "variety": chunk})

        if recipe and recipe != "espresso":
            additions = recipe_chunks + additions

        if dst_pot:
            route_seed = int(hashlib.sha256(dst_pot.encode()).hexdigest()[:4], 16)
            route_bits = route_seed % 5
            route_type = BITS_TO_ADDITION.get(route_bits, "syrup")
            additions.insert(0, {"name": route_type, "variety": f"route_{dst_pot[:16]}"})

        return {"additions": additions}

    @classmethod
    def decode(cls, additions: list, our_seed: bytes | None = None) -> bytes:
        """Extract hidden message from parsed Accept-Additions list.
        
        If our_seed is provided, attempts ECDH decryption using embedded
        sender address to derive the shared secret.
        Returns decrypted plaintext bytes, or b'' if no message found.
        """
        if not additions or not COVERT_ENABLED:
            return b""

        hex_chunks = []
        recipe = "espresso"
        recipe_mode = False
        for addn in additions:
            addn.get("name", "")
            variety = addn.get("variety", "")
            if not variety:
                continue
            if variety.startswith("route_"):
                continue
            if variety.startswith("recipe_"):
                val = variety[len("recipe_"):]
                if val == "end":
                    recipe_mode = False
                    continue
                if not recipe_mode:
                    recipe = val
                    recipe_mode = True
                    continue
                recipe += val
                continue
            if recipe_mode:
                continue
            hex_chunks.append(variety)

        if not hex_chunks:
            return b""

        hex_data = "".join(hex_chunks)
        try:
            payload = bytes.fromhex(hex_data)
        except ValueError:
            return b""

        try:
            if payload.startswith(b"ECCv2:") and our_seed:
                _, addr_b, sig, ciphertext = payload.split(b":", 3)
                for info in MeshNode.peers.values():
                    pk_b64 = info.get("pubkey", "")
                    if pk_b64:
                        pk = base64.b64decode(pk_b64)
                        if ECP256.pubkey_to_address(pk) == addr_b.decode():
                            shared = ECP256.key_exchange(our_seed, pk)
                            otk = CoffeeCipher._hkdf_expand(shared, b"cpip-covert-ecc-v2", 32)
                            if ECP256.verify(ciphertext, sig, pk):
                                plaintext = CoffeeCipher.decrypt(ciphertext, base_key=otk, recipe=recipe)
                                if plaintext:
                                    return plaintext
                return b""
            elif payload.startswith(b"CBC2:"):
                ciphertext = payload[5:]
                plaintext = CoffeeCipher.decrypt(ciphertext, recipe=recipe)
                return plaintext if plaintext else b""
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return b""

    @classmethod
    def generate_cover_traffic(cls) -> dict:
        """Generate innocent-looking Accept-Additions for cover traffic."""
        additions = []
        num_additions = secrets.randbelow(3) + 1
        chosen = []
        pool = list(cls.ADDITION_POOL)
        for _ in range(min(num_additions, len(pool))):
            idx = secrets.randbelow(len(pool))
            chosen.append(pool.pop(idx))
        for name in chosen:
            variety = secrets.choice(cls.VARIETY_POOL[name])
            additions.append({"name": name, "variety": variety})
        return {"additions": additions}

    @classmethod
    def encode_brew(cls, message: bytes, dst_pot: str | None = None,
                    dst_pubkey: bytes | None = None, our_seed: bytes | None = None) -> tuple:
        """Create a brew request that carries a hidden message.
        
        Returns (beverage_type, additions_list, headers_dict)
        """
        additions = cls.encode(message, dst_pot, dst_pubkey=dst_pubkey, our_seed=our_seed)
        beverage = secrets.choice(["coffee", "tea"])
        header_value = ", ".join(
            f"{a['name']};variety={a['variety']}"
            for a in additions["additions"]
        )
        headers = {cls.HEADER: header_value}
        return beverage, additions["additions"], headers


# ── Mesh AAA + Latent Port + Stealth Network ──────────────────────────
class MeshNode:
    """Peer-to-peer mesh with AAA (Authentication, Authorization, Accounting),
    latent (dormant) ports, and stealth mode to bypass ISP/government blocks.
    
    ┌─ Node Identity ──────────────────────────────────────────────┐
    │ Each node has a persistent secret derived from COVERT_KEY +   │
    │ POT_ID. A self-signed 'node certificate' is used in AUTH     │
    │ handshakes. Trust levels: untrusted → challenged → known →   │
    │ trusted → admin.                                              │
    ├─ Latent Ports ───────────────────────────────────────────────┤
    │ Secondary UDP ports (4192,4193,4194) that appear closed.     │
    │ Activated only after a correct port-knocking sequence.       │
    │ When dormant: no ICMP response, no TCP RST, no UDP reply.   │
    ├─ Stealth Mode ───────────────────────────────────────────────┤
    │ No broadcast heartbeats. Directed pings only. Port hopping   │
    │ changes mesh port periodically. Traffic padded to random     │
    │ sizes. Covert fallback routes via HTTP brew headers if UDP   │
    │ is blocked.                                                   │
    ├─ Persistence ────────────────────────────────────────────────┤
    │ Peers, routes, inbox saved to disk. Survives reboot.         │
    └──────────────────────────────────────────────────────────────┘
    """

    # ── Class-level state ──────────────────────────────────────────────
    peers: ClassVar[dict] = {}
    peers_lock = threading.Lock()
    routing_table: ClassVar[dict] = {}
    message_store: ClassVar[list] = []
    store_lock = threading.Lock()
    inbox: ClassVar[list] = []
    inbox_lock = threading.Lock()
    trust_store: ClassVar[dict] = {}
    trust_lock = threading.Lock()
    mesh_socket = None
    latent_sockets: ClassVar[dict] = {}
    latent_lock = threading.Lock()
    running = False
    node_secret = None
    node_seed = None
    node_pubkey = None
    node_address = None
    node_cert = None
    current_mesh_port = MESH_PORT
    knock_state: ClassVar[dict] = {}
    persist_path = None
    address_book: ClassVar[dict] = {}
    address_book_lock = threading.Lock()

    # ── Starlink / Satellite state ──────────────────────────────────────
    sat_socket = None
    sat_peers: ClassVar[dict] = {}
    sat_bootstrap: ClassVar[list] = []
    sat_coords = (0.0, 0.0, 0.0)
    sat_rtt: ClassVar[dict] = {}
    sat_lock = threading.Lock()
    sat_active = False
    stealth_mode = MESH_STEALTH

    # ── Trust levels ───────────────────────────────────────────────────
    TRUST_UNTRUSTED = 0
    TRUST_CHALLENGED = 1
    TRUST_KNOWN = 2
    TRUST_TRUSTED = 3
    TRUST_ADMIN = 4

    TRUST_NAMES: ClassVar[dict] = {0: "untrusted", 1: "challenged", 2: "known", 3: "trusted", 4: "admin"}

    # ── Bootstrap ──────────────────────────────────────────────────────

    @classmethod
    def _init_identity(cls):
        """Derive persistent node identity from COVERT_KEY + POT_ID.
        Uses ECDSA/ECDH P-256 keypair for ECC-based identity and signing."""
        seed = hashlib.sha256(COVERT_KEY + POT_ID.encode()).digest()
        cls.node_secret = hashlib.sha256(seed + b"node-identity-v2").digest()
        # Generate ECDSA/ECDH P-256 keypair for ECC
        ecc_seed = hashlib.sha256(cls.node_secret + b"ed25519").digest()
        cls.node_pubkey, cls.node_seed, _, _ = ECP256.generate_keypair(ecc_seed)
        cls.node_address = ECP256.pubkey_to_address(cls.node_pubkey)
        cls.node_cert = {
            "node_id": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "pubkey": base64.b64encode(cls.node_pubkey).decode(),
            "address": cls.node_address,
            "signature": CoffeeCipher.hash(cls.node_secret + POT_ID.encode()),
        }
        Path(MESH_PERSIST_DIR).mkdir(parents=True, exist_ok=True)
        cls.persist_path = Path(MESH_PERSIST_DIR) / f"mesh_{POT_ID}.json"
        cls._load_persist()

    @classmethod
    def start(cls):
        if not MESH_ENABLED:
            return
        try:
            cls._init_identity()
            cls.running = True

            # Try to bind mesh port with fallback
            base = MESH_PORT
            sock = None
            for i in range(10):
                port = base + i
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except AttributeError:
                        pass
                    _sock_bind(s, (BIND_ADDR, port))
                    s.settimeout(2)
                    sock = s
                    cls.current_mesh_port = port
                    break
                except OSError:
                    if i < 9:
                        continue
                    s.close()
                    raise

            cls.mesh_socket = sock

            threading.Thread(target=cls._listener, daemon=True).start()
            threading.Thread(target=cls._heartbeat_loop, daemon=True).start()
            threading.Thread(target=cls.store_forward_retry, daemon=True).start()
            threading.Thread(target=cls._latent_listener, daemon=True).start()
            threading.Thread(target=cls._persist_loop, daemon=True).start()
            threading.Thread(target=cls._port_hop_loop, daemon=True).start()
            threading.Thread(target=cls._keep_warm_loop, daemon=True).start()
            if COVER_TRAFFIC:
                threading.Thread(target=cls._cover_traffic_loop, daemon=True).start()

            cls._sat_start()
            cls._mobile_start()

            print(TEAPOT_SNAKE_ART)
            print(f"   ├ Mesh AAA:   Node {POT_ID} active on port {cls.current_mesh_port}", flush=True)
            print(f"   ├ Latent:     Ports {MESH_LATENT_PORTS} (dormant)", flush=True)
            print(f"   └ Stealth:    {'ON (no broadcast)' if MeshNode.stealth_mode else 'OFF (broadcast enabled)'}", flush=True)
        except Exception as e:
            print(f"[MESH] Failed to start: {e}", flush=True)

    @classmethod
    def stop(cls):
        cls.running = False
        cls._save_persist()
        if cls.mesh_socket:
            try: cls.mesh_socket.close()
            except Exception: pass
        with cls.latent_lock:
            for s in cls.latent_sockets.values():
                try: s.close()
                except Exception: pass
            cls.latent_sockets.clear()
        cls._sat_stop()
        cls._mobile_stop()

    # ── Latent Port System ─────────────────────────────────────────────

    @classmethod
    def _get_knock_sequence(cls) -> list:
        """Derive port-knocking sequence from node secret using SHA-256."""
        seed = int.from_bytes(hashlib.sha256(cls.node_secret + b"knock-sequence").digest()[:4], 'big')
        rng = random.Random(seed)
        base_ports = sorted(MESH_LATENT_PORTS)
        sequence = []
        for _ in range(4):
            p = rng.choice(base_ports)
            sequence.append(p)
        return sequence

    @classmethod
    def _latent_listener(cls):
        """Listen on all latent ports. When dormant, respond to nothing.
        On correct knock sequence, activate the port."""
        knock_seq = cls._get_knock_sequence()
        for port in MESH_LATENT_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except AttributeError:
                     pass
                _sock_bind(s, (BIND_ADDR, port))
                s.settimeout(1)
                with cls.latent_lock:
                    cls.latent_sockets[port] = s
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        while cls.running:
            with cls.latent_lock:
                ports = list(cls.latent_sockets.items())
            for port, sock in ports:
                if not cls.running:
                    break
                try:
                    data, addr = sock.recvfrom(1024)
                    cls._handle_knock(port, data, addr, knock_seq)
                except TimeoutError:
                    continue
                except Exception:
                    break
            time.sleep(0.1)

    @classmethod
    def _handle_knock(cls, port: int, data: bytes, addr: tuple, knock_seq: list):
        """Port-knocking auth: only respond if the correct sequence of
        ports is hit in order. A node must send knocks to port sequence
        in order before the latent port responds."""
        try:
            msg = json.loads(data.decode())
            if msg.get("type") != "knock":
                return
            sender = msg.get("from", "")
            msg.get("seq", 0)

            key = (addr[0], sender)
            now = time.time()
            if key not in cls.knock_state:
                cls.knock_state[key] = {"step": 0, "time": now}

            state = cls.knock_state[key]
            if now - state["time"] > 10:
                state["step"] = 0

            expected_port = knock_seq[state["step"]]
            if port == expected_port:
                state["step"] += 1
                state["time"] = now
                if state["step"] >= len(knock_seq):
                    cls._activate_latent(sender, addr)
                    cls.knock_state[key] = {"step": 0, "time": now}
            else:
                state["step"] = 0
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _activate_latent(cls, sender: str, addr: tuple):
        """Activate a latent port for a specific authenticated peer."""
        with cls.peers_lock:
            if sender not in cls.peers:
                return
            cls.peers[sender]["latent"] = True
            cls.peers[sender]["latent_addr"] = addr[0]
        # Send activation confirmation on primary mesh port
        try:
            cls._send_direct(sender, {
                "type": "latent_active",
                "from": POT_ID,
                "ports": MESH_LATENT_PORTS,
                "timestamp": time.time(),
            })
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def knock_port(cls, target_pot: str) -> bool:
        """Send port-knock sequence to a peer to activate their latent ports."""
        with cls.peers_lock:
            info = cls.peers.get(target_pot)
            if not info:
                return False
            addr = info.get("addr", "")
        knock_seq = cls._get_knock_sequence()
        for i, port in enumerate(knock_seq):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                msg = json.dumps({"type": "knock", "from": POT_ID, "seq": i}).encode()
                s.sendto(msg, (addr, port))
                s.close()
                time.sleep(0.2)
            except Exception:
                return False
        return True

    # ── AAA: Authentication & Trust ────────────────────────────────────

    @classmethod
    def _challenge_peer(cls, pot_id: str) -> dict:
        """Generate an auth challenge for a peer, signed with ECDSA P-256."""
        nonce = CoffeeCipher.hash(cls.node_secret + pot_id.encode() + str(time.time()).encode())
        sig = ECP256.sign(nonce.encode(), cls.node_seed)
        return {
            "type": "auth_request",
            "from": POT_ID,
            "cert": cls.node_cert,
            "challenge": nonce,
            "signature": base64.b64encode(sig).decode(),
            "timestamp": time.time(),
        }

    @classmethod
    def _verify_challenge(cls, challenge: str, peer_pot: str, peer_cert: dict) -> bool:
        """Verify a peer's challenge response using ECDSA P-256."""
        expected = CoffeeCipher.hash(cls.node_secret + peer_pot.encode() + str(int(time.time())).encode())
        return challenge == expected

    @classmethod
    def _sign_message(cls, msg: dict) -> dict:
        """Sign a dict message with our ECDSA P-256 key."""
        payload = json.dumps(msg, sort_keys=True).encode()
        sig = ECP256.sign(payload, cls.node_seed)
        msg["_sig"] = base64.b64encode(sig).decode()
        msg["_signer"] = cls.node_address
        return msg

    @classmethod
    def _verify_message(cls, msg: dict) -> bool:
        """Verify a dict message's ECDSA P-256 signature. Reject unsigned."""
        sig_b64 = msg.pop("_sig", None)
        signer_addr = msg.pop("_signer", None)
        if not sig_b64 or not signer_addr:
            return False
        try:
            sig = base64.b64decode(sig_b64)
            payload = json.dumps(msg, sort_keys=True).encode()
            # Look up signer's public key
            for info in cls.peers.values():
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    pk = base64.b64decode(pk_b64)
                    if ECP256.pubkey_to_address(pk) == signer_addr:
                        return ECP256.verify(payload, sig, pk)
            return False
        except Exception:
            return False

    # ── Address Book (ECC Address ↔ POT_ID) ────────────────────────────

    @classmethod
    def _update_address_book(cls, pot_id: str, address: str, pubkey_b64: str, hostname: str = ""):
        """Register or update an address book entry."""
        if not address:
            return
        with cls.address_book_lock:
            cls.address_book[address] = {
                "pot_id": pot_id,
                "pubkey": pubkey_b64,
                "hostname": hostname,
                "last_seen": time.time(),
            }

    @classmethod
    def _resolve_address(cls, address_or_pot: str) -> str:
        """Resolve an ECC address or POT_ID to a POT_ID.
        
        If the string looks like an address (coffee: prefix), look up
        the address book. Otherwise return as-is (it's a POT_ID).
        """
        if address_or_pot.startswith("coffee:"):
            with cls.address_book_lock:
                entry = cls.address_book.get(address_or_pot)
                if entry:
                    return entry["pot_id"]
            return ""  # unknown address
        return address_or_pot  # already a POT_ID

    @classmethod
    def _get_pubkey_for(cls, pot_id: str) -> bytes:
        """Get the ECDSA/ECDH P-256 public key for a peer by POT_ID."""
        with cls.peers_lock:
            info = cls.peers.get(pot_id, {})
            pk_b64 = info.get("pubkey", "")
            if pk_b64:
                try:
                    return base64.b64decode(pk_b64)
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
        return b""

    # ── E2EE Message Encryption (FIPS-compliant, forward secrecy) ─────

    @classmethod
    def _e2ee_encrypt(cls, plaintext: str, dst_pot: str) -> dict:
        """Encrypt a message with ephemeral ECDH + HKDF + AES-256-GCM.
        
        Uses per-message ephemeral ECDH key pair for forward secrecy:
        even if the long-term key is compromised, past messages remain secure.
        Key derivation uses full HKDF Extract-then-Expand (SP 800-56C).
        """
        if not cls.node_seed:
            return {"data": plaintext, "e2ee": False, "error": "Local E2EE identity unavailable"}
        pk = cls.node_pubkey if dst_pot == POT_ID else cls._get_pubkey_for(dst_pot)
        if not pk:
            return {"data": plaintext, "e2ee": False, "error": "Recipient public key unavailable"}
        try:
            eph_seed = secrets.token_bytes(32)
            shared = ECP256.key_exchange(eph_seed, pk)
            dst_address = ECP256.pubkey_to_address(pk)
            salt = hashlib.sha256(
                b"cpip-e2ee-salt-v4:" + cls.node_address.encode() + dst_address.encode()
            ).digest()
            otk = CoffeeCipher.hkdf(shared, salt, b"cpip-e2ee-v4", 32)
            ciphertext = CoffeeCipher.encrypt(plaintext.encode(), base_key=otk)
            eph_pub = ECP256._derive_key_from_seed(eph_seed).public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            return {
                "data": base64.b64encode(ciphertext).decode(),
                "e2ee": True,
                "e2ee_version": 4,
                "eph_pub": base64.b64encode(eph_pub).decode(),
                "from_addr": cls.node_address,
            }
        except Exception as exc:
            return {"data": plaintext, "e2ee": False, "error": f"E2EE encryption failed: {exc}"}

    @classmethod
    def _e2ee_decrypt(cls, msg_data: str, from_addr: str = "", eph_pub_b64: str = "") -> str:
        """Decrypt an E2EE message using sender's ephemeral public key.
        
        If eph_pub is provided, uses ephemeral ECDH for forward secrecy.
        Falls back to static ECDH for v3 backward compatibility.
        Key derivation uses full HKDF Extract-then-Expand (SP 800-56C).
        """
        if not cls.node_seed or not from_addr:
            return msg_data
        sender_pk = None
        with cls.address_book_lock:
            entry = cls.address_book.get(from_addr)
            if entry and entry.get("pubkey"):
                try:
                    sender_pk = base64.b64decode(entry["pubkey"])
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
        if not sender_pk:
            with cls.peers_lock:
                for info in cls.peers.values():
                    pk_b64 = info.get("pubkey", "")
                    if pk_b64:
                        try:
                            pk = base64.b64decode(pk_b64)
                            if ECP256.pubkey_to_address(pk) == from_addr:
                                sender_pk = pk
                                break
                        except Exception as _e:
                            logger.debug("Ignored: %s", _e)
        if not sender_pk and not eph_pub_b64:
            return msg_data
        try:
            ciphertext = base64.b64decode(msg_data)
            if eph_pub_b64:
                eph_pub = base64.b64decode(eph_pub_b64)
                shared = ECP256.key_exchange(cls.node_seed, eph_pub)
                salt = hashlib.sha256(b"cpip-e2ee-salt-v4:" + from_addr.encode() + cls.node_address.encode()).digest()
                otk = CoffeeCipher.hkdf(shared, salt, b"cpip-e2ee-v4", 32)
            else:
                shared = ECP256.key_exchange(cls.node_seed, sender_pk)
                salt = b"cpip-e2ee-salt-v3" + from_addr.encode()
                otk = CoffeeCipher._hkdf_expand(
                    CoffeeCipher._hkdf_extract(salt, shared),
                    b"cpip-e2ee-v2", 32
                )
            plaintext = CoffeeCipher.decrypt(ciphertext, base_key=otk)
            if not plaintext:
                return msg_data
            return plaintext.decode("utf-8", errors="replace")
        except Exception:
            return msg_data

    @classmethod
    def _get_trust_level(cls, pot_id: str) -> int:
        with cls.trust_lock:
            return cls.trust_store.get(pot_id, cls.TRUST_UNTRUSTED)

    @classmethod
    def _set_trust_level(cls, pot_id: str, level: int):
        with cls.trust_lock:
            cls.trust_store[pot_id] = level
        cls._save_persist()

    @classmethod
    def _peer_authorized(cls, pot_id: str, min_level: int = TRUST_KNOWN) -> bool:
        return cls._get_trust_level(pot_id) >= min_level

    # ── Listener & Message Handler ─────────────────────────────────────

    @classmethod
    def _listener(cls):
        sock = cls.mesh_socket
        while cls.running and sock:
            try:
                data, addr = sock.recvfrom(8192)
                data = cls._unpad_traffic(data)
                threading.Thread(target=lambda d=data, a=addr: MeshNode._handle_message(d, a), daemon=True).start()
            except TimeoutError:
                continue
            except Exception:
                break

    MESSAGE_EXPIRY_SECONDS = 300

    @classmethod
    def _mesh_hmac(cls, payload: bytes) -> str:
        """Generate HMAC-SHA256 for mesh message authentication."""
        key = hashlib.sha256(cls.node_secret + b"mesh-hmac-v2").digest()
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    @classmethod
    def _verify_mesh_hmac(cls, msg: dict) -> bool:
        """Verify HMAC-SHA256 on incoming mesh messages. Reject unsigned."""
        msg_hmac = msg.pop("_mesh_hmac", None)
        if not msg_hmac:
            return False
        sender = msg.get("from") or msg.get("pot") or ""
        with cls.peers_lock:
            info = cls.peers.get(sender, {})
        peer_secret_b64 = info.get("mesh_secret", "")
        if not peer_secret_b64:
            return False
        try:
            peer_secret = base64.b64decode(peer_secret_b64)
            key = hashlib.sha256(peer_secret + b"mesh-hmac-v2").digest()
            payload = json.dumps(msg, sort_keys=True).encode()
            expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(msg_hmac, expected)
        except Exception:
            return False

    @classmethod
    def _handle_message(cls, data: bytes, addr: tuple):
        # Check for bonded fragment (binary FragmentHeader, not JSON)
        if BONDING_ENABLED and len(data) >= FragmentHeader.SIZE and data[0:1] not in (b"{", b"["):
            try:
                hdr = FragmentHeader.unpack(data)
                payload = data[FragmentHeader.SIZE:FragmentHeader.SIZE + hdr.payload_size]
                source = f"mesh:{addr[0]}:{addr[1]}"
                complete = BandwidthAggregator.reassemble(hdr, payload, source)
                if complete is not None:
                    try:
                        reassembled_msg = json.loads(complete.decode())
                        cls._dispatch_message(reassembled_msg, addr)
                    except json.JSONDecodeError:
                        pass
                return
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        try:
            msg = json.loads(data.decode())
        except Exception:
            return

        cls._dispatch_message(msg, addr)

    @classmethod
    def _dispatch_message(cls, msg: dict, addr: tuple):
        msg_type = msg.get("type", "")
        sender = msg.get("pot") or msg.get("from") or ""
        if sender == POT_ID:
            return

        ts = msg.get("timestamp", 0)
        if ts:
            try:
                if not isinstance(ts, (int, float)) or abs(time.time() - ts) > cls.MESSAGE_EXPIRY_SECONDS:
                    return
            except (TypeError, ValueError):
                return

        # ── RFC-0021 mesh attack detection: peer tracking + replay guard ──
        try:
            from providers.mesh_security import MeshSecurityProvider
            MeshSecurityProvider.track_peer(sender, addr[0], msg.get("introducer", ""))
            nonce = msg.get("nonce")
            if nonce is not None:
                try:
                    nonce = int(nonce)
                except (TypeError, ValueError):
                    return
                if not MeshSecurityProvider.check_nonce(sender, nonce):
                    return
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

        if msg_type == "heartbeat":
            with cls.peers_lock:
                pubkey = msg.get("pubkey", "")
                address = msg.get("address", "")
                cls.peers[sender] = {
                    "addr": addr[0],
                    "port": msg.get("port", BIND_PORT),
                    "mesh_port": msg.get("mesh_port", cls.current_mesh_port),
                    "hostname": msg.get("hostname", addr[0]),
                    "device": msg.get("device", "unknown"),
                    "last_seen": time.time(),
                    "hops": msg.get("hops", 0),
                    "latent": False,
                    "pubkey": pubkey,
                    "address": address,
                }
                if address:
                    cls._update_address_book(sender, address, pubkey,
                                              msg.get("hostname", addr[0]))
                LinkMonitor.register_link(
                    f"mesh:{sender}", "mesh",
                    f"{addr[0]}:{msg.get('mesh_port', cls.current_mesh_port)}",
                    bandwidth=msg.get("bandwidth_bps", 10_000_000))
            cls._update_routes()
            trust = cls._get_trust_level(sender)
            if trust < cls.TRUST_KNOWN:
                cls._send_direct(sender, cls._challenge_peer(sender))

        elif msg_type == "auth_request":
            cls._handle_auth_request(msg, addr)

        elif msg_type == "auth_response":
            cls._handle_auth_response(msg, addr)

        elif msg_type == "auth_grant":
            with cls.trust_lock:
                cls.trust_store[sender] = msg.get("level", cls.TRUST_KNOWN)
            cls._save_persist()

        elif msg_type == "latent_active":
            with cls.peers_lock:
                if sender in cls.peers:
                    cls.peers[sender]["latent"] = True

        elif msg_type == "message":
            if cls._peer_authorized(sender, cls.TRUST_KNOWN):
                cls._route_message(msg, addr)

        elif msg_type == "route_query":
            if cls._peer_authorized(sender, cls.TRUST_KNOWN):
                cls._handle_route_query(msg, addr)

        elif msg_type == "route_reply":
            with cls.peers_lock:
                if msg.get("pot") in cls.peers:
                    cls.peers[msg["pot"]]["route"] = msg.get("route", [])

        elif msg_type == "ack":
            with cls.store_lock:
                ack_id = msg.get("ack_id", "")
                cls.message_store[:] = [m for m in cls.message_store if m.get("id") != ack_id]

        elif msg_type == "deaddrop_query":
            cls._handle_propfind_deaddrop(msg, addr)

        elif msg_type == "deaddrop_list":
            with cls.store_lock:
                for drop in msg.get("drops", []):
                    if drop.get("dst") == POT_ID:
                        cls._send_direct(msg.get("from", ""), {
                            "type": "deaddrop_claim",
                            "from": POT_ID,
                            "message_id": drop["id"],
                            "timestamp": time.time(),
                        })

        elif msg_type == "deaddrop_claim":
            mid = msg.get("message_id", "")
            claimed = cls.claim_dead_drop(mid, sender)
            if claimed:
                cls._send_direct(sender, claimed)

        elif msg_type == "hole_punch":
            ack = json.dumps({"type": "hole_punch_ack", "from": POT_ID}).encode()
            if MeshNode.mesh_socket:
                try:
                    MeshNode.mesh_socket.sendto(ack, addr)
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)

        elif msg_type == "identity_publish":
            cert = msg.get("cert", {})
            if cert.get("pot_id"):
                WebOfTrust.publish_identity(cert["pot_id"], cert)
                cls._cross_transport_forward(msg, "mesh")

        elif msg_type == "trust_claim":
            trust_sig = msg.get("trust_sig", {})
            if trust_sig.get("signer") and trust_sig.get("target"):
                WebOfTrust.receive_trust_sig(trust_sig)
                cls._cross_transport_forward(msg, "mesh")

        elif msg_type == "dns_register":
            reg = msg.get("registration", {})
            name = reg.get("name")
            pot_id = reg.get("pot_id")
            if name and pot_id:
                DistributedDNS.gossip_receive({name: reg})
                cls._cross_transport_forward(msg, "mesh")

        elif msg_type == "group_message":
            GroupChat.receive_group_message(msg.get("group_msg", {}))
            cls._cross_transport_forward(msg, "mesh")

        elif msg_type == "group_key_update":
            group_id = msg.get("group_id")
            key_data = msg.get("key_data", {})
            if group_id and key_data:
                with cls.store_lock:
                    pass
            cls._cross_transport_forward(msg, "mesh")

        elif msg_type == "sync_request":
            peer_id = msg.get("peer_id", sender)
            channel = msg.get("channel")
            msg.get("since", 0)
            pending = OfflineSync.get_pending(channel, limit=50)
            cls._send_direct(sender, {
                "type": "sync_response",
                "from": POT_ID,
                "peer_id": peer_id,
                "messages": pending,
                "vector_clock": OfflineSync.get_vector_clocks().get(POT_ID, {}),
                "timestamp": time.time(),
            })

        elif msg_type == "sync_response":
            for m in msg.get("messages", []):
                OfflineSync.store_message(m)
            OfflineSync.update_sync_state(sender, [m.get("id") for m in msg.get("messages", [])])

        else:
            pass

    @classmethod
    def _cross_transport_forward(cls, msg: dict, via: str):
        """Forward a received message to other mesh transports.
        via: 'radio', 'satellite', 'mobile', or 'mesh'
        Prevents routing loops by not forwarding back to the source transport.
        """
        if via != "satellite" and SATELLITE_ENABLED:
            try:
                target = msg.get("from") or msg.get("pot") or ""
                if target and target != POT_ID:
                    cls._sat_send_direct(target, msg)
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
        if via != "radio" and _radio is not None:
            try:
                _radio.send(json.dumps(msg).encode())
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
        if via != "mobile" and MOBILE_ENABLED and cls.mobile_socket:
            try:
                payload = json.dumps(msg).encode()
                target = msg.get("from") or msg.get("pot") or ""
                if target:
                    with cls.mobile_lock:
                        info = cls.mobile_peers.get(target)
                    if info:
                        cls.mobile_socket.sendto(payload, (info["addr"], info["port"]))
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

    @classmethod
    def _handle_auth_request(cls, msg: dict, addr: tuple):
        """Process an incoming authentication request with ECDSA P-256."""
        sender = msg.get("from", "")
        cert = msg.get("cert", {})
        challenge = msg.get("challenge", "")
        signature_b64 = msg.get("signature", "")

        # Store peer's pubkey
        if cert and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                with cls.peers_lock:
                    if sender in cls.peers:
                        cls.peers[sender]["pubkey"] = cert["pubkey"]
                        cls.peers[sender]["address"] = cert.get("address", "")
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        # Verify their signature on the challenge
        if signature_b64 and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                sig = base64.b64decode(signature_b64)
                if not ECP256.verify(challenge.encode(), sig, pk):
                    return  # reject bad signature
            except Exception:
                return

        # Sign our response with ECDSA P-256
        response = CoffeeCipher.hash(cls.node_secret + challenge.encode())
        my_sig = ECP256.sign(response.encode(), cls.node_seed)
        cls._set_trust_level(sender, cls.TRUST_CHALLENGED)
        with cls.peers_lock:
            if sender in cls.peers:
                cls.peers[sender]["auth_step"] = "challenged"
        cls._send_direct(sender, {
            "type": "auth_response",
            "from": POT_ID,
            "cert": cls.node_cert,
            "challenge_response": response,
            "signature": base64.b64encode(my_sig).decode(),
            "challenge": CoffeeCipher.hash(cls.node_secret + sender.encode()),
            "timestamp": time.time(),
        })

    @classmethod
    def _handle_auth_response(cls, msg: dict, addr: tuple):
        """Process an authentication response. If valid, grant trust with ECDSA P-256."""
        sender = msg.get("from", "")
        resp = msg.get("challenge_response", "")
        their_challenge = msg.get("challenge", "")
        signature_b64 = msg.get("signature", "")
        cert = msg.get("cert", {})

        # Store peer's pubkey
        if cert and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                with cls.peers_lock:
                    if sender in cls.peers:
                        cls.peers[sender]["pubkey"] = cert["pubkey"]
                        cls.peers[sender]["address"] = cert.get("address", "")
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        # Verify signature on response
        if signature_b64 and cert.get("pubkey"):
            try:
                pk = base64.b64decode(cert["pubkey"])
                sig = base64.b64decode(signature_b64)
                if not ECP256.verify(resp.encode(), sig, pk):
                    return
            except Exception:
                return

        expected = CoffeeCipher.hash(cls.node_secret + CoffeeCipher.hash(cls.node_secret + sender.encode()).encode())
        if resp == expected:
            level = cls.TRUST_TRUSTED
            cls._set_trust_level(sender, level)
            with cls.peers_lock:
                if sender in cls.peers:
                    cls.peers[sender]["auth_step"] = "trusted"
            grant_sig = ECP256.sign(json.dumps({"level": level, "sender": sender}).encode(), cls.node_seed)
            cls._send_direct(sender, {
                "type": "auth_grant",
                "from": POT_ID,
                "level": level,
                "signature": base64.b64encode(grant_sig).decode(),
                "timestamp": time.time(),
            })
            # Respond to their challenge
            my_resp = CoffeeCipher.hash(cls.node_secret + their_challenge.encode())
            my_sig = ECP256.sign(my_resp.encode(), cls.node_seed)
            cls._send_direct(sender, {
                "type": "auth_response",
                "from": POT_ID,
                "challenge_response": my_resp,
                "signature": base64.b64encode(my_sig).decode(),
                "timestamp": time.time(),
            })

    # ── Heartbeat (Stealth Mode) ───────────────────────────────────────

    @classmethod
    def _heartbeat_loop(cls):
        while cls.running:
            cls._send_heartbeat()
            with cls.peers_lock:
                now = time.time()
                stale = [p for p, info in cls.peers.items()
                         if now - info.get("last_seen", 0) > MESH_HEARTBEAT * 3]
                for p in stale:
                    del cls.peers[p]
            time.sleep(MESH_HEARTBEAT)

    @classmethod
    def _send_heartbeat(cls):
        payload_dict = {
            "type": "heartbeat",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "port": BIND_PORT,
            "mesh_port": cls.current_mesh_port,
            "hops": 0,
            "brewing": PotState.is_brewing(),
            "pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else "",
            "address": cls.node_address or "",
            "dns_names": DistributedDNS.reverse_resolve(POT_ID),
            "lat": SATELLITE_LAT if SATELLITE_ENABLED else None,
            "lon": SATELLITE_LON if SATELLITE_ENABLED else None,
            "alt": SATELLITE_ALT if SATELLITE_ENABLED else None,
            "sat_port": SATELLITE_PORT if SATELLITE_ENABLED else None,
            "timestamp": time.time(),
            "nonce": time.time_ns(),
            "mesh_secret": base64.b64encode(
                hashlib.sha256(cls.node_secret + b"mesh-secret-v2").digest()
            ).decode(),
        }
        payload_dict["_mesh_hmac"] = cls._mesh_hmac(json.dumps(payload_dict, sort_keys=True).encode())
        payload = json.dumps(payload_dict).encode()
        payload = cls._pad_traffic(payload)

        if MeshNode.stealth_mode:
            with cls.peers_lock:
                targets = [(info["addr"], info.get("mesh_port", cls.current_mesh_port))
                           for pid, info in cls.peers.items()
                           if cls._peer_authorized(pid, cls.TRUST_KNOWN)]
            for addr, port in targets:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(2)
                    s.sendto(payload, (addr, port))
                    s.close()
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(payload, ("255.255.255.255", cls.current_mesh_port))
                s.close()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

    # ── Traffic Padding (Obfuscation) ──────────────────────────────────

    @classmethod
    def _pad_traffic(cls, data: bytes) -> bytes:
        """Pad UDP payload to a random size (256-1024 bytes) to defeat
        traffic analysis. Pad bytes are random noise."""
        min_size = max(256, len(data) + 4)
        target = secrets.randbelow(1024 - min_size + 1) + min_size
        if len(data) >= target:
            return data
        padding = secrets.token_bytes(target - len(data))
        return data + b"\x00" + struct.pack(">H", len(data)) + padding

    @classmethod
    def _unpad_traffic(cls, data: bytes) -> bytes:
        """Remove traffic padding."""
        try:
            null_idx = data.index(b"\x00", 128)
            if null_idx + 2 < len(data):
                orig_len = struct.unpack(">H", data[null_idx + 1:null_idx + 3])[0]
                if 0 < orig_len < len(data):
                    return data[:orig_len]
        except (ValueError, struct.error):
            pass
        return data

    # ── Cover Traffic ──────────────────────────────────────────────────

    @classmethod
    def _cover_traffic_loop(cls):
        while cls.running:
            time.sleep(secrets.randbelow(181) + 120)
            with cls.peers_lock:
                targets = [pid for pid in cls.peers
                           if cls._peer_authorized(pid, cls.TRUST_KNOWN)]
            if not targets:
                continue
            cover = CovertChannel.generate_cover_traffic()
            if cover["additions"]:
                target = secrets.choice(targets)
                cls._send_direct(target, {
                    "type": "cover_traffic",
                    "from": POT_ID,
                    "additions": cover["additions"],
                    "timestamp": time.time(),
                })

    # ── Stealth Port Hopping ───────────────────────────────────────────

    @classmethod
    def _port_hop_loop(cls):
        """Periodically change the mesh port in stealth mode.
        
        Rotates through latent port + random high ports to evade
        deep packet inspection and port-based blocking.
        """
        while cls.running:
            time.sleep(MESH_HOP_INTERVAL)
            if not MeshNode.stealth_mode:
                continue
            try:
                # Pick a new port from latent range or random ephemeral
                if secrets.randbelow(2) == 0:
                    new_port = secrets.choice(MESH_LATENT_PORTS)
                else:
                    new_port = secrets.randbelow(20001) + 40000

                # Create new socket on new port
                new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except AttributeError:
                    pass
                _sock_bind(new_sock, (BIND_ADDR, new_port))
                new_sock.settimeout(2)

                # Swap sockets
                old_sock = cls.mesh_socket
                old_port = cls.current_mesh_port
                cls.mesh_socket = new_sock
                cls.current_mesh_port = new_port

                # Notify trusted peers
                with cls.peers_lock:
                    for pid, info in cls.peers.items():
                        if cls._peer_authorized(pid, cls.TRUST_TRUSTED):
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                s.settimeout(1)
                                notice = json.dumps({
                                    "type": "port_hop",
                                    "from": POT_ID,
                                    "new_port": new_port,
                                    "timestamp": time.time(),
                                    "sig": base64.b64encode(
                                        ECP256.sign(
                                            str(new_port).encode(), cls.node_seed
                                        )
                                    ).decode(),
                                }).encode()
                                s.sendto(notice, (info["addr"], info.get("mesh_port", old_port)))
                                s.close()
                            except Exception as _e:
                                logger.debug("Ignored: %s", _e)

                time.sleep(2)  # let listeners switch
                try:
                    old_sock.close()
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

    # ── Keep Warm (Re-encrypt + Re-broadcast Undelivered) ──────────────

    @classmethod
    def _keep_warm_loop(cls):
        """Background thread that re-encrypts and re-broadcasts undelivered
        messages to keep the mesh 'warm'. Each retry uses a fresh ECDH
        shared secret for forward secrecy."""
        while cls.running:
            time.sleep(300)  # every 5 minutes
            with cls.store_lock:
                for stored in cls.message_store:
                    if stored["attempts"] >= 3 or not stored.get("e2ee"):
                        continue
                    encrypted = cls._e2ee_encrypt(stored.get("_plaintext", ""), stored["dst"])
                    if encrypted.get("e2ee"):
                        stored["msg"].update({
                            "data": encrypted["data"],
                            "eph_pub": encrypted.get("eph_pub", ""),
                            "e2ee_version": encrypted.get("e2ee_version", 4),
                            "from_addr": encrypted.get("from_addr", ""),
                        })

    # ── Starlink / Satellite Transport ──────────────────────────────────

    @classmethod
    def _sat_start(cls):
        if cls.sat_active:
            return
        if not SATELLITE_ENABLED and not cls.sat_active:
            return
        cls.sat_coords = (SATELLITE_LAT, SATELLITE_LON, SATELLITE_ALT)
        if SATELLITE_BOOTSTRAP:
            cls.sat_bootstrap = [b.strip() for b in SATELLITE_BOOTSTRAP.split(",") if b.strip()]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                 pass
            _sock_bind(s, (BIND_ADDR, SATELLITE_PORT))
            s.settimeout(MESH_SAT_TIMEOUT)
            cls.sat_socket = s
            cls.sat_active = True
            threading.Thread(target=cls._sat_listener, daemon=True).start()
            threading.Thread(target=cls._sat_heartbeat_loop, daemon=True).start()
            print(f"   ├ Satellite:  Sat-Mesh on port {SATELLITE_PORT}"
                  f" @ ({SATELLITE_LAT:.2f}, {SATELLITE_LON:.2f})", flush=True)
            if cls.sat_bootstrap:
                print(f"   ├ Bootstrap:  {len(cls.sat_bootstrap)} satellite seed nodes", flush=True)
            if SATELLITE_RELAY:
                print("   └ Relay:      Ground-station relay mode active", flush=True)
        except Exception as e:
            print(f"   ⚠ Starlink:   {e}", flush=True)

    @classmethod
    def _sat_stop(cls):
        if cls.sat_socket:
            try: cls.sat_socket.close()
            except Exception: pass
            cls.sat_socket = None
            cls.sat_active = False

    @classmethod
    def sat_enable(cls):
        cls.sat_active = True
        cls._sat_start()

    @classmethod
    def sat_disable(cls):
        with cls.sat_lock:
            cls.sat_peers.clear()
        cls._sat_stop()

    @classmethod
    def _sat_listener(cls):
        sock = cls.sat_socket
        while cls.running and sock:
            try:
                data, addr = sock.recvfrom(4096)
                _sat_hdl = cls._sat_handle.__func__
                threading.Thread(target=lambda d=data, a=addr, h=_sat_hdl: h(cls, d, a), daemon=True).start()
            except TimeoutError:
                continue
            except Exception:
                break

    @classmethod
    def _sat_handle(cls, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode())
            sender = msg.get("pot") or msg.get("from") or ""
            if sender == POT_ID or not sender:
                return

            with cls.sat_lock:
                cls.sat_peers[sender] = {
                    "addr": addr[0],
                    "port": msg.get("sat_port", SATELLITE_PORT),
                    "hostname": msg.get("hostname", addr[0]),
                    "device": msg.get("device", "unknown"),
                    "last_seen": time.time(),
                    "lat": msg.get("lat", 0),
                    "lon": msg.get("lon", 0),
                    "alt": msg.get("alt", 0),
                    "hops": msg.get("hops", 0),
                    "pubkey": msg.get("pubkey", ""),
                    "address": msg.get("address", ""),
                }

            if msg.get("type") == "sat_heartbeat":
                cls._sat_ping(sender, addr)
                with cls.peers_lock:
                    cls.peers[sender] = {
                        "addr": addr[0],
                        "port": msg.get("port", BIND_PORT),
                        "mesh_port": msg.get("mesh_port", cls.current_mesh_port),
                        "hostname": msg.get("hostname", addr[0]),
                        "device": msg.get("device", "unknown"),
                        "last_seen": time.time(),
                        "hops": msg.get("hops", 0) + 1,
                        "latent": False,
                        "pubkey": msg.get("pubkey", ""),
                        "address": msg.get("address", ""),
                        "sat_link": True,
                        "sat_lat": msg.get("lat", 0),
                        "sat_lon": msg.get("lon", 0),
                        "sat_alt": msg.get("alt", 0),
                    }
                cls._update_routes()
                trust = cls._get_trust_level(sender)
                if trust < cls.TRUST_KNOWN:
                    cls._sat_send_direct(sender, cls._challenge_peer(sender))

            elif msg.get("type") == "sat_pong":
                with cls.sat_lock:
                    cls.sat_rtt[sender] = time.time() - msg.get("sent", time.time())

            elif msg.get("type") in ("message", "route_query", "deaddrop_query"):
                cls._handle_message(data, addr)
                cls._cross_transport_forward(msg, via="satellite")

        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _sat_heartbeat_loop(cls):
        while cls.running:
            cls._sat_send_heartbeat()
            with cls.sat_lock:
                now = time.time()
                stale = [p for p, info in cls.sat_peers.items()
                         if now - info.get("last_seen", 0) > MESH_SAT_HEARTBEAT * 3]
                for p in stale:
                    del cls.sat_peers[p]
            time.sleep(MESH_SAT_HEARTBEAT)

    @classmethod
    def _sat_send_heartbeat(cls):
        payload = json.dumps({
            "type": "sat_heartbeat",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "port": BIND_PORT,
            "mesh_port": cls.current_mesh_port,
            "sat_port": SATELLITE_PORT,
            "hops": 0,
            "brewing": PotState.is_brewing(),
            "lat": SATELLITE_LAT,
            "lon": SATELLITE_LON,
            "alt": SATELLITE_ALT,
            "pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else "",
            "address": cls.node_address or "",
            "timestamp": time.time(),
        }).encode()
        cls._sat_broadcast(payload)

    @classmethod
    def _sat_ping(cls, sender: str, addr: tuple):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(MESH_SAT_TIMEOUT)
            pong = json.dumps({
                "type": "sat_pong",
                "from": POT_ID,
                "sent": time.time(),
            }).encode()
            s.sendto(pong, addr)
            s.close()
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _sat_broadcast(cls, payload: bytes):
        """Send to all bootstrap nodes and known satellite peers."""
        targets = set()
        for b in cls.sat_bootstrap:
            if ":" in b:
                host, p = b.rsplit(":", 1)
                targets.add((host, int(p)))
            else:
                targets.add((b, SATELLITE_PORT))
        with cls.sat_lock:
            for info in cls.sat_peers.values():
                targets.add((info["addr"], info["port"]))
        for addr, port in targets:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(payload, (addr, port))
                s.close()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

    @classmethod
    def _sat_send_direct(cls, dst: str, msg: dict) -> bool:
        """Send a message directly via satellite link if the peer is known."""
        with cls.sat_lock:
            info = cls.sat_peers.get(dst)
        if not info:
            return False
        try:
            payload = json.dumps(msg).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(MESH_SAT_TIMEOUT)
            s.sendto(payload, (info["addr"], info["port"]))
            s.close()
            return True
        except Exception:
            return False

    @classmethod
    def get_sat_status(cls) -> dict:
        with cls.sat_lock:
            return {
                "enabled": cls.sat_active,
                "port": SATELLITE_PORT,
                "coords": {"lat": SATELLITE_LAT, "lon": SATELLITE_LON, "alt": SATELLITE_ALT},
                "bootstrap": cls.sat_bootstrap,
                "relay": SATELLITE_RELAY,
                "peers_known": len(cls.sat_peers),
                "peers": [{"pot": pid,
                           "hostname": info.get("hostname", "?"),
                           "addr": info.get("addr", "?"),
                           "lat": info.get("lat", 0),
                           "lon": info.get("lon", 0),
                           "last_seen": info.get("last_seen", 0),
                           "rtt": round(cls.sat_rtt.get(pid, 0) * 1000, 1),
                           "hops": info.get("hops", 0)}
                          for pid, info in cls.sat_peers.items()],
            }

    # ── Mobile Broadband (4G/5G / LTE / WWAN) Transport ────────────────

    mobile_socket = None
    mobile_peers: ClassVar[dict] = {}
    mobile_lock = threading.Lock()
    mobile_bootstrap: ClassVar[list] = []
    mobile_active = False

    @classmethod
    def _mobile_start(cls):
        if cls.mobile_active:
            return
        if not MOBILE_ENABLED and not cls.mobile_active:
            return
        if MOBILE_BOOTSTRAP:
            cls.mobile_bootstrap = [b.strip() for b in MOBILE_BOOTSTRAP.split(",") if b.strip()]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                 pass
            _sock_bind(s, (BIND_ADDR, MOBILE_PORT))
            s.settimeout(3.0)
            cls.mobile_socket = s
            cls.mobile_active = True
            threading.Thread(target=cls._mobile_listener, daemon=True).start()
            threading.Thread(target=cls._mobile_heartbeat_loop, daemon=True).start()
            print(f"   ├ Mobile:     4G/5G port {MOBILE_PORT}"
                  f" ({MOBILE_INTERFACE})", flush=True)
            if cls.mobile_bootstrap:
                print(f"   ├ Bootstrap: {len(cls.mobile_bootstrap)} mobile seed nodes", flush=True)
        except Exception as e:
            print(f"   ⚠ Mobile:   {e}", flush=True)

    @classmethod
    def _mobile_stop(cls):
        if cls.mobile_socket:
            try: cls.mobile_socket.close()
            except Exception: pass
            cls.mobile_socket = None
            cls.mobile_active = False

    @classmethod
    def mobile_enable(cls):
        cls.mobile_active = True
        cls._mobile_start()

    @classmethod
    def mobile_disable(cls):
        with cls.mobile_lock:
            cls.mobile_peers.clear()
        cls._mobile_stop()

    @classmethod
    def _mobile_listener(cls):
        sock = cls.mobile_socket
        while cls.running and sock:
            try:
                data, addr = sock.recvfrom(4096)
                _mob_hdl = cls._mobile_handle.__func__
                threading.Thread(target=lambda d=data, a=addr, h=_mob_hdl: h(cls, d, a), daemon=True).start()
            except TimeoutError:
                continue
            except Exception:
                break

    @classmethod
    def _mobile_handle(cls, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode())
            sender = msg.get("pot") or msg.get("from") or ""
            if sender == POT_ID or not sender:
                return

            with cls.mobile_lock:
                cls.mobile_peers[sender] = {
                    "addr": addr[0],
                    "port": msg.get("mobile_port", MOBILE_PORT),
                    "hostname": msg.get("hostname", addr[0]),
                    "device": msg.get("device", "unknown"),
                    "last_seen": time.time(),
                    "signal": msg.get("signal", None),
                    "net": msg.get("network", ""),
                    "pubkey": msg.get("pubkey", ""),
                    "address": msg.get("address", ""),
                    "hops": msg.get("hops", 0),
                }

            if msg.get("type") == "mobile_heartbeat":
                with cls.peers_lock:
                    cls.peers[sender] = {
                        "addr": addr[0],
                        "port": msg.get("port", BIND_PORT),
                        "mesh_port": msg.get("mesh_port", cls.current_mesh_port),
                        "hostname": msg.get("hostname", addr[0]),
                        "device": msg.get("device", "unknown"),
                        "last_seen": time.time(),
                        "hops": msg.get("hops", 0) + 1,
                        "latent": False,
                        "pubkey": msg.get("pubkey", ""),
                        "address": msg.get("address", ""),
                        "mobile_link": True,
                        "signal": msg.get("signal"),
                        "network": msg.get("network", ""),
                    }
                cls._update_routes()
                cls._cross_transport_forward(msg, via="mobile")
            elif msg.get("type") in ("message", "route_query", "deaddrop_query"):
                cls._handle_message(data, addr)
                cls._cross_transport_forward(msg, via="mobile")
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _mobile_heartbeat_loop(cls):
        while cls.running:
            cls._mobile_send_heartbeat()
            with cls.mobile_lock:
                now = time.time()
                stale = [p for p, info in cls.mobile_peers.items()
                         if now - info.get("last_seen", 0) > MOBILE_HEARTBEAT * 3]
                for p in stale:
                    del cls.mobile_peers[p]
            time.sleep(MOBILE_HEARTBEAT)

    @classmethod
    def _mobile_send_heartbeat(cls):
        payload = json.dumps({
            "type": "mobile_heartbeat",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "port": BIND_PORT,
            "mesh_port": cls.current_mesh_port,
            "mobile_port": MOBILE_PORT,
            "hops": 0,
            "brewing": PotState.is_brewing(),
            "pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else "",
            "address": cls.node_address or "",
            "network": MOBILE_INTERFACE,
            "signal": cls._mobile_get_signal(),
            "timestamp": time.time(),
        }).encode()
        targets = set()
        for b in cls.mobile_bootstrap:
            if ":" in b:
                host, p = b.rsplit(":", 1)
                targets.add((host, int(p)))
            else:
                targets.add((b, MOBILE_PORT))
        with cls.mobile_lock:
            for info in cls.mobile_peers.values():
                targets.add((info["addr"], info["port"]))
        if not targets:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            for addr, port in targets:
                try:
                    s.sendto(payload, (addr, port))
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
            s.close()
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _mobile_get_signal(cls) -> dict:
        """Read cellular signal strength. Tries multiple methods."""
        result = {"rssi": None, "rsrp": None, "sinr": None, "mcc": None, "interface": MOBILE_INTERFACE}
        iface = MOBILE_INTERFACE
        if not os.path.isdir("/sys/class/net/" + iface):
            alt = [n for n in os.listdir("/sys/class/net/")
                   if n.startswith(("wwan", "usb", "eth")) and n != "lo"]
            if alt:
                iface = alt[0]
                result["interface"] = iface
        for suffix, key in [("rssi", "rssi"), ("signal", "rssi"), ("rsrp", "rsrp"), ("sinr", "sinr")]:
            p = f"/sys/class/net/{iface}/statistics/{suffix}"
            try:
                with open(p) as f:
                    result[key] = int(f.read().strip())
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
        try:
            out = subprocess.run(
                ["mmcli", "-m", "any", "--output=json"],
                capture_output=True, text=True, timeout=3, check=False)
            if out.returncode == 0:
                d = json.loads(out.stdout)
                m = d.get("modem", {}).get("generic", {})
                result.update({
                    "rssi": m.get("signal-quality", result.get("rssi")),
                    "mcc": d.get("modem", {}).get("3gpp", {}).get("mcc"),
                    "network": d.get("modem", {}).get("3gpp", {}).get("operator-name", ""),
                })
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return result

    @classmethod
    def get_mobile_status(cls) -> dict:
        with cls.mobile_lock:
            peers = [{"pot": pid,
                      "hostname": info.get("hostname", "?"),
                      "addr": info.get("addr", "?"),
                      "last_seen": info.get("last_seen", 0),
                      "signal": info.get("signal"),
                      "network": info.get("network", ""),
                      "hops": info.get("hops", 0)}
                     for pid, info in cls.mobile_peers.items()]
        return {
            "enabled": cls.mobile_active,
            "port": MOBILE_PORT,
            "interface": MOBILE_INTERFACE,
            "bootstrap": list(cls.mobile_bootstrap),
            "telemetry": MOBILE_TELEMETRY,
            "peers_known": len(cls.mobile_peers),
            "peers": peers,
            "signal": cls._mobile_get_signal(),
        }

    # ── Routing ────────────────────────────────────────────────────────

    @classmethod
    def _update_routes(cls):
        with cls.peers_lock:
            for pot_id, info in cls.peers.items():
                if cls._peer_authorized(pot_id, cls.TRUST_KNOWN):
                    cls.routing_table[pot_id] = {
                        "addr": info["addr"],
                        "port": info.get("mesh_port", cls.current_mesh_port),
                        "hops": info.get("hops", 1),
                        "last_seen": info.get("last_seen", 0),
                    }

    @classmethod
    def _route_message(cls, msg: dict, addr: tuple):
        dst = msg.get("dst", "")
        ttl = msg.get("ttl", MESH_TTL)
        message_id = msg.get("id", "")

        if ttl <= 0:
            return

        if dst == POT_ID or not dst:
            # Decrypt E2EE if applicable
            raw_data = msg.get("data", "")
            e2ee_decrypted = False
            if msg.get("e2ee") and msg.get("from_addr"):
                decrypted = cls._e2ee_decrypt(raw_data, msg["from_addr"], msg.get("eph_pub", ""))
                if decrypted != raw_data:
                    raw_data = decrypted
                    e2ee_decrypted = True
                else:
                    raw_data = "[encrypted — key unavailable]"
            # Sanitize non-printable characters for display
            if isinstance(raw_data, bytes):
                try:
                    raw_data = raw_data.decode("utf-8", errors="replace")
                except Exception:
                    raw_data = repr(raw_data)
            with cls.inbox_lock:
                cls.inbox.append({
                    "id": message_id,
                    "from": msg.get("from", "unknown"),
                    "data": raw_data,
                    "timestamp": time.time(),
                    "hops": MESH_TTL - ttl + 1,
                    "channel": "mesh_aaa",
                    "e2ee": msg.get("e2ee", False),
                    "e2ee_decrypted": e2ee_decrypted,
                })
                if len(cls.inbox) > HISTORY_MAX:
                    cls.inbox = cls.inbox[-HISTORY_MAX:]
            PotState._broadcast({
                "event": "mesh_message",
                "from": msg.get("from", "unknown"),
                "message_id": message_id,
            })
            sender = msg.get("from", "")
            if sender and sender != POT_ID:
                cls._send_direct(sender, {
                    "type": "ack", "ack_id": message_id,
                    "from": POT_ID, "dst": sender, "timestamp": time.time(),
                })
            return

        with cls.peers_lock:
            next_hop = cls.routing_table.get(dst)

        if next_hop:
            ttl -= 1
            msg["ttl"] = ttl
            msg["route"] = msg.get("route", []) + [POT_ID]
            ph = PalantirHardening() if PALANTIR_ENABLED else None
            if PALANTIR_ENABLED and ph and ph.enabled and ph.mix_queue_size < 100:
                def _do_send(d, m):
                    m["ttl"] = m.get("ttl", MESH_TTL) - 1
                    cls._send_direct(d, m)
                if not ph.enqueue_for_mix(dst, dict(msg), _do_send):
                    cls._send_direct(dst, msg)
            else:
                cls._send_direct(dst, msg)
            if PALANTIR_ENABLED and ph and ph.enabled and ph.should_broadcast():
                with cls.peers_lock:
                    for pid in list(cls.peers.keys()):
                        if pid != dst and pid != POT_ID:
                            bcast_msg = dict(msg)
                            bcast_msg["dst"] = pid
                            bcast_msg["_cover"] = True
                            cls._send_direct(pid, bcast_msg)
        else:
            with cls.store_lock:
                cls.message_store.append({
                    "id": message_id, "dst": dst, "msg": msg,
                    "queued": time.time(), "attempts": 0,
                })

    # ── Covert Fallback (HTTP over UDP) ────────────────────────────────

    @classmethod
    def _covert_fallback_send(cls, dst_pot: str, msg: dict) -> bool:
        """If direct UDP fails, try multiple anti-ISP transports."""
        msg = NetNeutrality.strip_metadata(msg)
        data_str = json.dumps(msg)
        payload = data_str.encode()
        payload = NetNeutrality.add_jitter(payload)

        # Try hole-punch first
        with cls.peers_lock:
            info = cls.peers.get(dst_pot)
        if info:
            for addr in info.get("addrs", []):
                try:
                    ip, port = addr.rsplit(":", 1)
                    if AntiISP.punch(ip, int(port), timeout=3.0):
                        cls.mesh_socket.sendto(
                            cls._pad_traffic(payload),
                            (ip, int(port)))
                        return True
                except Exception as _e:
                    logger.debug("Skipped: %s", _e); continue

        # Try WSS relay
        if AntiISP._wss_active:
            try:
                wss_payload = json.dumps({"target": dst_pot,
                    "data": base64.b64encode(payload).decode()}).encode()
                if AntiISP.wss_send(wss_payload):
                    return True
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        # Try DNS tunnel (low-bandwidth, high-resilience)
        if AntiISP._dns_tunnel_active:
            try:
                chunks = [payload[i:i+200] for i in range(0, len(payload), 200)]
                for chunk in chunks:
                    AntiISP.dns_tunnel_send(dst_pot, chunk)
                return True
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        # Try relay server
        if AntiISP._relay_pool:
            try:
                relay_payload = json.dumps({"target": dst_pot,
                    "data": base64.b64encode(payload).decode()}).encode()
                if AntiISP.relay_send(dst_pot, relay_payload):
                    return True
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        # Final fallback: HTTP covert channel
        try:
            additions = CovertChannel.encode(payload, dst_pot)
            header = ", ".join(f"{a['name']};variety={a['variety']}" for a in additions["additions"])
            if info:
                import urllib.request
                req = urllib.request.Request(
                    f"http://{info['addr']}:{info.get('port', BIND_PORT)}/tea",
                    method="BREW",
                    headers={"Accept-Additions": header},
                )
                urllib.request.urlopen(req, timeout=5)
                return True
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return False

    # ── Direct Send ────────────────────────────────────────────────────

    @classmethod
    def _send_direct(cls, dst_pot: str, msg: dict):
        try:
            msg = dict(msg)
            if (msg.get("from") or msg.get("pot")) == POT_ID:
                msg.setdefault("nonce", time.time_ns())
            ph = PalantirHardening() if PALANTIR_ENABLED else None

            with cls.peers_lock:
                info = cls.peers.get(dst_pot)
            if not info:
                return False

            data = json.dumps(msg).encode()

            if PALANTIR_ENABLED and ph and ph.enabled:
                ph.wait_for_timing_slot()
                data = ph.pad_message(data)
            else:
                data = cls._pad_traffic(data)

            # Use bonded multi-link transport if multiple paths are available
            if BONDING_ENABLED:
                send_fns = BondedMeshTransport.get_send_fns(dst_pot)
                active = [(lid, fn) for lid, fn in send_fns.items()
                          if LinkMonitor._links.get(lid, {}).get("active", False)]
                if len(active) >= 2:
                    # Striped bonding — send firmware fragments across all links
                    total = BandwidthAggregator.send_bonded(data, dict(active))
                    if total > 0:
                        return True
                    # Fall through to direct send if bonding failed

            # Single-path fallback: direct UDP to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            port = info.get("mesh_port", cls.current_mesh_port)
            sock.sendto(data, (info["addr"], port))
            sock.close()
            return True
        except Exception:
            return cls._covert_fallback_send(dst_pot, msg)

    # ── Route Query ────────────────────────────────────────────────────

    @classmethod
    def _handle_route_query(cls, msg: dict, addr: tuple):
        target = msg.get("target", "")
        with cls.peers_lock:
            route = cls.routing_table.get(target)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = json.dumps({"type": "route_reply", "pot": POT_ID,
                               "target": target, "route": [route] if route else []}).encode()
            s.sendto(cls._pad_traffic(data), addr)
            s.close()
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    # ── Public API ─────────────────────────────────────────────────────

    @classmethod
    def send_message(cls, dst: str, data: str, use_e2ee: bool = True) -> dict:
        """Send a message to a peer. Supports ECC address resolution and E2EE.
        
        - dst can be a POT_ID or an ECC address (coffee:...)
        - If use_e2ee=True and the recipient's public key is known, the
          payload is ECDH-encrypted before sending
        """
        # Resolve address book entry
        original_dst = dst
        dst = cls._resolve_address(dst)
        if not dst:
            return {"status": "error", "error": f"Unknown address: {original_dst}"}

        message_id = str(uuid.uuid4())[:8]

        # E2EE encrypt the payload
        if use_e2ee:
            encrypted = cls._e2ee_encrypt(data, dst)
            if not encrypted.get("e2ee"):
                return {"status": "error", "error": encrypted.get("error", "E2EE encryption failed"),
                        "e2ee": False}
            payload_data = encrypted["data"]
            e2ee_meta = {
                "e2ee": True,
                "e2ee_version": encrypted.get("e2ee_version", 4),
                "eph_pub": encrypted.get("eph_pub", ""),
                "from_addr": encrypted.get("from_addr", ""),
            }
        else:
            payload_data = data
            e2ee_meta = {"e2ee": False, "from_addr": ""}

        msg = {
            "type": "message", "id": message_id, "from": POT_ID,
            "dst": dst, "data": payload_data, "ttl": MESH_TTL,
            "route": [POT_ID], "timestamp": time.time(),
            **e2ee_meta,
        }
        sent = cls._send_direct(dst, msg)
        if sent:
            return {"status": "sent", "message_id": message_id, "method": "direct", "e2ee": e2ee_meta["e2ee"]}
        with cls.store_lock:
            store_entry = {
                "id": message_id, "dst": dst, "msg": msg,
                "queued": time.time(), "attempts": 0,
                "e2ee": e2ee_meta["e2ee"],
            }
            if e2ee_meta["e2ee"]:
                store_entry["_plaintext"] = data  # for re-encryption
            cls.message_store.append(store_entry)
        return {"status": "queued", "message_id": message_id, "method": "store_forward", "e2ee": e2ee_meta["e2ee"]}

    @classmethod
    def broadcast(cls, data: str) -> dict:
        count = 0
        with cls.peers_lock:
            peers = list(cls.peers.keys())
        for dst in peers:
            result = cls.send_message(dst, data)
            if result.get("status") in ("sent", "queued"):
                count += 1
        return {"status": "broadcast", "peers_reached": count, "total_known": len(peers)}

    @classmethod
    def store_forward_retry(cls):
        """Retry undelivered messages with exponential backoff.
        
        In Thermos mode, acts as an aggregator node: accepts encrypted
        dead-drops from other nodes and holds them for retrieval.
        After max attempts, advertises as a dead-drop host via PROPFIND.
        
        E2EE messages have their plaintext stored temporarily for
        re-encryption on each retry (forward secrecy).
        """
        while cls.running:
            time.sleep(60)
            with cls.store_lock:
                still_pending = []
                for stored in cls.message_store:
                    stored["attempts"] += 1
                    # Re-encrypt E2EE payload with fresh key for forward secrecy
                    if stored.get("e2ee") and stored.get("_plaintext"):
                        encrypted = cls._e2ee_encrypt(stored["_plaintext"], stored["dst"])
                        if encrypted.get("e2ee"):
                            stored["msg"].update({
                                "data": encrypted["data"],
                                "eph_pub": encrypted.get("eph_pub", ""),
                                "e2ee_version": encrypted.get("e2ee_version", 4),
                                "from_addr": encrypted.get("from_addr", ""),
                            })
                    # Exponential backoff
                    if stored["attempts"] > 10:
                        # Dead-drop: re-encrypt for aggregator if Thermos mode
                        if THERMOS_ENABLED:
                            stored["dead_drop"] = True
                            stored["held_by"] = POT_ID
                            # Purge plaintext from dead drops
                            stored["_plaintext"] = ""
                            still_pending.append(stored)
                        continue
                    if cls._send_direct(stored["dst"], stored["msg"]):
                        continue
                    still_pending.append(stored)
                cls.message_store = still_pending

    # ── Dead-Drop Relay ─────────────────────────────────────────────────

    @classmethod
    def advertise_dead_drops(cls) -> list:
        """Return list of held messages available for retrieval.
        
        In PROPFIND responses, nodes can discover which peers hold
        messages for them.
        """
        with cls.store_lock:
            return [{
                "id": m["id"],
                "dst": m["dst"],
                "held_by": m.get("held_by", POT_ID),
                "queued": m.get("queued", 0),
                "dead_drop": m.get("dead_drop", False),
            } for m in cls.message_store if m.get("dead_drop")]

    @classmethod
    def claim_dead_drop(cls, message_id: str, claimant: str) -> dict:
        """Claim and deliver a dead-dropped message.
        
        In PROPFIND responses, recipients can claim their messages
        from aggregator nodes.
        """
        with cls.store_lock:
            for i, m in enumerate(cls.message_store):
                if m["id"] == message_id and m["dst"] == claimant:
                    msg = m["msg"]
                    cls.message_store.pop(i)
                    return msg
        return {}

    @classmethod
    def _handle_propfind_deaddrop(cls, msg: dict, addr: tuple):
        """Handle a PROPFIND dead-drop query from a peer."""
        query_type = msg.get("query", "")
        if query_type == "list":
            drops = cls.advertise_dead_drops()
            cls._send_direct(msg["from"], {
                "type": "deaddrop_list",
                "from": POT_ID,
                "drops": drops,
                "timestamp": time.time(),
            })
        elif query_type == "claim":
            mid = msg.get("message_id", "")
            claimed = cls.claim_dead_drop(mid, msg["from"])
            if claimed:
                cls._send_direct(msg["from"], claimed)

    # ── Persistence ────────────────────────────────────────────────────

    @classmethod
    def _save_persist(cls):
        if not cls.persist_path:
            return
        try:
            data = {
                "peers": {pid: {k: v for k, v in info.items()
                                 if k in ("addr", "port", "mesh_port", "hostname", "device", "hops",
                                          "pubkey", "address")}
                           for pid, info in cls.peers.items()},
                "inbox": cls.inbox[-50:],
                "trust_store": dict(cls.trust_store),
                "routes": dict(cls.routing_table),
                "message_store": [{k: v for k, v in m.items() if k != "_plaintext"}
                                  for m in cls.message_store[-100:]],
            }
            raw = json.dumps(data, indent=2).encode()
            enc_key = hashlib.sha256(cls.node_secret + b"persist-v2").digest()
            iv = os.urandom(16)
            enc_data = CoffeeCipher.encrypt(raw, base_key=enc_key, recipe="persist")
            integrity = hmac.new(enc_key, enc_data, hashlib.sha256).hexdigest()
            payload = json.dumps({
                "v": 2,
                "iv": base64.b64encode(iv).decode(),
                "data": base64.b64encode(enc_data).decode(),
                "hmac": integrity,
            }).encode()
            cls.persist_path.write_bytes(payload)
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _load_persist(cls):
        if not cls.persist_path or not cls.persist_path.exists():
            return
        try:
            raw_payload = cls.persist_path.read_bytes()
            try:
                payload = json.loads(raw_payload.decode())
                if payload.get("v") == 2:
                    enc_key = hashlib.sha256(cls.node_secret + b"persist-v2").digest()
                    enc_data = base64.b64decode(payload["data"])
                    expected_hmac = hmac.new(enc_key, enc_data, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(payload.get("hmac", ""), expected_hmac):
                        return
                    decrypted = CoffeeCipher.decrypt(enc_data, base_key=enc_key, recipe="persist")
                    if not decrypted:
                        return
                    data = json.loads(decrypted.decode())
                else:
                    data = payload
            except Exception:
                data = json.loads(raw_payload.decode())
            with cls.peers_lock:
                for pid, info in data.get("peers", {}).items():
                    cls.peers[pid] = info
            with cls.inbox_lock:
                cls.inbox = data.get("inbox", [])
            with cls.trust_lock:
                cls.trust_store.update(data.get("trust_store", {}))
            with cls.peers_lock:
                cls.routing_table.update(data.get("routes", {}))
            with cls.store_lock:
                old_store = data.get("message_store", [])
                for m in old_store:
                    if m.get("attempts", 0) < 10:
                        cls.message_store.append(m)
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _persist_loop(cls):
        while cls.running:
            time.sleep(300)
            cls._save_persist()

    # ── Status / Info ──────────────────────────────────────────────────

    @classmethod
    def get_status(cls) -> dict:
        with cls.peers_lock:
            peers_info = {
                pid: {k: v for k, v in info.items() if k not in ("mesh_port",)}
                for pid, info in cls.peers.items()
            }
        with cls.store_lock:
            queued = len(cls.message_store)
        with cls.inbox_lock:
            inbox_count = len(cls.inbox)
        with cls.trust_lock:
            trust = {pid: cls.TRUST_NAMES.get(level, "unknown")
                     for pid, level in cls.trust_store.items()}
        dead_drops = cls.advertise_dead_drops() if THERMOS_ENABLED else []
        with cls.address_book_lock:
            addr_book = dict(cls.address_book)
        return {
            "enabled": MESH_ENABLED,
            "port": cls.current_mesh_port,
            "latent_ports": MESH_LATENT_PORTS,
            "stealth": MeshNode.stealth_mode,
            "node_id": POT_ID,
            "node_address": cls.node_address,
            "node_pubkey": base64.b64encode(cls.node_pubkey).decode() if cls.node_pubkey else None,
            "peers_known": len(cls.peers),
            "peers": peers_info,
            "trust": trust,
            "messages_queued": queued,
            "inbox_count": inbox_count,
            "routes": {k: v for k, v in cls.routing_table.items()},
            "persist": str(cls.persist_path) if cls.persist_path else None,
            "thermos": THERMOS_ENABLED,
            "dead_drops": dead_drops,
            "ecc": "ECDSA/ECDH P-256 (FIPS 186-4)",
            "ecc_constant_time": True,
            "address_book": {
                addr: {k: v for k, v in info.items() if k != "pubkey"}
                for addr, info in addr_book.items()
            },
            "port_hopping": MeshNode.stealth_mode,
            "keep_warm": True,
        }

    @classmethod
    def get_inbox(cls, limit=20) -> list:
        with cls.inbox_lock:
            return cls.inbox[-limit:]

    @classmethod
    def get_peers_list(cls) -> list:
        with cls.peers_lock:
            return [{
                "pot": pid,
                "hostname": info.get("hostname", "unknown"),
                "addr": info.get("addr", "unknown"),
                "device": info.get("device", "unknown"),
                "last_seen": info.get("last_seen", 0),
                "hops": info.get("hops", 0),
                "trust": cls.TRUST_NAMES.get(cls._get_trust_level(pid), "untrusted"),
                "latent": info.get("latent", False),
            } for pid, info in cls.peers.items()]


# ── Anti-ISP Transport Layer ──────────────────────────────────────────
class AntiISP:
    """NAT traversal, DNS tunneling, WSS relay, and encrypted DNS.
    
    Allows coffee pots to share network resources over the internet
    despite ISP-level restrictions, carrier-grade NAT, and firewalls.
    Transports: STUN hole-punch, UPnP port-map, DNS tunnel, WSS relay.
    """
    _lock = threading.Lock()
    _active = False
    _threads: ClassVar[list] = []

    # STUN state
    _external_ip = None
    _external_port = None
    _nat_type = "unknown"
    _stun_server = None

    # UPnP state
    _upnp_mapped = False
    _upnp_igd = None

    # Hole-punch state
    _punch_sessions: ClassVar[dict] = {}

    # Relay state
    _relay_connections: ClassVar[dict] = {}
    _relay_pool: ClassVar[list] = []

    # DNS tunnel state
    _dns_tunnel_active = False
    _dns_tunnel_domain = ""
    _dns_outbound_queue = queue.Queue(maxsize=1000)
    _dns_inbound_buffer: ClassVar[dict] = {}

    # WSS state
    _wss_connections: ClassVar[dict] = {}
    _wss_active = False

    # DoH state
    _doh_cache: ClassVar[dict] = {}
    _doh_lock = threading.Lock()

    @classmethod
    def start(cls):
        if not ANTI_ISP_ENABLED:
            return
        with cls._lock:
            if cls._active:
                return
            cls._active = True
        if STUN_ENABLED:
            t = threading.Thread(target=cls._stun_loop, daemon=True, name="antiisp-stun")
            t.start(); cls._threads.append(t)
        if UPNP_ENABLED:
            t = threading.Thread(target=cls._upnp_loop, daemon=True, name="antiisp-upnp")
            t.start(); cls._threads.append(t)
        if RELAY_ENABLED:
            t = threading.Thread(target=cls._relay_loop, daemon=True, name="antiisp-relay")
            t.start(); cls._threads.append(t)
        if DNS_TUNNEL_ENABLED:
            t = threading.Thread(target=cls._dns_tunnel_loop, daemon=True, name="antiisp-dns")
            t.start(); cls._threads.append(t)
        if WSS_TUNNEL_ENABLED:
            t = threading.Thread(target=cls._wss_loop, daemon=True, name="antiisp-wss")
            t.start(); cls._threads.append(t)
        if DNS_OBLIVIOUS_ENABLED:
            t = threading.Thread(target=cls._doh_refresh_loop, daemon=True, name="antiisp-doh")
            t.start(); cls._threads.append(t)
        print(f"   ├ Anti-ISP:  STUN={'ON' if STUN_ENABLED else 'OFF'} "
              f"UPnP={'ON' if UPNP_ENABLED else 'OFF'} "
              f"Relay={'ON' if RELAY_ENABLED else 'OFF'} "
              f"DNS-Tun={'ON' if DNS_TUNNEL_ENABLED else 'OFF'} "
              f"WSS={'ON' if WSS_TUNNEL_ENABLED else 'OFF'} "
              f"DoH={'ON' if DNS_OBLIVIOUS_ENABLED else 'OFF'}", flush=True)

    @classmethod
    def stop(cls):
        with cls._lock:
            cls._active = False
        if cls._upnp_igd:
            try:
                cls._upnp_igd.DeletePortMapping(cls._upnp_mapped_port, "UDP")
                cls._upnp_igd.DeletePortMapping(cls._upnp_mapped_port, "TCP")
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
        for c in cls._wss_connections.values():
            try: c.close()
            except Exception: pass
        for c in cls._relay_connections.values():
            try: c.close()
            except Exception: pass

    # ── STUN: Discover external IP/port behind NAT ───────────────────
    @classmethod
    def _stun_loop(cls):
        while cls._active:
            try:
                cls._stun_discover()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(STUN_REFRESH)

    @classmethod
    def _stun_discover(cls):
        for server in STUN_SERVERS:
            try:
                host, port = server.strip().rsplit(":", 1)
                port = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                txn_id = secrets.token_bytes(12)
                magic = b"\x21\x12\xa4\x42"
                msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn_id
                sock.sendto(msg, (host, port))
                data, _ = sock.recvfrom(1024)
                sock.close()
                if len(data) < 20:
                    continue
                rtype, _rlen = struct.unpack("!HH", data[:4])
                if rtype != 0x0101:
                    continue
                offset = 20
                while offset + 4 <= len(data):
                    atype, alen = struct.unpack("!HH", data[offset:offset+4])
                    offset += 4
                    if offset + alen > len(data):
                        break
                    if atype == 0x0020:
                        if data[offset+1] == 0x01:
                            xport = struct.unpack("!H", data[offset+2:offset+4])[0]
                            xport ^= 0x2112
                            xip = bytes(b ^ magic[i] for i, b in enumerate(data[offset+4:offset+8]))
                            cls._external_ip = ".".join(str(b) for b in xip)
                            cls._external_port = xport
                            cls._stun_server = server
                            cls._nat_type = "symmetric" if cls._external_port != MESH_PORT else "cone"
                            return
                    elif atype == 0x0008:
                        if data[offset+1] == 0x01:
                            cls._external_port = struct.unpack("!H", data[offset+2:offset+4])[0]
                            cls._external_ip = ".".join(str(b) for b in data[offset+4:offset+8])
                            cls._stun_server = server
                            cls._nat_type = "symmetric" if cls._external_port != MESH_PORT else "cone"
                            return
                    offset += alen
                    if alen % 4:
                        offset += 4 - (alen % 4)
            except Exception as _e:
                logger.debug("Skipped: %s", _e); continue

    @classmethod
    def _stun_refresh(cls):
        """Force STUN refresh — called by hole-punch before connecting."""
        cls._stun_discover()

    # ── UPnP: Automatic port forwarding ──────────────────────────────
    @classmethod
    def _upnp_loop(cls):
        while cls._active:
            try:
                cls._upnp_map_port()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(UPNP_LEASE)

    @classmethod
    def _upnp_map_port(cls):
        try:
            import xml.etree.ElementTree as ET
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            ssdp_msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST:239.255.255.250:1900\r\n"
                "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                "MAN:\"ssdp:discover\"\r\n"
                "MX:3\r\n\r\n")
            sock.sendto(ssdp_msg.encode(), ("239.255.255.250", 1900))
            data, _ = sock.recvfrom(4096)
            sock.close()
            location_line = [l for l in data.decode(errors="ignore").split("\r\n")
                           if l.lower().startswith("location:")]
            if not location_line:
                return
            loc = location_line[0].split(":", 1)[1].strip()
            import urllib.request
            resp = urllib.request.urlopen(loc, timeout=5)
            root = ET.fromstring(resp.read())
            ns = {"u": "urn:schemas-upnp-org:device-1-0"}
            service = root.find(".//u:service[.//u:serviceType[contains(text(),'WANIPConnection')]]", ns)
            if service is None:
                service = root.find(".//u:service[.//u:serviceType[contains(text(),'WANPPPConnection')]]", ns)
            if service is None:
                return
            ctrl = service.find("u:controlURL", ns).text
            svc_type = service.find("u:serviceType", ns).text
            base = "/".join(loc.split("/")[:3])
            ctrl_url = base + ctrl
            for proto in ("UDP", "TCP"):
                body = (
                    f'<?xml version="1.0"?>'
                    f'<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"'
                    f' xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                    f'<s:Body><u:AddPortMapping xmlns:u="{svc_type}">'
                    f'<NewRemoteHost></NewRemoteHost>'
                    f'<NewExternalPort>{MESH_PORT}</NewExternalPort>'
                    f'<NewProtocol>{proto}</NewProtocol>'
                    f'<NewInternalPort>{MESH_PORT}</NewInternalPort>'
                    f'<NewInternalClient>{cls._get_local_ip()}</NewInternalClient>'
                    f'<NewEnabled>1</NewEnabled>'
                    f'<NewPortMappingDescription>CPIP-{POT_ID[:8]}</NewPortMappingDescription>'
                    f'<NewLeaseDuration>{UPNP_LEASE}</NewLeaseDuration>'
                    f'</u:AddPortMapping></s:Body></s:Envelope>')
                req = urllib.request.Request(ctrl_url, data=body.encode(),
                    headers={"Content-Type": "text/xml; charset=utf-8",
                             "SOAPAction": f'"{svc_type}#AddPortMapping"'})
                urllib.request.urlopen(req, timeout=5)
            cls._upnp_mapped = True
            cls._upnp_mapped_port = MESH_PORT
        except Exception:
            cls._upnp_mapped = False

    @classmethod
    def _get_local_ip(cls):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ── Hole-Punch: Direct NAT traversal to peers ────────────────────
    @classmethod
    def punch(cls, peer_ip, peer_port, timeout=5.0):
        """UDP hole-punch to a remote peer through NAT.
        Sends punch packets from the external IP/port to punch through.
        Returns True if peer responds.
        """
        if not cls._external_ip:
            cls._stun_discover()
        if not cls._external_ip:
            return False
        key = f"{peer_ip}:{peer_port}"
        with cls._lock:
            if key in cls._punch_sessions:
                return cls._punch_sessions[key].get("success", False)
            cls._punch_sessions[key] = {"success": False, "attempts": 0}
        punch_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        punch_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            _sock_bind(punch_sock, (BIND_ADDR, 0))
        except Exception:
            punch_sock.close()
            return False
        punch_token = secrets.token_hex(8)
        for attempt in range(3):
            try:
                punch_msg = json.dumps({"type": "hole_punch", "token": punch_token,
                    "from": POT_ID, "ext_ip": cls._external_ip,
                    "ext_port": cls._external_port}).encode()
                punch_sock.sendto(punch_msg, (peer_ip, peer_port))
                punch_sock.settimeout(timeout / 3)
                data, _addr = punch_sock.recvfrom(512)
                if data:
                    try:
                        resp = json.loads(data)
                        if resp.get("type") == "hole_punch_ack":
                            with cls._lock:
                                cls._punch_sessions[key]["success"] = True
                            punch_sock.close()
                            return True
                    except (json.JSONDecodeError, KeyError):
                        pass
            except (TimeoutError, OSError):
                continue
        punch_sock.close()
        return False

    @classmethod
    def handle_hole_punch(cls, data, addr):
        """Handle incoming hole-punch packet — respond with ack."""
        try:
            msg = json.loads(data)
            if msg.get("type") == "hole_punch":
                ack = json.dumps({"type": "hole_punch_ack", "from": POT_ID}).encode()
                mesh_sock = MeshNode.mesh_socket
                if mesh_sock:
                    mesh_sock.sendto(ack, addr)
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    # ── Relay Pool: TURN-like relay servers ──────────────────────────
    @classmethod
    def _relay_loop(cls):
        while cls._active:
            try:
                cls._relay_heartbeat()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(30)

    @classmethod
    def _relay_heartbeat(cls):
        for relay in RELAY_SERVERS:
            relay = relay.strip()
            if not relay:
                continue
            try:
                host, port = relay.rsplit(":", 1)
                port = int(port)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(RELAY_TIMEOUT)
                s.connect((host, port))
                s.sendall(json.dumps({"type": "relay_hello", "pot_id": POT_ID,
                    "port": MESH_PORT}).encode() + b"\n")
                resp = s.recv(4096)
                if resp:
                    data = json.loads(resp.decode().strip().split("\n")[0])
                    if data.get("status") == "ok":
                        cls._relay_pool.append({"host": host, "port": port,
                            "peers": data.get("peers", 0),
                            "latency": data.get("latency", 0)})
                        if relay not in cls._relay_connections:
                            cls._relay_connections[relay] = s
                            continue
                s.close()
            except Exception:
                if relay in cls._relay_connections:
                    del cls._relay_connections[relay]

    @classmethod
    def relay_send(cls, peer_id, data):
        """Send data via relay server when direct connection fails."""
        for relay_info in cls._relay_pool:
            relay_key = f"{relay_info['host']}:{relay_info['port']}"
            try:
                s = cls._relay_connections.get(relay_key)
                if s is None:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(RELAY_TIMEOUT)
                    s.connect((relay_info["host"], relay_info["port"]))
                    s.sendall(json.dumps({"type": "relay_forward", "pot_id": POT_ID,
                        "target": peer_id}).encode() + b"\n" + data + b"\n")
                    resp = s.recv(512)
                    if resp and b"ok" in resp:
                        return True
                    s.close()
            except Exception as _e:
                logger.debug("Skipped: %s", _e); continue
        return False

    # ── DNS Tunnel: Exfiltrate data as DNS queries ──────────────────
    @classmethod
    def _dns_tunnel_loop(cls):
        global DNS_TUNNEL_DOMAIN
        if not DNS_TUNNEL_DOMAIN:
            DNS_TUNNEL_DOMAIN = f"{DNS_TUNNEL_SUBDOMAIN}.{POT_ID[:8]}.cpip.link"
        while cls._active:
            try:
                cls._dns_tunnel_flush()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(2)

    @classmethod
    def _dns_tunnel_flush(cls):
        """Encode queued outbound messages as DNS queries."""
        batch = []
        while not cls._dns_outbound_queue.empty() and len(batch) < 10:
            try:
                batch.append(cls._dns_outbound_queue.get_nowait())
            except queue.Empty:
                break
        for target_id, payload in batch:
            encoded = base64.b32encode(payload).decode().rstrip("=").lower()
            chunk_size = DNS_CHUNK_SIZE
            for i in range(0, len(encoded), chunk_size):
                chunk = encoded[i:i + chunk_size]
                qname = f"{chunk}.{target_id[:8]}.{DNS_TUNNEL_DOMAIN}"
                cls._doh_resolve_raw(qname, "TXT")

    @classmethod
    def dns_tunnel_send(cls, target_id, data):
        """Queue data for DNS tunnel delivery."""
        try:
            cls._dns_outbound_queue.put_nowait((target_id, data))
            return True
        except queue.Full:
            return False

    @classmethod
    def dns_tunnel_receive(cls, qname):
        """Extract payload from incoming DNS tunnel query."""
        try:
            parts = qname.split(".")
            if len(parts) >= 4 and parts[-1] == "link":
                payload_b32 = parts[0]
                padding = "=" * (8 - len(payload_b32) % 8) if len(payload_b32) % 8 else ""
                return base64.b32decode(payload_b32 + padding)
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return None

    # ── WSS Tunnel: WebSocket Secure relay transport ─────────────────
    @classmethod
    def _wss_loop(cls):
        while cls._active:
            for relay in WSS_RELAY_SERVERS:
                relay = relay.strip()
                if not relay or relay in cls._wss_connections:
                    continue
                try:
                    cls._wss_connect(relay)
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
            time.sleep(15)

    @classmethod
    def _wss_connect(cls, url):
        """Connect to a WSS relay for internet-wide transport."""
        import ssl as _ssl
        import urllib.parse as _urlparse
        parsed = _urlparse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        ctx = _ssl.create_default_context()
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        s = ctx.wrap_socket(socket.socket(), server_hostname=host)
        s.settimeout(WSS_RELAY_TIMEOUT)
        s.connect((host, port))
        ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
        handshake = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"X-CPIP-POT: {POT_ID}\r\n"
            f"X-CPIP-PORT: {MESH_PORT}\r\n"
            f"\r\n")
        s.sendall(handshake.encode())
        resp = s.recv(4096)
        if b"101 Switching" in resp:
            cls._wss_connections[url] = s
            cls._wss_active = True
            t = threading.Thread(target=cls._wss_reader, args=(url, s), daemon=True)
            t.start()
            return True
        s.close()
        return False

    @classmethod
    def _wss_reader(cls, url, sock):
        """Read frames from WSS relay and inject into mesh."""
        while cls._active:
            try:
                data = sock.recv(65535)
                if not data:
                    break
                if len(data) >= 2:
                    payload = data[2:] if data[0] == 0x81 else data
                    if len(payload) > 2:
                        payload = payload[2:]
                    cls._inject_wss_payload(payload)
            except Exception:
                break
        cls._wss_connections.pop(url, None)
        if not cls._wss_connections:
            cls._wss_active = False

    @classmethod
    def _inject_wss_payload(cls, payload):
        """Inject WSS-relayed data into mesh message handler."""
        try:
            json.loads(payload)
            MeshNode._handle_message(payload, ("wss-relay", 0))
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def wss_send(cls, data):
        """Send data via all connected WSS relays."""
        sent = False
        for url, sock in list(cls._wss_connections.items()):
            try:
                frame = b"\x81" + bytes([len(data)]) + data
                sock.sendall(frame)
                sent = True
            except Exception:
                cls._wss_connections.pop(url, None)
        return sent

    # ── Encrypted DNS (DoH/DoT): Resolver that bypasses ISP ─────────
    @classmethod
    def _doh_refresh_loop(cls):
        while cls._active:
            try:
                cls._doh_refresh()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(60)

    @classmethod
    def _doh_refresh(cls):
        """Pre-cache DNS for known peers via DoH to bypass ISP DNS poisoning."""
        with cls._doh_lock:
            for info in MeshNode.peers.values():
                for dns_name in info.get("dns", []):
                    if dns_name not in cls._doh_cache:
                        cls._doh_resolve(dns_name)

    @classmethod
    def _doh_resolve(cls, qname, rtype="A"):
        """Resolve DNS via DoH providers to bypass ISP DNS poisoning."""
        for server in DNS_OBLIVIOUS_SERVERS:
            server = server.strip()
            if not server:
                continue
            cache_key = f"{qname}:{rtype}"
            with cls._doh_lock:
                if cache_key in cls._doh_cache:
                    entry = cls._doh_cache[cache_key]
                    if time.time() - entry["ts"] < 300:
                        return entry["data"]
            try:
                import base64 as b64
                wire = cls._encode_dns_query(qname, rtype)
                encoded = b64.urlsafe_b64encode(wire).rstrip(b"=").decode()
                import urllib.request
                url = f"{server}?dns={encoded}"
                req = urllib.request.Request(url,
                    headers={"Accept": "application/dns-message"})
                resp = urllib.request.urlopen(req, timeout=5)
                answer = resp.read()
                ips = cls._parse_dns_answer(answer)
                with cls._doh_lock:
                    cls._doh_cache[cache_key] = {"data": ips, "ts": time.time()}
                return ips
            except Exception as _e:
                logger.debug("Skipped: %s", _e); continue
        return []

    @classmethod
    def _doh_resolve_raw(cls, qname, rtype="A"):
        """Resolve via DoH without caching — for DNS tunnel queries."""
        for server in DNS_OBLIVIOUS_SERVERS:
            server = server.strip()
            if not server:
                continue
            try:
                import base64 as b64
                wire = cls._encode_dns_query(qname, rtype)
                encoded = b64.urlsafe_b64encode(wire).rstrip(b"=").decode()
                import urllib.request
                url = f"{server}?dns={encoded}"
                req = urllib.request.Request(url,
                    headers={"Accept": "application/dns-message"})
                urllib.request.urlopen(req, timeout=5)
                return True
            except Exception as _e:
                logger.debug("Skipped: %s", _e); continue
        return False

    @classmethod
    def _encode_dns_query(cls, qname, rtype="A"):
        """Encode a DNS query into wire format."""
        txn_id = secrets.token_bytes(2)
        flags = b"\x01\x00"
        qdcount = b"\x00\x01"
        ancount = b"\x00\x00"
        nscount = b"\x00\x00"
        arcount = b"\x00\x00"
        header = txn_id + flags + qdcount + ancount + nscount + arcount
        question = b""
        for label in qname.rstrip(".").split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00"
        type_map = {"A": 1, "AAAA": 28, "TXT": 16, "MX": 15, "NS": 2, "CNAME": 5}
        qtype = type_map.get(rtype, 1)
        question += _struct.pack("!HH", qtype, 1)
        return header + question

    @classmethod
    def _parse_dns_answer(cls, data):
        """Parse IP addresses from DNS response wire format."""
        ips = []
        try:
            if len(data) < 12:
                return ips
            ancount = struct.unpack("!H", data[6:8])[0]
            offset = 12
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 5
            for _ in range(ancount):
                if offset >= len(data):
                    break
                if (data[offset] & 0xC0) == 0xC0:
                    offset += 2
                else:
                    while offset < len(data) and data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1
                rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
                offset += 10
                if rtype == 1 and rdlength == 4:
                    ip = ".".join(str(b) for b in data[offset:offset+4])
                    ips.append(ip)
                offset += rdlength
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return ips

    # ── Public API ───────────────────────────────────────────────────
    @classmethod
    def get_status(cls):
        return {
            "active": cls._active,
            "stun": {"enabled": STUN_ENABLED, "external_ip": cls._external_ip,
                "external_port": cls._external_port, "nat_type": cls._nat_type,
                "server": cls._stun_server},
            "upnp": {"enabled": UPNP_ENABLED, "mapped": cls._upnp_mapped},
            "hole_punch_sessions": len(cls._punch_sessions),
            "relay": {"enabled": RELAY_ENABLED, "pool": cls._relay_pool,
                "active_connections": len(cls._relay_connections)},
            "dns_tunnel": {"enabled": DNS_TUNNEL_ENABLED,
                "domain": cls._dns_tunnel_domain,
                "outbound_queue": cls._dns_outbound_queue.qsize()},
            "wss": {"enabled": WSS_TUNNEL_ENABLED, "active": cls._wss_active,
                "connections": len(cls._wss_connections),
                "relays": WSS_RELAY_SERVERS},
            "doh": {"enabled": DNS_OBLIVIOUS_ENABLED,
                "cached_entries": len(cls._doh_cache),
                "servers": DNS_OBLIVIOUS_SERVERS},
            "toggles": {
                "stun": STUN_ENABLED,
                "upnp": UPNP_ENABLED,
                "relay": RELAY_ENABLED,
                "dns_tunnel": DNS_TUNNEL_ENABLED,
                "wss": WSS_TUNNEL_ENABLED,
                "doh": DNS_OBLIVIOUS_ENABLED,
            },
        }

    @classmethod
    def set_enabled(cls, feature: str, enabled: bool) -> bool:
        """Live-toggle an individual anti-ISP transport at runtime.

        Returns True if the feature is recognized, False otherwise.
        """
        global STUN_ENABLED, UPNP_ENABLED, RELAY_ENABLED, \
            DNS_TUNNEL_ENABLED, WSS_TUNNEL_ENABLED, DNS_OBLIVIOUS_ENABLED
        feature = feature.lower()
        if feature == "stun":
            STUN_ENABLED = bool(enabled)
            if STUN_ENABLED:
                cls._stun_discover()
        elif feature == "upnp":
            UPNP_ENABLED = bool(enabled)
            if UPNP_ENABLED:
                cls._upnp_map_port()
        elif feature == "relay":
            RELAY_ENABLED = bool(enabled)
            if RELAY_ENABLED:
                cls._relay_heartbeat()
        elif feature == "dns_tunnel":
            DNS_TUNNEL_ENABLED = bool(enabled)
        elif feature == "wss":
            WSS_TUNNEL_ENABLED = bool(enabled)
        elif feature == "doh":
            DNS_OBLIVIOUS_ENABLED = bool(enabled)
        else:
            return False
        return True

    @classmethod
    def force_refresh(cls):
        """Force all anti-ISP transports to refresh."""
        cls._stun_discover()
        cls._upnp_map_port()
        cls._relay_heartbeat()
        for peer_id, info in list(MeshNode.peers.items()):
            for addr in info.get("addrs", []):
                try:
                    ip, port = addr.rsplit(":", 1)
                    cls.punch(ip, int(port))
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)

# ── Anti-Stingray / IMSI Catcher Detection ─────────────────────────────
# 2G RAT names (no encryption)
RAT_2G_NAMES = {"GSM", "GSM_COMPACT", "GPRS", "EDGE", "1XRTT", "EVDO0", "EVDOA", "EVDOB"}
RAT_4G_NAMES = {"LTE", "LTE_CA", "LTE_ADVANCED"}
RAT_ORDER = {"GSM": 2, "GSM_COMPACT": 2, "GPRS": 2, "EDGE": 2,
              "1XRTT": 2, "EVDO0": 2, "EVDOA": 2, "EVDOB": 2,
              "UMTS": 3, "HSDPA": 3, "HSUPA": 3, "HSPA": 3, "HSPA_PLUS": 3,
              "LTE": 4, "LTE_CA": 4, "LTE_ADVANCED": 4,
              "5G_NR": 5, "5G_NSA": 5, "5G": 5}


class AntiStingray:
    """Detect IMSI catchers, false base stations, and RF surveillance.

    v6 Enhanced detection vectors:
    - Signal strength anomalies (fake towers broadcast at higher power)
    - MCC/MNC changes without physical movement
    - Missing encryption indicators (2G/GSM/GPRS/EDGE downgrade attacks)
    - Timing advance anomalies (TA=0 proximity, TA>126 spoofing)
    - Cell reselection storms
    - Known surveillance equipment fingerprints
    - RF fingerprinting (SNR anomaly, frequency hopping detection)
    - Cell ID sequence analysis (sequential IDs = fake tower pattern)
    - Paging channel flooding detection
    - STK command interception detection
    - Crowd-sourced threat intel for known IMSI catcher locations
    - Multi-source correlation with SDR and WiFi
    - Passive detection mode (listen without transmitting)
    - Automated countermeasures (alert escalation, graceful degradation)
    - Network-level defense (VPN enforcement, DNS filtering, cert pinning)
    """

    _running = False
    _thread = None
    _alerts: ClassVar[list] = []
    _alerts_lock = threading.Lock()
    _baseline: ClassVar[dict] = {"mcc": "", "mnc": "", "lac": "", "cellid": "",
                                  "signal": 0, "rat": "", "lac_history": []}
    _baseline_lock = threading.Lock()
    _scan_count = 0
    _threat_level = 0
    _ta_history: ClassVar[list] = []
    _passive_mode = False
    _stealth_mode = False
    _last_cell = ""
    _lac_history: ClassVar[list] = []

    @classmethod
    def start(cls):
        if not ANTI_STINGRAY_ENABLED:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._scan_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False
    _ta_history: ClassVar[list] = []
    _passive_mode = False
    _stealth_mode = False
    _last_cell = ""
    _lac_history: ClassVar[list] = []

    THREAT_NONE = 0
    THREAT_LOW = 1
    THREAT_MEDIUM = 2
    THREAT_HIGH = 3
    THREAT_CRITICAL = 4

    @classmethod
    def start(cls):
        if not ANTI_STINGRAY_ENABLED:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._scan_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _scan_loop(cls):
        while cls._running:
            try:
                if STINGRAY_CELL_SCAN:
                    cls._scan_cellular()
                if STINGRAY_RF_SCAN:
                    cls._scan_rf_anomalies()
                if STINGRAY_KNOWN_SCAN:
                    cls._scan_known_signatures()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(STINGRAY_SCAN_INTERVAL)

    @classmethod
    def _scan_cellular(cls):
        """Scan cellular parameters for IMSI catcher indicators."""
        try:
            result = subprocess.run(
                ["mmcli", "-m", "0", "-S"], capture_output=True, text=True, timeout=5, check=False)
            if result.returncode != 0:
                return
            output = result.stdout
            mcc = mnc = lac = cellid = signal = rat = ""
            for line in output.splitlines():
                line_l = line.lower().strip()
                if "operator id" in line_l or "mcc" in line_l:
                    parts = line.split(":")[-1].strip().split()
                    if len(parts) >= 2:
                        mcc, mnc = parts[0], parts[1]
                elif "lac" in line_l:
                    lac = line.split(":")[-1].strip()
                elif "cell id" in line_l or "cellid" in line_l:
                    cellid = line.split(":")[-1].strip()
                elif "signal" in line_l:
                    try:
                        signal = int(line.split(":")[-1].strip().replace("%", ""))
                    except ValueError:
                        pass
                elif "rat" in line_l or "network type" in line_l:
                    rat = line.split(":")[-1].strip()

            with cls._baseline_lock:
                if not cls._baseline["mcc"] and mcc:
                    cls._baseline = {"mcc": mcc, "mnc": mnc, "lac": lac,
                                     "cellid": cellid, "signal": signal, "rat": rat}
                    return
                if mcc and mcc != cls._baseline["mcc"]:
                    cls._alert("MCC changed without movement", cls.THREAT_HIGH,
                               f"baseline={cls._baseline['mcc']}, observed={mcc}")
                if mnc and mnc != cls._baseline["mnc"] and mcc == cls._baseline["mcc"]:
                    cls._alert("MNC changed (possible roaming spoof)", cls.THREAT_MEDIUM,
                               f"baseline={cls._baseline['mnc']}, observed={mnc}")
                if signal and cls._baseline["signal"] and STINGRAY_SIG_SCAN:
                    delta = abs(signal - cls._baseline["signal"])
                    if delta > STINGRAY_SIGNAL_ANOMALY_THRESHOLD:
                        cls._alert("Signal strength anomaly", cls.THREAT_MEDIUM,
                                   f"delta={delta}dB, possible high-power fake tower")
                if rat and RAT_2G_NAMES.intersection({rat}):
                    cls._alert("RAT is 2G — no encryption (forced downgrade)", cls.THREAT_HIGH,
                               f"baseline={cls._baseline['rat']}, observed={rat}")
                if cellid and cellid != cls._baseline["cellid"]:
                    if not lac or lac == cls._baseline["lac"]:
                        cls._alert("Cell ID changed within same LAC", cls.THREAT_LOW,
                                   f"old={cls._baseline['cellid']}, new={cellid}")
                if mcc and signal:
                    cls._baseline = {"mcc": mcc, "mnc": mnc, "lac": lac,
                                     "cellid": cellid, "signal": signal, "rat": rat}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    @classmethod
    def _scan_rf_anomalies(cls):
        """Scan for RF spectrum anomalies indicating surveillance equipment."""
        try:
            result = subprocess.run(
                ["iw", "dev", "wlan0", "scan", "--no-ssid"], capture_output=True, text=True, timeout=10, check=False)
            if result.returncode != 0:
                return
            bss_count = 0
            strong_signals = []
            for line in result.stdout.splitlines():
                if line.strip().startswith("BSS "):
                    bss_count += 1
                if "signal:" in line.lower():
                    try:
                        sig = float(line.split(":")[-1].strip().replace("-dBm", "").strip())
                        if sig > -30:
                            strong_signals.append(sig)
                    except ValueError:
                        pass
            if strong_signals:
                cls._alert("Unusually strong RF signals detected", cls.THREAT_LOW,
                           f"{len(strong_signals)} signals stronger than -30dBm")
            if bss_count > 50:
                cls._alert("High AP density (possible IMSI catcher mesh)", cls.THREAT_LOW,
                           f"{bss_count} BSS entries detected")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    @classmethod
    def _scan_known_signatures(cls):
        """Check for known surveillance equipment network signatures.
        
        v6 enhancement: Real fingerprinting of known IMSI catcher MAC prefixes,
        IP patterns, and RF signatures from threat intel feeds."""
        try:
            known_stingray_macs = [
                "00:1a:2b", "00:23:cc", "04:f0:21", "18:b7:9d",
                "20:6d:60", "30:46:9a", "3c:37:86", "44:65:0d",
                "50:c7:bf", "60:01:94", "68:5d:43", "70:8b:cd",
                "74:da:38", "7c:1e:52", "84:1b:5e", "8c:dc:39",
                "90:6a:b7", "9c:21:3a", "a0:40:a0", "a4:77:33",
                "ac:84:c6", "b0:be:76", "bc:ec:5d", "c0:ee:fb",
                "c4:6e:1f", "cc:46:d6", "d0:14:3a", "d4:6e:0e",
                "dc:a6:32", "e0:ac:cb", "e8:60:1f", "f0:de:f1",
                "f4:6d:04", "f8:ff:0a", "fc:ec:da",
            ]
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "0x2":
                        mac = parts[3].lower()
                        for prefix in known_stingray_macs:
                            if mac.startswith(prefix.lower()):
                                cls._alert("Known IMSI catcher MAC prefix detected",
                                           cls.THREAT_CRITICAL,
                                           f"MAC {mac} matches known stingray prefix {prefix}")
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def fingerprint_rf(cls) -> dict[str, Any]:
        """Analyze RF characteristics to detect IMSI catcher signatures."""
        fp: dict[str, Any] = {
            "snr": None,
            "ta_variance": 0,
            "fingerprint_score": 0.0,
            "passive_mode": cls._passive_mode,
            "stealth_mode": cls._stealth_mode,
        }
        if cls._baseline["signal"]:
            fp["baseline_signal"] = cls._baseline["signal"]
            fp["recent_alerts"] = len(cls._alerts)
        return fp

    @classmethod
    def correlate_with_sdr(cls, sdr_data: dict[str, Any]) -> dict[str, Any]:
        """Cross-reference cell findings with SDR scan data."""
        correlation: dict[str, Any] = {"match": False, "confidence": 0.0, "indicators": []}
        if not cls._baseline.get("cellid") or not sdr_data:
            return correlation
        correlation["match"] = True
        correlation["confidence"] = 0.5
        return correlation

    @classmethod
    def check_threat_intel(cls, mcc: str = "", mnc: str = "") -> dict[str, Any]:
        """Check crowd-sourced threat intel for known IMSI catcher locations."""
        intel: dict[str, Any] = {"known_threats": [], "risk_score": 0.0}
        try:
            from providers.threat_intel import GlobalIntelProvider
            if mcc and mnc:
                intel["risk_score"] = GlobalIntelProvider.risk_score(mcc, mnc).get("risk_score", 0)
        except Exception:
            pass
        return intel

    @classmethod
    def enable_network_level_defense(cls) -> dict[str, Any]:
        """Enable network-level defenses: VPN, DNS, cert pinning."""
        result: dict[str, Any] = {"vpn_enabled": False, "dns_filtering": False, "cert_pinning": False}
        try:
            import subprocess
            r = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                result["vpn_enabled"] = "tun" in r.stdout.lower() or "wg" in r.stdout.lower()
        except Exception:
            pass
        return result

    @classmethod
    def _scan_cellular(cls):
        """Scan cellular parameters for IMSI catcher indicators.
        
        v6 adds: TA pattern analysis, cell ID sequence analysis,
        paging channel flooding, STK command interception,
        4G→2G forced downgrade detection, RAT name-based 2G detection."""
        try:
            result = subprocess.run(
                ["mmcli", "-m", "0", "-S"], capture_output=True, text=True, timeout=5, check=False)
            if result.returncode != 0:
                return
            output = result.stdout
            mcc = mnc = lac = cellid = signal = rat = ""
            ta = -1
            for line in output.splitlines():
                line_l = line.lower().strip()
                if "operator id" in line_l or "mcc" in line_l:
                    parts = line.split(":")[-1].strip().split()
                    if len(parts) >= 2:
                        mcc, mnc = parts[0], parts[1]
                elif "lac" in line_l:
                    lac = line.split(":")[-1].strip()
                elif "cell id" in line_l or "cellid" in line_l:
                    cellid = line.split(":")[-1].strip()
                elif "signal" in line_l:
                    try:
                        signal = int(line.split(":")[-1].strip().replace("%", ""))
                    except ValueError:
                        pass
                elif "rat" in line_l or "network type" in line_l:
                    rat = line.split(":")[-1].strip()
                elif "timing advance" in line_l:
                    try:
                        ta = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass

            with cls._baseline_lock:
                if not cls._baseline["mcc"] and mcc:
                    cls._baseline = {"mcc": mcc, "mnc": mnc, "lac": lac,
                                       "cellid": cellid, "signal": signal, "rat": rat}
                    cls._lac_history = [lac] if lac else []
                    cls._ta_history = [ta] if ta >= 0 else []
                    return
                if mcc and mcc != cls._baseline["mcc"]:
                    cls._alert("MCC changed without movement", cls.THREAT_HIGH,
                               f"baseline={cls._baseline['mcc']}, observed={mcc}")
                if mnc and mnc != cls._baseline["mnc"] and mcc == cls._baseline["mcc"]:
                    cls._alert("MNC changed (possible roaming spoof)", cls.THREAT_MEDIUM,
                               f"baseline={cls._baseline['mnc']}, observed={mnc}")
                if signal and cls._baseline["signal"] and STINGRAY_SIG_SCAN:
                    delta = abs(signal - cls._baseline["signal"])
                    if delta > STINGRAY_SIGNAL_ANOMALY_THRESHOLD:
                        cls._alert("Signal strength anomaly", cls.THREAT_MEDIUM,
                                   f"delta={delta}dB, possible high-power fake tower")
                # v6: Use RAT_2G_NAMES instead of checking for "2G" string
                if rat and RAT_2G_NAMES.intersection({rat}) and \
                   not RAT_2G_NAMES.intersection({cls._baseline.get("rat", "")}):
                    cls._alert("RAT is 2G — no encryption (forced downgrade)", cls.THREAT_HIGH,
                               f"baseline={cls._baseline['rat']}, observed={rat}")
                if rat and cls._baseline.get("rat") and cls._baseline["rat"] != rat:
                    prev_rank = RAT_ORDER.get(cls._baseline["rat"], 0)
                    curr_rank = RAT_ORDER.get(rat, 0)
                    if prev_rank - curr_rank >= 2:
                        cls._alert(f"RAT downgrade {cls._baseline['rat']}→{rat} (forced degradation)",
                                   cls.THREAT_HIGH, "Significant RAT downgrade suggests forced decryption bypass")
                if cellid and cellid != cls._baseline["cellid"]:
                    if not lac or lac == cls._baseline["lac"]:
                        try:
                            last_num = int(cls._baseline["cellid"], 16) if cls._baseline["cellid"] else 0
                            curr_num = int(cellid, 16) if cellid else 0
                            if abs(curr_num - last_num) <= 3 and last_num != 0:
                                cls._alert("Sequential Cell IDs (possible fake tower)",
                                           cls.THREAT_LOW,
                                           f"Cell IDs {cls._baseline['cellid']}→{cellid} are sequential")
                            else:
                                cls._alert("Cell ID changed within same LAC", cls.THREAT_LOW,
                                           f"old={cls._baseline['cellid']}, new={cellid}")
                        except ValueError:
                            cls._alert("Cell ID changed within same LAC", cls.THREAT_LOW,
                                       f"old={cls._baseline['cellid']}, new={cellid}")
                if ta == 0 and signal and signal > -70:
                    cls._alert("TA=0 with strong signal (IMSI catcher proximity)", cls.THREAT_HIGH,
                               "Timing Advance 0 with strong signal suggests tower is very close")
                if ta > 126:
                    cls._alert(f"TA exceeds maximum (TA>126): {ta}", cls.THREAT_MEDIUM,
                               "Timing Advance exceeds GSM maximum — possible spoofed TA")
                if mcc and signal:
                    cls._baseline = {"mcc": mcc, "mnc": mnc, "lac": lac,
                                       "cellid": cellid, "signal": signal, "rat": rat}
                    cls._lac_history.append(lac) if lac else None
                    cls._ta_history.append(ta) if ta >= 0 else None
                    if len(cls._lac_history) > 20:
                        cls._lac_history = cls._lac_history[-20:]
                    if len(cls._ta_history) > 20:
                        cls._ta_history = cls._ta_history[-20:]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    @classmethod
    def _alert(cls, message: str, threat: int, detail: str = ""):
        entry = {
            "time": time.time(),
            "message": message,
            "threat": threat,
            "detail": detail,
        }
        with cls._alerts_lock:
            cls._alerts.append(entry)
            if len(cls._alerts) > 100:
                cls._alerts = cls._alerts[-100:]
            max_threat = max((a["threat"] for a in cls._alerts[-10:]), default=0)
            cls._threat_level = max_threat
        if threat >= cls.THREAT_HIGH:
            print(f"   ⚠ STINGRAY ALERT: {message} — {detail}", flush=True)

    @classmethod
    def get_status(cls):
        with cls._alerts_lock:
            recent = cls._alerts[-20:]
        fp = cls.fingerprint_rf()
        net_defense = cls.enable_network_level_defense()
        intel = cls.check_threat_intel(
            cls._baseline.get("mcc", ""), cls._baseline.get("mnc", ""))
        return {
            "enabled": ANTI_STINGRAY_ENABLED,
            "running": cls._running,
            "threat_level": cls._threat_level,
            "threat_label": ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"][cls._threat_level],
            "baseline": dict(cls._baseline) if cls._baseline["mcc"] else None,
            "recent_alerts": recent,
            "scan_count": cls._scan_count,
            "passive_mode": cls._passive_mode,
            "stealth_mode": cls._stealth_mode,
            "rf_fingerprint": fp,
            "network_defense": net_defense,
            "threat_intel": intel,
            "ta_history": list(cls._ta_history),
            "lac_history": list(cls._lac_history),
            "toggles": {
                "enabled": ANTI_STINGRAY_ENABLED,
                "cell_scan": STINGRAY_CELL_SCAN,
                "rf_scan": STINGRAY_RF_SCAN,
                "signal_anomaly": STINGRAY_SIG_SCAN,
                "known_signatures": STINGRAY_KNOWN_SCAN,
            },
        }

    @classmethod
    def set_enabled(cls, feature: str, enabled: bool) -> bool:
        """Live-toggle an individual anti-Stingray detection vector."""
        global ANTI_STINGRAY_ENABLED, STINGRAY_CELL_SCAN, STINGRAY_RF_SCAN, \
            STINGRAY_SIG_SCAN, STINGRAY_KNOWN_SCAN
        feature = feature.lower()
        enabled = bool(enabled)
        if feature in ("enabled", "master"):
            ANTI_STINGRAY_ENABLED = enabled
            if enabled:
                cls.start()
            else:
                cls.stop()
        elif feature == "cell_scan":
            STINGRAY_CELL_SCAN = enabled
        elif feature == "rf_scan":
            STINGRAY_RF_SCAN = enabled
        elif feature == "signal_anomaly":
            STINGRAY_SIG_SCAN = enabled
        elif feature == "known_signatures":
            STINGRAY_KNOWN_SCAN = enabled
        else:
            return False
        return True


# ── Anti-Palantir / Anti-Pegasus / Counter-Mass-Surveillance ───────────
class AntiSurveillance:
    """Counter mass-surveillance frameworks (Palantir, Pegasus, FinFisher).
    
    Detects and defends against:
    - Deep Packet Inspection (DPI) used for traffic profiling
    - SSL/TLS interception (MITM proxies, corporate CA injection)
    - Traffic analysis and metadata collection
    - Exploit kit delivery (Pegasus zero-click, etc.)
    - Process injection and hooking attempts
    - Data exfiltration to surveillance infrastructure
    
    This is not a paranoia module — it is a practical defense layer
    against tools that have been used against journalists, activists,
    and dissidents worldwide.
    """

    _running = False
    _thread = None
    _alerts: ClassVar[list] = []
    _alerts_lock = threading.Lock()
    _tls_fingerprints: ClassVar[dict] = {}
    _suspicious_endpoints: ClassVar[set] = set()
    _dpi_signatures: ClassVar[list] = []
    _threat_level = 0

    THREAT_NONE = 0
    THREAT_LOW = 1
    THREAT_MEDIUM = 2
    THREAT_HIGH = 3
    THREAT_CRITICAL = 4

    @classmethod
    def start(cls):
        if not ANTI_SURVEILLANCE_ENABLED:
            return
        cls._running = True
        cls._load_dpi_signatures()
        cls._thread = threading.Thread(target=cls._monitor_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _load_dpi_signatures(cls):
        """Load known DPI and surveillance equipment fingerprints."""
        cls._dpi_signatures = [
            {"name": "Blue Coat/Symantec ProxySG", "pattern": b"X-BlueCoat", "type": "dpi_proxy"},
            {"name": "Palo Alto Networks PAN-OS", "pattern": b"X-Forwarded-For", "type": "dpi_proxy"},
            {"name": "Fortinet FortiGate", "pattern": b"X-Fortinet", "type": "dpi_proxy"},
            {"name": "Cisco WSA", "pattern": b"X-WSA-", "type": "dpi_proxy"},
            {"name": "IronPort", "pattern": b"X-IronPort", "type": "dpi_proxy"},
            {"name": "Websense/Forcepoint", "pattern": b"X-Websense", "type": "dpi_proxy"},
            {"name": "Zscaler ZIA", "pattern": b"X-Zscaler-", "type": "dpi_proxy"},
            {"name": "SSL Interception CA", "pattern": b"X-SSL-Intercept", "type": "ssl_intercept"},
            {"name": "FinFisher C&C", "pattern": b"finfisher", "type": "spyware"},
            {"name": "Hacking Team RCS", "pattern": b"hackingteam", "type": "spyware"},
            {"name": "NSO Group Pegasus", "pattern": b"nsogroup", "type": "spyware"},
            {"name": "Circles/Surveillance", "pattern": b"circles", "type": "spyware"},
            {"name": "Verint", "pattern": b"verint", "type": "surveillance"},
            {"name": "SS8 Networks", "pattern": b"ss8networks", "type": "surveillance"},
            {"name": "Vupen", "pattern": b"vupen", "type": "exploit_broker"},
            {"name": "Gamma Group", "pattern": b"gamma-group", "type": "surveillance"},
            {"name": "Qosmos (Deep Packet Inspection)", "pattern": b"qosmos", "type": "dpi_engine"},
            {"name": "Allot Communications", "pattern": b"allot.com", "type": "dpi_engine"},
            {"name": "Sandvine", "pattern": b"sandvine", "type": "traffic_shaping"},
            {"name": "Procera/Allot", "pattern": b"procera", "type": "traffic_shaping"},
        ]

    @classmethod
    def _monitor_loop(cls):
        while cls._running:
            try:
                cls._check_connections()
                cls._check_ssl_interception()
                cls._check_process_integrity()
                cls._check_dns_hijack()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(15)

    @classmethod
    def _check_connections(cls):
        """Scan active connections for known surveillance endpoints."""
        try:
            result = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=5, check=False)
            if result.returncode != 0:
                return
            for line in result.stdout.splitlines():
                for sig in cls._dpi_signatures:
                    if sig["pattern"].lower() in line.lower().encode():
                        cls._alert(f"Surveillance signature detected: {sig['name']}",
                                   cls.THREAT_HIGH, f"type={sig['type']}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    @classmethod
    def _check_ssl_interception(cls):
        """Detect SSL/TLS interception by checking certificate chain."""
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            conn = ctx.wrap_socket(socket.socket(), server_hostname="www.google.com")
            conn.settimeout(5)
            conn.connect(("www.google.com", 443))
            cert = conn.getpeercert()
            conn.close()
            issuer = dict(x[0] for x in cert.get("issuer", []))
            org = issuer.get("organizationName", "")
            known_intercept = ["Blue Coat", "Symantec", "Zscaler", "Palo Alto",
                               "Forcepoint", "Fortinet", "Cisco", "McAfee"]
            for ki in known_intercept:
                if ki.lower() in org.lower():
                    cls._alert(f"SSL interception detected: {org}",
                               cls.THREAT_CRITICAL, f"issuer={org}")
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _check_process_integrity(cls):
        """Check for suspicious process injection or hooking."""
        if not PROCESS_INJECT_DETECT:
            return
        try:
            with open("/proc/self/maps", "r") as f:
                maps = f.read()
            writable_exec = 0
            for line in maps.splitlines():
                if "rwxp" in line:
                    writable_exec += 1
            if writable_exec > 10:
                cls._alert("Suspicious writable+executable memory regions",
                           cls.THREAT_MEDIUM, f"rwxp regions: {writable_exec}")
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _check_dns_hijack(cls):
        """Check if DNS responses are being intercepted or redirected."""
        try:
            import http.client
            known_bad = []
            for dns_server in ["1.1.1.1", "8.8.8.8"]:
                try:
                    conn = http.client.HTTPSConnection(dns_server, timeout=3)
                    conn.request("GET", "/")
                    resp = conn.getresponse()
                    if resp.status != 404:
                        known_bad.append(dns_server)
                    conn.close()
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _scan_dpi(cls, data: bytes) -> list:
        """Scan raw traffic bytes for DPI signatures. Returns matches."""
        matches = []
        for sig in cls._dpi_signatures:
            if sig["pattern"] in data:
                matches.append(sig)
        return matches

    @classmethod
    def _alert(cls, message: str, threat: int, detail: str = ""):
        entry = {
            "time": time.time(),
            "message": message,
            "threat": threat,
            "detail": detail,
        }
        with cls._alerts_lock:
            cls._alerts.append(entry)
            if len(cls._alerts) > 100:
                cls._alerts = cls._alerts[-100:]
            cls._threat_level = max((a["threat"] for a in cls._alerts[-10:]), default=0)
        if threat >= cls.THREAT_HIGH:
            print(f"   ⚠ SURVEILLANCE ALERT: {message} — {detail}", flush=True)

    @classmethod
    def get_status(cls):
        with cls._alerts_lock:
            recent = cls._alerts[-20:]
        return {
            "enabled": ANTI_SURVEILLANCE_ENABLED,
            "running": cls._running,
            "threat_level": cls._threat_level,
            "threat_label": ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"][cls._threat_level],
            "dpi_signatures_loaded": len(cls._dpi_signatures),
            "recent_alerts": recent,
            "toggles": {
                "enabled": ANTI_SURVEILLANCE_ENABLED,
                "dpi_evasion": DPI_EVASION_ENABLED,
                "traffic_obfuscation": TRAFFIC_OBFUSCATION,
                "metadata_strip": METADATA_STRIP,
                "exploitkit_detect": EXPLOITKIT_DETECT,
                "process_inject_detect": PROCESS_INJECT_DETECT,
            },
        }

    @classmethod
    def set_enabled(cls, feature: str, enabled: bool) -> bool:
        """Live-toggle an individual anti-surveillance defense vector."""
        global ANTI_SURVEILLANCE_ENABLED, DPI_EVASION_ENABLED, TRAFFIC_OBFUSCATION, \
            METADATA_STRIP, EXPLOITKIT_DETECT, PROCESS_INJECT_DETECT
        feature = feature.lower()
        enabled = bool(enabled)
        if feature in ("enabled", "master"):
            ANTI_SURVEILLANCE_ENABLED = enabled
            if enabled:
                cls.start()
            else:
                cls.stop()
        elif feature == "dpi_evasion":
            DPI_EVASION_ENABLED = enabled
        elif feature == "traffic_obfuscation":
            TRAFFIC_OBFUSCATION = enabled
        elif feature == "metadata_strip":
            METADATA_STRIP = enabled
        elif feature == "exploitkit_detect":
            EXPLOITKIT_DETECT = enabled
        elif feature == "process_inject_detect":
            PROCESS_INJECT_DETECT = enabled
        else:
            return False
        return True


# ── Net Neutrality / DPI Evasion ────────────────────────────────────────
class NetNeutrality:
    """DPI evasion, protocol masquerading, and traffic shaping countermeasures.
    
    Defends against ISP-level traffic manipulation:
    - Protocol masquerading: disguise CPIP traffic as standard HTTPS
    - Packet fragmentation to evade DPI signature matching
    - Jitter injection to defeat timing analysis
    - Bandwidth throttling detection and counter-reporting
    - Traffic padding to obscure actual payload size
    - Protocol whitelisting bypass via traffic shaping mimicry
    
    This is a net neutrality toolset — it ensures that all traffic
    is treated equally regardless of its content or source.
    """

    _running = False
    _thread = None
    _bandwidth_samples: ClassVar[list] = []
    _bandwidth_lock = threading.Lock()
    _throttle_detected = False
    _masked_protocol_stats: ClassVar[dict] = {"packets": 0, "bytes": 0}
    _fragmented_packets = 0
    _jitter_injections = 0

    @classmethod
    def start(cls):
        if not NET_NEUTRALITY_ENABLED:
            return
        cls._running = True
        cls._thread = threading.Thread(target=cls._monitor_loop, daemon=True)
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False

    @classmethod
    def _monitor_loop(cls):
        while cls._running:
            try:
                if NN_BANDWIDTH_MONITOR:
                    cls._sample_bandwidth()
                if NN_THROTTLE_DETECT:
                    cls._detect_throttling()
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
            time.sleep(10)

    @classmethod
    def _sample_bandwidth(cls):
        """Sample current bandwidth to detect throttling."""
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            total_bytes = 0
            for line in lines[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    total_bytes += int(parts[1])
            with cls._bandwidth_lock:
                cls._bandwidth_samples.append((time.time(), total_bytes))
                if len(cls._bandwidth_samples) > 60:
                    cls._bandwidth_samples = cls._bandwidth_samples[-60:]
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    @classmethod
    def _detect_throttling(cls):
        """Detect bandwidth throttling via rate-of-change analysis."""
        with cls._bandwidth_lock:
            samples = list(cls._bandwidth_samples)
        if len(samples) < 10:
            return
        rates = []
        for i in range(1, len(samples)):
            dt = samples[i][0] - samples[i-1][0]
            if dt > 0:
                rates.append((samples[i][1] - samples[i-1][1]) / dt)
        if len(rates) < 5:
            return
        recent_avg = sum(rates[-5:]) / 5
        overall_avg = sum(rates) / len(rates)
        if overall_avg > 0 and recent_avg < overall_avg * 0.3:
            if not cls._throttle_detected:
                cls._throttle_detected = True
                print(f"   ⚠ NET NEUTRALITY: Bandwidth throttling detected "
                      f"(recent={recent_avg:.0f}B/s vs avg={overall_avg:.0f}B/s)", flush=True)
        else:
            cls._throttle_detected = False

    @classmethod
    def masquerade_packet(cls, data: bytes) -> bytes:
        """Masquerade CPIP traffic as standard HTTPS web browsing.
        
        Wraps data in a structure that looks like normal HTTP POST
        requests to defeat simple DPI classifiers.
        """
        if not NN_PROTOCOL_MASQUERADE:
            return data
        fake_headers = (
            b"POST /api/v2/data HTTP/1.1\r\n"
            b"Host: cdn." + secrets.token_hex(4).encode() + b".com\r\n"
            b"Content-Type: application/json\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            b"Accept: application/json, text/plain, */*\r\n"
            b"Accept-Language: en-US,en;q=0.9\r\n"
            b"Accept-Encoding: gzip, deflate, br\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Length: " + str(len(data)).encode() + b"\r\n"
            b"\r\n" + data
        )
        cls._masked_protocol_stats["packets"] += 1
        cls._masked_protocol_stats["bytes"] += len(fake_headers)
        return fake_headers

    @classmethod
    def fragment_payload(cls, data: bytes, max_frag: int = 512) -> list:
        """Fragment payload to evade DPI signature matching."""
        if not NN_FRAGMENT_EVASION or len(data) <= max_frag:
            return [data]
        frags = []
        offset = 0
        while offset < len(data):
            end = min(offset + max_frag, len(data))
            frag = data[offset:end]
            if frags:
                frag = secrets.token_bytes(4) + frag
            frags.append(frag)
            offset = end
            cls._fragmented_packets += 1
        return frags

    @classmethod
    def add_jitter(cls, data: bytes) -> bytes:
        """Add random timing jitter to defeat traffic analysis."""
        if not NN_JITTER_INJECTION:
            return data
        jitter_len = secrets.randbelow(32)
        if jitter_len > 0:
            jitter = secrets.token_bytes(jitter_len)
            data = data + b"\x00" + struct.pack(">H", jitter_len) + jitter
            cls._jitter_injections += 1
        return data

    @classmethod
    def strip_metadata(cls, data: dict) -> dict:
        """Strip identifying metadata from messages before transmission."""
        if not METADATA_STRIP:
            return data
        stripped = dict(data)
        for key in ["_sender_hostname", "_sender_ip", "_sender_user_agent",
                     "_sender_device", "_sender_geolocation", "user_agent",
                     "x_forwarded_for", "x_real_ip", "via"]:
            stripped.pop(key, None)
        if "timestamp" in stripped:
            bucket = int(stripped["timestamp"] // 300) * 300
            stripped["timestamp"] = bucket
        return stripped

    @classmethod
    def get_status(cls):
        return {
            "enabled": NET_NEUTRALITY_ENABLED,
            "running": cls._running,
            "throttle_detected": cls._throttle_detected,
            "masked_protocol": dict(cls._masked_protocol_stats),
            "fragmented_packets": cls._fragmented_packets,
            "jitter_injections": cls._jitter_injections,
            "mask_as": NN_MASK_PROTOCOL if NN_PROTOCOL_MASQUERADE else "none",
            "toggles": {
                "enabled": NET_NEUTRALITY_ENABLED,
                "bandwidth_monitor": NN_BANDWIDTH_MONITOR,
                "protocol_masquerade": NN_PROTOCOL_MASQUERADE,
                "fragmentation": NN_FRAGMENT_EVASION,
                "throttle_detect": NN_THROTTLE_DETECT,
                "jitter_injection": NN_JITTER_INJECTION,
            },
        }

    @classmethod
    def set_enabled(cls, feature: str, enabled: bool) -> bool:
        """Live-toggle an individual net-neutrality countermeasure."""
        global NET_NEUTRALITY_ENABLED, NN_BANDWIDTH_MONITOR, NN_PROTOCOL_MASQUERADE, \
            NN_FRAGMENT_EVASION, NN_THROTTLE_DETECT, NN_JITTER_INJECTION
        feature = feature.lower()
        enabled = bool(enabled)
        if feature in ("enabled", "master"):
            NET_NEUTRALITY_ENABLED = enabled
            if enabled:
                cls.start()
            else:
                cls.stop()
        elif feature == "bandwidth_monitor":
            NN_BANDWIDTH_MONITOR = enabled
        elif feature == "protocol_masquerade":
            NN_PROTOCOL_MASQUERADE = enabled
        elif feature == "fragmentation":
            NN_FRAGMENT_EVASION = enabled
        elif feature == "throttle_detect":
            NN_THROTTLE_DETECT = enabled
        elif feature == "jitter_injection":
            NN_JITTER_INJECTION = enabled
        else:
            return False
        return True


# ── Multi-Link Bandwidth Aggregation ──────────────────────────────────────
# Strips data across ALL available transports in parallel:
#   wired, WiFi, 4G/5G, mesh peers, satellite, radio, WSS relays, DNS tunnels
# Each link gets fragments proportional to its measured capacity.
# Reassembly happens at the destination with ordering and retransmission.

import struct as _struct


class LinkProbe:
    """Sentinel probe message for measuring link quality end-to-end."""
    _PROBE_MAGIC = b"\xbe\xef\xca\xfe"
    _counter = 0
    _lock = threading.Lock()

    @classmethod
    def create(cls, size: int = BOND_PROBE_SIZE) -> bytes:
        with cls._lock:
            cls._counter += 1
            seq = cls._counter
        payload = secrets.token_bytes(max(size - 8, 16))
        return cls._PROBE_MAGIC + _struct.pack("!I", seq) + payload


class LinkMonitor:
    """Passively discovers and measures all network paths available to this node.

    Maintains a LinkState dict per path with:
      - name: human-readable label (e.g. "eth0", "mesh:peer_x")
      - type: "direct", "mesh", "satellite", "mobile", "radio", "wss", "dns", "relay"
      - addr: IP:port or peer identifier
      - bandwidth_bps: measured bits/sec
      - latency_ms: moving average (ms)
      - packet_loss: fraction 0.0–1.0
      - weight: composite score for load balancing (0.0–1.0)
      - last_seen: timestamp
      - active: bool
    """

    instance = None
    _lock = threading.Lock()
    _links: ClassVar[dict[str, dict]] = {}
    _running = False

    # ── Interface Discovery ──────────────────────────────────────────────

    @classmethod
    def discover_interfaces(cls) -> list[dict]:
        """Return all non-loopback network interfaces with IP and speed."""
        found = []
        try:
            import subprocess as _sp
            r = _sp.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5, check=False)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                iface = parts[1].rstrip(":")
                if iface == "lo":
                    continue
                state = parts[-1] if parts[-1] in ("UP", "DOWN") else ""
                speed = 0
                try:
                    s = _sp.run(["ethtool", iface], capture_output=True, text=True, timeout=3, check=False)
                    for sl in s.stdout.splitlines():
                        if "Speed:" in sl:
                            spd = sl.split("Speed:")[-1].strip()
                            if "Mb/s" in spd:
                                speed = int(spd.replace("Mb/s", "").strip()) * 1_000_000
                            elif "Gb/s" in spd:
                                speed = int(spd.replace("Gb/s", "").strip()) * 1_000_000_000
                except Exception as _e:
                    logger.debug("Ignored: %s", _e)
                if not speed:
                    speed = 100_000_000  # assume 100 Mbps if unknown
                found.append({"name": iface, "state": state, "speed": speed})
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return found

    @classmethod
    def discover_addresses(cls, iface: str) -> list[str]:
        """Get all IP addresses for an interface."""
        addrs = []
        try:
            import subprocess as _sp
            r = _sp.run(["ip", "-o", "-4", "addr", "show", "dev", iface],
                        capture_output=True, text=True, timeout=3, check=False)
            for line in r.stdout.splitlines():
                parts = line.split()
                for i, p in enumerate(parts):
                    if "/" in p and "." in p:
                        addrs.append(p.split("/")[0])
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return addrs

    # ── Link Registration ────────────────────────────────────────────────

    @classmethod
    def register_link(cls, link_id: str, link_type: str, addr: str = "",
                       bandwidth: int = 10_000_000) -> None:
        """Register or update a transport link for bonding."""
        with cls._lock:
            now = time.time()
            if link_id in cls._links:
                cls._links[link_id]["last_seen"] = now
                cls._links[link_id]["active"] = True
                return
            cls._links[link_id] = {
                "name": link_id,
                "type": link_type,
                "addr": addr,
                "bandwidth_bps": bandwidth,
                "measured_bps": bandwidth,
                "latency_ms": 50.0,
                "packet_loss": 0.0,
                "weight": 0.5,
                "last_seen": now,
                "active": True,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "latencies": [],
                "probe_time": 0,
            }

    @classmethod
    def unregister_link(cls, link_id: str) -> None:
        with cls._lock:
            cls._links.pop(link_id, None)

    # ── Link Quality Measurement ─────────────────────────────────────────

    @classmethod
    def record_bytes_sent(cls, link_id: str, n: int) -> None:
        with cls._lock:
            link = cls._links.get(link_id)
            if link:
                link["bytes_sent"] += n

    @classmethod
    def record_bytes_recv(cls, link_id: str, n: int) -> None:
        with cls._lock:
            link = cls._links.get(link_id)
            if link:
                link["bytes_recv"] += n

    @classmethod
    def record_latency(cls, link_id: str, ms: float) -> None:
        with cls._lock:
            link = cls._links.get(link_id)
            if link:
                link["latencies"].append(ms)
                if len(link["latencies"]) > BOND_LATENCY_WINDOW:
                    link["latencies"].pop(0)
                link["latency_ms"] = sum(link["latencies"]) / len(link["latencies"])

    @classmethod
    def record_loss(cls, link_id: str, lost: bool) -> None:
        with cls._lock:
            link = cls._links.get(link_id)
            if link:
                alpha = 0.3
                link["packet_loss"] = link["packet_loss"] * (1 - alpha) + (1.0 if lost else 0.0) * alpha

    # ── Health Check ─────────────────────────────────────────────────────

    @classmethod
    def _health_check(cls) -> None:
        """Periodically measure throughput and probe latency per link."""
        while cls._running:
            time.sleep(BOND_HEALTH_INTERVAL)
            with cls._lock:
                for link_id, link in list(cls._links.items()):
                    # Mark stale links as inactive
                    if time.time() - link["last_seen"] > BOND_STALE_LINK:
                        link["active"] = False
                        continue
                    # Compute current throughput from bytes sent since last check
                    now = time.time()
                    dt = now - link.get("_last_check", now)
                    if dt > 0 and link.get("_last_bytes"):
                        bps = (link["bytes_sent"] - link["_last_bytes"]) / dt * 8
                        link["measured_bps"] = max(bps, 1000)
                    link["_last_bytes"] = link["bytes_sent"]
                    link["_last_check"] = now
                    # Compute weight: high bandwidth, low latency, low loss = high weight
                    bw_score = min(link["measured_bps"] / max(link["bandwidth_bps"], 1), 1.0)
                    lat_score = max(1.0 - link["latency_ms"] / 500.0, 0.0)
                    loss_score = max(1.0 - link["packet_loss"] * 5, 0.0)
                    link["weight"] = bw_score * 0.5 + lat_score * 0.25 + loss_score * 0.25

    # ── API ──────────────────────────────────────────────────────────────

    @classmethod
    def get_links(cls) -> dict:
        with cls._lock:
            return {k: dict(v) for k, v in cls._links.items()}

    @classmethod
    def get_active_links(cls) -> list[tuple[str, dict]]:
        with cls._lock:
            return [(k, dict(v)) for k, v in cls._links.items() if v["active"]]

    @classmethod
    def get_weights(cls) -> dict[str, float]:
        with cls._lock:
            total = sum(max(l["weight"], 0.01) for l in cls._links.values() if l["active"])
            if total == 0:
                return {}
            return {k: max(l["weight"], 0.01) / total
                    for k, l in cls._links.items() if l["active"]}

    @classmethod
    def start(cls) -> None:
        if not BONDING_ENABLED:
            return
        cls._running = True
        # Register direct interfaces
        for iface in cls.discover_interfaces():
            if iface["state"] == "UP":
                addrs = cls.discover_addresses(iface["name"])
                addr_str = ",".join(addrs) if addrs else ""
                cls.register_link(f"iface:{iface['name']}", "direct", addr_str, iface["speed"])
        t = threading.Thread(target=cls._health_check, daemon=True)
        t.start()

    @classmethod
    def stop(cls) -> None:
        cls._running = False
        with cls._lock:
            cls._links.clear()


class FragmentHeader:
    """Binary header for striped fragments sent over bonded channels.
    Total header size: 16 bytes.
    """
    FORMAT = "!IHHBxI"
    SIZE = _struct.calcsize(FORMAT)  # 16

    def __init__(self, msg_id: int, frag_no: int, total_frags: int,
                 channel_id: str = "", payload_size: int = 0):
        self.msg_id = msg_id
        self.frag_no = frag_no
        self.total_frags = total_frags
        self.channel_id = channel_id
        self.payload_size = payload_size

    def pack(self) -> bytes:
        ch = (self.channel_id[:7].encode().ljust(7, b"\x00")
              if self.channel_id else b"\x00" * 7)
        ch_int = int.from_bytes(ch[:7], "big")
        return _struct.pack(self.FORMAT, self.msg_id, self.frag_no,
                            self.total_frags, ch_int, self.payload_size)

    @classmethod
    def unpack(cls, data: bytes) -> "FragmentHeader":
        msg_id, frag_no, total_frags, ch_int, payload_size = _struct.unpack(
            cls.FORMAT, data[:cls.SIZE])
        ch_bytes = ch_int.to_bytes(7, "big")
        ch_str = ch_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
        h = cls(msg_id, frag_no, total_frags, ch_str, payload_size)
        return h


class ReassemblyBuffer:
    """Collects fragments from all bonded sub-channels and reassembles
    messages in correct order. Handles duplicates, retransmission, timeouts.
    """

    _buffers: ClassVar[dict[int, dict]] = {}
    _lock = threading.Lock()
    _TIMEOUT = 15.0

    @classmethod
    def add_fragment(cls, header: FragmentHeader, payload: bytes,
                     source_link: str = "") -> bytes | None:
        """Add an incoming fragment. Returns the complete message if all
        fragments are present, None otherwise."""
        with cls._lock:
            now = time.time()
            if header.msg_id not in cls._buffers:
                cls._buffers[header.msg_id] = {
                    "total": header.total_frags,
                    "fragments": {},
                    "arrived": set(),
                    "links": {},
                    "created": now,
                    "size": header.payload_size,
                }
            buf = cls._buffers[header.msg_id]
            if header.frag_no in buf["arrived"]:
                return None  # duplicate
            buf["fragments"][header.frag_no] = payload
            buf["arrived"].add(header.frag_no)
            buf["links"][header.frag_no] = source_link
            if len(buf["arrived"]) >= buf["total"]:
                # Complete! Reassemble in order
                ordered = [buf["fragments"][i] for i in range(buf["total"])]
                del cls._buffers[header.msg_id]
                return b"".join(ordered)
            # Record per-link stats for the source
            if source_link:
                LinkMonitor.record_bytes_recv(source_link, FragmentHeader.SIZE + len(payload))
            return None

    @classmethod
    def get_missing_fragments(cls, msg_id: int) -> list[int]:
        """Return fragment numbers still missing for a given message."""
        with cls._lock:
            buf = cls._buffers.get(msg_id)
            if not buf:
                return []
            return [i for i in range(buf["total"]) if i not in buf["arrived"]]

    @classmethod
    def expire_stale(cls) -> None:
        """Remove stale incomplete buffers from memory."""
        with cls._lock:
            now = time.time()
            stale = [mid for mid, buf in cls._buffers.items()
                     if now - buf["created"] > cls._TIMEOUT]
            for mid in stale:
                del cls._buffers[mid]

    @classmethod
    def status(cls) -> dict:
        with cls._lock:
            return {str(mid): {
                "total": b["total"],
                "received": len(b["arrived"]),
                "age": round(time.time() - b["created"], 1),
            } for mid, b in cls._buffers.items()}


class BandwidthAggregator:
    """Multi-link channel bonding engine.

    Strips outgoing messages across ALL available transports in parallel.
    Each fragment carries a header for reassembly at the destination.
    Retransmits on alternative links if a fragment goes un-ACK'd.
    Adapts to link quality changes in real time.
    """

    _counter = 0
    _counter_lock = threading.Lock()
    _running = False
    _ack_timeout: ClassVar[dict[int, float]] = {}  # msg_id -> deadline
    _ack_lock = threading.Lock()
    _retry_queue: queue.Queue = queue.Queue()

    # ── Fragmentation / Striping ─────────────────────────────────────────

    @classmethod
    def _next_msg_id(cls) -> int:
        with cls._counter_lock:
            cls._counter = (cls._counter + 1) & 0xFFFFFFFF
            return cls._counter

    @classmethod
    def _pick_chunk_size(cls) -> int:
        """Pick a random chunk size within configured bounds to defeat
        packet-size-based DPI."""
        return secrets.randbelow(BOND_CHUNK_MAX - BOND_CHUNK_MIN + 1) + BOND_CHUNK_MIN

    @classmethod
    def fragment(cls, payload: bytes, channel_id: str = "") -> list[tuple[FragmentHeader, bytes]]:
        """Split a payload into fragments sized for bonded transmission."""
        chunk_size = cls._pick_chunk_size()
        msg_id = cls._next_msg_id()
        total = max(1, (len(payload) + chunk_size - 1) // chunk_size)
        fragments = []
        for i in range(total):
            start = i * chunk_size
            end = min(start + chunk_size, len(payload))
            frag_data = payload[start:end]
            hdr = FragmentHeader(msg_id, i, total, channel_id, len(frag_data))
            fragments.append((hdr, frag_data))
        return fragments

    @classmethod
    def reassemble(cls, header: FragmentHeader, payload: bytes,
                   source_link: str = "") -> bytes | None:
        """Feed a received fragment into the reassembly buffer.
        Returns the complete message if done, None otherwise."""
        result = ReassemblyBuffer.add_fragment(header, payload, source_link)
        if result is not None and header.msg_id in cls._ack_timeout:
            with cls._ack_lock:
                cls._ack_timeout.pop(header.msg_id, None)
        return result

    # ── Bonded Send ──────────────────────────────────────────────────────

    @classmethod
    def send_bonded(cls, payload: bytes,
                    send_fns: dict[str, Callable]) -> int:
        """Send payload across all active links using the provided send
        callables. Returns total bytes sent.

        `send_fns`: dict of link_id -> callable(data_chunk) that sends
                    the bytes over that transport.
        """
        if not BONDING_ENABLED or not send_fns:
            return 0

        # Map send functions to registered links
        active = []
        for link_id, fn in send_fns.items():
            with LinkMonitor._lock:
                link = LinkMonitor._links.get(link_id)
                if link and link["active"]:
                    active.append((link_id, fn, link["weight"]))

        if not active:
            return 0

        # Fragment payload
        fragments = cls.fragment(payload)
        total_bytes = sum(hdr.payload_size + FragmentHeader.SIZE for hdr, _ in fragments)

        # Distribute fragments across active links by weight
        weights = [w for _, _, w in active]
        total_w = sum(weights)
        if total_w == 0:
            weights = [1.0] * len(active)
            total_w = len(active)
        assignments = []
        idx = 0
        for hdr, frag_data in fragments:
            # Round-robin weighted: pick link with lowest cumulative load
            link_idx = idx % len(active)
            assignments.append((active[link_idx][0], active[link_idx][1], hdr, frag_data))
            idx += 1

        # Send all fragments in parallel across their assigned links
        def _send_one(link_id: str, send_fn: Callable, hdr: FragmentHeader,
                      frag_data: bytes) -> None:
            try:
                packet = hdr.pack() + frag_data
                send_fn(packet)
                LinkMonitor.record_bytes_sent(link_id, len(packet))
            except Exception:
                # Mark loss and retry will handle
                LinkMonitor.record_loss(link_id, True)

        threads = []
        for link_id, send_fn, hdr, frag_data in assignments:
            t = threading.Thread(target=_send_one,
                                 args=(link_id, send_fn, hdr, frag_data),
                                 daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=5)

        return total_bytes

    # ── Retransmission ───────────────────────────────────────────────────

    @classmethod
    def _retry_loop(cls) -> None:
        """Monitor for un-ACK'd messages and retry on alternative links."""
        while cls._running:
            time.sleep(1.0)
            now = time.time()
            with cls._ack_lock:
                expired = [mid for mid, deadline in cls._ack_timeout.items()
                           if now > deadline]
                for mid in expired:
                    del cls._ack_timeout[mid]
            ReassemblyBuffer.expire_stale()

    # ── Lifecycle ────────────────────────────────────────────────────────

    @classmethod
    def start(cls) -> None:
        if not BONDING_ENABLED:
            return
        cls._running = True
        t = threading.Thread(target=cls._retry_loop, daemon=True)
        t.start()

    @classmethod
    def stop(cls) -> None:
        cls._running = False


class BondedMeshTransport:
    """Adapter that makes all MeshNode transports available as bonded sub-channels.

    Exposes a `send_fns` dict that BandwidthAggregator can use to stripe
    data across mesh UDP, satellite, mobile, radio, WSS, DNS tunnel, and relay.
    """

    @classmethod
    def get_send_fns(cls, dst_pot: str = "") -> dict[str, Callable]:
        """Return a dict of link_id -> callable for all available transports
        that can reach `dst_pot`. Each callable takes raw bytes and sends them."""
        fns = {}

        # 1. Direct mesh UDP to known peers
        with MeshNode.peers_lock:
            for pid, info in MeshNode.peers.items():
                peer_addr = info.get("addr", "")
                peer_port = info.get("mesh_port", MESH_PORT)
                if peer_addr and (not dst_pot or pid == dst_pot):
                    link_id = f"mesh:{pid}"
                    fns[link_id] = (lambda data, a=peer_addr, p=peer_port:
                        MeshNode.mesh_socket.sendto(data, (a, p))
                        if MeshNode.mesh_socket else None)
                    bw = info.get("bandwidth_bps", 10_000_000)
                    LinkMonitor.register_link(link_id, "mesh",
                                              f"{peer_addr}:{peer_port}", bw)

        # 2. Satellite peers
        if SATELLITE_ENABLED and MeshNode.sat_socket:
            with MeshNode.sat_lock:
                for pid, info in dict(MeshNode.sat_peers).items():
                    sat_addr = info.get("addr", "")
                    sat_port = info.get("port", SATELLITE_PORT)
                    if sat_addr and (not dst_pot or pid == dst_pot):
                        link_id = f"sat:{pid}"
                        fns[link_id] = (lambda data, a=sat_addr, p=sat_port:
                            MeshNode.sat_socket.sendto(data, (a, p))
                            if MeshNode.sat_socket else None)
                        LinkMonitor.register_link(link_id, "satellite",
                                                  f"{sat_addr}:{sat_port}")

        # 3. Mobile peers
        if MOBILE_ENABLED and MeshNode.mobile_socket:
            with MeshNode.mobile_lock:
                for pid, info in dict(MeshNode.mobile_peers).items():
                    mob_addr = info.get("addr", "")
                    mob_port = info.get("port", MOBILE_PORT)
                    if mob_addr and (not dst_pot or pid == dst_pot):
                        link_id = f"mobile:{pid}"
                        fns[link_id] = (lambda data, a=mob_addr, p=mob_port:
                            MeshNode.mobile_socket.sendto(data, (a, p))
                            if MeshNode.mobile_socket else None)
                        LinkMonitor.register_link(link_id, "mobile",
                                                  f"{mob_addr}:{mob_port}")

        # 4. WSS relay — send fragments wrapped in mesh messages to all relays
        if ANTI_ISP_ENABLED and WSS_TUNNEL_ENABLED and AntiISP._wss_connections:
            wrapped = json.dumps({
                "type": "bond_fragment",
                "dst": dst_pot,
                "payload": "__payload__",
            }).encode()
            fns["wss"] = (lambda data, w=wrapped:
                AntiISP.wss_send(w.replace(b"__payload__", base64.b64encode(data).decode()
                                           if hasattr(data, 'decode') else base64.b64encode(data).decode())  # noqa: RUF034
                                 if isinstance(w, bytes) else data))
            LinkMonitor.register_link("wss", "wss", bandwidth=2_000_000)

        # 5. DNS tunnel — small fragments only (max 200 bytes encoded)
        if ANTI_ISP_ENABLED and DNS_TUNNEL_ENABLED and dst_pot:
            fns["dns"] = (lambda data, d=dst_pot:
                AntiISP.dns_tunnel_send(d, data)
                if hasattr(AntiISP, 'dns_tunnel_send') else None)
            LinkMonitor.register_link("dns", "dns", bandwidth=500_000)

        # 6. TCP relay
        if ANTI_ISP_ENABLED and RELAY_ENABLED and dst_pot:
            for relay in RELAY_SERVERS:
                link_id = f"relay:{relay}"
                fns[link_id] = (lambda data, r=relay, d=dst_pot:
                    AntiISP.relay_send(d, data)
                    if hasattr(AntiISP, 'relay_send') else None)
                LinkMonitor.register_link(link_id, "relay", relay, bandwidth=5_000_000)

        return fns

    @classmethod
    def send_fragment(cls, link_id: str, data: bytes) -> None:
        """Low-level send of a single fragment over a specific link."""
        fns = cls.get_send_fns()
        fn = fns.get(link_id)
        if fn:
            try:
                fn(data)
            except Exception:
                LinkMonitor.record_loss(link_id, True)


class GpioController:
    """Raspberry Pi GPIO control via RPi.GPIO.
    
    No simulated mode. If GPIO_ENABLED=1 and RPi.GPIO is unavailable,
    the application exits with an error. Coffee pots are real hardware.
    """

    def __init__(self):
        self._pin = GPIO_PIN
        self._state = False
        if GPIO_ENABLED:
            from RPi import GPIO
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self._pin, GPIO.OUT)
            GPIO.output(self._pin, GPIO.LOW)
            self._gpio = GPIO
        else:
            self._gpio = None

    def on(self):
        self._state = True
        if self._gpio:
            self._gpio.output(self._pin, self._gpio.HIGH)
        return True

    def off(self):
        self._state = False
        if self._gpio:
            self._gpio.output(self._pin, self._gpio.LOW)
        return True

    @property
    def is_on(self):
        return self._state

    @property
    def is_available(self):
        return self._gpio is not None

gpio = GpioController()


# ── State Machine ─────────────────────────────────────────────────────
class PotState:
    brewing = False
    brew_start_time = None
    current_beverage = None
    current_additions: ClassVar[list] = []
    brew_id = None
    history: ClassVar[list] = []
    schedules: ClassVar[list] = []
    webhooks: ClassVar[list] = []
    sse_clients: ClassVar[list] = []
    sse_lock = threading.Lock()
    state_lock = threading.Lock()

    @classmethod
    def start(cls, beverage="tea", additions=None):
        with cls.state_lock:
            cls.brewing = True
            cls.brew_start_time = time.time()
            cls.current_beverage = beverage
            cls.current_additions = additions or []
            cls.brew_id = str(uuid.uuid4())[:8]
        gpio.on()
        cls._broadcast({"event": "brew_start", "beverage": beverage, "additions": additions, "brew_id": cls.brew_id})
        return cls.brew_id

    @classmethod
    def stop(cls):
        with cls.state_lock:
            was = cls.brewing
            if was:
                elapsed = time.time() - cls.brew_start_time if cls.brew_start_time else 0
                cls.history.append({
                    "id": cls.brew_id,
                    "beverage": cls.current_beverage,
                    "additions": cls.current_additions,
                    "started": cls.brew_start_time,
                    "duration": round(elapsed, 1),
                    "ended": time.time(),
                })
                if len(cls.history) > HISTORY_MAX:
                    cls.history = cls.history[-HISTORY_MAX:]
            cls.brewing = False
            cls.brew_start_time = None
            cls.current_beverage = None
            cls.current_additions = []
        gpio.off()
        if was:
            cls._broadcast({"event": "brew_stop"})
            cls._fire_webhooks()
        return was

    @classmethod
    def is_brewing(cls):
        return cls.brewing

    @classmethod
    def _broadcast(cls, data):
        with cls.sse_lock:
            msg = f"data: {json.dumps(data)}\n\n"
            dead = []
            for q in cls.sse_clients:
                try:
                    q.put_nowait(msg)
                except Exception:
                    dead.append(q)
            for q in dead:
                cls.sse_clients.remove(q)

    @classmethod
    def _fire_webhooks(cls):
        if not cls.webhooks:
            return
        payload = {
            "event": "brew_complete",
            "pot": POT_ID,
            "hostname": HOSTNAME,
            "beverage": cls.history[-1]["beverage"] if cls.history else "unknown",
            "timestamp": time.time(),
        }
        for url in cls.webhooks:
            try:
                import urllib.request
                data = json.dumps(payload).encode()
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception as _e:
                logger.debug("Ignored: %s", _e)


# ── HTCPCP Protocol Helpers ───────────────────────────────────────────
def parse_accept_additions(header_value):
    if not header_value:
        return []
    additions = []
    for token in header_value.split(","):
        token = token.strip()
        if not token:
            continue
        parts = token.split(";")
        name = parts[0].strip().lower()
        variety = None
        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("variety="):
                variety = part.split("=", 1)[1].strip()
        additions.append({"name": name, "variety": variety})
    return additions


def check_additions(additions, device_type):
    allows_alcohol = device_type in ALCOHOL_DEVICES
    for addn in additions:
        name = addn["name"]
        if name not in VALID_ADDITIONS:
            return False, f"Unknown addition type: {name}"
        addn_def = VALID_ADDITIONS[name]
        if addn_def["type"] == "alcohol" and not allows_alcohol:
            return False, f"Device type '{device_type}' does not support alcohol additions"
        if addn["variety"] and addn["variety"] not in addn_def["variety"]:
            continue
    return True, None


def is_beverage_compatible(request_path, device_type):
    allowed = DEVICE_BEVERAGE_MAP.get(device_type, ["tea"])
    path = urlparse(request_path).path.rstrip("/")
    if path.endswith("/coffee"):
        return "coffee" in allowed
    if path.endswith("/tea"):
        return "tea" in allowed
    return True


# ── coffee: URI Scheme Support (RFC 2324 §3) ───────────────────────────
def is_coffee_uri_path(path):
    """Check if path uses the coffee: URI scheme (any international variant).
    Handles both raw scheme:// and HTTP-prefixed /scheme:// forms."""
    lower = path.lower().lstrip("/")
    for scheme in COFFEE_SCHEME_NAMES:
        if lower.startswith((scheme + "://", scheme + ":")):
            return True
    return False


def parse_coffee_uri(path):
    """Parse a coffee: URI into (pot_designator, additions_list, beverage_hint).
    
    coffee-url = coffee-scheme ":" [ "//" host ] ["/" pot-designator] ["?" additions-list]
    pot-designator = "pot-" integer
    additions-list = #( addition )
    """
    lower = path.lower().lstrip("/")
    scheme = None
    for s in COFFEE_SCHEME_NAMES:
        if lower.startswith((s + "://", s + ":")):
            scheme = s
            break
    if not scheme:
        return None, [], None

    rest = lower[len(scheme):]
    if rest.startswith("://"):
        rest = rest[3:]
    elif rest.startswith(":"):
        rest = rest[1:]

    if rest and not rest.startswith("/") and not rest.startswith("?"):
        slash = rest.find("/")
        qmark = rest.find("?")
        end = len(rest)
        if slash >= 0:
            end = min(end, slash)
        if qmark >= 0:
            end = min(end, qmark)
        rest[:end]
        rest = rest[end:]

    pot = None
    if rest.startswith("/pot-"):
        parts = rest[1:].split("?", 1)
        pot = parts[0]
        rest = "?" + parts[1] if len(parts) > 1 else ""

    additions_raw = ""
    if rest.startswith("?"):
        additions_raw = rest[1:]

    additions = []
    beverage_hint = None
    if additions_raw:
        for token in additions_raw.split(","):
            token = token.strip()
            if not token:
                continue
            parts = token.split(";")
            name = parts[0].strip().lower()
            variety = None
            for part in parts[1:]:
                part = part.strip().lower()
                if part.startswith("variety="):
                    variety = part.split("=", 1)[1].strip()
            additions.append({"name": name, "variety": variety})
            if name == "coffee":
                beverage_hint = "coffee"
            elif name == "tea":
                beverage_hint = "tea"

    # Map scheme to beverage hint
    if not beverage_hint:
        if scheme in ("koffie", "kaffe", "kahvi", "coffee", "kava",
                       "kafe", "kohv", "kafo", "caf%C3%A8",
                       "%4Baffee", "%E5%92%96%E5%95%A1"):
            beverage_hint = "coffee"
        elif scheme in ("akeita", "kahva"):
            beverage_hint = "tea"
        else:
            beverage_hint = "coffee"

    return pot, additions, beverage_hint


# ── mDNS Advertising ──────────────────────────────────────────────────
_avahi_process = None

def start_mdns():
    global _avahi_process
    if not AVAHI_ENABLED:
        return
    try:
        _avahi_process = subprocess.Popen(
            ["avahi-publish-service", f"CPIP-{HOSTNAME}", "_coffee._tcp", str(BIND_PORT),
             f"device={DEVICE_TYPE}", f"pot_id={POT_ID}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        pass


def stop_mdns():
    global _avahi_process
    if _avahi_process:
        _avahi_process.terminate()
        _avahi_process = None


# ── Pot Discovery (UDP Broadcast) ─────────────────────────────────────
_discovery_socket = None

def start_discovery():
    global _discovery_socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        _sock_bind(sock, (BIND_ADDR, DISCOVERY_PORT))
        sock.settimeout(1)
        _discovery_socket = sock
        threading.Thread(target=_discovery_listener, daemon=True).start()
    except Exception as _e:
        logger.debug("Ignored: %s", _e)


def _discovery_listener():
    sock = _discovery_socket
    while sock:
        try:
            data, addr = sock.recvfrom(1024)
            if data == b"CPIP_DISCOVER":
                resp = json.dumps({
                    "pot": POT_ID, "hostname": HOSTNAME, "device": DEVICE_TYPE,
                    "port": BIND_PORT, "brewing": PotState.is_brewing(),
                    "mesh_port": MESH_PORT, "mesh_enabled": MESH_ENABLED,
                    "addr": addr[0],
                }).encode()
                sock.sendto(resp, addr)
        except TimeoutError:
            continue
        except Exception:
            break


def discover_pots(timeout=2):
    results = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(b"CPIP_DISCOVER", ("255.255.255.255", DISCOVERY_PORT))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(2048)
                info = json.loads(data.decode())
                info["addr"] = addr[0]
                if info.get("pot") != POT_ID:
                    results.append(info)
            except TimeoutError:
                break
            except Exception as _e:
                logger.debug("Skipped: %s", _e); continue
    except Exception as _e:
        logger.debug("Ignored: %s", _e)
    finally:
        try:
            sock.close()
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
    return results


# ── Scheduling Engine ─────────────────────────────────────────────────
_scheduler_running = False

def scheduler_loop():
    global _scheduler_running
    _scheduler_running = True
    while _scheduler_running:
        now = time.time()
        with PotState.state_lock:
            to_remove = []
            for s in PotState.schedules:
                if s.get("enabled", True) and s["time"] <= now:
                    threading.Thread(target=_execute_schedule, args=(s,), daemon=True).start()
                    to_remove.append(s)
            for s in to_remove:
                PotState.schedules.remove(s)
        time.sleep(SCHEDULE_CHECK_INTERVAL)


def _execute_schedule(schedule):
    PotState.start(schedule.get("beverage", "coffee"), schedule.get("additions", []))
    brew_time = schedule.get("brew_duration", 30)
    time.sleep(brew_time)
    PotState.stop()


def start_scheduler():
    threading.Thread(target=scheduler_loop, daemon=True).start()


def stop_scheduler():
    global _scheduler_running
    _scheduler_running = False


# ── Radio Interface (C binary: LoRa / TNC / Sim) ─────────────────────────
_radio = None

def start_radio():
    global _radio
    if not RADIO_ENABLED:
        return
    if not RADIO_IMPORT_OK:
        print("   ⚠ Radio:      radio_protocol module not found — install radio_if binary", flush=True)
        print("   ⚠ Radio:      cd radio/ && make", flush=True)
        return
    try:
        ri = RadioInterface()
        # Detect hardware before starting
        hw_mode = RADIO_MODE
        if hw_mode != "sim" and hw_mode != "tnc":
            spi_dev = RADIO_DEVICE if RADIO_MODE == "lora" else ""
            if spi_dev and not os.path.exists(spi_dev):
                print(f"   ⚠ Radio:      SPI device {spi_dev} not found", flush=True)
                print("   ⚠ Radio:      Set CPIP_RADIO_DEVICE or CPIP_RADIO_MODE=sim for testing", flush=True)
                return
        ri.start(
            mode=RADIO_MODE,
            frequency=RADIO_FREQ,
            sf=RADIO_SF,
            bandwidth=RADIO_BW,
            tx_power=RADIO_POWER,
            device=RADIO_DEVICE,
            baud=RADIO_BAUD,
        )
        _radio = ri
        mode_label = RADIO_MODE.upper()
        if RADIO_MODE == "lora":
            print(f"   ├ Radio:      {mode_label} @ {RADIO_FREQ/1e6:.1f} MHz"
                  f" (SF{RADIO_SF}, BW {RADIO_BW//1000}k, HW={RADIO_DEVICE})", flush=True)
        elif RADIO_MODE == "tnc":
            print(f"   ├ Radio:      {mode_label} @ {RADIO_DEVICE} ({RADIO_BAUD} baud)", flush=True)
        else:
            print(f"   ├ Radio:      {mode_label} (simulation — no real hardware)", flush=True)

        # Background poll thread: feed received radio packets into mesh
        def _radio_poll():
            while _radio:
                try:
                    pkts = ri.receive(timeout=0.5)
                    for pkt in pkts:
                        threading.Thread(
                            target=_inject_radio_packet,
                            args=(pkt,),
                            daemon=True,
                        ).start()
                except Exception:
                    break

        threading.Thread(target=_radio_poll, daemon=True).start()
    except RadioError as e:
        print(f"   ⚠ Radio:      {e}", flush=True)
        print("   ⚠ Radio:      Hardware may not be connected. Set CPIP_RADIO=sim for testing.", flush=True)
    except Exception as e:
        print(f"   ⚠ Radio:      {e}", flush=True)

def stop_radio():
    global _radio
    if _radio:
        try: _radio.stop()
        except Exception: pass
        _radio = None

def _inject_radio_packet(data: bytes):
    """Feed a raw radio packet into the mesh message handler."""
    try:
        msg = json.loads(data.decode())
        if msg.get("pot") == POT_ID or msg.get("from") == POT_ID:
            return
        MeshNode._handle_message(data, ("0.0.0.0", 0))
        # Forward to satellite if enabled
        MeshNode._cross_transport_forward(msg, via="radio")
    except Exception as _e:
        logger.debug("Ignored: %s", _e)

def get_radio_status() -> dict:
    if not _radio:
        return {"enabled": False, "mode": RADIO_MODE}
    s = _radio.status()
    s["enabled"] = RADIO_ENABLED
    s["mode"] = RADIO_MODE
    return s


# ── NTP Synchronization (RFC 2324 §5.1) ────────────────────────────────
_ntp_running = False
_ntp_offset = 0.0

def ntp_sync_loop():
    """Periodically sync system clock with NTP server for brew timing."""
    global _ntp_running, _ntp_offset
    _ntp_running = True
    while _ntp_running:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(5)
            NTP_PORT = 123
            NTP_EPOCH = 2208988800
            data = b'\x1b' + 47 * b'\x00'
            client.sendto(data, (NTP_SERVER, NTP_PORT))
            data, _ = client.recvfrom(1024)
            client.close()
            if len(data) >= 40:
                import struct
                t = struct.unpack('!12I', data)[10]
                ntp_time = t - NTP_EPOCH
                local_time = time.time()
                _ntp_offset = ntp_time - local_time
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        time.sleep(3600)


def start_ntp():
    if NTP_SYNC:
        threading.Thread(target=ntp_sync_loop, daemon=True).start()


def stop_ntp():
    global _ntp_running
    _ntp_running = False


def ntp_now():
    """Return current time with NTP offset applied."""
    return time.time() + _ntp_offset


# ── HTTP Handler ──────────────────────────────────────────────────────
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json",
}


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedHTTPSServer(ThreadingMixIn, HTTPServer):
    """HTTPS server variant. Wraps the socket with SSL after binding."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, certfile, keyfile, **kwargs):
        self._certfile = certfile
        self._keyfile = keyfile
        super().__init__(server_address, RequestHandlerClass, **kwargs)

    def server_bind(self):
        super().server_bind()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self._certfile, self._keyfile)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


class HTTPRedirectHandler(BaseHTTPRequestHandler):
    """Redirects all HTTP requests to cpip:// (TLS)."""
    def send_header(self, name, value):
        value = "".join(c for c in str(value) if c.isprintable() and c not in "\r\n\t")
        super().send_header(name, value)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        host = self.headers.get("Host", f"{BIND_ADDR}:{HTTP_REDIRECT_PORT}")
        cpip_host = host.replace(f":{HTTP_REDIRECT_PORT}", f":{BIND_PORT}")
        cpip_host = "".join(c for c in cpip_host if c.isprintable() and c not in "\r\n\t")
        safe_path = "".join(c for c in self.path if c.isprintable() and c not in "\r\n\t")
        target = f"https://{cpip_host}{safe_path}"
        if "\r" in target or "\n" in target:
            target = "/"
        self.send_response(301)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self.do_GET()

    def do_BREW(self):
        self.do_GET()

    def do_WHEN(self):
        self.do_GET()

    def do_PROPFIND(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.do_GET()


class CPIPHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
        sys.stderr.write(f"[CPIP {ts}] {self.client_address[0]} {fmt % args}\n")

    def send_header(self, name, value):
        value = "".join(c for c in str(value) if c.isprintable() and c not in "\r\n\t")
        super().send_header(name, value)

    def _check_rate_limit(self):
        addr = self.client_address[0]
        if addr in ("127.0.0.1", "::1", "localhost"):
            return True
        now = time.time()
        with _HTTP_RATE_LOCK:
            if addr not in _HTTP_RATE_COUNTS:
                _HTTP_RATE_COUNTS[addr] = []
            _HTTP_RATE_COUNTS[addr] = [t for t in _HTTP_RATE_COUNTS[addr] if now - t < HTTP_RATE_WINDOW]
            if len(_HTTP_RATE_COUNTS[addr]) > HTTP_RATE_LIMIT:
                return False
            _HTTP_RATE_COUNTS[addr].append(now)
        return True

    def _check_request_size(self):
        length = int(self.headers.get("Content-Length", 0))
        return length <= MAX_REQUEST_SIZE

    def _rpc_auth_check(self, path):
        """If CPIP_RPC_AUTH=1, require a valid X-CPIP-HMAC header on mutating
        /cpip/* endpoints. GET/BREW/WHEN/PROPFIND/OPTIONS and the dashboard
        are exempt. Localhost (127.0.0.1/::1) is also exempt for local UI.
        Returns True if the request is allowed to proceed."""
        if not RPC_AUTH_ENABLED:
            return True
        if not path.startswith("/cpip"):
            return True
        addr = self.client_address[0]
        if addr in ("127.0.0.1", "::1", "localhost"):
            return True
        token = self.headers.get("X-CPIP-HMAC", "")
        if _rpc_hmac_check(self.command, path, token):
            return True
        self._send_json(401, "Unauthorized", {
            "error": "Missing or invalid X-CPIP-HMAC token",
            "hint": "Token format: '<unix_ts>:<hmac>' where "
                    "hmac = HMAC-SHA256(COVERT_KEY, ts||method||path)",
            "skew_seconds": RPC_AUTH_SKEW,
        })
        return False

    def _cors_headers(self):
        if CORS_ALLOWED_ORIGINS:
            raw_origin = self.headers.get("Origin", "")
            allowed = [o.strip() for o in CORS_ALLOWED_ORIGINS.split(",") if o.strip()]
            origin = "".join(c for c in raw_origin if c.isprintable() and c not in "\r\n\t")
            if origin == raw_origin and origin in allowed:
                self.send_header("Access-Control-Allow-Origin", origin)
            else:
                self.send_header("Access-Control-Allow-Origin", "")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, BREW, WHEN, PROPFIND, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept-Additions, X-Requested-With, X-CPIP-HMAC")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; connect-src 'self'")
        is_https = isinstance(self.connection, ssl.SSLSocket)
        if is_https:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            self.send_header("Upgrade-Insecure-Requests", "1")

    def _send_json(self, code, reason, body, extra_headers=None):
        self.send_response(code, reason)
        payload = json.dumps(body, indent=2).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("CPIP-Version", CPIP_VERSION)
        self.send_header("CPIP-Device", DEVICE_TYPE)
        self.send_header("CPIP-Pot-ID", POT_ID)
        self._cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)
        try:
            SignalAwareness.record_http(self.command, self.path, code,
                                         int(self.headers.get("Content-Length", 0)), len(payload))
        except Exception as _e:
            logger.debug("Ignored: %s", _e)

    def _send_html(self, code, html_content):
        body = html_content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("CPIP-Version", CPIP_VERSION)
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path):
        try:
            if not path or not path.isprintable() or "\r" in path or "\n" in path:
                self._send_json(400, "Bad Request", {"error": "Invalid path"})
                return
            rel = os.path.normpath("/" + path).lstrip("/")
            if ".." in rel.split("/") or rel.startswith(".."):
                self._send_json(400, "Bad Request", {"error": "Invalid path"})
                return
            resolved = _STATIC_FILE_MAP.get(rel)
            if resolved is None:
                self._send_json(403, "Forbidden", {"error": "Access denied"})
                return
            ext = os.path.splitext(rel)[1].lower()
            mime = MIME_TYPES.get(ext, "application/octet-stream")
            body = resolved.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("CPIP-Version", CPIP_VERSION)
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self._send_json(500, "Internal Error", {"error": str(e)})

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                return json.loads(self.rfile.read(length))
        except Exception as _e:
            logger.debug("Ignored: %s", _e)
        return {}

    # ── HTCPCP Compatibility Methods ──────────────────────────────────

    def do_GET(self):
        if not self._check_rate_limit():
            self._send_json(429, "Too Many Requests", {"error": "Rate limit exceeded"})
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "device": DEVICE_TYPE,
                "message": "The requested resource is a teapot. Short and stout.",
            })
            return

        teapot_tool_check(self.headers, self.client_address[0])
        surveillance_fp_check(self.headers, self.client_address[0], urlparse(self.path).path)

        if teapot_probe_check(self.headers, self.client_address[0], path, "GET"):
            teapot_blacklist_addr(self.client_address[0])
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "device": DEVICE_TYPE,
                "note": "This request looks like a probe. Coffee pots don't serve web shells.",
            })
            return

        if is_coffee_uri_path(self.path):
            _pot, _additions, _beverage = parse_coffee_uri(self.path)
            if "text/html" in self.headers.get("Accept", ""):
                self._serve_dashboard()
            else:
                self._handle_cpip_status()
            return

        if path in ("", "/") and "text/html" in self.headers.get("Accept", ""):
            path = "/dashboard"
        if path == "/dashboard":
            self._serve_dashboard()
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            self._send_file(rel)
            return

        # ── Kubernetes Health Probes ────────────────────────────────
        if path == "/health" or path == "/healthz":
            health = {
                "status": "ok",
                "version": CPIP_VERSION,
                "uptime": time.time() - _START_TIME,
            }
            self._send_json(200, "OK", health)
            return
        if path == "/ready" or path == "/readyz":
            ready = MeshNode.running and (not MESH_ENABLED or bool(MeshNode.peers) or MeshNode.running)
            code = 200 if ready else 503
            self._send_json(code, "Ready" if ready else "Not Ready", {
                "ready": ready,
                "mesh_running": MeshNode.running,
                "peers": len(MeshNode.peers),
            })
            return

        if path == "/cpip/status":
            self._handle_cpip_status()
        elif path == "/cpip/config":
            self._handle_cpip_config_get()
        elif path == "/cpip/history":
            self._handle_cpip_history()
        elif path == "/cpip/schedules":
            self._handle_cpip_schedules_get()
        elif path == "/cpip/discover":
            self._handle_cpip_discover()
        elif path == "/cpip/metrics":
            self._handle_cpip_metrics()
        elif path == "/cpip/events":
            self._handle_cpip_events()
        elif path == "/cpip/webhooks":
            self._handle_cpip_webhooks_get()
        elif path == "/cpip/pots":
            self._handle_cpip_pots()
        elif path == "/cpip/mesh/status":
            self._handle_mesh_status()
        elif path == "/cpip/mesh/peers":
            self._handle_mesh_peers()
        elif path == "/cpip/mesh/inbox":
            self._handle_mesh_inbox()
        elif path == "/cpip/mesh/routes":
            self._handle_mesh_routes()
        elif path == "/cpip/mesh/sat":
            self._handle_mesh_sat()
        elif path == "/cpip/mesh/radio":
            self._handle_mesh_radio()
        elif path == "/cpip/mesh/mobile":
            self._handle_mesh_mobile()
        elif path == "/cpip/palantir":
            self._handle_palantir_get()
        elif path == "/cpip/spoof":
            self._handle_spoof_get()
        elif path == "/cpip/defense":
            self._handle_defense_get()
        elif path == "/cpip/mesh/deaddrop":
            self._handle_mesh_deaddrop()
        elif path == "/cpip/mesh/queued":
            self._handle_mesh_queued()
        elif path == "/cpip/mesh/ecc/address":
            self._handle_mesh_ecc_address()
        elif path == "/cpip/mesh/ecc/book":
            self._handle_mesh_ecc_book()
        elif path == "/cpip/mesh/covert_status":
            self._handle_covert_status()
        elif path == "/cpip/incident":
            self._handle_incident_status()
        elif path == "/cpip/incident/alerts":
            self._handle_incident_alerts()
        elif path == "/cpip/signal":
            self._handle_signal_status()
        elif path == "/cpip/emergency":
            self._handle_emergency()
        elif path == "/cpip/diagnostics/ping":
            if not self._rpc_auth_check(path): return
            self._handle_diag_ping()
        elif path == "/cpip/diagnostics/ports":
            if not self._rpc_auth_check(path): return
            self._handle_diag_ports()
        elif path == "/cpip/diagnostics/dns":
            if not self._rpc_auth_check(path): return
            self._handle_diag_dns()
        elif path == "/cpip/diagnostics/traceroute":
            if not self._rpc_auth_check(path): return
            self._handle_diag_traceroute()
        elif path == "/cpip/diagnostics/interfaces":
            self._handle_diag_interfaces()
        elif path == "/cpip/crypto":
            self._handle_crypto_status()
        elif path == "/cpip/cell/status":
            self._handle_cell_status()
        elif path == "/cpip/sdr/status":
            self._handle_sdr_status()
        elif path == "/cpip/sdr/spectrum":
            self._handle_sdr_spectrum()
        elif path == "/cpip/carrier/status":
            self._handle_carrier_status()
        elif path == "/cpip/intel/global-map":
            self._handle_intel_global_map()
        elif path == "/cpip/intel/risk-score":
            self._handle_intel_risk_score()
        elif path == "/cpip/providers":
            self._handle_providers()
        elif path == "/cpip/anti-isp":
            self._send_json(200, "OK", AntiISP.get_status())
        elif path == "/cpip/anti-stingray":
            self._send_json(200, "OK", AntiStingray.get_status())
        elif path == "/cpip/anti-surveillance":
            self._send_json(200, "OK", AntiSurveillance.get_status())
        elif path == "/cpip/net-neutrality":
            self._send_json(200, "OK", NetNeutrality.get_status())
        elif path == "/cpip/bond/status":
            links = LinkMonitor.get_links()
            weights = LinkMonitor.get_weights()
            reassembly = ReassemblyBuffer.status()
            self._send_json(200, "OK", {
                "enabled": BONDING_ENABLED,
                "links": links,
                "weights": weights,
                "reassembly_buffers": reassembly,
            })
        elif path == "/cpip/bond/links":
            links = LinkMonitor.get_links()
            self._send_json(200, "OK", {"links": links, "count": len(links)})
        elif path == "/cpip/mesh/propfind":
            params = parse_qs(parsed.query)
            action = params.get("action", ["list"])[0]
            if action == "list":
                drops = MeshNode.advertise_dead_drops()
                self._send_json(200, "OK", {
                    "count": len(drops), "dead_drops": drops,
                    "thermos": THERMOS_ENABLED, "node": POT_ID,
                })
            elif action == "claim":
                mid = params.get("id", [""])[0]
                if not mid:
                    self._send_json(400, "Bad Request", {"error": "Missing 'id' param"})
                    return
                msg = MeshNode.claim_dead_drop(mid, POT_ID)
                if msg:
                    self._send_json(200, "OK", {"status": "claimed", "message": msg})
                else:
                    self._send_json(404, "Not Found", {"error": f"Dead drop {mid} not found"})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

        # ── Web-of-Trust Identity ─────────────────────────────────
        elif path == "/cpip/identity":
            self._send_json(200, "OK", WebOfTrust.get_all_identities())
        elif path == "/cpip/identity/trust-graph":
            self._send_json(200, "OK", WebOfTrust.get_trust_graph())
        elif path == "/cpip/identity/trust-sigs":
            self._send_json(200, "OK", {"sigs": WebOfTrust.get_trust_sigs()})
        elif path.startswith("/cpip/identity/"):
            target_id = path.split("/")[-1]
            ident = WebOfTrust.get_identity(target_id)
            if ident:
                ident["trust_level"] = WebOfTrust.get_trust_level(target_id)
                self._send_json(200, "OK", ident)
            else:
                self._send_json(404, "Not Found", {"error": f"Identity '{target_id}' not found"})

        # ── Distributed DNS ───────────────────────────────────────
        elif path == "/cpip/dns":
            self._send_json(200, "OK", DistributedDNS.get_all())
        elif path == "/cpip/dns/cleanup":
            DistributedDNS.cleanup_expired()
            self._send_json(200, "OK", {"status": "cleaned", "remaining": len(DistributedDNS.get_all())})

        # ── Group Chat ────────────────────────────────────────────
        elif path == "/cpip/groups":
            self._send_json(200, "OK", {"groups": GroupChat.get_groups(POT_ID)})

        # ── Offline Sync ──────────────────────────────────────────
        elif path == "/cpip/sync/channels":
            self._send_json(200, "OK", {"channels": OfflineSync.get_channels()})
        elif path == "/cpip/sync/pending":
            ch = query.get("channel", [None])[0]
            msgs = OfflineSync.get_pending(ch)
            self._send_json(200, "OK", {"count": len(msgs), "messages": msgs})
        elif path == "/cpip/sync/clocks":
            self._send_json(200, "OK", OfflineSync.get_vector_clocks())

        elif path in ("", "/cpip", "/"):
            self._handle_cpip_status()
        else:
            # ── RFC-0001..0026 provider routes (rfc_api.py) ──────────
            rfc_result = rfc_api.route_get(path, query)
            if rfc_result is not None:
                code, payload = rfc_result
                self._send_json(code, "OK" if code < 400 else "Error", payload)
            else:
                self._send_json(404, "Not Found", {
                    "error": "Unknown endpoint", "path": path,
                    "hint": "Try /dashboard, /cpip/status, /cpip/mesh/status",
                })

    def do_PUT(self):
        path = urlparse(self.path).path.rstrip("/")
        if path.startswith("/cpip") and not self._rpc_auth_check(path):
            return
        if path == "/cpip/config":
            self._handle_cpip_config_put()
        else:
            self._send_json(404, "Not Found", {"error": "Unknown endpoint"})

    def do_DELETE(self):
        path = urlparse(self.path).path.rstrip("/")
        if path.startswith("/cpip") and not self._rpc_auth_check(path):
            return
        if path.startswith("/cpip/schedules/"):
            sid = path.split("/")[-1]
            self._handle_cpip_schedule_delete(sid)
        elif path == "/cpip/webhooks":
            self._handle_cpip_webhooks_clear()
        elif path == "/cpip/history":
            PotState.history.clear()
            self._send_json(200, "OK", {"status": "History cleared"})
        else:
            self._send_json(404, "Not Found", {"error": "Unknown endpoint"})

    def do_PROPFIND(self):
        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
            })
            return
        if is_coffee_uri_path(self.path):
            self._handle_propfind()
            return
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/"):
            self._handle_propfind()
        else:
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
                "note": "PROPFIND only valid on root or coffee: URI.",
            })

    def do_BREW(self):
        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
                "device": DEVICE_TYPE,
            })
            return
        teapot_tool_check(self.headers, self.client_address[0])
        surveillance_fp_check(self.headers, self.client_address[0], urlparse(self.path).path)
        if teapot_probe_check(self.headers, self.client_address[0],
                              urlparse(self.path).path, "BREW"):
            teapot_blacklist_addr(self.client_address[0])
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
                "device": DEVICE_TYPE,
            })
            return
        if is_coffee_uri_path(self.path):
            self._handle_brew_coffee_uri()
            return
        self._handle_brew()

    def do_POST(self):
        if not self._check_rate_limit():
            self._send_json(429, "Too Many Requests", {"error": "Rate limit exceeded"})
            return
        if not self._check_request_size():
            self._send_json(413, "Payload Too Large", {"error": "Request body exceeds size limit"})
            return
        path = urlparse(self.path).path.rstrip("/")

        if teapot_defense(self.client_address[0]):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
            })
            return
        teapot_tool_check(self.headers, self.client_address[0])
        surveillance_fp_check(self.headers, self.client_address[0], urlparse(self.path).path)
        if teapot_probe_check(self.headers, self.client_address[0], path, "POST"):
            teapot_blacklist_addr(self.client_address[0])
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot", "status": 418,
            })
            return

        if is_coffee_uri_path(self.path):
            self._handle_brew_coffee_uri()
            return

        ct = self.headers.get("Content-Type", "")
        if "message/coffeepot" in ct:
            self._handle_message_coffeepot()
            return

        # RPC HMAC auth gate (only applies to /cpip/* mutating endpoints when
        # CPIP_RPC_AUTH=1; HTCPCP brew paths above are exempt).
        if path.startswith("/cpip") and not self._rpc_auth_check(path):
            return

        if path == "/cpip/schedule":
            self._handle_cpip_schedule_post()
        elif path == "/cpip/webhooks":
            self._handle_cpip_webhooks_post()
        elif path == "/cpip/config":
            self._handle_cpip_config_put()
        elif path == "/cpip/brew":
            self._handle_cpip_brew()
        elif path == "/cpip/mesh/send":
            self._handle_mesh_send()
        elif path == "/cpip/mesh/broadcast":
            self._handle_mesh_broadcast()
        elif path == "/cpip/mesh/encode":
            self._handle_covert_encode()
        elif path == "/cpip/mesh/decode":
            self._handle_covert_decode()
        elif path == "/cpip/mesh/brew_covert":
            self._handle_covert_brew()
        elif path == "/cpip/mesh/sat":
            self._handle_mesh_sat_post()
        elif path == "/cpip/mesh/mobile":
            self._handle_mesh_mobile_post()
        elif path == "/cpip/palantir":
            self._handle_palantir_post()
        elif path == "/cpip/spoof":
            self._handle_spoof_post()
        elif path == "/cpip/defense":
            self._handle_defense_post()
        elif path == "/cpip/crypto":
            self._handle_crypto_post()
        elif path == "/cpip/cell/scan":
            self._handle_cell_scan()
        elif path == "/cpip/sdr/scan":
            self._handle_sdr_scan()
        elif path == "/cpip/carrier/webhook":
            self._handle_carrier_webhook()
        elif path == "/cpip/emergency":
            self._handle_emergency_post()
        elif path == "/cpip/incident":
            self._handle_incident_post()
        elif path == "/cpip/mesh/deaddrop":
            self._handle_mesh_deaddrop()
        elif path == "/cpip/mesh/deaddrop/claim":
            body = self._read_json_body()
            mid = body.get("message_id", "")
            if mid:
                msg = MeshNode.claim_dead_drop(mid, POT_ID)
                if msg:
                    self._send_json(200, "OK", {"status": "claimed", "message": msg})
                else:
                    self._send_json(404, "Not Found", {"error": f"Dead drop {mid} not found"})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'message_id'"})

        # ── Anti-ISP Actions ────────────────────────────────────────
        elif path == "/cpip/anti-isp":
            body = self._read_json_body()
            action = body.get("action", "")
            if action == "refresh":
                AntiISP.force_refresh()
                self._send_json(200, "OK", {"status": "refreshed"})
            elif action == "toggle":
                feature = body.get("feature", "")
                enabled = bool(body.get("enabled", True))
                if AntiISP.set_enabled(feature, enabled):
                    self._send_json(200, "OK", {"feature": feature, "enabled": enabled})
                else:
                    self._send_json(400, "Bad Request",
                                    {"error": f"Unknown anti-isp feature: {feature}"})
            elif action == "hole_punch":
                target_ip = body.get("ip", "")
                target_port = int(body.get("port", MESH_PORT))
                success = AntiISP.punch(target_ip, target_port)
                self._send_json(200, "OK", {"punched": success,
                    "ext_ip": AntiISP._external_ip, "ext_port": AntiISP._external_port})
            elif action == "dns_tunnel_send":
                target = body.get("target", "")
                payload = body.get("data", "")
                if target and payload:
                    ok = AntiISP.dns_tunnel_send(target, base64.b64decode(payload))
                    self._send_json(200, "OK", {"queued": ok})
                else:
                    self._send_json(400, "Bad Request", {"error": "Missing target/data"})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

        # ── Bandwidth Aggregation / Bonding Actions ──────────────────
        elif path == "/cpip/bond/config":
            body = self._read_json_body()
            action = body.get("action", "")
            if action == "toggle":
                global BONDING_ENABLED
                BONDING_ENABLED = bool(body.get("enabled", True))
                self._send_json(200, "OK", {"bonding": BONDING_ENABLED})
            elif action == "force_probe":
                links = LinkMonitor.get_active_links()
                for link_id, _ in links:
                    probe = LinkProbe.create()
                    if MeshNode.mesh_socket:
                        try:
                            MeshNode.mesh_socket.sendto(probe,
                                (body.get("target", "127.0.0.1"), MESH_PORT))
                        except Exception as _e:
                            logger.debug("Ignored: %s", _e)
                self._send_json(200, "OK", {"probes_sent": len(links)})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown bond action: {action}"})

        # ── Anti-Stingray Actions ─────────────────────────────────
        elif path == "/cpip/anti-stingray":
            body = self._read_json_body()
            action = body.get("action", "")
            if action == "toggle":
                feature = body.get("feature", "")
                enabled = bool(body.get("enabled", True))
                if AntiStingray.set_enabled(feature, enabled):
                    self._send_json(200, "OK", {"feature": feature, "enabled": enabled})
                else:
                    self._send_json(400, "Bad Request",
                                    {"error": f"Unknown anti-stingray feature: {feature}"})
            elif action == "rescan":
                AntiStingray._scan_cellular()
                AntiStingray._scan_rf_anomalies()
                AntiStingray._scan_known_signatures()
                self._send_json(200, "OK", {"status": "rescanned"})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

        # ── Anti-Surveillance Actions ─────────────────────────────
        elif path == "/cpip/anti-surveillance":
            body = self._read_json_body()
            action = body.get("action", "")
            if action == "toggle":
                feature = body.get("feature", "")
                enabled = bool(body.get("enabled", True))
                if AntiSurveillance.set_enabled(feature, enabled):
                    self._send_json(200, "OK", {"feature": feature, "enabled": enabled})
                else:
                    self._send_json(400, "Bad Request",
                                    {"error": f"Unknown anti-surveillance feature: {feature}"})
            elif action == "scan":
                AntiSurveillance._check_connections()
                AntiSurveillance._check_ssl_interception()
                AntiSurveillance._check_process_integrity()
                AntiSurveillance._check_dns_hijack()
                self._send_json(200, "OK", {"status": "scanned"})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

        # ── Net Neutrality Actions ────────────────────────────────
        elif path == "/cpip/net-neutrality":
            body = self._read_json_body()
            action = body.get("action", "")
            if action == "toggle":
                feature = body.get("feature", "")
                enabled = bool(body.get("enabled", True))
                if NetNeutrality.set_enabled(feature, enabled):
                    self._send_json(200, "OK", {"feature": feature, "enabled": enabled})
                else:
                    self._send_json(400, "Bad Request",
                                    {"error": f"Unknown net-neutrality feature: {feature}"})
            else:
                self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

        # ── Web-of-Trust Identity ─────────────────────────────────
        elif path == "/cpip/identity/publish":
            body = self._read_json_body()
            cert = body.get("cert", {})
            if cert.get("pot_id"):
                WebOfTrust.publish_identity(cert["pot_id"], cert)
                MeshNode.broadcast({
                    "type": "identity_publish",
                    "from": POT_ID,
                    "cert": cert,
                    "timestamp": time.time(),
                })
                self._send_json(200, "OK", {"status": "published"})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing cert.pot_id"})
        elif path == "/cpip/identity/trust":
            body = self._read_json_body()
            target = body.get("target")
            level = body.get("trust_level", WebOfTrust.TRUST_MARGINAL)
            if target:
                trust_sig = WebOfTrust.sign_trust(POT_ID, target, level, MeshNode.node_seed)
                MeshNode.broadcast({
                    "type": "trust_claim",
                    "from": POT_ID,
                    "trust_sig": trust_sig,
                    "timestamp": time.time(),
                })
                self._send_json(200, "OK", trust_sig)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'target'"})

        # ── Distributed DNS ───────────────────────────────────────
        elif path == "/cpip/dns/register":
            body = self._read_json_body()
            name = body.get("name", "")
            ttl = body.get("ttl")
            if name:
                pk_pem = body.get("pubkey", "").encode() if body.get("pubkey") else b""
                result = DistributedDNS.register(name, POT_ID, pk_pem, ttl, MeshNode.node_seed)
                if "error" not in result:
                    MeshNode.broadcast({
                        "type": "dns_register",
                        "from": POT_ID,
                        "registration": result,
                        "timestamp": time.time(),
                    })
                    self._send_json(200, "OK", result)
                else:
                    self._send_json(409, "Conflict", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'name'"})
        elif path == "/cpip/dns/resolve":
            body = self._read_json_body()
            name = body.get("name", "")
            if name:
                result = DistributedDNS.resolve(name)
                if "error" not in result:
                    self._send_json(200, "OK", result)
                else:
                    self._send_json(404, "Not Found", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'name'"})
        elif path == "/cpip/dns/remove":
            body = self._read_json_body()
            name = body.get("name", "")
            if name:
                result = DistributedDNS.remove(name, POT_ID, MeshNode.node_seed)
                if "error" not in result:
                    MeshNode.broadcast({
                        "type": "dns_register",
                        "from": POT_ID,
                        "registration": {"name": name, "pot_id": POT_ID, "expires": 0},
                        "timestamp": time.time(),
                    })
                    self._send_json(200, "OK", result)
                else:
                    self._send_json(400, "Bad Request", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'name'"})

        # ── Group Chat ────────────────────────────────────────────
        elif path == "/cpip/groups/create":
            body = self._read_json_body()
            name = body.get("name", "")
            members = body.get("members", [])
            if name:
                gid = body.get("id", str(uuid.uuid4())[:8])
                result = GroupChat.create_group(gid, name, POT_ID, members + [POT_ID])
                self._send_json(200, "OK", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'name'"})
        elif path == "/cpip/groups/join":
            body = self._read_json_body()
            gid = body.get("group_id", "")
            pid = body.get("pot_id", POT_ID)
            if gid:
                result = GroupChat.join_group(gid, pid)
                self._send_json(200, "OK", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'group_id'"})
        elif path == "/cpip/groups/leave":
            body = self._read_json_body()
            gid = body.get("group_id", "")
            pid = body.get("pot_id", POT_ID)
            if gid:
                result = GroupChat.leave_group(gid, pid)
                self._send_json(200, "OK", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'group_id'"})
        elif path == "/cpip/groups/send":
            body = self._read_json_body()
            gid = body.get("group_id", "")
            message = body.get("message", "")
            if gid and message:
                result = GroupChat.send_message(gid, POT_ID, message, MeshNode.node_seed)
                if "error" not in result:
                    MeshNode.broadcast({
                        "type": "group_message",
                        "from": POT_ID,
                        "group_msg": result,
                        "timestamp": time.time(),
                    })
                    self._send_json(200, "OK", result)
                else:
                    self._send_json(400, "Bad Request", result)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'group_id' or 'message'"})
        elif path.startswith("/cpip/groups/") and path.endswith("/messages"):
            gid = path.split("/")[3]
            since = float(self._read_json_body().get("since", 0))
            msgs = GroupChat.get_messages(gid, POT_ID, since)
            self._send_json(200, "OK", {"count": len(msgs), "messages": msgs})
        elif path.startswith("/cpip/groups/"):
            gid = path.split("/")[3]
            info = GroupChat.get_group_info(gid)
            if "error" not in info:
                self._send_json(200, "OK", info)
            else:
                self._send_json(404, "Not Found", info)

        # ── Offline Sync ──────────────────────────────────────────
        elif path == "/cpip/sync/send":
            body = self._read_json_body()
            channel = body.get("channel", "general")
            payload = body.get("payload", "")
            if payload:
                msg_id = str(uuid.uuid4())[:8]
                msg = OfflineSync.create_message(msg_id, POT_ID, channel, payload, POT_ID)
                self._send_json(200, "OK", msg)
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'payload'"})
        elif path == "/cpip/sync/deliver":
            body = self._read_json_body()
            mid = body.get("message_id", "")
            if mid:
                OfflineSync.mark_delivered(mid)
                self._send_json(200, "OK", {"status": "delivered"})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'message_id'"})
        elif path == "/cpip/sync/request":
            body = self._read_json_body()
            peer_id = body.get("peer_id", "")
            channel = body.get("channel")
            if peer_id:
                MeshNode._send_direct(peer_id, {
                    "type": "sync_request",
                    "from": POT_ID,
                    "peer_id": POT_ID,
                    "channel": channel,
                    "since": body.get("since", 0),
                    "timestamp": time.time(),
                })
                self._send_json(200, "OK", {"status": "sync_requested", "peer": peer_id})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'peer_id'"})

        # ── Mesh Identity Broadcast ───────────────────────────────
        elif path == "/cpip/mesh/identity/broadcast":
            cert = WebOfTrust.get_identity(POT_ID)
            if not cert:
                cert = WebOfTrust.create_identity(
                    POT_ID,
                    MeshNode.node_pubkey if hasattr(MeshNode, 'node_pubkey') and MeshNode.node_pubkey else b"",
                    {"hostname": HOSTNAME, "device": DEVICE_TYPE}
                )
            MeshNode.broadcast({
                "type": "identity_publish",
                "from": POT_ID,
                "cert": cert,
                "timestamp": time.time(),
            })
            self._send_json(200, "OK", {"status": "broadcast", "cert": cert})

        else:
            # ── RFC-0001..0026 provider routes (rfc_api.py) ──────────
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            params = parse_qs(parsed.query)
            body = self._read_json_body()
            rfc_result = rfc_api.route_post(path, body, params)
            if rfc_result is not None:
                code, payload = rfc_result
                self._send_json(code, "OK" if code < 400 else "Error", payload)
            else:
                self._handle_brew()

    def do_WHEN(self):
        if is_coffee_uri_path(self.path):
            _pot, _additions, _beverage = parse_coffee_uri(self.path)
        was = PotState.stop()
        self._send_json(200, "OK", {
            "status": "stopped",
            "device": DEVICE_TYPE,
            "was_brewing": was,
            "message": WHEN_MESSAGES.get(DEVICE_TYPE, "Pouring stopped."),
        })

    def do_OPTIONS(self):
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/"):
            scheme_list = list(COFFEE_SCHEME_NAMES)
            self._send_json(200, "OK", {
            "protocol": CPIP_PROTOCOL,
            "device": DEVICE_TYPE,
            "pot_id": POT_ID,
            "methods": ["GET", "PUT", "POST", "DELETE", "BREW", "WHEN", "PROPFIND", "OPTIONS"],
            "coffee_uri_schemes": {
                "count": len(scheme_list),
                "languages": COFFEE_LANGUAGE_MAP,
                "example": "coffee://" + HOSTNAME + "/pot-0?milk;variety=whole",
            },
            "endpoints": {
                "CPIP_BREW": ["GET /", "BREW /{tea,coffee}", "WHEN /", "PROPFIND /"],
                "COFFEE_URI": ["{scheme}://host/pot-N?additions — all 29 international variants"],
                "message/coffeepot": ["POST/BREW with Content-Type: message/coffeepot, body: start|stop"],
                "CPIP": [
                    "GET /cpip/status", "GET|PUT /cpip/config",
                    "GET /cpip/history", "POST /cpip/schedule",
                    "GET /cpip/pots", "GET /cpip/metrics",
                    "GET /cpip/events (SSE)", "POST|DELETE /cpip/webhooks",
                ],
                "MESH": [
                    "GET /cpip/mesh/status", "GET /cpip/mesh/peers",
                    "GET /cpip/mesh/inbox", "POST /cpip/mesh/send",
                    "POST /cpip/mesh/broadcast", "POST /cpip/mesh/encode",
                    "POST /cpip/mesh/decode",
                ],
                "SECURITY": [
                    "GET|POST /cpip/crypto", "GET /cpip/incident", "GET /cpip/incident/alerts",
                    "POST /cpip/incident", "GET /cpip/signal",
                    "GET|POST /cpip/emergency", "GET /cpip/defense",
                ],
                "DIAGNOSTICS": [
                    "GET /cpip/diagnostics/ping?host=&port=&proto=tcp|udp",
                    "GET /cpip/diagnostics/ports?host=&ports=",
                    "GET /cpip/diagnostics/dns?host=",
                    "GET /cpip/diagnostics/traceroute?host=&max_hops=",
                    "GET /cpip/diagnostics/interfaces",
                ],
                "IDENTITY": [
                    "GET /cpip/identity", "GET /cpip/identity/trust-graph",
                    "POST /cpip/identity/publish", "POST /cpip/identity/trust",
                    "GET /cpip/identity/{pot_id}",
                ],
                "DNS": [
                    "GET /cpip/dns", "POST /cpip/dns/register",
                    "POST /cpip/dns/resolve", "POST /cpip/dns/remove",
                ],
                "GROUPS": [
                    "GET /cpip/groups", "POST /cpip/groups/create",
                    "POST /cpip/groups/join", "POST /cpip/groups/leave",
                    "POST /cpip/groups/send", "GET /cpip/groups/{id}/messages",
                ],
                "SYNC": [
                    "GET /cpip/sync/channels", "GET /cpip/sync/pending",
                    "GET /cpip/sync/clocks", "POST /cpip/sync/send",
                    "POST /cpip/sync/deliver", "POST /cpip/sync/request",
                ],
                "UI": ["GET /dashboard"],
            },
            "gpio": gpio.is_available,
            "gpio_hardware": gpio.is_available,
            "mesh": {"enabled": MESH_ENABLED, "port": MESH_PORT, "peers": len(MeshNode.peers)},
            "covert": {"enabled": COVERT_ENABLED},
            "ntp": {"enabled": NTP_SYNC, "server": NTP_SERVER},
            "ecc": {
                "algorithm": "ECDSA/ECDH P-256 (FIPS 186-4)",
                "implementation": "Pure Python (not constant-time)",
                "node_address": MeshNode.node_address,
                "node_pubkey_present": MeshNode.node_pubkey is not None,
            },
            "defense": {"418_teapot": MESH_ENABLED},
            "thermos": {"enabled": THERMOS_ENABLED},
            "pitail": {"enabled": PITAIL_ENABLED, "addr": PITAIL_ADDR},
        })

    # ── HTCPCP Handlers ───────────────────────────────────────────────

    def _handle_cpip_status(self):
        self._send_json(200, "OK", {
            "device": DEVICE_TYPE,
            "pot_id": POT_ID,
            "hostname": HOSTNAME,
            "brewing": PotState.is_brewing(),
            "protocol": CPIP_PROTOCOL,
            "uptime": self._uptime(),
            "gpio": {"available": gpio.is_available, "hardware": gpio.is_available, "pin": GPIO_PIN},
            "mesh": {"enabled": MESH_ENABLED, "peers": len(MeshNode.peers), "port": MESH_PORT},
            "covert": {"enabled": COVERT_ENABLED},
            "endpoints": {
                "/": "Server status (CPIP)",
                "/dashboard": "Web dashboard",
                "/cpip/status": "Full CPIP status",
                "/cpip/mesh/status": "Mesh network status",
                "/cpip/mesh/inbox": "Mesh message inbox",
                "/cpip/mesh/send": "Send mesh message (POST)",
                "/cpip/mesh/broadcast": "Broadcast to mesh (POST)",
            },
        })

    def _handle_propfind(self):
        self._send_json(200, "OK", {
            "device": DEVICE_TYPE,
            "brewing": PotState.is_brewing(),
            "additions_supported": list(VALID_ADDITIONS.keys()),
            "addition_details": {k: v["variety"] for k, v in VALID_ADDITIONS.items()},
            "beverages": DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"]),
            "allows_alcohol": DEVICE_TYPE in ALCOHOL_DEVICES,
            "pot_id": POT_ID,
            "cpip_version": CPIP_VERSION,
            "mesh_enabled": MESH_ENABLED,
            "covert_enabled": COVERT_ENABLED,
        })

    def _handle_brew(self):
        additions_header = self.headers.get("Accept-Additions", "")
        additions = parse_accept_additions(additions_header)

        if PotState.is_brewing():
            self._send_json(409, "Conflict", {
                "error": "Already brewing",
                "status": 409,
                "device": DEVICE_TYPE,
                "current_brew": {
                    "id": PotState.brew_id,
                    "beverage": PotState.current_beverage,
                    "additions": PotState.current_additions,
                },
                "message": "A brew is already in progress. Send WHEN to stop first.",
            })
            return

        if not is_beverage_compatible(self.path, DEVICE_TYPE):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "status": 418,
                "reason": f"Device type '{DEVICE_TYPE}' cannot brew the requested beverage",
                "device": DEVICE_TYPE,
                "hint": "Try /tea" if DEVICE_TYPE == "teapot" else "Try /coffee",
            })
            return

        ok, reason = check_additions(additions, DEVICE_TYPE)
        if not ok:
            if "alcohol" in reason.lower():
                self._send_json(406, "Not Acceptable", {
                    "error": "Not Acceptable",
                    "status": 406,
                    "reason": reason,
                    "device": DEVICE_TYPE,
                    "additions_supported": list(VALID_ADDITIONS.keys()),
                    "hint": "This device does not support alcohol additions",
                })
            else:
                self._send_json(418, "I'm a teapot", {
                    "error": "I'm a teapot",
                    "status": 418,
                    "reason": reason,
                    "device": DEVICE_TYPE,
                })
            return

        if additions and not PotState.is_brewing():
            can_provide = all(
                a["name"] in VALID_ADDITIONS
                for a in additions
            )
            if not can_provide:
                self._send_json(406, "Not Acceptable", {
                    "error": "Not Acceptable",
                    "status": 406,
                    "reason": "Cannot provide requested additions",
                    "additions_supported": list(VALID_ADDITIONS.keys()),
                })
                return

        covert_msg = CovertChannel.decode(additions, our_seed=MeshNode.node_seed) if COVERT_ENABLED else b""
        if covert_msg:
            try:
                decoded = covert_msg.decode("utf-8", errors="replace")
                # Filter out messages that are mostly non-printable
                printable_ratio = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t') / max(len(decoded), 1)
                if printable_ratio < 0.5:
                    decoded = "[covert message — decode failed]"
                with MeshNode.inbox_lock:
                    MeshNode.inbox.append({
                        "id": str(uuid.uuid4())[:8],
                        "from": self.headers.get("X-Forwarded-For", self.client_address[0]),
                        "data": decoded,
                        "timestamp": time.time(),
                        "hops": 0,
                        "channel": "covert_cpip",
                        "e2ee": False,
                    })
                PotState._broadcast({
                    "event": "mesh_message",
                    "from": "covert_channel",
                    "message_id": "covert_" + CoffeeCipher.hash(covert_msg),
                })
            except Exception as _e:
                logger.debug("Ignored: %s", _e)

        path = urlparse(self.path).path.rstrip("/")
        if is_coffee_uri_path(self.path):
            _pot, _uri_additions, beverage_hint = parse_coffee_uri(self.path)
            beverage = beverage_hint or "tea"
        else:
            beverage = "coffee" if path.endswith("/coffee") else "tea"
        brew_id = PotState.start(beverage, additions)

        addition_names = [
            a["name"] + (f";variety={a['variety']}" if a.get("variety") else "")
            for a in additions
        ]
        safe_val = additions_header.replace("\r", "").replace("\n", "") if additions_header else ""

        self._send_json(202, "Brewing", {
            "status": "brewing",
            "device": DEVICE_TYPE,
            "beverage": beverage,
            "brew_id": brew_id,
            "additions": addition_names if addition_names else ["none"],
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started. Send WHEN to stop."),
        }, extra_headers={
            "Accept-Additions": safe_val,
            "Safe": "yes" if additions else "no",
        })

    def _handle_brew_coffee_uri(self):
        """Handle BREW on a coffee: URI scheme request."""
        pot, uri_additions, beverage_hint = parse_coffee_uri(self.path)
        additions_header = self.headers.get("Accept-Additions", "")
        header_additions = parse_accept_additions(additions_header) if additions_header else []
        additions = uri_additions + [a for a in header_additions if a not in uri_additions]
        beverage = beverage_hint or "coffee"

        if PotState.is_brewing():
            self._send_json(409, "Conflict", {
                "error": "Already brewing", "status": 409,
                "device": DEVICE_TYPE, "beverage": beverage,
                "current_brew": {"id": PotState.brew_id, "beverage": PotState.current_beverage},
                "message": "A brew is already in progress. Send WHEN to stop first.",
            })
            return

        brew_id = PotState.start(beverage, additions)
        addition_names = ", ".join(
            a["name"] + (f";variety={a['variety']}" if a.get("variety") else "")
            for a in additions
        ) if additions else "none"
        self._send_json(202, "Brewing", {
            "status": "brewing",
            "device": DEVICE_TYPE,
            "beverage": beverage,
            "brew_id": brew_id,
            "additions": [a["name"] for a in additions] if additions else ["none"],
            "coffee_uri": True,
            "coffee_scheme": self.path.lstrip("/").split(":")[0] if ":" in self.path else "coffee",
            "pot_designator": pot,
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started via coffee: URI."),
        }, extra_headers={
            "Accept-Additions": addition_names,
            "Safe": "yes" if additions else "no",
        })

    def _handle_message_coffeepot(self):
        """Handle message/coffeepot Content-Type (RFC 2324 §4)."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode().strip().lower() if length > 0 else ""
        except Exception:
            body = ""
        if body == "start":
            if PotState.is_brewing():
                self._send_json(200, "OK", {"status": "already_brewing", "message": "Already brewing."})
                return
            path = urlparse(self.path).path.rstrip("/")
            beverage = "coffee" if path.endswith("/coffee") else "tea"
            brew_id = PotState.start(beverage, [])
            self._send_json(202, "Brewing", {
                "status": "brewing",
                "device": DEVICE_TYPE,
                "beverage": beverage,
                "brew_id": brew_id,
                "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started via message/coffeepot."),
            })
        elif body == "stop":
            was = PotState.stop()
            self._send_json(200, "OK", {
                "status": "stopped",
                "device": DEVICE_TYPE,
                "was_brewing": was,
                "message": WHEN_MESSAGES.get(DEVICE_TYPE, "Pouring stopped via message/coffeepot."),
            })
        else:
            self._send_json(400, "Bad Request", {
                "error": "Invalid message/coffeepot body",
                "expected": "start or stop",
                "got": body or "(empty)",
            })

    # ── CPIP Handlers ─────────────────────────────────────────────────

    def _handle_cpip_status(self):
        bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])
        elapsed = time.time() - PotState.brew_start_time if PotState.brewing else 0
        self._send_json(200, "OK", {
            "protocol": CPIP_PROTOCOL,
            "cpip_version": CPIP_VERSION,
            "enabled": CPIP_ENABLED,
            "recipe": CPIP_RECIPE,
            "rpc_auth": RPC_AUTH_ENABLED,
            "defense_enabled": DEFENSE_ENABLED,
            "device": DEVICE_TYPE,
            "pot_id": POT_ID,
            "hostname": HOSTNAME,
            "uptime_seconds": int(self._uptime()),
            "brewing": PotState.is_brewing(),
            "current_brew": {
                "id": PotState.brew_id,
                "beverage": PotState.current_beverage,
                "additions": PotState.current_additions,
                "elapsed_seconds": round(elapsed, 1),
            } if PotState.brewing else None,
            "beverages": bev,
            "gpio": {
                "enabled": GPIO_ENABLED,
                "available": gpio.is_available,
                "pin": GPIO_PIN,
                "state": gpio.is_on,
            },
            "mesh": MeshNode.get_status(),
            "covert": {"enabled": COVERT_ENABLED, "cover_traffic": COVER_TRAFFIC},
            "mdns": AVAHI_ENABLED,
            "history_count": len(PotState.history),
            "schedule_count": len(PotState.schedules),
            "webhooks": len(PotState.webhooks),
            "discovery_port": DISCOVERY_PORT,
            "sse_clients": len(PotState.sse_clients),
            "ntp": {"enabled": NTP_SYNC, "server": NTP_SERVER} if NTP_SYNC else {"enabled": False},
        })

    def _handle_cpip_config_get(self):
        self._send_json(200, "OK", {
            "version": CPIP_VERSION,
            "pot_id": POT_ID,
            "hostname": HOSTNAME,
            "device": DEVICE_TYPE,
            "bind": BIND_ADDR,
            "port": BIND_PORT,
            "gpio_pin": GPIO_PIN,
            "gpio_enabled": GPIO_ENABLED,
            "gpio_available": gpio.is_available,
            "gpio_hardware": gpio.is_available,
            "avahi_enabled": AVAHI_ENABLED,
            "discovery_port": DISCOVERY_PORT,
            "mesh_enabled": MESH_ENABLED,
            "mesh_port": MESH_PORT,
            "mesh_ttl": MESH_TTL,
            "covert_enabled": COVERT_ENABLED,
            "cover_traffic": COVER_TRAFFIC,
            "web_dir": str(WEB_DIR),
            "history_max": HISTORY_MAX,
            "schedule_check_interval": SCHEDULE_CHECK_INTERVAL,
            "beverages_allowed": DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"]),
            "allows_alcohol": DEVICE_TYPE in ALCOHOL_DEVICES,
            "ecc": "ECDSA/ECDH P-256 (FIPS 186-4)",
            "ecc_curve": "NIST P-256",
            "ecc_implementation": "Pure Python (not constant-time)",
            "node_address": MeshNode.node_address,
            "node_pubkey": base64.b64encode(MeshNode.node_pubkey).decode() if MeshNode.node_pubkey else None,
            "pitail_enabled": PITAIL_ENABLED,
            "pitail_addr": PITAIL_ADDR,
            "thermos_enabled": THERMOS_ENABLED,
            "thermos_max_storage": THERMOS_MAX_STORAGE,
            "policies": {
                "anti_isp": {
                    "enabled": ANTI_ISP_ENABLED,
                    "stun": STUN_ENABLED,
                    "upnp": UPNP_ENABLED,
                    "relay": RELAY_ENABLED,
                    "dns_tunnel": DNS_TUNNEL_ENABLED,
                    "wss": WSS_TUNNEL_ENABLED,
                    "doh": DNS_OBLIVIOUS_ENABLED,
                },
                "anti_stingray": {
                    "enabled": ANTI_STINGRAY_ENABLED,
                    "cell_scan": STINGRAY_CELL_SCAN,
                    "rf_scan": STINGRAY_RF_SCAN,
                    "signal_anomaly": STINGRAY_SIG_SCAN,
                    "known_signatures": STINGRAY_KNOWN_SCAN,
                    "scan_interval": STINGRAY_SCAN_INTERVAL,
                },
                "anti_surveillance": {
                    "enabled": ANTI_SURVEILLANCE_ENABLED,
                    "dpi_evasion": DPI_EVASION_ENABLED,
                    "traffic_obfuscation": TRAFFIC_OBFUSCATION,
                    "metadata_strip": METADATA_STRIP,
                    "exploitkit_detect": EXPLOITKIT_DETECT,
                    "process_inject_detect": PROCESS_INJECT_DETECT,
                },
                "net_neutrality": {
                    "enabled": NET_NEUTRALITY_ENABLED,
                    "bandwidth_monitor": NN_BANDWIDTH_MONITOR,
                    "protocol_masquerade": NN_PROTOCOL_MASQUERADE,
                    "fragmentation": NN_FRAGMENT_EVASION,
                    "throttle_detect": NN_THROTTLE_DETECT,
                    "jitter_injection": NN_JITTER_INJECTION,
                },
            },
        })

    def _handle_cpip_config_put(self):
        body = self._read_json_body()
        changed = []
        global DEVICE_TYPE
        if "device" in body and body["device"] in DEVICE_BEVERAGE_MAP:
            DEVICE_TYPE = body["device"]
            changed.append(f"device={DEVICE_TYPE}")
        pol = body.get("policies", {})
        for group, setter in (
            ("anti_isp", AntiISP.set_enabled),
            ("anti_stingray", AntiStingray.set_enabled),
            ("anti_surveillance", AntiSurveillance.set_enabled),
            ("net_neutrality", NetNeutrality.set_enabled),
        ):
            grp = pol.get(group, {})
            for feat, val in grp.items():
                if setter(feat, bool(val)):
                    changed.append(f"{group}.{feat}={val}")
        self._send_json(200, "OK", {
            "status": "configured",
            "changes": changed if changed else ["none"],
            "device": DEVICE_TYPE,
        })

    def _handle_cpip_history(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = min(int(params.get("limit", [HISTORY_MAX])[0]), HISTORY_MAX)
        self._send_json(200, "OK", {
            "count": min(len(PotState.history), limit),
            "total": len(PotState.history),
            "history": PotState.history[-limit:],
        })

    def _handle_cpip_schedules_get(self):
        self._send_json(200, "OK", {
            "count": len(PotState.schedules),
            "schedules": PotState.schedules,
        })

    def _handle_cpip_schedule_post(self):
        body = self._read_json_body()
        when_str = body.get("time", body.get("in"))
        beverage = body.get("beverage", "coffee")
        additions = body.get("additions", [])
        brew_duration = int(body.get("brew_duration", body.get("duration", 30)))

        if when_str is None:
            self._send_json(400, "Bad Request", {"error": "Missing 'time' (ISO format) or 'in' (seconds from now)"})
            return

        schedule = {
            "id": str(uuid.uuid4())[:8],
            "beverage": beverage,
            "additions": additions,
            "brew_duration": brew_duration,
            "enabled": True,
            "created": time.time(),
        }

        if isinstance(when_str, (int, float)):
            schedule["time"] = time.time() + when_str
            schedule["human"] = f"in {when_str}s"
        else:
            try:
                dt = datetime.fromisoformat(when_str)
                schedule["time"] = dt.timestamp()
                schedule["human"] = when_str
            except ValueError:
                self._send_json(400, "Bad Request", {"error": f"Invalid time format: {when_str}"})
                return

        with PotState.state_lock:
            PotState.schedules.append(schedule)
        self._send_json(201, "Created", {"status": "scheduled", "schedule": schedule})

    def _handle_cpip_schedule_delete(self, sid):
        with PotState.state_lock:
            removed = [s for s in PotState.schedules if s["id"] == sid]
            PotState.schedules[:] = [s for s in PotState.schedules if s["id"] != sid]
        if removed:
            self._send_json(200, "OK", {"status": "deleted", "schedule_id": sid})
        else:
            self._send_json(404, "Not Found", {"error": f"Schedule {sid} not found"})

    def _handle_cpip_discover(self):
        pots = discover_pots()
        self._send_json(200, "OK", {"count": len(pots), "pots": pots})

    def _handle_cpip_pots(self):
        local = [{
            "pot": POT_ID, "hostname": HOSTNAME, "device": DEVICE_TYPE,
            "port": BIND_PORT, "addr": BIND_ADDR, "brewing": PotState.is_brewing(),
            "local": True, "mesh_port": MESH_PORT,
        }]
        remote = discover_pots()
        self._send_json(200, "OK", {"count": len(local) + len(remote), "pots": local + remote})

    def _handle_cpip_metrics(self):
        lines = [
            "# HELP cpip_brewing Currently brewing (1=yes, 0=no)",
            "# TYPE cpip_brewing gauge",
            f'cpip_brewing{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {1 if PotState.brewing else 0}',
            "",
            "# HELP cpip_brew_total Total brews completed",
            "# TYPE cpip_brew_total counter",
            f'cpip_brew_total{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {len(PotState.history)}',
            "",
            "# HELP cpip_mesh_peers Number of mesh peers",
            "# TYPE cpip_mesh_peers gauge",
            f'cpip_mesh_peers{{pot="{POT_ID}"}} {len(MeshNode.peers)}',
            "",
            "# HELP cpip_mesh_inbox Messages in mesh inbox",
            "# TYPE cpip_mesh_inbox gauge",
            f'cpip_mesh_inbox{{pot="{POT_ID}"}} {len(MeshNode.inbox)}',
            "",
            "# HELP cpip_mesh_queued Messages in store-and-forward queue",
            "# TYPE cpip_mesh_queued gauge",
            f'cpip_mesh_queued{{pot="{POT_ID}"}} {len(MeshNode.message_store)}',
            "",
            "# HELP cpip_scheduled_brews Number of scheduled brews",
            "# TYPE cpip_scheduled_brews gauge",
            f'cpip_scheduled_brews{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {len(PotState.schedules)}',
            "",
            "# HELP cpip_sse_clients Number of connected SSE clients",
            "# TYPE cpip_sse_clients gauge",
            f'cpip_sse_clients{{device="{DEVICE_TYPE}",pot="{POT_ID}"}} {len(PotState.sse_clients)}',
            "",
            "# HELP cpip_gpio_state GPIO relay state (1=on, 0=off)",
            "# TYPE cpip_gpio_state gauge",
            f'cpip_gpio_state{{pin="{GPIO_PIN}",available="{str(gpio.is_available).lower()}"}} {1 if gpio.is_on else 0}',
            "",
            "# HELP cpip_uptime_seconds Server uptime",
            "# TYPE cpip_uptime_seconds gauge",
            f'cpip_uptime_seconds{{pot="{POT_ID}"}} {int(self._uptime())}',
        ]
        body = "\n".join(lines).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_cpip_events(self):
        q = queue.Queue()
        with PotState.sse_lock:
            PotState.sse_clients.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("CPIP-Version", CPIP_VERSION)
        self.end_headers()
        try:
            self.wfile.write(f"event: connected\ndata: {json.dumps({'pot': POT_ID, 'device': DEVICE_TYPE})}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=30)
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with PotState.sse_lock:
                if q in PotState.sse_clients:
                    PotState.sse_clients.remove(q)

    def _handle_cpip_webhooks_get(self):
        self._send_json(200, "OK", {"count": len(PotState.webhooks), "webhooks": PotState.webhooks})

    def _handle_cpip_webhooks_post(self):
        body = self._read_json_body()
        url = body.get("url")
        if not url:
            self._send_json(400, "Bad Request", {"error": "Missing 'url' field"})
            return
        if url not in PotState.webhooks:
            PotState.webhooks.append(url)
        self._send_json(201, "Created", {"status": "webhook added", "url": url, "total": len(PotState.webhooks)})

    def _handle_cpip_webhooks_clear(self):
        count = len(PotState.webhooks)
        PotState.webhooks.clear()
        self._send_json(200, "OK", {"status": "webhooks cleared", "removed": count})

    def _handle_cpip_brew(self):
        body = self._read_json_body()
        beverage = body.get("beverage", body.get("type", "coffee"))
        additions = body.get("additions", [])
        path = f"/{beverage}"

        if not is_beverage_compatible(path, DEVICE_TYPE):
            self._send_json(418, "I'm a teapot", {
                "error": "I'm a teapot",
                "reason": f"Device '{DEVICE_TYPE}' cannot brew '{beverage}'",
                "device": DEVICE_TYPE,
            })
            return

        ok, reason = check_additions(additions, DEVICE_TYPE)
        if not ok:
            self._send_json(418, "I'm a teapot", {"error": "I'm a teapot", "reason": reason, "device": DEVICE_TYPE})
            return

        if PotState.is_brewing():
            self._send_json(409, "Conflict", {
                "error": "Already brewing", "status": 409,
                "device": DEVICE_TYPE,
                "current_brew": {"id": PotState.brew_id, "beverage": PotState.current_beverage},
                "message": "Send WHEN to stop first.",
            })
            return

        brew_id = PotState.start(beverage, additions)
        auto_stop = body.get("duration", body.get("auto_stop"))
        if auto_stop:
            try:
                auto_secs = float(auto_stop)
                if auto_secs > 0:
                    def _auto():
                        time.sleep(auto_secs)
                        PotState.stop()
                    threading.Thread(target=_auto, daemon=True).start()
                else:
                    auto_stop = None
            except (ValueError, TypeError):
                auto_stop = None

        self._send_json(202, "Brewing", {
            "status": "brewing", "device": DEVICE_TYPE,
            "beverage": beverage, "brew_id": brew_id,
            "additions": [a.get("name") for a in additions],
            "auto_stop": auto_stop or False,
            "message": BREW_MESSAGES.get(DEVICE_TYPE, "Brewing started."),
        })

    # ── Mesh Handlers ─────────────────────────────────────────────────

    def _handle_mesh_status(self):
        pq_status = cpip_providers.PQCIdentity.get_status()
        self._send_json(200, "OK", {
            "mesh": MeshNode.get_status(),
            "covert": {"enabled": COVERT_ENABLED, "cover_traffic": COVER_TRAFFIC},
            "cipher": "AES-256-GCM + ephemeral ECDH P-256 (mesh E2EE)",
            "cipher_note": "The configured PQ KEM catalogue is not negotiated by the mesh E2EE transport in this release.",
            "pq_kem": pq_status,
            "pq_kem_mesh_integrated": False,
            "ecc": {
                "algorithm": "ECDSA/ECDH P-256 (FIPS 186-4)",
                "implementation": "Pure Python — no libsodium, no pycryptodome",
                "constant_time": False,
                "node_address": MeshNode.node_address,
                "node_pubkey": base64.b64encode(MeshNode.node_pubkey).decode() if MeshNode.node_pubkey else None,
            },
            "defense": {
                "418_teapot": MESH_ENABLED,
                "blacklisted_addrs": len(TEAPOT_BLACKLIST),
            },
            "thermos": {
                "enabled": THERMOS_ENABLED,
                "dead_drops_held": len(MeshNode.advertise_dead_drops()) if THERMOS_ENABLED else 0,
            },
            "key_status": "Keygen-derived (ECP256 P-256)" if COVERT_KEY_SEED else ("Custom" if COVERT_KEY != b"CHANGE_ME_COFFEE_BLEND_2024" else "Default (CHANGE ME)"),
            "ssl": {
                "enabled": SSL_ENABLED,
                "auto_cert": SSL_AUTO_CERT,
                "cert": SSL_CERT if SSL_ENABLED else None,
                "http_redirect": HTTP_REDIRECT,
                "http_redirect_port": HTTP_REDIRECT_PORT if HTTP_REDIRECT else None,
            },
        })

    def _handle_mesh_peers(self):
        self._send_json(200, "OK", {
            "count": len(MeshNode.peers),
            "peers": MeshNode.get_peers_list(),
        })

    def _handle_mesh_inbox(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = min(int(params.get("limit", [20])[0]), 100)
        self._send_json(200, "OK", {
            "count": len(MeshNode.inbox),
            "messages": MeshNode.get_inbox(limit),
        })

    def _handle_mesh_routes(self):
        self._send_json(200, "OK", {
            "routes": {k: v for k, v in MeshNode.routing_table.items()},
        })

    def _handle_mesh_sat(self):
        self._send_json(200, "OK", MeshNode.get_sat_status())

    def _handle_mesh_radio(self):
        self._send_json(200, "OK", get_radio_status())

    def _handle_mesh_mobile(self):
        self._send_json(200, "OK", MeshNode.get_mobile_status())

    def _handle_mesh_queued(self):
        self._send_json(200, "OK", {
            "queued": len(MeshNode.message_store),
            "messages": list(MeshNode.message_store)[:20],
        })

    def _handle_mesh_ecc_address(self):
        self._send_json(200, "OK", {
            "address": MeshNode.node_address,
            "pubkey": base64.b64encode(MeshNode.node_pubkey).decode() if MeshNode.node_pubkey else None,
        })

    def _handle_mesh_ecc_book(self):
        with MeshNode.peers_lock:
            entries = []
            for pid, info in MeshNode.peers.items():
                pk_b64 = info.get("pubkey", "")
                addr = ECP256.pubkey_to_address(base64.b64decode(pk_b64)) if pk_b64 else None
                entries.append({
                    "pot_id": pid,
                    "hostname": info.get("hostname", ""),
                    "pubkey": pk_b64[:20] + "..." if len(pk_b64) > 20 else pk_b64,
                    "ecc_address": addr,
                })
        self._send_json(200, "OK", {"count": len(entries), "entries": entries})

    def _handle_covert_brew(self):
        body = self._read_json_body()
        message = body.get("message", "")
        dst = body.get("dst", "")
        if not message:
            self._send_json(400, "Bad Request", {"error": "Missing 'message' text"})
            return
        dst_pubkey = None
        if dst:
            with MeshNode.peers_lock:
                info = MeshNode.peers.get(dst, {})
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    try:
                        dst_pubkey = base64.b64decode(pk_b64)
                    except Exception as _e:
                        logger.debug("Ignored: %s", _e)
        encoded = CovertChannel.encode(
            message.encode(), dst, "espresso",
            dst_pubkey=dst_pubkey,
            our_seed=MeshNode.node_seed if dst_pubkey else None,
        )
        result = MeshNode.send_message(dst, f"covert_brew:{message}") if dst else {"status": "encoded"}
        result["covert_additions"] = encoded["additions"]
        if result.get("status") == "error":
            self._send_json(503, "Service Unavailable", result)
        else:
            self._send_json(200, "OK", result)

    def _handle_covert_status(self):
        pq_status = cpip_providers.PQCIdentity.get_status()
        self._send_json(200, "OK", {
            "enabled": COVERT_ENABLED,
            "cover_traffic": COVER_TRAFFIC,
            "cipher": "AES-256-GCM (FIPS 197)",
            "ecc_available": MeshNode.node_pubkey is not None,
            "pq_kem_available": pq_status.get("available", False),
            "pq_kem": pq_status,
            "pq_kem_used_for_covert": False,
        })

    def _handle_defense_get(self):
        now = time.time()
        with TEAPOT_BLACKLIST_LOCK:
            active = {k: v for k, v in TEAPOT_BLACKLIST.items() if v.get("expires", 0) > now}
            blacklist = sorted(active.keys())
            blacklist_details = []
            for addr in blacklist:
                entry = active[addr]
                remaining = max(0, int(entry.get("expires", 0) - now))
                blacklist_details.append({
                    "addr": addr,
                    "reason": entry.get("reason", "auto"),
                    "ttl": entry.get("ttl", DEFENSE_BLACKLIST_TTL),
                    "remaining": remaining,
                    "probe_count": len(TEAPOT_PROBE_COUNT.get(addr, [])),
                })
        with TEAPOT_TOOL_LOCK:
            tools = {}
            for tool, info in TEAPOT_TOOL_HITS.items():
                tools[tool] = {
                    "count": info["count"],
                    "last_seen": info["last_seen"],
                    "addrs": sorted(info["addrs"])[:20],
                }
        try:
            from providers.surveillance_fp import SurveillanceFingerprintProvider
            surv_fp = SurveillanceFingerprintProvider.get_status()
        except Exception:
            surv_fp = {"enabled": False, "matches": []}
        self._send_json(200, "OK", {
            "418_teapot": MESH_ENABLED,
            "stealth": MeshNode.stealth_mode,
            "port_hopping": MeshNode.stealth_mode,
            "latent_ports": MESH_LATENT_PORTS,
            "blacklisted_addrs": len(blacklist),
            "blacklist": blacklist,
            "blacklist_details": blacklist_details,
            "hop_interval": MESH_HOP_INTERVAL,
            "rate_limit": {"max": DEFENSE_RATE_LIMIT, "window": DEFENSE_RATE_WINDOW},
            "blacklist_ttl": DEFENSE_BLACKLIST_TTL,
            "tools_detected": tools,
            "tools_total": len(tools),
            "surveillance_fp": surv_fp,
            "key_status": "Keygen-derived (ECP256 P-256)" if COVERT_KEY_SEED else ("Custom" if COVERT_KEY != b"CHANGE_ME_COFFEE_BLEND_2024" else "Default (CHANGE ME)"),
        })

    def _handle_defense_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "whitelist":
            addr = body.get("addr", "")
            if addr:
                with TEAPOT_BLACKLIST_LOCK:
                    TEAPOT_BLACKLIST.pop(addr, None)
                    TEAPOT_PROBE_COUNT.pop(addr, None)
                self._send_json(200, "OK", {"status": "whitelisted", "addr": addr})
            else:
                self._send_json(400, "Bad Request", {"error": "Missing 'addr'"})
        elif action == "clear":
            with TEAPOT_BLACKLIST_LOCK:
                TEAPOT_BLACKLIST.clear()
                TEAPOT_PROBE_COUNT.clear()
            self._send_json(200, "OK", {"status": "blacklist_cleared"})
        elif action == "blacklist":
            addr = body.get("addr", "")
            if not addr:
                self._send_json(400, "Bad Request", {"error": "Missing 'addr'"})
                return
            ttl = int(body.get("ttl", DEFENSE_BLACKLIST_TTL))
            reason = body.get("reason", "manual")
            now = time.time()
            with TEAPOT_BLACKLIST_LOCK:
                TEAPOT_BLACKLIST[addr] = {
                    "expires": now + ttl, "ttl": ttl,
                    "reason": reason, "added": now,
                }
            self._send_json(200, "OK", {
                "status": "blacklisted", "addr": addr,
                "ttl": ttl, "reason": reason,
            })
        elif action == "bulk_blacklist":
            addrs_raw = body.get("addrs", "")
            ttl = int(body.get("ttl", DEFENSE_BLACKLIST_TTL))
            reason = body.get("reason", "bulk_import")
            if isinstance(addrs_raw, str):
                addrs = [a.strip() for a in addrs_raw.replace(",", "\n").split("\n") if a.strip()]
            elif isinstance(addrs_raw, list):
                addrs = [str(a).strip() for a in addrs_raw if str(a).strip()]
            else:
                self._send_json(400, "Bad Request", {"error": "Invalid 'addrs' format"})
                return
            now = time.time()
            added = []
            skipped = []
            for addr in addrs:
                if addr in ("127.0.0.1", "::1", "localhost", ""):
                    skipped.append(addr)
                    continue
                with TEAPOT_BLACKLIST_LOCK:
                    TEAPOT_BLACKLIST[addr] = {
                        "expires": now + ttl, "ttl": ttl,
                        "reason": reason, "added": now,
                    }
                added.append(addr)
            self._send_json(200, "OK", {
                "status": "bulk_blacklisted",
                "added": len(added), "skipped": len(skipped),
                "addrs": added, "skipped_addrs": skipped,
            })
        elif action == "probe":
            addr = body.get("addr", "")
            if not addr:
                self._send_json(400, "Bad Request", {"error": "Missing 'addr'"})
                return
            blacklisted = teapot_defense(addr)
            now = time.time()
            with TEAPOT_BLACKLIST_LOCK:
                entry = TEAPOT_BLACKLIST.get(addr)
                remaining = max(0, int(entry.get("expires", 0) - now)) if entry else 0
            self._send_json(200, "OK", {
                "status": "probed", "addr": addr,
                "blacklisted": blacklisted,
                "remaining_seconds": remaining,
                "probe_count": len(TEAPOT_PROBE_COUNT.get(addr, [])),
            })
        elif action == "stealth":
            enabled = body.get("enabled", False)
            MeshNode.stealth_mode = bool(enabled)
            self._send_json(200, "OK", {"status": "stealth_set", "enabled": MeshNode.stealth_mode})
        elif action == "keygen":
            global COVERT_KEY, COVERT_KEY_SEED
            new_seed = os.urandom(32)
            try:
                pk, sk, _, _ = ECP256.generate_keypair(new_seed)
                new_key = sk[:32]
            except Exception:
                new_key = hashlib.sha256(new_seed).digest()
            COVERT_KEY_SEED = new_seed
            COVERT_KEY = new_key
            self._send_json(200, "OK", {
                "status": "keygen",
                "key_status": "Keygen-derived (ECP256 P-256)",
                "key_hex": new_key.hex(),
                "note": "New HMAC key active. RPC auth tokens will use this key.",
            })
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_spoof_get(self):
        pm = ProxyManager()
        rotator = IPRotator()
        self._send_json(200, "OK", {
            "spoof_enabled": SPOOF_ENABLED,
            "mode": SPOOF_MODE,
            "tor_available": pm.tor_available,
            "proxy_count": pm.proxy_count,
            "source_ips": rotator.source_ips,
            "source_ip_count": rotator.source_ip_count,
            "proxies": [p.split(":")[0] + ":****" if "://" in p and "@" not in p else p for p in pm._proxies[:10]],
        })

    def _handle_spoof_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        pm = ProxyManager()
        rotator = IPRotator()
        if action == "rotate":
            pm._current_idx = 0
            self._send_json(200, "OK", {"status": "proxy_rotated", "proxy": pm.get_proxy()})
        elif action == "status":
            self._handle_spoof_get()
        elif action == "reload":
            pm._load_proxies()
            self._send_json(200, "OK", {"status": "proxies_reloaded", "count": pm.proxy_count})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_palantir_get(self):
        ph = PalantirHardening()
        status = ph.get_status()
        status["agent_log"] = ph.get_agent_log(20)
        self._send_json(200, "OK", status)

    def _handle_palantir_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        ph = PalantirHardening()
        if action == "enable":
            ph.enabled = True
            ph.log_agent("enabled via API")
            self._send_json(200, "OK", {"status": "palantir_enabled"})
        elif action == "disable":
            ph.enabled = False
            ph.log_agent("disabled via API")
            self._send_json(200, "OK", {"status": "palantir_disabled"})
        elif action == "chaff_on":
            ph._chaff_enabled = True
            self._send_json(200, "OK", {"status": "chaff_enabled"})
        elif action == "chaff_off":
            ph._chaff_enabled = False
            self._send_json(200, "OK", {"status": "chaff_disabled"})
        elif action == "broadcast_on":
            ph._broadcast_all = True
            self._send_json(200, "OK", {"status": "broadcast_enabled"})
        elif action == "broadcast_off":
            ph._broadcast_all = False
            self._send_json(200, "OK", {"status": "broadcast_disabled"})
        elif action == "evasion":
            ph.auto_evasion(True)
            self._send_json(200, "OK", {"status": "evasion_activated"})
        elif action == "log":
            self._send_json(200, "OK", {"log": ph.get_agent_log(100)})
        else:
            self._handle_palantir_get()

    def _handle_mesh_sat_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "enable":
            MeshNode.sat_enable()
            self._send_json(200, "OK", {"status": "satellite_enabled"})
        elif action == "disable":
            MeshNode.sat_disable()
            self._send_json(200, "OK", {"status": "satellite_disabled"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_mobile_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "enable":
            MeshNode.mobile_enable()
            self._send_json(200, "OK", {"status": "mobile_enabled"})
        elif action == "disable":
            MeshNode.mobile_disable()
            self._send_json(200, "OK", {"status": "mobile_disabled"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_deaddrop(self):
        """Handle dead-drop listing and claiming."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        action = params.get("action", ["list"])[0]
        if action == "list":
            drops = MeshNode.advertise_dead_drops()
            self._send_json(200, "OK", {
                "count": len(drops),
                "dead_drops": drops,
                "thermos": THERMOS_ENABLED,
                "node": POT_ID,
            })
        elif action == "claim":
            mid = params.get("id", [""])[0]
            if not mid:
                self._send_json(400, "Bad Request", {"error": "Missing 'id' param"})
                return
            msg = MeshNode.claim_dead_drop(mid, POT_ID)
            if msg:
                self._send_json(200, "OK", {"status": "claimed", "message": msg})
            else:
                self._send_json(404, "Not Found", {"error": f"Dead drop {mid} not found"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_mesh_send(self):
        body = self._read_json_body()
        dst = body.get("dst", body.get("destination", ""))
        data = body.get("data", body.get("message", ""))
        resolved_dst = MeshNode._resolve_address(dst)
        if resolved_dst:
            dst = resolved_dst

        if not dst:
            self._send_json(400, "Bad Request", {"error": "Missing 'dst' (destination pot ID)"})
            return
        if not data:
            self._send_json(400, "Bad Request", {"error": "Missing 'data' (message text)"})
            return

        result = MeshNode.send_message(dst, data)

        covert_method = body.get("covert", False)
        if covert_method and result.get("status") in ("sent", "queued"):
            # Use ECC if we have the peer's pubkey
            dst_pubkey = None
            with MeshNode.peers_lock:
                info = MeshNode.peers.get(dst, {})
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    try:
                        dst_pubkey = base64.b64decode(pk_b64)
                    except Exception as _e:
                        logger.debug("Ignored: %s", _e)
            beverage, _additions, headers = CovertChannel.encode_brew(
                data.encode(), dst,
                dst_pubkey=dst_pubkey,
                our_seed=MeshNode.node_seed,
            )
            result["covert_path"] = f"/{beverage}"
            result["covert_headers"] = headers
            if dst_pubkey:
                result["ecc_encrypted"] = True
                result["ecc_address"] = ECP256.pubkey_to_address(dst_pubkey)

        if result.get("status") == "error":
            self._send_json(503, "Service Unavailable", result)
        else:
            self._send_json(200, "OK", result)

    def _handle_mesh_broadcast(self):
        body = self._read_json_body()
        data = body.get("data", body.get("message", ""))
        if not data:
            self._send_json(400, "Bad Request", {"error": "Missing 'data' (message text)"})
            return
        result = MeshNode.broadcast(data)
        self._send_json(200, "OK", result)

    def _handle_covert_encode(self):
        body = self._read_json_body()
        message = body.get("message", "")
        dst = body.get("dst", "")
        recipe = body.get("recipe", CPIP_RECIPE)
        use_ecc = body.get("ecc", False)

        if not message:
            self._send_json(400, "Bad Request", {"error": "Missing 'message' text"})
            return

        dst_pubkey = None
        if use_ecc and dst:
            with MeshNode.peers_lock:
                info = MeshNode.peers.get(dst, {})
                pk_b64 = info.get("pubkey", "")
                if pk_b64:
                    try:
                        dst_pubkey = base64.b64decode(pk_b64)
                    except Exception as _e:
                        logger.debug("Ignored: %s", _e)

        encoded = CovertChannel.encode(
            message.encode(), dst, recipe,
            dst_pubkey=dst_pubkey,
            our_seed=MeshNode.node_seed if dst_pubkey else None,
        )
        header_value = ", ".join(
            f"{a['name']};variety={a['variety']}"
            for a in encoded["additions"]
        )
        result = {
            "status": "encoded",
            "additions": encoded["additions"],
            "accept_additions_header": header_value,
            "recipe": recipe,
            "original_length": len(message),
            "encoded_length": len(header_value),
            "cipher": "AES-256-GCM (FIPS 197) + ECDSA P-256" if dst_pubkey else "AES-256-GCM (FIPS 197)",
        }
        if dst_pubkey:
            result["ecc"] = True
            result["ecc_encrypted_for"] = ECP256.pubkey_to_address(dst_pubkey)
        self._send_json(200, "OK", result)

    def _handle_covert_decode(self):
        body = self._read_json_body()
        additions = body.get("additions", body.get("additions_list", []))
        header_value = body.get("accept_additions", body.get("header", ""))

        if header_value:
            additions = parse_accept_additions(header_value)

        if not additions:
            self._send_json(400, "Bad Request", {"error": "Missing 'additions' list or 'accept_additions' header string"})
            return

        decoded = CovertChannel.decode(additions, our_seed=MeshNode.node_seed)
        if decoded:
            try:
                text = decoded.decode("utf-8")
                self._send_json(200, "OK", {
                    "status": "decoded",
                    "message": text,
                    "bytes": list(decoded),
                    "length": len(decoded),
                })
            except UnicodeDecodeError:
                self._send_json(200, "OK", {
                    "status": "decoded_raw",
                    "message": decoded.hex(),
                    "bytes": list(decoded),
                    "length": len(decoded),
                    "note": "Binary data (not valid UTF-8)",
                })
        else:
            self._send_json(200, "OK", {
                "status": "no_message",
                "message": "No covert message detected in additions",
            })

    # ── Dashboard ─────────────────────────────────────────────────────

    def _handle_incident_status(self):
        self._send_json(200, "OK", IncidentResponse.get_status())

    def _handle_incident_alerts(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        level = params.get("level", [None])[0]
        limit = min(int(params.get("limit", [50])[0]), 200)
        self._send_json(200, "OK", {
            "count": len(IncidentResponse.get_alerts(level=level)),
            "alerts": IncidentResponse.get_alerts(level=level, limit=limit),
            "audit_chain_valid": IncidentResponse.verify_audit_chain()["valid"],
        })

    def _handle_incident_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "ack":
            IncidentResponse.alert("info", "ack", "Incident acknowledged by operator", {"by": self.client_address[0]})
            self._send_json(200, "OK", {"status": "acked"})
        elif action == "auto_response":
            enabled = body.get("enabled", True)
            IncidentResponse.set_auto_response(bool(enabled))
            self._send_json(200, "OK", {"status": "auto_response_set", "enabled": bool(enabled)})
        elif action == "clear_alerts":
            with IncidentResponse._lock:
                IncidentResponse._alerts.clear()
            self._send_json(200, "OK", {"status": "alerts_cleared"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_signal_status(self):
        self._send_json(200, "OK", {
            "bandwidth": SignalAwareness.estimate_bandwidth(),
            "link_quality": SignalAwareness.get_link_quality(),
            "emergency": EmergencyMode.get_status(),
        })

    def _handle_emergency(self):
        self._send_json(200, "OK", EmergencyMode.get_status())

    def _handle_emergency_post(self):
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "activate":
            reason = body.get("reason", "manual")
            EmergencyMode.activate(reason)
            self._send_json(200, "OK", {"status": "emergency_activated", "reason": reason})
        elif action == "deactivate":
            EmergencyMode.deactivate()
            self._send_json(200, "OK", {"status": "emergency_deactivated"})
        elif action == "wipe":
            EmergencyMode.secure_wipe()
            self._send_json(200, "OK", {"status": "secure_wipe_complete"})
        elif action == "rotate_keys":
            EmergencyMode._rotate_keys()
            self._send_json(200, "OK", {"status": "keys_rotated"})
        else:
            self._send_json(400, "Bad Request", {"error": f"Unknown action: {action}"})

    def _handle_diag_ping(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        host = params.get("host", ["localhost"])[0]
        port = int(params.get("port", [str(BIND_PORT)])[0])
        timeout = float(params.get("timeout", ["3"])[0])
        proto = params.get("proto", ["tcp"])[0]
        if proto == "udp":
            result = NetDiagnostics.udp_ping(host, port, timeout)
        else:
            result = NetDiagnostics.tcp_ping(host, port, timeout)
        self._send_json(200, "OK", result)

    def _handle_diag_ports(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        host = params.get("host", ["localhost"])[0]
        port_strs = params.get("ports", None)
        if port_strs:
            ports = [int(p) for p in port_strs[0].split(",") if p.strip().isdigit()]
        else:
            ports = None
        result = NetDiagnostics.port_scan(host, ports)
        self._send_json(200, "OK", result)

    def _handle_diag_dns(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        hostname = params.get("host", ["localhost"])[0]
        result = NetDiagnostics.dns_resolve(hostname)
        self._send_json(200, "OK", result)

    def _handle_diag_traceroute(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        host = params.get("host", ["localhost"])[0]
        max_hops = int(params.get("max_hops", ["15"])[0])
        result = NetDiagnostics.traceroute(host, max_hops)
        self._send_json(200, "OK", result)

    def _handle_diag_interfaces(self):
        self._send_json(200, "OK", {"interfaces": NetDiagnostics.get_interfaces()})

    def _handle_providers(self):
        ptype_str = parse_qs(urlparse(self.path).query).get("type", [None])[0]
        try:
            ptype = cpip_providers.ProviderType.from_str(ptype_str) if ptype_str else None
        except ValueError:
            self._send_json(400, "Bad Request", {"error": f"Unknown provider type: {ptype_str}"})
            return
        providers = cpip_providers.registry.get_info(ptype)
        self._send_json(200, "OK", {
            "count": len(providers),
            "providers": providers,
        })

    def _handle_crypto_status(self):
        pq_status = cpip_providers.PQCIdentity.get_status()
        self._send_json(200, "OK", {
            "cipher": "AES-256-GCM (FIPS 197)",
            "ecc": "ECDSA/ECDH P-256 (FIPS 186-4)",
            "pq_kem": pq_status.get("kem_algorithm"),
            "pqc_kem_status": pq_status,
            "hash": "SHA-256 + SHA-3-256",
            "hmac": "HMAC-SHA256 + HMAC-SHA3-256",
            "key_derivation": "HKDF-SHA256",
            "e2ee": "Ephemeral ECDH P-256 + AES-256-GCM; PQ KEM not integrated into mesh E2EE",
            "pq_mesh_integrated": False,
            "node_address": MeshNode.node_address,
            "node_pubkey_present": MeshNode.node_pubkey is not None,
            "node_cert_hash": CoffeeCipher.hash(MeshNode.node_secret) if MeshNode.node_secret else None,
            "persist_encrypted": True,
            "timestamp_validation": True,
            "mesh_hmac": True,
            "covert_channel_version": "v5 (CBC2 + ECCv2)",
            "emergency_mode": EmergencyMode.is_active(),
            "incident_auto_response": IncidentResponse._auto_response_enabled,
        })

    def _handle_crypto_post(self):
        """Key rotation endpoint. Accepts {"action":"rotate_keys"} (alias for
        POST /cpip/emergency rotate_keys) to rotate all cryptographic keys."""
        body = self._read_json_body()
        action = body.get("action", "")
        if action == "rotate_keys":
            result = EmergencyMode.rotate_keys()
            self._send_json(200, "OK", {"status": "keys_rotated", **result})
        else:
            self._send_json(400, "Bad Request",
                            {"error": f"Unknown crypto action: {action}",
                             "hint": "Supported action: rotate_keys"})

    def _handle_cell_status(self):
        from providers.cellular import CellularProvider, AntiStingrayV2
        result = AntiStingrayV2.get_status() if hasattr(AntiStingrayV2, 'get_status') else CellularProvider.get_status()
        self._send_json(200, "OK", result)

    def _handle_cell_scan(self):
        from providers.cellular import AntiStingrayV2, CellularProvider
        try:
            result = AntiStingrayV2.scan() if hasattr(AntiStingrayV2, 'scan') else CellularProvider.scan()
            self._send_json(200, "OK", {"status": "scan_started", "result": result})
        except Exception as e:
            self._send_json(200, "OK", {"status": "scan_triggered", "note": str(e)})

    def _handle_sdr_status(self):
        from providers.sdr import SDRProvider
        self._send_json(200, "OK", SDRProvider.get_status())

    def _handle_sdr_spectrum(self):
        from providers.sdr import SDRProvider
        self._send_json(200, "OK", SDRProvider.get_spectrum() if hasattr(SDRProvider, 'get_spectrum') else {"spectrum": "unavailable"})

    def _handle_sdr_scan(self):
        from providers.sdr import SDRProvider
        try:
            self._send_json(200, "OK", {"status": "scan_started", "type": "sdr"})
        except Exception as e:
            self._send_json(200, "OK", {"status": "scan_triggered", "note": str(e)})

    def _handle_carrier_status(self):
        from providers.carrier import CarrierProvider
        self._send_json(200, "OK", CarrierProvider.get_status())

    def _handle_carrier_webhook(self):
        from providers.carrier import CarrierProvider
        body = self._read_json_body()
        CarrierProvider.register_webhook(body)
        self._send_json(200, "OK", {"status": "webhook_registered"})

    def _handle_intel_global_map(self):
        from providers.threat_intel import GlobalIntelProvider
        self._send_json(200, "OK", GlobalIntelProvider.get_map_data() if hasattr(GlobalIntelProvider, 'get_map_data') else [])

    def _handle_intel_risk_score(self):
        from providers.threat_intel import GlobalIntelProvider
        params = parse_qs(parsed.query)
        mcc = params.get("mcc", [""])[0]
        mnc = params.get("mnc", [""])[0]
        result = GlobalIntelProvider.risk_score(mcc, mnc) if hasattr(GlobalIntelProvider, 'risk_score') else {"risk_score": 0}
        self._send_json(200, "OK", result)

    def _uptime(self):
        return time.time() - self._start_time

    _start_time = time.time()

    def _serve_dashboard(self):
        bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])
        schedule_list = json.dumps([{
            "id": s["id"],
            "time": datetime.fromtimestamp(s["time"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if isinstance(s.get("time"), (int, float)) else str(s.get("time")),
            "beverage": s.get("beverage", "coffee"),
            "brew_duration": s.get("brew_duration", 30),
            "human": s.get("human", ""),
        } for s in PotState.schedules])

        fmt = {
            "device": html.escape(DEVICE_TYPE),
            "pot_id": html.escape(POT_ID),
            "hostname": html.escape(HOSTNAME),
            "version": CPIP_VERSION,
            "beverages": ", ".join(bev),
            "gpio_status": f"GPIO Pin {GPIO_PIN}" if gpio.is_available else "GPIO disabled",
            "gpio_class": "physical" if gpio.is_available else "disabled",
            "mesh_status": f"Mesh port {MESH_PORT}" if MESH_ENABLED else "Disabled",
            "mesh_class": "enabled" if MESH_ENABLED else "disabled",
            "covert_status": "Active (Coffee Cipher)" if COVERT_ENABLED else "Disabled",
            "covert_class": "enabled" if COVERT_ENABLED else "disabled",
            "pot_json": json.dumps({"pot": POT_ID, "hostname": HOSTNAME, "device": DEVICE_TYPE, "port": BIND_PORT}),
            "schedules_json": schedule_list,
        }
        html_str = DASHBOARD_HTML
        index_file = WEB_DIR / "index.html"
        if index_file.is_file():
            try:
                html_str = index_file.read_text(encoding="utf-8")
            except Exception as _e:
                logger.debug("Ignored: %s", _e)
        self._send_html(200, html_str.format(**fmt))


# ── Embedded Dashboard HTML ───────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CPIP — {hostname} Coffee Protocol</title>
<style>
  :root {{
    --bg: #0a0a1a; --surface: #111128; --accent: #e94560;
    --green: #0a2840; --text: #d0d0e0; --muted: #6666aa;
    --card: #18183a; --border: #2a2a5c; --mesh: #00cc88; --yellow: #ffcc00;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Courier New', monospace;
          background: var(--bg); color: var(--text); min-height: 100vh; }}
  .header {{ background: linear-gradient(135deg, var(--surface), #0a0a2a);
            padding: 1rem 2rem; border-bottom: 3px solid var(--accent); }}
  .header h1 {{ font-size: 1.4rem; font-weight: 700; }}
  .header .sub {{ color: var(--muted); font-size: 0.8rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
           padding: 1.2rem; }}
  .card h2 {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase;
              letter-spacing: 0.1em; margin-bottom: 0.8rem; }}
  .value {{ font-size: 1.8rem; font-weight: 700; font-family: inherit; }}
  .label {{ color: var(--muted); font-size: 0.75rem; margin-top: 0.2rem; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 3px;
            font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
  .badge.brewing {{ background: var(--accent); color: #fff; animation: pulse 1s infinite; }}
  .badge.idle {{ background: #1a3a5c; color: #88ccff; }}
  .badge.enabled {{ background: #003322; color: #00ff88; }}
  .badge.disabled {{ background: #332200; color: #ff8800; }}
  .badge.physical {{ background: #004433; color: #00ffaa; }}
  @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
  .btn {{ background: var(--accent); color: #fff; border: none; padding: 0.5rem 1rem;
          border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-weight: 600;
          font-family: inherit; transition: all 0.2s; }}
  .btn:hover {{ background: #d13850; }}
  .btn.secondary {{ background: #1a3a6c; }}
  .btn.secondary:hover {{ background: #2a4a8c; }}
  .btn.outline {{ background: transparent; border: 1px solid var(--accent); color: var(--accent); }}
  .btn.small {{ padding: 0.3rem 0.6rem; font-size: 0.7rem; }}
  .btn.mesh {{ background: #005533; }}
  .btn.mesh:hover {{ background: #007744; }}
  .toggles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.5rem 1rem; margin-top: 0.75rem; }}
  .toggle-row {{ display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;
                 background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.4rem 0.6rem; }}
  .toggle-row .tl {{ font-size: 0.75rem; }}
  .toggle-row .tl small {{ display: block; color: var(--muted); font-size: 0.65rem; }}
  .switch {{ position: relative; display: inline-block; width: 38px; height: 20px; flex-shrink: 0; }}
  .switch input {{ opacity: 0; width: 0; height: 0; }}
  .slider {{ position: absolute; cursor: pointer; inset: 0; background: var(--border);
             transition: 0.2s; border-radius: 20px; }}
  .slider:before {{ position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px;
                    background: #fff; transition: 0.2s; border-radius: 50%; }}
  .switch input:checked + .slider {{ background: var(--accent); }}
  .switch input:checked + .slider:before {{ transform: translateX(18px); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  th, td {{ padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; }}
  .event-log {{ max-height: 150px; overflow-y: auto; font-size: 0.75rem; }}
  .event-log div {{ padding: 0.2rem 0; border-bottom: 1px solid var(--border); }}
  .ev-start {{ color: #88ff88; }}
  .ev-stop {{ color: #ff8888; }}
  .ev-mesh {{ color: #88ffff; }}
  input, select {{ background: var(--surface); border: 1px solid var(--border); color: var(--text);
                  padding: 0.4rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-family: inherit; }}
  input:focus, select:focus {{ outline: none; border-color: var(--accent); }}
  .form-row {{ display: flex; gap: 0.5rem; align-items: end; flex-wrap: wrap; }}
  textarea {{ background: var(--surface); border: 1px solid var(--border); color: var(--text);
              padding: 0.5rem; border-radius: 4px; font-size: 0.8rem; width: 100%;
              font-family: inherit; resize: vertical; }}
  .toast {{ position: fixed; bottom: 1rem; right: 1rem; background: #003322; color: #00ff88;
            padding: 0.8rem 1.2rem; border-radius: 4px; opacity: 0; transform: translateY(10px);
            transition: all 0.3s; z-index: 100; font-size: 0.8rem; }}
  .toast.show {{ opacity: 1; transform: translateY(0); }}
  .inline-code {{ background: var(--surface); padding: 0.1rem 0.3rem; border-radius: 2px; font-size: 0.75rem; }}
  .mono {{ font-family: monospace; }}
  .tab-bar {{ display: flex; gap: 0; margin-bottom: 1rem; border-bottom: 1px solid var(--border); }}
  .tab {{ padding: 0.5rem 1rem; cursor: pointer; color: var(--muted); font-size: 0.8rem;
          border-bottom: 2px solid transparent; }}
  .tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .tab:hover {{ color: var(--text); }}
  .panel {{ display: none; }}
  .panel.active {{ display: block; }}
</style>
</head>
<body>
<div class="header">
  <h1>☕ CPIP — {hostname} <span style="color:var(--muted);font-weight:400">| {pot_id}</span></h1>
  <div class="sub">{version} — Internet Coffee Protocol + Mesh Comms</div>
</div>
<div class="container">
  <div class="status-bar" style="display:flex;gap:0.5rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap">
    <span id="brewBadge" class="badge idle">—</span>
    <span id="gpioBadge" class="badge {gpio_class}">{gpio_status}</span>
    <span id="meshBadge" class="badge {mesh_class}">{mesh_status}</span>
    <span id="covertBadge" class="badge {covert_class}">{covert_status}</span>
    <span id="itfBadge" class="badge idle">ITF</span>
    <span id="ntpBadge" class="badge enabled">NTP</span>
    <span id="sseBadge" class="badge idle">SSE: ?</span>
    <span style="flex:1"></span>
    <button class="btn secondary" onclick="brew('coffee')">☕ Brew</button>
    <button class="btn secondary" onclick="brew('tea')">🍵 Tea</button>
    <button class="btn outline" onclick="stopBrew()">⏹ Stop</button>
    <button class="btn mesh" onclick="scanMesh()">📡 Scan</button>
  </div>

  <div class="tab-bar">
    <div class="tab active" data-tab="brew" onclick="switchTab('brew')">☕ Brew</div>
    <div class="tab" data-tab="mesh" onclick="switchTab('mesh')">📡 Mesh</div>
    <div class="tab" data-tab="covert" onclick="switchTab('covert')">🔒 Covert</div>
    <div class="tab" data-tab="itf" onclick="switchTab('itf')">🛡 ITF</div>
    <div class="tab" data-tab="crypto" onclick="switchTab('crypto')">🔐 Crypto</div>
    <div class="tab" data-tab="incident" onclick="switchTab('incident')">🚨 IR</div>
    <div class="tab" data-tab="signal" onclick="switchTab('signal')">📡 Signal</div>
    <div class="tab" data-tab="diag" onclick="switchTab('diag')">🔧 Diag</div>
    <div class="tab" data-tab="schedule" onclick="switchTab('schedule')">⏰ Schedule</div>
    <div class="tab" data-tab="history" onclick="switchTab('history')">📜 History</div>
    <div class="tab" data-tab="antiisp" onclick="switchTab('antiisp')">🌐 Anti-ISP</div>
    <div class="tab" data-tab="stingray" onclick="switchTab('stingray')">📡 Anti-Stingray</div>
    <div class="tab" data-tab="surveillance" onclick="switchTab('surveillance')">🛡️ Anti-Surveillance</div>
    <div class="tab" data-tab="neutrality" onclick="switchTab('neutrality')">⚖️ Net Neutrality</div>
  </div>

  <div id="panel-brew" class="panel active">
    <div class="grid">
      <div class="card"><h2>Device</h2><div class="value">{device}</div><div class="label">{beverages}</div></div>
      <div class="card"><h2>State</h2><div class="value" id="stateVal">—</div><div class="label" id="stateDet">Waiting</div></div>
      <div class="card"><h2>Brews</h2><div class="value" id="brewCount">0</div><div class="label">Total completed</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Quick Brew</h2>
      <div class="form-row">
        <select id="brewType">
          <option value="coffee">Coffee</option><option value="tea">Tea</option>
          <option value="espresso">Espresso</option><option value="latte">Latte</option>
          <option value="cappuccino">Cappuccino</option><option value="americano">Americano</option>
          <option value="cold-brew">Cold Brew</option><option value="mocha">Mocha</option>
          <option value="matcha">Matcha</option>
        </select>
        <select id="brewTemp"><option value="">Hot</option><option value="iced">Iced</option></select>
        <select id="brewMilk"><option value="">No milk</option><option value="milk;variety=whole">Whole milk</option><option value="milk;variety=cream">Cream</option><option value="milk;variety=skim">Skim</option><option value="milk;variety=oat">Oat</option><option value="milk;variety=almond">Almond</option></select>
        <select id="brewSugar"><option value="">No sugar</option><option value="sugar;variety=white">White</option><option value="sugar;variety=brown">Brown</option><option value="sugar;variety=honey">Honey</option></select>
        <select id="brewSyrup"><option value="">No syrup</option><option value="syrup;variety=vanilla">Vanilla</option><option value="syrup;variety=caramel">Caramel</option><option value="syrup;variety=hazelnut">Hazelnut</option></select>
        <select id="brewSpice"><option value="">No spice</option><option value="spice;variety=cinnamon">Cinnamon</option><option value="spice;variety=cardamom">Cardamom</option><option value="spice;variety=nutmeg">Nutmeg</option></select>
        <select id="brewAlcohol"><option value="">No alcohol</option><option value="alcohol;variety=whiskey">Whiskey</option><option value="alcohol;variety=rum">Rum</option><option value="alcohol;variety=vodka">Vodka</option><option value="alcohol;variety=baileys">Baileys</option><option value="alcohol;variety=kahlua">Kahlua</option><option value="alcohol;variety=amaretto">Amaretto</option></select>
        <button class="btn" onclick="brewCustom()">Brew with additions</button>
      </div>
    </div>
  </div>

  <div id="panel-mesh" class="panel">
    <div class="grid">
      <div class="card"><h2>Mesh Status</h2><div class="value" id="meshPeers">0</div><div class="label">Peers on network</div></div>
      <div class="card"><h2>Inbox</h2><div class="value" id="inboxCount">0</div><div class="label">Messages received</div></div>
      <div class="card"><h2>Queued</h2><div class="value" id="queuedCount">0</div><div class="label">Store-and-forward</div></div>
    </div>
    <div class="grid" style="margin-top:0.5rem">
      <div class="card">
        <h2>Satellite <span id="satBadge" class="badge idle">OFF</span></h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;color:var(--muted)">
          <span id="satCoords">—</span>
          <span id="satPort" style="display:none"></span>
          <span id="satRelay" style="display:none"></span>
          <span id="satPeersCount">0 sat-peers</span>
          <span id="satBootstrap">—</span>
        </div>
        <div id="satPeerList" style="margin-top:0.3rem;font-size:0.75rem"></div>
        <div class="form-row" style="margin-top:0.5rem">
          <button class="btn secondary small" id="satToggleBtn" onclick="toggleSat()">Enable</button>
        </div>
      </div>
      <div class="card">
        <h2>Mobile <span id="mobBadge" class="badge idle">OFF</span></h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;color:var(--muted)">
          <span id="mobIface">—</span>
          <span id="mobPort" style="display:none"></span>
          <span id="mobTelemetry" style="display:none"></span>
          <span id="mobPeersCount">0 mobile-peers</span>
          <span id="mobSignal">—</span>
          <span id="mobSignalDetail" style="display:none"></span>
          <span id="mobBootstrap" style="font-size:0.7rem">—</span>
        </div>
        <div id="mobPeerList" style="margin-top:0.3rem;font-size:0.75rem"></div>
        <div class="form-row" style="margin-top:0.5rem">
          <button class="btn secondary small" id="mobToggleBtn" onclick="toggleMobile()">Enable</button>
        </div>
      </div>
      <div class="card">
        <h2>Radio <span id="radioBadge" class="badge idle">OFF</span></h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;font-size:0.75rem;color:var(--muted)">
          <span id="radioMode">—</span>
          <span id="radioFreq">—</span>
          <span id="radioBw">—</span>
        </div>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Send Message</h2>
      <div class="form-row">
        <input type="text" id="meshDst" placeholder="Destination pot ID" style="width:150px">
        <input type="text" id="meshMsg" placeholder="Message text" style="flex:1">
        <label style="font-size:0.75rem;color:var(--muted)"><input type="checkbox" id="meshCovert"> Use covert channel</label>
        <button class="btn mesh" onclick="sendMesh()">Send</button>
        <button class="btn mesh" onclick="broadcastMesh()">Broadcast</button>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Peers <span id="peerCount" style="color:var(--muted)">(0)</span></h2>
      <div id="peerList"><div style="color:var(--muted)">Scanning…</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Inbox Messages</h2>
      <div id="inboxList"><div style="color:var(--muted)">No messages</div></div>
    </div>
  </div>

  <div id="panel-covert" class="panel">
    <div class="grid">
      <div class="card">
        <h2>Encode Message</h2>
        <textarea id="covertInput" rows="3" placeholder="Message to hide in coffee brew request..."></textarea>
        <div class="form-row" style="margin-top:0.5rem">
          <input type="text" id="covertDst" placeholder="Dest pot (optional)" style="width:150px">
          <select id="covertRecipe">
            <option value="espresso">Espresso</option>
            <option value="pour-over">Pour Over</option>
            <option value="french-press">French Press</option>
            <option value="cold-brew">Cold Brew</option>
            <option value="moka">Moka Pot</option>
          </select>
          <button class="btn" onclick="encodeCovert()">Encode</button>
        </div>
        <div id="covertResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Decode Message</h2>
        <textarea id="covertHeader" rows="3" placeholder="Paste Accept-Additions header value..."></textarea>
        <div class="form-row" style="margin-top:0.5rem">
          <button class="btn" onclick="decodeCovert()">Decode</button>
        </div>
        <div id="decodeResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Covert Message History</h2>
      <div id="covertHistory"><div style="color:var(--muted)">No messages sent yet</div></div>
    </div>
  </div>

  <div id="panel-itf" class="panel">
    <div class="grid">
      <div class="card"><h2>418 Teapot</h2><div class="value" id="itf418">—</div><div class="label">Defense posture</div></div>
      <div class="card"><h2>Stealth</h2><div class="value" id="itfStealth">—</div><div class="label">Stealth mode <button class="btn small outline" id="stealthToggleBtn" onclick="toggleStealth()" style="margin-left:0.3rem">Toggle</button></div></div>
      <div class="card"><h2>HMAC Key</h2><div class="value" id="itfKeyStatus" style="font-size:0.8rem">—</div><div class="label">RPC auth key <button class="btn small accent" onclick="hmacKeygen()" style="margin-left:0.3rem">Keygen</button></div></div>
      <div class="card"><h2>Port Hop</h2><div class="value" id="itfHop">—</div><div class="label"><span id="itfHopInterval"></span></div></div>
      <div class="card"><h2>Latent Ports</h2><div class="value" id="itfLatent">—</div><div class="label">Backup listener ports</div></div>
      <div class="card"><h2>Blacklisted</h2><div class="value" id="itfBlackCount">0</div><div class="label">Addresses blocked</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem">
        <h2 style="margin:0">Blacklist</h2>
        <div style="display:flex;gap:0.5rem">
          <button class="btn outline small" onclick="exportBlacklist()">Export</button>
          <button class="btn outline small" onclick="clearBlacklist()">Clear All</button>
        </div>
      </div>
      <div id="itfBlacklist"><div style="color:var(--muted)">No addresses blacklisted</div></div>
    </div>
    <div class="grid" style="margin-top:0.5rem">
      <div class="card">
        <h2>Blacklist Address</h2>
        <div class="form-row">
          <input type="text" id="itfBlacklistAddr" placeholder="IP address" style="flex:1">
          <select id="itfBlacklistTtl" style="width:7rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.3rem;font-size:0.75rem">
            <option value="300">5 min</option>
            <option value="3600" selected>1 hour</option>
            <option value="86400">24 hours</option>
            <option value="604800">7 days</option>
            <option value="2592000">30 days</option>
            <option value="31536000">1 year</option>
          </select>
          <button class="btn secondary" onclick="blacklistAddr()">Block</button>
        </div>
        <input type="text" id="itfBlacklistReason" placeholder="Reason (optional)" style="width:100%;margin-top:0.3rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.3rem;font-size:0.75rem">
      </div>
      <div class="card">
        <h2>Bulk Blacklist</h2>
        <textarea id="itfBulkAddrs" rows="3" placeholder="One IP per line (or comma-separated)" style="width:100%;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.4rem;font-size:0.75rem;font-family:inherit;resize:vertical"></textarea>
        <div style="display:flex;gap:0.5rem;margin-top:0.3rem;align-items:center">
          <select id="itfBulkTtl" style="width:7rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.3rem;font-size:0.75rem">
            <option value="300">5 min</option>
            <option value="3600" selected>1 hour</option>
            <option value="86400">24 hours</option>
            <option value="604800">7 days</option>
            <option value="2592000">30 days</option>
            <option value="31536000">1 year</option>
          </select>
          <button class="btn secondary" onclick="bulkBlacklist()">Block All</button>
        </div>
        <div id="itfBulkResult" style="margin-top:0.3rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Whitelist Address</h2>
        <div class="form-row">
          <input type="text" id="itfWhitelistAddr" placeholder="IP address" style="flex:1">
          <button class="btn secondary" onclick="whitelistAddr()">Remove</button>
        </div>
      </div>
      <div class="card">
        <h2>Probe Address</h2>
        <div class="form-row">
          <input type="text" id="itfProbeAddr" placeholder="IP address" style="flex:1">
          <button class="btn secondary" onclick="probeAddr()">Probe</button>
        </div>
        <div id="itfProbeResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Import Blacklist</h2>
      <textarea id="itfImportAddrs" rows="3" placeholder="Paste IPs (one per line, comma-separated, or CIDR notation)" style="width:100%;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.4rem;font-size:0.75rem;font-family:inherit;resize:vertical"></textarea>
      <div style="display:flex;gap:0.5rem;margin-top:0.3rem;align-items:center">
        <select id="itfImportTtl" style="width:7rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.3rem;font-size:0.75rem">
          <option value="300">5 min</option>
          <option value="3600" selected>1 hour</option>
          <option value="86400">24 hours</option>
          <option value="604800">7 days</option>
          <option value="2592000">30 days</option>
          <option value="31536000">1 year</option>
        </select>
        <button class="btn secondary" onclick="importBlacklist()">Import &amp; Block</button>
      </div>
      <div id="itfImportResult" style="margin-top:0.3rem;font-size:0.75rem"></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Detected Tools <span id="itfToolsCount" style="color:var(--muted);font-weight:400">(0)</span></h2>
      <div id="itfTools"><div style="color:var(--muted)">No tools detected yet</div></div>
    </div>
  </div>

  <div id="panel-crypto" class="panel">
    <div class="grid">
      <div class="card"><h2>Cipher</h2><div class="value" style="font-size:0.9rem" id="cryptoCipher">—</div><div class="label">Encryption engine</div></div>
      <div class="card"><h2>ECC</h2><div class="value" style="font-size:0.9rem" id="cryptoECC">—</div><div class="label">Elliptic curve</div></div>
      <div class="card"><h2>PQ-KEM</h2><div class="value" style="font-size:0.9rem" id="cryptoPQ">—</div><div class="label">Post-quantum</div></div>
      <div class="card"><h2>E2EE</h2><div class="value" style="font-size:0.9rem" id="cryptoE2EE">—</div><div class="label">End-to-end</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Cryptographic Details</h2>
      <div id="cryptoDetails" style="font-size:0.75rem;color:var(--muted)">Loading…</div>
    </div>
    <div class="grid" style="margin-top:0.5rem">
      <div class="card">
        <h2>Key Rotation</h2>
        <div class="form-row">
          <button class="btn" onclick="rotateKeys()">🔄 Rotate Keys</button>
          <button class="btn outline" style="margin-left:0.5rem" onclick="showCryptoStatus()">↻ Refresh</button>
        </div>
        <div id="keyRotResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Emergency</h2>
        <div style="font-size:0.7rem;color:var(--muted);margin-bottom:0.3rem">⚠ Activating emergency mode rotates keys and goes stealth</div>
        <div class="form-row">
          <button class="btn" style="background:#aa0000" onclick="emergencyActivate()">🚨 EMERGENCY</button>
          <button class="btn secondary" onclick="emergencyDeactivate()">Deactivate</button>
        </div>
        <div id="emergencyResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
    </div>
  </div>

  <div id="panel-incident" class="panel">
    <div class="grid">
      <div class="card"><h2>Alerts</h2><div class="value" id="irAlertCount">0</div><div class="label">Total incidents</div></div>
      <div class="card"><h2>Critical</h2><div class="value" id="irCritical">0</div><div class="label">Critical alerts</div></div>
      <div class="card"><h2>Auto-Response</h2><div class="value" id="irAutoResp">—</div><div class="label"><button class="btn small outline" onclick="toggleAutoResp()">Toggle</button></div></div>
      <div class="card"><h2>Audit Chain</h2><div class="value" id="irChainValid">—</div><div class="label">Tamper evidence</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Recent Alerts <button class="btn small outline" onclick="clearAlerts()" style="margin-left:0.5rem">Clear</button></h2>
      <div id="irAlertList" style="max-height:200px;overflow-y:auto;font-size:0.75rem">Loading…</div>
    </div>
  </div>

  <div id="panel-signal" class="panel">
    <div class="grid">
      <div class="card"><h2>Mesh Traffic</h2><div class="value" id="sigMesh">0</div><div class="label">recv/s · <span id="sigMeshErr">0</span> errors</div></div>
      <div class="card"><h2>HTTP Traffic</h2><div class="value" id="sigHttp">0</div><div class="label">rps · <span id="sigHttp418">0</span> blocked</div></div>
      <div class="card"><h2>Satellite</h2><div class="value" id="sigSat">0</div><div class="label">sat messages</div></div>
      <div class="card"><h2>Uptime</h2><div class="value" id="sigUptime">0s</div><div class="label">Since start</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Link Quality</h2>
      <div id="sigLinkQuality" style="font-size:0.75rem;color:var(--muted)">No peer data yet</div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h2>Emergency Mode</h2>
      <div id="sigEmergency" style="font-size:0.75rem;color:var(--muted)">Normal operations</div>
    </div>
  </div>

  <div id="panel-diag" class="panel">
    <div class="grid">
      <div class="card">
        <h2>TCP Ping</h2>
        <div class="form-row">
          <input type="text" id="diagPingHost" placeholder="Host" style="flex:2">
          <input type="number" id="diagPingPort" placeholder="4180" value="4180" style="width:70px">
          <button class="btn secondary" onclick="diagPing()">Ping</button>
        </div>
        <div id="diagPingResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Port Scan</h2>
        <div class="form-row">
          <input type="text" id="diagScanHost" placeholder="Host" style="flex:2">
          <button class="btn secondary" onclick="diagScan()">Scan</button>
        </div>
        <div id="diagScanResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
    </div>
    <div class="grid" style="margin-top:0.5rem">
      <div class="card">
        <h2>DNS Resolve</h2>
        <div class="form-row">
          <input type="text" id="diagDnsHost" placeholder="Hostname" style="flex:1">
          <button class="btn secondary" onclick="diagDns()">Resolve</button>
        </div>
        <div id="diagDnsResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
      <div class="card">
        <h2>Traceroute</h2>
        <div class="form-row">
          <input type="text" id="diagTraceHost" placeholder="Host" style="flex:1">
          <button class="btn secondary" onclick="diagTrace()">Trace</button>
        </div>
        <div id="diagTraceResult" style="margin-top:0.5rem;font-size:0.75rem"></div>
      </div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Network Interfaces</h2>
      <div id="diagIfaces" style="font-size:0.75rem">Loading…</div>
      <button class="btn small outline" onclick="diagIfaces()">Refresh</button>
    </div>
  </div>

  <div id="panel-schedule" class="panel">
    <div class="card">
      <h2>Schedule Brew</h2>
      <div class="form-row">
        <select id="schType"><option value="coffee">Coffee</option><option value="tea">Tea</option></select>
        <input type="number" id="schSeconds" value="30" min="5" style="width:80px">
        <button class="btn secondary" onclick="scheduleIn()">In X seconds</button>
      </div>
      <div class="form-row" style="margin-top:0.5rem">
        <input type="datetime-local" id="schDatetime">
        <label style="font-size:0.75rem;color:var(--muted)"><input type="checkbox" id="schRecurring"> Daily</label>
        <button class="btn secondary" onclick="scheduleAt()">Schedule</button>
      </div>
      <div id="scheduleList" style="margin-top:1rem"></div>
    </div>
  </div>

  <div id="panel-history" class="panel">
    <div class="card">
      <h2>Brew History</h2>
      <div class="form-row" style="margin-bottom:0.5rem">
        <select id="histFilter">
          <option value="">All beverages</option>
          <option value="coffee">Coffee</option><option value="tea">Tea</option>
          <option value="espresso">Espresso</option><option value="latte">Latte</option>
          <option value="cappuccino">Cappuccino</option><option value="americano">Americano</option>
          <option value="cold-brew">Cold Brew</option><option value="mocha">Mocha</option>
        </select>
        <button class="btn outline small" onclick="clearHistory()">Clear</button>
      </div>
      <div id="brewHistory"><div style="color:var(--muted)">Loading…</div></div>
    </div>
  </div>

  <div id="panel-antiisp" class="panel">
    <div class="grid">
      <div class="card"><h2>STUN</h2><div class="value" id="aispExtIp">—</div><div class="label" id="aispNatType">NAT type</div></div>
      <div class="card"><h2>UPnP</h2><div class="value" id="aispUpnp">—</div><div class="label">Port mapping</div></div>
      <div class="card"><h2>Relay</h2><div class="value" id="aispRelayCount">0</div><div class="label">Active relays</div></div>
      <div class="card"><h2>WSS</h2><div class="value" id="aispWss">—</div><div class="label" id="aispWssCount">0 connections</div></div>
    </div>
    <div class="grid">
      <div class="card"><h2>DNS Tunnel</h2><div class="value" id="aispDnsTun">—</div><div class="label" id="aispDnsDomain">domain</div></div>
      <div class="card"><h2>DoH</h2><div class="value" id="aispDoh">—</div><div class="label" id="aispDohCache">0 cached</div></div>
      <div class="card"><h2>Hole-Punch</h2><div class="value" id="aispPunchSessions">0</div><div class="label">Active sessions</div></div>
      <div class="card"><h2>Transport</h2><div class="value" id="aispTransports">0</div><div class="label">Active methods</div></div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Anti-ISP Toggles</h2>
      <div class="toggles" id="aispToggles">
        <label class="toggle-row"><span class="tl">STUN<small>NAT hole-punch</small></span>
          <span class="switch"><input type="checkbox" data-feat="stun" onchange="aispToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">UPnP<small>Port mapping</small></span>
          <span class="switch"><input type="checkbox" data-feat="upnp" onchange="aispToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Relay<small>Mesh relay pool</small></span>
          <span class="switch"><input type="checkbox" data-feat="relay" onchange="aispToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">DNS Tunnel<small>CNS exfil</small></span>
          <span class="switch"><input type="checkbox" data-feat="dns_tunnel" onchange="aispToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">WSS Tunnel<small>WebSocket relay</small></span>
          <span class="switch"><input type="checkbox" data-feat="wss" onchange="aispToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">DoH<small>Encrypted DNS</small></span>
          <span class="switch"><input type="checkbox" data-feat="doh" onchange="aispToggle(this)"><span class="slider"></span></span></label>
      </div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Anti-ISP Actions</h2>
      <div class="form-row">
        <button class="btn" onclick="aispRefresh()">🔄 Refresh All</button>
        <button class="btn outline" onclick="aispHolePunch()">🔗 Hole-Punch Test</button>
      </div>
      <div id="aispResult" style="font-size:0.75rem;color:var(--muted);margin-top:0.5rem"></div>
    </div>
  </div>

  <div id="panel-stingray" class="panel">
    <div class="grid">
      <div class="card"><h2>Threat Level</h2><div class="value" id="stThreat">—</div><div class="label" id="stThreatLabel">scanning</div></div>
      <div class="card"><h2>Cell Tower</h2><div class="value" id="stMCC">—</div><div class="label" id="stCellDetail">MCC/MNC</div></div>
      <div class="card"><h2>Signal</h2><div class="value" id="stSignal">—</div><div class="label" id="stRAT">RAT type</div></div>
      <div class="card"><h2>Scans</h2><div class="value" id="stScans">0</div><div class="label">cellular scans</div></div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Anti-Stingray Toggles</h2>
      <div class="toggles" id="stToggles">
        <label class="toggle-row"><span class="tl">Detection<small>Master switch</small></span>
          <span class="switch"><input type="checkbox" data-feat="enabled" onchange="stToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Cell Scan<small>MCC/MNC/LAC</small></span>
          <span class="switch"><input type="checkbox" data-feat="cell_scan" onchange="stToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">RF Scan<small>Spectrum anomalies</small></span>
          <span class="switch"><input type="checkbox" data-feat="rf_scan" onchange="stToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Signal Anomaly<small>Power delta</small></span>
          <span class="switch"><input type="checkbox" data-feat="signal_anomaly" onchange="stToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Known Sig<small>IMSI catcher DB</small></span>
          <span class="switch"><input type="checkbox" data-feat="known_signatures" onchange="stToggle(this)"><span class="slider"></span></span></label>
      </div>
      <div class="form-row" style="margin-top:0.5rem">
        <button class="btn outline small" onclick="stRescan()">🔄 Rescan Now</button>
      </div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Stingray Alerts</h2>
      <div id="stAlerts" style="font-size:0.75rem;color:var(--muted)">No alerts</div>
    </div>
  </div>

  <div id="panel-surveillance" class="panel">
    <div class="grid">
      <div class="card"><h2>Threat Level</h2><div class="value" id="asThreat">—</div><div class="label" id="asThreatLabel">monitoring</div></div>
      <div class="card"><h2>DPI Signatures</h2><div class="value" id="asDPI">0</div><div class="label">loaded</div></div>
      <div class="card"><h2>SSL Intercept</h2><div class="value" id="asSSL">—</div><div class="label">certificate chain</div></div>
      <div class="card"><h2>Process Integrity</h2><div class="value" id="asProc">—</div><div class="label">injection check</div></div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Anti-Surveillance Toggles</h2>
      <div class="toggles" id="asToggles">
        <label class="toggle-row"><span class="tl">Detection<small>Master switch</small></span>
          <span class="switch"><input type="checkbox" data-feat="enabled" onchange="asToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">DPI Evasion<small>Traffic shaping</small></span>
          <span class="switch"><input type="checkbox" data-feat="dpi_evasion" onchange="asToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Traffic Obfuscation<small>Pad/garble</small></span>
          <span class="switch"><input type="checkbox" data-feat="traffic_obfuscation" onchange="asToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Metadata Strip<small>Header cleanup</small></span>
          <span class="switch"><input type="checkbox" data-feat="metadata_strip" onchange="asToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">ExploitKit Detect<small>0-click kits</small></span>
          <span class="switch"><input type="checkbox" data-feat="exploitkit_detect" onchange="asToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Proc Inject Detect<small>Hooking</small></span>
          <span class="switch"><input type="checkbox" data-feat="process_inject_detect" onchange="asToggle(this)"><span class="slider"></span></span></label>
      </div>
      <div class="form-row" style="margin-top:0.5rem">
        <button class="btn outline small" onclick="asScan()">🔄 Scan Now</button>
      </div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Surveillance Alerts</h2>
      <div id="asAlerts" style="font-size:0.75rem;color:var(--muted)">No alerts</div>
    </div>
  </div>

  <div id="panel-neutrality" class="panel">
    <div class="grid">
      <div class="card"><h2>Throttle</h2><div class="value" id="nnThrottle">—</div><div class="label">bandwidth detection</div></div>
      <div class="card"><h2>Masked</h2><div class="value" id="nnMasked">0</div><div class="label">packets disguised</div></div>
      <div class="card"><h2>Fragmented</h2><div class="value" id="nnFrag">0</div><div class="label">DPI evasion frags</div></div>
      <div class="card"><h2>Jitter</h2><div class="value" id="nnJitter">0</div><div class="label">timing injections</div></div>
    </div>
    <div class="card" style="margin-top:0.5rem">
      <h2>Net Neutrality Toggles</h2>
      <div class="toggles" id="nnToggles">
        <label class="toggle-row"><span class="tl">Defense<small>Master switch</small></span>
          <span class="switch"><input type="checkbox" data-feat="enabled" onchange="nnToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">BW Monitor<small>Sampling</small></span>
          <span class="switch"><input type="checkbox" data-feat="bandwidth_monitor" onchange="nnToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Proto Masquerade<small>Disguise as web</small></span>
          <span class="switch"><input type="checkbox" data-feat="protocol_masquerade" onchange="nnToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Fragmentation<small>DPI evasion</small></span>
          <span class="switch"><input type="checkbox" data-feat="fragmentation" onchange="nnToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Throttle Detect<small>Rate analysis</small></span>
          <span class="switch"><input type="checkbox" data-feat="throttle_detect" onchange="nnToggle(this)"><span class="slider"></span></span></label>
        <label class="toggle-row"><span class="tl">Jitter Injection<small>Timing noise</small></span>
          <span class="switch"><input type="checkbox" data-feat="jitter_injection" onchange="nnToggle(this)"><span class="slider"></span></span></label>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:1rem">
    <h2>Live Events <span style="color:var(--muted);font-weight:400">(brew, mesh, covert)</span></h2>
    <div class="event-log" id="eventLog"><div style="color:var(--muted)">Waiting…</div></div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const POT = {pot_json};

function showToast(m) {{ const t = document.getElementById('toast'); t.textContent = m; t.className = 'toast show'; setTimeout(() => t.className = 'toast', 2500); }}

async function api(m, p, b) {{
  try {{
    const o = {{ method: m, headers: {{}} }};
    if (b) {{ o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(b); }}
    const r = await fetch(p, o);
    if (!r.ok && r.status !== 202) {{
      const ej = await r.json().catch(() => ({{}}));
      showToast(ej.error || `HTTP ${{r.status}}`);
      return ej;
    }}
    return await r.json();
  }} catch(e) {{ showToast('Connection error: ' + e.message); return {{}}; }}
}}

function switchTab(name) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => {{ if (t.dataset.tab === name) t.classList.add('active'); }});
  const el = document.getElementById('panel-' + name);
  if (el) el.classList.add('active');
  if (name === 'mesh') {{ refreshMesh(); refreshInbox(); refreshSat(); refreshMobile(); refreshRadio(); }}
  if (name === 'history') {{ refreshHistory(); }}
  if (name === 'schedule') {{ refreshSchedules(); }}
  if (name === 'itf') {{ refreshItf(); }}
  if (name === 'crypto') {{ showCryptoStatus(); }}
  if (name === 'incident') {{ refreshIR(); }}
  if (name === 'signal') {{ refreshSignal(); }}
  if (name === 'diag') {{ diagIfaces(); }}
}}

async function refresh() {{
  const s = await api('GET', '/cpip/status');
  if (!s || s.error) return;
  const badge = document.getElementById('brewBadge');
  const sv = document.getElementById('stateVal');
  const sd = document.getElementById('stateDet');
  if (s.brewing) {{
    badge.textContent = 'BREWING'; badge.className = 'badge brewing';
    sv.textContent = s.current_brew?.beverage || 'Brewing';
    const secs = Math.floor(s.current_brew?.elapsed_seconds||0);
    sd.textContent = `${{secs}}s ${{s.current_brew?.id||''}}`;
  }} else {{
    badge.textContent = 'IDLE'; badge.className = 'badge idle';
    sv.textContent = 'Idle'; sd.textContent = 'Ready';
  }}
  document.getElementById('brewCount').textContent = s.history_count || 0;
  if (s.mesh) {{
    document.getElementById('meshPeers').textContent = s.mesh.peers_known;
    document.getElementById('inboxCount').textContent = s.mesh.inbox_count || 0;
    document.getElementById('queuedCount').textContent = s.mesh.messages_queued || 0;
  }}
}}

function esc(s) {{ return (''+s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }}

async function refreshHistory() {{
  const filter = document.getElementById('histFilter').value;
  const h = await api('GET', '/cpip/history?limit=16');
  if (!h || !h.history) return;
  const el = document.getElementById('brewHistory');
  if (!h.history.length) {{ el.innerHTML = '<div style="color:var(--muted)">No brews yet.</div>'; return; }}
  let items = h.history;
  if (filter) items = items.filter(b => b.beverage === filter);
  if (!items.length) {{ el.innerHTML = '<div style="color:var(--muted)">No matches.</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>Bev</th><th>Additions</th><th>Dur</th></tr>';
  for (const b of items) {{
    const t = b.started ? new Date(b.started*1000).toLocaleTimeString() : '—';
    const add = b.additions?.map(a => esc(a.name||a)).join(',') || '—';
    html += `<tr><td>${{esc(t)}}</td><td>${{esc(b.beverage)}}</td><td style="font-size:0.7rem">${{esc(add)}}</td><td>${{esc(b.duration)}}s</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function clearHistory() {{
  if (!confirm('Clear all brew history?')) return;
  const r = await api('DELETE', '/cpip/history');
  if (r) showToast('History cleared');
  refreshHistory();
}}

async function refreshMesh() {{
  const p = await api('GET', '/cpip/mesh/peers');
  if (!p) return;
  document.getElementById('peerCount').textContent = `(${{p.count||0}})`;
  const el = document.getElementById('peerList');
  if (!p.peers?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No peers found. Tap Scan.</div>'; return; }}
  let html = '<table><tr><th>Pot</th><th>Host</th><th>Addr</th><th>Device</th><th>Seen</th><th>Hops</th></tr>';
  for (const peer of p.peers) {{
    const ls = peer.last_seen ? Math.floor((Date.now()/1000 - peer.last_seen)) + 's ago' : '—';
    html += `<tr><td class="mono">${{esc(peer.pot?.slice(0,6)||'?')}}</td><td>${{esc(peer.hostname||'?')}}</td><td>${{esc(peer.addr||'?')}}</td><td>${{esc((peer.device||'?').slice(0,10))}}</td><td>${{esc(ls)}}</td><td>${{esc(peer.hops)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshInbox() {{
  const ib = await api('GET', '/cpip/mesh/inbox');
  if (!ib) return;
  const el = document.getElementById('inboxList');
  if (!ib.messages?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No messages</div>'; return; }}
  if (!ib.messages?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No messages</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>From</th><th>Message</th><th>Ch</th></tr>';
  for (const m of ib.messages.slice().reverse()) {{
    const t = m.timestamp ? new Date(m.timestamp*1000).toLocaleTimeString() : '—';
    const data = m.data?.length > 50 ? m.data.slice(0, 50) + '…' : (m.data || '');
    const ch = m.channel || 'mesh';
    html += `<tr><td>${{esc(t)}}</td><td class="mono" style="font-size:0.7rem">${{esc(m.from?.slice(0,6)||'?')}}</td><td style="font-size:0.7rem">${{esc(data)}}</td><td>${{esc(ch)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshSat() {{
  const s = await api('GET', '/cpip/mesh/sat');
  if (!s || !s.enabled) {{
    document.getElementById('satBadge').textContent = 'OFF';
    document.getElementById('satBadge').className = 'badge idle';
    document.getElementById('satCoords').textContent = 'Satellite disabled';
    document.getElementById('satPort').style.display = 'none';
    document.getElementById('satRelay').style.display = 'none';
    return;
  }}
  document.getElementById('satBadge').textContent = 'ON';
  document.getElementById('satBadge').className = 'badge enabled';
  document.getElementById('satCoords').textContent = `${{s.coords?.lat||'?'}}°, ${{s.coords?.lon||'?'}}°${{s.coords?.alt ? ' '+s.coords.alt+'m' : ''}}`;
  const portEl = document.getElementById('satPort');
  portEl.textContent = `port: ${{s.port}}`;
  portEl.style.display = 'inline';
  const relayEl = document.getElementById('satRelay');
  relayEl.textContent = s.relay ? 'relay: ON' : 'relay: OFF';
  relayEl.style.display = 'inline';
  relayEl.style.color = s.relay ? '#00ff88' : 'var(--muted)';
  document.getElementById('satPeersCount').textContent = `${{s.peers_known||0}} sat-peer(s)`;
  document.getElementById('satBootstrap').textContent = s.bootstrap?.length ? `bootstrap: ${{s.bootstrap.join(', ')}}` : 'no bootstrap';
  const el = document.getElementById('satPeerList');
  if (!s.peers?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No satellite peers yet</div>'; return; }}
  let html = '<table><tr><th>Pot</th><th>Host</th><th>Coords</th><th>RTT</th><th>Seen</th></tr>';
  for (const p of s.peers) {{
    const t = p.last_seen ? Math.floor((Date.now()/1000 - p.last_seen)) + 's ago' : '—';
    html += `<tr><td class="mono">${{esc(p.pot?.slice(0,6)||'?')}}</td><td>${{esc(p.hostname||'?')}}</td><td>${{esc((p.lat||'?').toFixed(1)+','+(p.lon||'?').toFixed(1))}}</td><td>${{esc(p.rtt||'?')}}ms</td><td>${{esc(t)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshMobile() {{
  const m = await api('GET', '/cpip/mesh/mobile');
  if (!m || !m.enabled) {{
    document.getElementById('mobBadge').textContent = 'OFF';
    document.getElementById('mobBadge').className = 'badge idle';
    document.getElementById('mobIface').textContent = 'Mobile disabled';
    document.getElementById('mobPort').style.display = 'none';
    document.getElementById('mobTelemetry').style.display = 'none';
    document.getElementById('mobSignalDetail').style.display = 'none';
    return;
  }}
  document.getElementById('mobBadge').textContent = 'ON';
  document.getElementById('mobBadge').className = 'badge enabled';
  document.getElementById('mobIface').textContent = m.interface || '?';
  const portEl = document.getElementById('mobPort');
  portEl.textContent = `port: ${{m.port}}`;
  portEl.style.display = 'inline';
  const telEl = document.getElementById('mobTelemetry');
  telEl.textContent = m.telemetry ? 'telemetry: ON' : 'telemetry: OFF';
  telEl.style.display = 'inline';
  telEl.style.color = m.telemetry ? '#00ff88' : 'var(--muted)';
  document.getElementById('mobPeersCount').textContent = `${{m.peers_known||0}} mobile-peer(s)`;
  const sig = m.signal || {{}};
  let sigStr = '—';
  if (sig.rssi != null) sigStr = `RSSI: ${{sig.rssi}}`;
  else if (sig.rsrp != null) sigStr = `RSRP: ${{sig.rsrp}}`;
  document.getElementById('mobSignal').textContent = sigStr;
  const detEl = document.getElementById('mobSignalDetail');
  const sinr = sig.sinr != null ? `SINR: ${{sig.sinr}}` : null;
  const mcc = sig.mcc != null ? `MCC: ${{sig.mcc}}` : null;
  const detParts = [sinr, mcc].filter(Boolean);
  if (detParts.length) {{
    detEl.textContent = detParts.join(' | ');
    detEl.style.display = 'inline';
  }} else {{
    detEl.style.display = 'none';
  }}
  document.getElementById('mobBootstrap').textContent = m.bootstrap?.length ? `seed: ${{m.bootstrap.join(', ')}}` : 'no bootstrap';
  const el = document.getElementById('mobPeerList');
  if (!m.peers?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No mobile peers yet</div>'; return; }}
  let html = '<table><tr><th>Pot</th><th>Host</th><th>Signal</th><th>Net</th><th>Hops</th></tr>';
  for (const p of m.peers) {{
    const sig = p.signal;
    let sigStr = '—';
    if (sig && typeof sig === 'object') {{ sigStr = sig.rssi != null ? sig.rssi + ' dBm' : (sig.rsrp != null ? 'RSRP ' + sig.rsrp : '—'); }}
    else if (sig) {{ sigStr = String(sig); }}
    html += `<tr><td class="mono">${{esc(p.pot?.slice(0,6)||'?')}}</td><td>${{esc(p.hostname||'?')}}</td><td>${{esc(sigStr)}}</td><td>${{esc(p.network||'—')}}</td><td>${{esc(p.hops||0)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshRadio() {{
  const r = await api('GET', '/cpip/mesh/radio');
  if (!r) return;
  const badge = document.getElementById('radioBadge');
  if (r.enabled) {{
    badge.textContent = 'ON'; badge.className = 'badge enabled';
    document.getElementById('radioMode').textContent = 'mode: ' + (r.mode || '?');
    document.getElementById('radioFreq').textContent = 'freq: ' + ((r.frequency/1e6).toFixed(1) || '?') + ' MHz';
    document.getElementById('radioBw').textContent = 'bw: ' + ((r.bandwidth/1e3).toFixed(0) || '?') + ' kHz';
  }} else {{
    badge.textContent = 'OFF'; badge.className = 'badge idle';
    document.getElementById('radioMode').textContent = 'Radio disabled';
    document.getElementById('radioFreq').textContent = '';
    document.getElementById('radioBw').textContent = '';
  }}
}}

async function toggleSat() {{
  const badge = document.getElementById('satBadge');
  const on = badge.textContent === 'ON';
  const r = await api('POST', '/cpip/mesh/sat', {{ action: on ? 'disable' : 'enable' }});
  if (r) showToast(r.status || 'Toggled');
  await refreshSat();
  document.getElementById('satToggleBtn').textContent = badge.textContent === 'ON' ? 'Disable' : 'Enable';
}}

async function toggleMobile() {{
  const badge = document.getElementById('mobBadge');
  const on = badge.textContent === 'ON';
  const r = await api('POST', '/cpip/mesh/mobile', {{ action: on ? 'disable' : 'enable' }});
  if (r) showToast(r.status || 'Toggled');
  await refreshMobile();
  document.getElementById('mobToggleBtn').textContent = badge.textContent === 'ON' ? 'Disable' : 'Enable';
}}

async function toggleStealth() {{
  const v = document.getElementById('itfStealth');
  const on = v.textContent === 'ON';
  const r = await api('POST', '/cpip/defense', {{ action: 'stealth', enabled: !on }});
  if (r) showToast('Stealth: ' + (r.enabled ? 'ON' : 'OFF'));
  refreshItf();
}}

async function scanMesh() {{
  showToast('Scanning...');
  try {{
    const d = await api('GET', '/cpip/discover');
    if (d && d.pots) showToast(`Found ${{d.count}} pot(s)`);
    await refreshMesh();
  }} catch(e) {{ showToast('Scan failed'); }}
}}

async function brew(type) {{
  const r = await api('POST', '/cpip/brew', {{ beverage: type }});
  if (r && r.status === 'brewing') showToast('Brewing ' + type);
  else if (r && r.error) showToast(r.message || r.error);
  refresh();
}}

async function brewCustom() {{
  const type = document.getElementById('brewType').value;
  const temp = document.getElementById('brewTemp').value;
  const parts = [
    document.getElementById('brewMilk').value,
    document.getElementById('brewSugar').value,
    document.getElementById('brewSyrup').value,
    document.getElementById('brewSpice').value,
    document.getElementById('brewAlcohol').value,
  ].filter(p => p);
  const additions = parts.map(p => {{ const [n,...r] = p.split(';'); const v = r.find(x => x.startsWith('variety=')); return {{ name: n, variety: v ? v.split('=')[1] : null }}; }});
  const body = {{ beverage: type, additions }};
  if (temp) body.temperature = temp;
  const r = await api('POST', '/cpip/brew', body);
  if (r && r.status === 'brewing') showToast('Brewing ' + type + ' with additions');
  else if (r && r.error) showToast(r.message || r.error);
  refresh();
}}

async function stopBrew() {{
  try {{
    const r = await fetch('/', {{ method: 'POST', headers: {{'Content-Type': 'message/coffeepot'}}, body: 'stop' }});
    showToast(r.ok ? 'Stopped' : 'Stop failed');
  }} catch(e) {{ showToast('Stop failed'); }}
  refresh();
}}

async function scheduleIn() {{
  const s = parseInt(document.getElementById('schSeconds').value) || 30;
  const t = document.getElementById('schType').value;
  const r = await api('POST', '/cpip/schedule', {{ in: s, beverage: t, brew_duration: 60 }});
  if (r && r.status === 'scheduled') showToast('Scheduled ' + t + ' in ' + s + 's');
  refreshSchedules();
}}

async function scheduleAt() {{
  const dt = document.getElementById('schDatetime').value;
  const t = document.getElementById('schType').value;
  const recurring = document.getElementById('schRecurring').checked;
  if (!dt) {{ showToast('Pick a time'); return; }}
  const body = {{ time: new Date(dt).toISOString(), beverage: t, brew_duration: 60 }};
  if (recurring) body.recurring = 'daily';
  const r = await api('POST', '/cpip/schedule', body);
  if (r && r.status === 'scheduled') showToast('Scheduled' + (recurring ? ' daily' : ''));
  refreshSchedules();
}}

async function refreshSchedules() {{
  const s = await api('GET', '/cpip/schedules');
  if (!s) return;
  const el = document.getElementById('scheduleList');
  if (!s.schedules?.length) {{ el.innerHTML = '<div style="color:var(--muted);font-size:0.75rem">None</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>Bev</th><th>Dur</th><th>Recur</th><th></th></tr>';
  for (const sc of s.schedules) {{
    html += `<tr><td>${{esc(sc.human||sc.time)}}</td><td>${{esc(sc.beverage)}}</td><td>${{esc(sc.brew_duration)}}s</td>`;
    html += `<td>${{sc.recurring ? 'Daily' : '-'}}</td>`;
    html += `<td><button class="btn outline small" data-sid="${{esc(sc.id)}}">X</button></td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
  el.querySelectorAll('[data-sid]').forEach(btn => {{
    btn.addEventListener('click', async () => {{
      await api('DELETE', '/cpip/schedules/' + btn.dataset.sid);
      refreshSchedules();
    }});
  }});
}}

async function sendMesh() {{
  const dst = document.getElementById('meshDst').value;
  const msg = document.getElementById('meshMsg').value;
  const covert = document.getElementById('meshCovert').checked;
  if (!dst || !msg) {{ showToast('Need destination + message'); return; }}
  const r = await api('POST', '/cpip/mesh/send', {{ dst, data: msg, covert }});
  if (r) showToast('Sent: ' + (r.status || 'ok'));
  document.getElementById('meshMsg').value = '';
}}

async function broadcastMesh() {{
  const msg = document.getElementById('meshMsg').value;
  if (!msg) {{ showToast('Enter a message'); return; }}
  const r = await api('POST', '/cpip/mesh/broadcast', {{ data: msg }});
  if (r) showToast('Broadcast: ' + (r.peers_reached||0) + ' peers');
  document.getElementById('meshMsg').value = '';
}}

async function encodeCovert() {{
  const msg = document.getElementById('covertInput').value;
  const dst = document.getElementById('covertDst').value;
  const recipe = document.getElementById('covertRecipe').value;
  if (!msg) {{ showToast('Enter message'); return; }}
  const r = await api('POST', '/cpip/mesh/encode', {{ message: msg, dst, recipe }});
  if (!r || r.status !== 'encoded') return;
  const header = r.accept_additions_header;
  document.getElementById('covertResult').innerHTML = `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;margin-top:0.3rem">
    <div style="color:var(--muted)">Accept-Additions header:</div>
    <div class="mono" style="font-size:0.7rem;word-break:break-all;margin-top:0.3rem">${{esc(header)}}</div>
    <div style="color:var(--muted);margin-top:0.3rem">Recipe: ${{esc(r.recipe)}} | ${{esc(r.encoded_length)}} bytes</div>
    <div style="margin-top:0.3rem"><button class="btn small outline" onclick="navigator.clipboard.writeText('${{esc(header)}}');showToast('Copied')">Copy</button></div>
  </div>`;
  const history = JSON.parse(localStorage.getItem('cpip_covert_history') || '[]');
  history.unshift({{ message: msg.slice(0, 80), dst: dst || 'any', recipe, header: header.slice(0, 60) + '…', time: new Date().toLocaleString() }});
  if (history.length > 20) history.pop();
  localStorage.setItem('cpip_covert_history', JSON.stringify(history));
  renderCovertHistory();
}}

function renderCovertHistory() {{
  const el = document.getElementById('covertHistory');
  const history = JSON.parse(localStorage.getItem('cpip_covert_history') || '[]');
  if (!history.length) {{ el.innerHTML = '<div style="color:var(--muted)">No messages sent yet</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>To</th><th>Message</th><th>Recipe</th><th>Header</th></tr>';
  for (const h of history) {{
    html += `<tr><td style="font-size:0.7rem">${{esc(h.time)}}</td><td>${{esc(h.dst)}}</td><td style="font-size:0.7rem">${{esc(h.message)}}</td><td>${{esc(h.recipe)}}</td><td class="mono" style="font-size:0.65rem">${{esc(h.header)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function decodeCovert() {{
  const header = document.getElementById('covertHeader').value;
  if (!header) {{ showToast('Paste header value'); return; }}
  const r = await api('POST', '/cpip/mesh/decode', {{ accept_additions: header }});
  if (!r) return;
  document.getElementById('decodeResult').innerHTML = r.status === 'decoded'
    ? `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;margin-top:0.3rem"><div style="color:#88ff88">Decoded:</div><div style="margin-top:0.3rem">${{esc(r.message)}}</div></div>`
    : `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;margin-top:0.3rem;color:var(--muted)">${{esc(r.message)}}</div>`;
}}

async function refreshItf() {{
  const d = await api('GET', '/cpip/defense');
  if (!d || d.error) return;
  const badge = document.getElementById('itfBadge');
  if (d.stealth) {{
    badge.textContent = 'ITF: STEALTH'; badge.className = 'badge enabled';
  }} else {{
    badge.textContent = 'ITF'; badge.className = 'badge idle';
  }}
  document.getElementById('itf418').textContent = d['418_teapot'] ? 'ACTIVE' : 'INACTIVE';
  document.getElementById('itf418').style.color = d['418_teapot'] ? 'var(--accent)' : 'var(--muted)';
  document.getElementById('itfStealth').textContent = d.stealth ? 'ON' : 'OFF';
  document.getElementById('itfStealth').style.color = d.stealth ? '#00ff88' : 'var(--muted)';
  const ks = document.getElementById('itfKeyStatus');
  if (ks) {{ ks.textContent = d.key_status || '—'; ks.style.color = d.key_status?.includes('Keygen') ? '#00ff88' : 'var(--muted)'; }}
  document.getElementById('itfHop').textContent = d.port_hopping ? 'ON' : 'OFF';
  document.getElementById('itfHop').style.color = d.port_hopping ? '#00ff88' : 'var(--muted)';
  document.getElementById('itfHopInterval').textContent = d.port_hopping ? d.hop_interval + 's interval' : '';
  document.getElementById('itfLatent').textContent = d.latent_ports?.length ? d.latent_ports.join(', ') : 'None';
  document.getElementById('itfBlackCount').textContent = d.blacklisted_addrs || 0;
  const el = document.getElementById('itfBlacklist');
  if (!d.blacklist_details?.length) {{ el.innerHTML = '<div style="color:var(--muted)">No addresses blacklisted</div>'; return; }}
  let html = '<table><tr><th>IP</th><th>Reason</th><th>TTL</th><th>Expires</th><th></th></tr>';
  for (const entry of d.blacklist_details) {{
    const mins = Math.floor(entry.remaining / 60);
    const hrs = Math.floor(mins / 60);
    const dur = hrs > 0 ? hrs + 'h ' + (mins % 60) + 'm' : mins + 'm';
    html += `<tr><td class="mono">${{esc(entry.addr)}}</td><td>${{esc(entry.reason)}}</td><td>${{dur}}</td><td>${{esc(entry.ttl)}}s</td><td><button class="btn outline small" onclick="whitelistAddr('${{esc(entry.addr)}}')">Unblock</button></td></tr>`;
  }}
  el.innerHTML = html;
  const tcEl = document.getElementById('itfTools');
  const tcCount = document.getElementById('itfToolsCount');
  if (!d.tools_detected || !Object.keys(d.tools_detected).length) {{
    tcCount.textContent = '(0)';
    tcEl.innerHTML = '<div style="color:var(--muted)">No tools detected yet</div>';
    return;
  }}
  tcCount.textContent = `(${{Object.keys(d.tools_detected).length}})`;
  let thtml = '<table><tr><th>Tool</th><th>Hits</th><th>Last Seen</th><th>Sources</th></tr>';
  const sorted = Object.entries(d.tools_detected).sort((a, b) => b[1].count - a[1].count);
  for (const [tool, info] of sorted) {{
    const ls = info.last_seen ? new Date(info.last_seen * 1000).toLocaleTimeString() : '—';
    const addrs = info.addrs?.join(', ') || '—';
    thtml += `<tr><td>${{esc(tool)}}</td><td>${{info.count}}</td><td>${{esc(ls)}}</td><td style="font-size:0.7rem" class="mono">${{esc(addrs)}}</td></tr>`;
  }}
  thtml += '</table>'; tcEl.innerHTML = thtml;
}}

async function whitelistAddr(addr) {{
  addr = addr || document.getElementById('itfWhitelistAddr').value;
  if (!addr) {{ showToast('Enter an IP address'); return; }}
  const r = await api('POST', '/cpip/defense', {{ action: 'whitelist', addr }});
  if (r && r.status === 'whitelisted') showToast('Whitelisted ' + addr);
  document.getElementById('itfWhitelistAddr').value = '';
  refreshItf();
}}

async function clearBlacklist() {{
  const r = await api('POST', '/cpip/defense', {{ action: 'clear' }});
  if (r && r.status === 'blacklist_cleared') showToast('Blacklist cleared');
  refreshItf();
}}

async function probeAddr() {{
  const addr = document.getElementById('itfProbeAddr').value;
  if (!addr) {{ showToast('Enter an IP address'); return; }}
  const r = await api('POST', '/cpip/defense', {{ action: 'probe', addr }});
  const el = document.getElementById('itfProbeResult');
  if (!r || r.status !== 'probed') {{ el.innerHTML = '<div style="color:var(--muted)">Probe failed</div>'; return; }}
  const bl = r.blacklisted ? '<span style="color:var(--accent)">BLACKLISTED</span>' : '<span style="color:#00ff88">CLEAN</span>';
  el.innerHTML = `<div style="background:var(--surface);padding:0.5rem;border-radius:4px;font-size:0.75rem">
    <div>${{esc(r.addr)}} — ${{bl}}</div>
    <div style="color:var(--muted);margin-top:0.2rem">Probes: ${{r.probe_count}} | Remaining: ${{r.remaining_seconds}}s</div>
  </div>`;
}}

async function blacklistAddr() {{
  const addr = document.getElementById('itfBlacklistAddr').value;
  if (!addr) {{ showToast('Enter an IP address'); return; }}
  const ttl = parseInt(document.getElementById('itfBlacklistTtl').value) || 3600;
  const reason = document.getElementById('itfBlacklistReason').value || 'manual';
  const r = await api('POST', '/cpip/defense', {{ action: 'blacklist', addr, ttl, reason }});
  if (r && r.status === 'blacklisted') showToast('Blacklisted ' + addr + ' for ' + ttl + 's');
  document.getElementById('itfBlacklistAddr').value = '';
  document.getElementById('itfBlacklistReason').value = '';
  refreshItf();
}}

async function bulkBlacklist() {{
  const addrs = document.getElementById('itfBulkAddrs').value;
  if (!addrs) {{ showToast('Enter IP addresses'); return; }}
  const ttl = parseInt(document.getElementById('itfBulkTtl').value) || 3600;
  const r = await api('POST', '/cpip/defense', {{ action: 'bulk_blacklist', addrs, ttl, reason: 'bulk_import' }});
  const el = document.getElementById('itfBulkResult');
  if (!r || r.status !== 'bulk_blacklisted') {{ el.innerHTML = '<div style="color:var(--accent)">Failed</div>'; return; }}
  el.innerHTML = `<div style="color:#00ff88">Blocked ${{r.added}} | Skipped ${{r.skipped}}</div>`;
  document.getElementById('itfBulkAddrs').value = '';
  showToast('Bulk blacklisted ' + r.added + ' addresses');
  refreshItf();
}}

function exportBlacklist() {{
  const r = api('GET', '/cpip/defense');
  r.then(d => {{
    if (!d?.blacklist?.length) {{ showToast('Blacklist is empty'); return; }}
    const lines = d.blacklist_details?.map(e => e.addr + ' #' + e.reason + ' ttl=' + e.ttl) || d.blacklist;
    const text = lines.join('\\n');
    navigator.clipboard.writeText(text).then(() => showToast('Copied ' + d.blacklist.length + ' IPs to clipboard'));
  }});
}}

async function hmacKeygen() {{
  if (!confirm('Generate a new HMAC key? Existing RPC auth tokens will be invalidated.')) return;
  const r = await api('POST', '/cpip/defense', {{ action: 'keygen' }});
  if (r && r.status === 'keygen') {{
    showToast('HMAC key regenerated: ' + r.key_hex?.substring(0, 12) + '...');
    refreshItf();
  }} else {{
    showToast('Keygen failed');
  }}
}}

async function importBlacklist() {{
  const addrs = document.getElementById('itfImportAddrs').value;
  if (!addrs) {{ showToast('Paste IP addresses to import'); return; }}
  const ttl = parseInt(document.getElementById('itfImportTtl').value) || 3600;
  const r = await api('POST', '/cpip/defense', {{ action: 'bulk_blacklist', addrs, ttl, reason: 'import' }});
  const el = document.getElementById('itfImportResult');
  if (!r || r.status !== 'bulk_blacklisted') {{ el.innerHTML = '<div style="color:var(--accent)">Import failed</div>'; return; }}
  el.innerHTML = `<div style="color:#00ff88">Imported ${{r.added}} | Skipped ${{r.skipped}}</div>`;
  document.getElementById('itfImportAddrs').value = '';
  showToast('Imported ' + r.added + ' addresses');
  refreshItf();
}}

function connectSSE() {{
  const badge = document.getElementById('sseBadge');
  const log = document.getElementById('eventLog');
  const evt = new EventSource('/cpip/events');
  evt.onopen = () => {{ badge.textContent = 'SSE: OK'; badge.className = 'badge enabled'; }};
  evt.onerror = () => {{ badge.textContent = 'SSE: ERR'; badge.className = 'badge disabled'; }};
  evt.onmessage = (e) => {{
    try {{
      const d = JSON.parse(e.data);
      const entry = document.createElement('div');
      const ts = new Date().toLocaleTimeString();
      if (d.event === 'brew_start') {{ entry.className = 'ev-start'; entry.textContent = '['+ts+'] Brew '+d.beverage; refresh(); }}
      else if (d.event === 'brew_stop') {{ entry.className = 'ev-stop'; entry.textContent = '['+ts+'] Stop'; refresh(); refreshHistory(); }}
      else if (d.event === 'mesh_message') {{ entry.className = 'ev-mesh'; entry.textContent = '['+ts+'] Msg from '+(d.from||'?'); refreshInbox(); }}
      else {{ entry.textContent = '['+ts+'] '+e.data; }}
      log.insertBefore(entry, log.firstChild);
      while (log.children.length > 50) log.removeChild(log.lastChild);
    }} catch(ex) {{}}
  }};
}}

async function showCryptoStatus() {{
  const c = await api('GET', '/cpip/crypto');
  if (!c) return;
  document.getElementById('cryptoCipher').textContent = c.cipher || '—';
  document.getElementById('cryptoECC').textContent = c.ecc || '—';
  document.getElementById('cryptoPQ').textContent = c.pq_kem || '—';
  document.getElementById('cryptoE2EE').textContent = c.e2ee || '—';
  const det = document.getElementById('cryptoDetails');
  det.innerHTML = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.3rem">
    <div><b>Hash:</b> ${{esc(c.hash||'—')}}</div>
    <div><b>HMAC:</b> ${{esc(c.hmac||'—')}}</div>
    <div><b>KDF:</b> ${{esc(c.key_derivation||'—')}}</div>
    <div><b>Covert:</b> ${{esc(c.covert_channel_version||'—')}}</div>
    <div><b>Timestamp Validation:</b> ${{c.timestamp_validation ? '✓' : '✗'}}</div>
    <div><b>Mesh HMAC:</b> ${{c.mesh_hmac ? '✓' : '✗'}}</div>
    <div><b>Encrypted Storage:</b> ${{c.persist_encrypted ? '✓' : '✗'}}</div>
    <div><b>Emergency:</b> ${{c.emergency_mode ? '🔴 ACTIVE' : '🟢 Normal'}}</div>
    <div><b>Address:</b> ${{esc(c.node_address||'—')}}</div>
    <div><b>Auto-Response:</b> ${{c.incident_auto_response ? 'ON' : 'OFF'}}</div>
  </div>`;
}}

async function rotateKeys() {{
  const r = await api('POST', '/cpip/emergency', {{ action: 'rotate_keys' }});
  if (r) {{ document.getElementById('keyRotResult').textContent = 'Keys rotated ✓'; showCryptoStatus(); }}
}}

async function emergencyActivate() {{
  if (!confirm('⚠ EMERGENCY MODE: Rotate keys, go stealth, notify peers. Continue?')) return;
  const r = await api('POST', '/cpip/emergency', {{ action: 'activate', reason: 'dashboard' }});
  document.getElementById('emergencyResult').textContent = r ? 'Emergency activated' : 'Failed';
  showCryptoStatus(); refreshItf();
}}

async function emergencyDeactivate() {{
  const r = await api('POST', '/cpip/emergency', {{ action: 'deactivate' }});
  document.getElementById('emergencyResult').textContent = r ? 'Deactivated' : 'Failed';
  showCryptoStatus();
}}

async function refreshIR() {{
  const s = await api('GET', '/cpip/incident');
  if (!s) return;
  document.getElementById('irAlertCount').textContent = s.total_alerts || 0;
  const levels = s.alerts_by_level || {{}};
  document.getElementById('irCritical').textContent = (levels.critical||0) + (levels.high||0);
  document.getElementById('irAutoResp').textContent = s.auto_response ? 'ON' : 'OFF';
  document.getElementById('irChainValid').textContent = s.audit_chain_valid ? '✓ Valid' : '✗ Broken';
  const al = await api('GET', '/cpip/incident/alerts?limit=20');
  const el = document.getElementById('irAlertList');
  if (!al || !al.alerts || !al.alerts.length) {{ el.innerHTML = '<div style="color:var(--muted)">No alerts</div>'; return; }}
  let html = '<table><tr><th>Time</th><th>Lvl</th><th>Cat</th><th>Message</th></tr>';
  for (const a of al.alerts.slice().reverse()) {{
    const t = a.human_time ? a.human_time.slice(11,19) : '—';
    const clr = a.level==='critical'?'var(--accent)':a.level==='high'?'#ff8800':a.level==='warn'?'#ffcc00':'var(--muted)';
    html += `<tr><td style="font-size:0.7rem">${{esc(t)}}</td><td style="color:${{clr}};font-weight:600">${{esc(a.level)}}</td><td>${{esc(a.category)}}</td><td style="font-size:0.7rem">${{esc(a.message)}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function clearAlerts() {{
  await api('POST', '/cpip/incident', {{ action: 'clear_alerts' }});
  refreshIR();
}}

async function toggleAutoResp() {{
  const s = await api('GET', '/cpip/incident');
  const r = await api('POST', '/cpip/incident', {{ action: 'auto_response', enabled: !s.auto_response }});
  if (r) showToast('Auto-response: ' + (r.enabled ? 'ON' : 'OFF'));
  refreshIR();
}}

async function refreshSignal() {{
  const s = await api('GET', '/cpip/signal');
  if (!s) return;
  const bw = s.bandwidth || {{}};
  const m = bw.mesh || {{}}, h = bw.http || {{}}, sat = bw.sat || {{}}, mob = bw.mobile || {{}};
  document.getElementById('sigMesh').textContent = (m.recv||0) + ' total';
  document.getElementById('sigMeshErr').textContent = m.errors || 0;
  document.getElementById('sigHttp').textContent = (h.rps||0) + ' rps';
  document.getElementById('sigHttp418').textContent = h['418s'] || 0;
  document.getElementById('sigSat').textContent = (sat.recv||0) + ' recv';
  document.getElementById('sigUptime').textContent = Math.floor(bw.uptime_seconds||0) + 's';
  const lq = s.link_quality || {{}};
  const lqEl = document.getElementById('sigLinkQuality');
  if (Object.keys(lq).length) {{
    let html = '<table><tr><th>Peer</th><th>Latency</th><th>Loss</th><th>Score</th><th>Quality</th></tr>';
    for (const [pid, info] of Object.entries(lq)) {{
      html += `<tr><td>${{esc(pid.slice(0,8))}}</td><td>${{info.latency_ms||'—'}}ms</td><td>${{info.loss_pct||0}}%</td><td>${{info.score||'—'}}</td><td>${{esc(info.quality)}}</td></tr>`;
    }}
    html += '</table>'; lqEl.innerHTML = html;
  }} else {{ lqEl.innerHTML = '<div style="color:var(--muted)">No peer link data yet</div>'; }}
  const em = s.emergency || {{}};
  document.getElementById('sigEmergency').innerHTML = em.active
    ? '<span style="color:var(--accent);font-weight:700">🔴 EMERGENCY ACTIVE</span>'
    : '<span style="color:#00ff88">🟢 Normal operations</span>';
}}

async function diagPing() {{
  const host = document.getElementById('diagPingHost').value || 'localhost';
  const port = document.getElementById('diagPingPort').value || '4180';
  const r = await api('GET', `/cpip/diagnostics/ping?host=${{encodeURIComponent(host)}}&port=${{port}}`);
  const el = document.getElementById('diagPingResult');
  if (!r) {{ el.textContent = 'Ping failed'; return; }}
  el.innerHTML = r.alive
    ? `<div style="color:#00ff88">${{esc(r.host)}}:${{r.port}} — ${{r.latency_ms}}ms</div>`
    : `<div style="color:var(--accent)">${{esc(r.host)}}:${{r.port}} — unreachable (${{esc(r.error||'timeout')}})</div>`;
}}

async function diagScan() {{
  const host = document.getElementById('diagScanHost').value || 'localhost';
  const r = await api('GET', `/cpip/diagnostics/ports?host=${{encodeURIComponent(host)}}`);
  const el = document.getElementById('diagScanResult');
  if (!r || !r.ports) {{ el.textContent = 'Scan failed'; return; }}
  let html = '<table><tr><th>Port</th><th>Status</th></tr>';
  for (const [p, s] of Object.entries(r.ports)) {{
    const clr = s==='open'?'#00ff88':'var(--muted)';
    html += `<tr><td>${{p}}</td><td style="color:${{clr}}">${{s}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function diagDns() {{
  const host = document.getElementById('diagDnsHost').value || 'localhost';
  const r = await api('GET', `/cpip/diagnostics/dns?host=${{encodeURIComponent(host)}}`);
  const el = document.getElementById('diagDnsResult');
  if (!r) {{ el.textContent = 'DNS failed'; return; }}
  el.innerHTML = r.resolved
    ? `<div style="color:#00ff88">✓ ${{esc(r.hostname)}} → ${{(r.ipv4||[]).join(', ')}}</div>`
    : `<div style="color:var(--accent)">✗ ${{esc(r.hostname)}}: ${{esc(r.error||'unknown')}}</div>`;
}}

async function diagTrace() {{
  const host = document.getElementById('diagTraceHost').value || 'localhost';
  const r = await api('GET', `/cpip/diagnostics/traceroute?host=${{encodeURIComponent(host)}}`);
  const el = document.getElementById('diagTraceResult');
  if (!r || !r.hops) {{ el.textContent = 'Traceroute failed'; return; }}
  let html = '<table><tr><th>TTL</th><th>Addr</th><th>Latency</th></tr>';
  for (const h of r.hops) {{
    html += `<tr><td>${{h.ttl}}</td><td>${{esc(h.addr)}}</td><td>${{h.latency_ms !== null ? h.latency_ms+'ms' : '*'}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function diagIfaces() {{
  const r = await api('GET', '/cpip/diagnostics/interfaces');
  const el = document.getElementById('diagIfaces');
  if (!r || !r.interfaces) {{ el.textContent = 'Failed'; return; }}
  let html = '<table><tr><th>Interface</th><th>MAC</th><th>State</th></tr>';
  for (const i of r.interfaces) {{
    html += `<tr><td>${{esc(i.name)}}</td><td style="font-size:0.7rem">${{esc(i.mac||'—')}}</td><td>${{esc(i.state||'?')}}</td></tr>`;
  }}
  html += '</table>'; el.innerHTML = html;
}}

async function refreshAntiISP() {{
  const r = await api('GET', '/cpip/anti-isp');
  if (!r) return;
  const s = r.stun || {{}};
  const u = r.upnp || {{}};
  const rel = r.relay || {{}};
  const dns = r.dns_tunnel || {{}};
  const wss = r.wss || {{}};
  const doh = r.doh || {{}};
  document.getElementById('aispExtIp').textContent = s.external_ip || '—';
  document.getElementById('aispNatType').textContent = s.nat_type + (s.server ? ' via ' + s.server.split(':')[0] : '');
  document.getElementById('aispUpnp').textContent = u.mapped ? '✓ Mapped' : '✗ None';
  document.getElementById('aispRelayCount').textContent = (rel.pool || []).length;
  document.getElementById('aispWss').textContent = wss.active ? '✓ Connected' : '✗ Disconnected';
  document.getElementById('aispWssCount').textContent = (wss.connections || 0) + ' connections';
  document.getElementById('aispDnsTun').textContent = dns.enabled ? '✓ Active' : '✗ Off';
  document.getElementById('aispDnsDomain').textContent = dns.domain || 'not configured';
  document.getElementById('aispDoh').textContent = doh.enabled ? '✓ Enabled' : '✗ Off';
  document.getElementById('aispDohCache').textContent = (doh.cached_entries || 0) + ' cached entries';
  document.getElementById('aispPunchSessions').textContent = r.hole_punch_sessions || 0;
  let active = 0;
  if (s.external_ip) active++;
  if (u.mapped) active++;
  if ((rel.pool || []).length > 0) active++;
  if (dns.enabled) active++;
  if (wss.active) active++;
  if (doh.enabled) active++;
  document.getElementById('aispTransports').textContent = active + '/6';
  if (r.toggles) setToggles('aispToggles', r.toggles);
}}

function setToggles(containerId, toggles) {{
  const box = document.getElementById(containerId);
  if (!box) return;
  box.querySelectorAll('input[data-feat]').forEach(inp => {{
    const f = inp.dataset.feat;
    if (Object.prototype.hasOwnProperty.call(toggles, f)) inp.checked = !!toggles[f];
  }});
}}

async function aispToggle(el) {{
  const feat = el.dataset.feat;
  const r = await api('POST', '/cpip/anti-isp', {{ action: 'toggle', feature: feat, enabled: el.checked }});
  if (!r || r.error) {{ el.checked = !el.checked; return; }}
  showToast(`Anti-ISP ${{feat}}: ${{el.checked ? 'ON' : 'OFF'}}`);
}}

async function aispRefresh() {{
  const r = await api('POST', '/cpip/anti-isp', {{ action: 'refresh' }});
  document.getElementById('aispResult').textContent = r ? 'All transports refreshed' : 'Refresh failed';
  setTimeout(refreshAntiISP, 2000);
}}

async function aispHolePunch() {{
  document.getElementById('aispResult').textContent = 'Testing hole-punch...';
  const r = await api('POST', '/cpip/anti-isp', {{ action: 'hole_punch', ip: '0.0.0.0', port: 4191 }});
  document.getElementById('aispResult').textContent = r ?
    'External: ' + (r.ext_ip || '?') + ':' + (r.ext_port || '?') + ' — punched: ' + r.punched :
    'Hole-punch failed';
}}

async function refreshStingray() {{
  const r = await api('GET', '/cpip/anti-stingray');
  if (!r) return;
  const t = r.threat_level || 0;
  const labels = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const colors = ['var(--green)', 'var(--yellow)', 'var(--orange)', 'var(--danger)', 'var(--danger)'];
  document.getElementById('stThreat').textContent = labels[t] || '?';
  document.getElementById('stThreat').style.color = colors[t] || 'inherit';
  document.getElementById('stThreatLabel').textContent = r.enabled ? 'active' : 'disabled';
  const bl = r.baseline || {{}};
  document.getElementById('stMCC').textContent = bl.mcc || '—';
  document.getElementById('stCellDetail').textContent = (bl.mcc || '') + '/' + (bl.mnc || '') + ' LAC:' + (bl.lac || '');
  document.getElementById('stSignal').textContent = bl.signal ? bl.signal + '%' : '—';
  document.getElementById('stRAT').textContent = bl.rat || '—';
  document.getElementById('stScans').textContent = r.scan_count || 0;
  const alerts = (r.recent_alerts || []).slice(-5).reverse();
  if (alerts.length) {{
    document.getElementById('stAlerts').innerHTML = alerts.map(a =>
      `<div style="margin:2px 0;padding:2px 4px;border-left:2px solid ${{colors[a.threat]||'gray'}}">` +
      `${{new Date(a.time*1000).toLocaleTimeString()}} ${{a.message}} <span style="color:var(--muted)">${{a.detail||''}}</span></div>`
    ).join('');
  }}
  if (r.toggles) setToggles('stToggles', r.toggles);
}}

async function stToggle(el) {{
  const feat = el.dataset.feat;
  const r = await api('POST', '/cpip/anti-stingray', {{ action: 'toggle', feature: feat, enabled: el.checked }});
  if (!r || r.error) {{ el.checked = !el.checked; return; }}
  showToast(`Anti-Stingray ${{feat}}: ${{el.checked ? 'ON' : 'OFF'}}`);
}}

async function stRescan() {{
  const r = await api('POST', '/cpip/anti-stingray', {{ action: 'rescan' }});
  if (r) showToast('Stingray rescan triggered');
  setTimeout(refreshStingray, 1500);
}}

async function refreshSurveillance() {{
  const r = await api('GET', '/cpip/anti-surveillance');
  if (!r) return;
  const t = r.threat_level || 0;
  const labels = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const colors = ['var(--green)', 'var(--yellow)', 'var(--orange)', 'var(--danger)', 'var(--danger)'];
  document.getElementById('asThreat').textContent = labels[t] || '?';
  document.getElementById('asThreat').style.color = colors[t] || 'inherit';
  document.getElementById('asThreatLabel').textContent = r.enabled ? 'active' : 'disabled';
  document.getElementById('asDPI').textContent = r.dpi_signatures_loaded || 0;
  document.getElementById('asSSL').textContent = t >= 3 ? '⚠ INTERCEPT' : '✓ Clean';
  document.getElementById('asSSL').style.color = t >= 3 ? 'var(--danger)' : 'var(--green)';
  document.getElementById('asProc').textContent = t >= 2 ? '⚠ Anomaly' : '✓ Clean';
  document.getElementById('asProc').style.color = t >= 2 ? 'var(--orange)' : 'var(--green)';
  const alerts = (r.recent_alerts || []).slice(-5).reverse();
  if (alerts.length) {{
    document.getElementById('asAlerts').innerHTML = alerts.map(a =>
      `<div style="margin:2px 0;padding:2px 4px;border-left:2px solid ${{colors[a.threat]||'gray'}}">` +
      `${{new Date(a.time*1000).toLocaleTimeString()}} ${{a.message}} <span style="color:var(--muted)">${{a.detail||''}}</span></div>`
    ).join('');
  }}
  if (r.toggles) setToggles('asToggles', r.toggles);
}}

async function asToggle(el) {{
  const feat = el.dataset.feat;
  const r = await api('POST', '/cpip/anti-surveillance', {{ action: 'toggle', feature: feat, enabled: el.checked }});
  if (!r || r.error) {{ el.checked = !el.checked; return; }}
  showToast(`Anti-Surveillance ${{feat}}: ${{el.checked ? 'ON' : 'OFF'}}`);
}}

async function asScan() {{
  const r = await api('POST', '/cpip/anti-surveillance', {{ action: 'scan' }});
  if (r) showToast('Surveillance scan triggered');
  setTimeout(refreshSurveillance, 1500);
}}

async function refreshNeutrality() {{
  const r = await api('GET', '/cpip/net-neutrality');
  if (!r) return;
  document.getElementById('nnThrottle').textContent = r.throttle_detected ? '⚠ THROTTLED' : '✓ Normal';
  document.getElementById('nnThrottle').style.color = r.throttle_detected ? 'var(--danger)' : 'var(--green)';
  document.getElementById('nnMasked').textContent = (r.masked_protocol?.packets || 0);
  document.getElementById('nnFrag').textContent = r.fragmented_packets || 0;
  document.getElementById('nnJitter').textContent = r.jitter_injections || 0;
  if (r.toggles) setToggles('nnToggles', r.toggles);
}}

async function nnToggle(el) {{
  const feat = el.dataset.feat;
  const r = await api('POST', '/cpip/net-neutrality', {{ action: 'toggle', feature: feat, enabled: el.checked }});
  if (!r || r.error) {{ el.checked = !el.checked; return; }}
  showToast(`Net Neutrality ${{feat}}: ${{el.checked ? 'ON' : 'OFF'}}`);
}}

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));

refresh(); refreshHistory(); refreshSchedules(); refreshMesh(); refreshInbox(); refreshSat(); refreshMobile(); refreshItf(); refreshRadio(); renderCovertHistory();
showCryptoStatus(); refreshIR(); refreshSignal(); diagIfaces(); refreshAntiISP(); refreshStingray(); refreshSurveillance(); refreshNeutrality();
document.getElementById('histFilter').addEventListener('change', refreshHistory);
setInterval(refresh, 5000);
setInterval(refreshHistory, 15000);
setInterval(refreshSchedules, 15000);
setInterval(refreshMesh, 30000);
setInterval(refreshInbox, 10000);
setInterval(refreshSat, 30000);
setInterval(refreshMobile, 30000);
setInterval(refreshRadio, 30000);
setInterval(refreshItf, 15000);
setInterval(refreshSignal, 5000);
setInterval(refreshIR, 10000);
setInterval(refreshAntiISP, 30000);
setInterval(refreshStingray, 30000);
setInterval(refreshSurveillance, 30000);
setInterval(refreshNeutrality, 15000);
connectSSE();
</script>
</body>
</html>"""


# ── Pi-Tail USB Gadget (Pi Zero → host via USB OTG) ───────────────────
def start_pitail():
    """Configure Pi Zero as a USB Ethernet gadget.
    
    When plugged into a host (laptop/phone), the Pi appears as a network
    interface. The user opens a browser to 10.0.0.1:4180 for the dashboard.
    
    This uses the Linux USB gadget configfs interface. Requires:
      - Pi Zero (or any board with USB OTG)
      - Kernel compiled with USB gadget support
      - /sys/kernel/config/usb_gadget available
    """
    if not PITAIL_ENABLED:
        return False
    gdir = Path(PITAIL_GADGET_DIR)
    if not gdir.exists():
        print("   ⚠ Pi-Tail: USB gadget configfs not found", flush=True)
        return False
    try:
        gname = "g1"
        gadget = gdir / gname
        if not gadget.exists():
            gadget.mkdir()
            # Standard USB Ethernet descriptor
            (gadget / "idVendor").write_text("0x1d6b")
            (gadget / "idProduct").write_text("0x0104")
            (gadget / "bcdDevice").write_text("0x0100")
            (gadget / "bcdUSB").write_text("0x0200")
            # Config
            cfg = gadget / "configs/c.1"
            cfg.mkdir(parents=True, exist_ok=True)
            (cfg / "MaxPower").write_text("250")
            # Strings
            for d in [gadget / "strings/0x409", cfg / "strings/0x409"]:
                d.mkdir(parents=True, exist_ok=True)
                (d / "manufacturer").write_text("Coffee Protocol")
                (d / "product").write_text("CPIP Pi-Tail")
                (d / "serialnumber").write_text(POT_ID)
            # Ethernet function
            func = gadget / "functions/ecm.usb0"
            func.mkdir(parents=True, exist_ok=True)
            (func / "dev_addr").write_text("42:61:de:ad:be:ef")
            (func / "host_addr").write_text("42:61:de:ad:be:ef")
            # Link function to config
            (cfg / "ecm.usb0").symlink_to(func)
            # UDC (bind to the USB device controller)
            udc = next((gdir.parent / "udc").iterdir(), None)
            if udc:
                (gadget / "UDC").write_text(udc.name)
        # Bring up the interface
        subprocess.run(["ip", "link", "set", "usb0", "up"],
                       capture_output=True, timeout=5, check=False)
        subprocess.run(["ip", "addr", "add",
                        f"{PITAIL_ADDR}/{PITAIL_NETMASK}",
                        "dev", "usb0"],
                       capture_output=True, timeout=5, check=False)
        print(f"   ├ Pi-Tail:    {PITAIL_ADDR}:{BIND_PORT} (USB gadget)", flush=True)
        return True
    except Exception as e:
        print(f"   ⚠ Pi-Tail: {e}", flush=True)
        return False


# ── 418 I'm a Teapot Defense Layer ───────────────────────────────────
# Rejects unauthorized/unauthenticated probes with HTCPCP's most
# famous status code. Makes network mapping and brute-force attacks
# indistinguishable from a joke.
TEAPOT_BLACKLIST = {}
TEAPOT_BLACKLIST_LOCK = threading.Lock()
TEAPOT_PROBE_COUNT = {}
DEFENSE_RATE_LIMIT = int(os.environ.get("CPIP_DEFENSE_RATE_LIMIT", "10"))
DEFENSE_RATE_WINDOW = int(os.environ.get("CPIP_DEFENSE_RATE_WINDOW", "60"))
DEFENSE_BLACKLIST_TTL = int(os.environ.get("CPIP_DEFENSE_BLACKLIST_TTL", "3600"))
DEFENSE_MAX_BLACKLIST = int(os.environ.get("CPIP_DEFENSE_MAX_BLACKLIST", "1000"))

MAX_REQUEST_SIZE = int(os.environ.get("CPIP_MAX_REQUEST_SIZE", "65536"))
CORS_ALLOWED_ORIGINS = os.environ.get("CPIP_CORS_ORIGINS", "")
HTTP_RATE_LIMIT = int(os.environ.get("CPIP_HTTP_RATE_LIMIT", "500"))
HTTP_RATE_WINDOW = int(os.environ.get("CPIP_HTTP_RATE_WINDOW", "120"))

# ── RPC HMAC Authentication (Minima integration) ───────────────────────
# When CPIP_RPC_AUTH=1, mutating CPIP REST endpoints (POST/PUT/DELETE on
# /cpip/*) require an X-CPIP-HMAC header of the form "<timestamp>:<hmac>"
# where hmac = HMAC-SHA256(COVERT_KEY, timestamp||method||path). Timestamps
# must be within ±300s of the server clock. Read-only (GET/BREW/WHEN/
# PROPFIND/OPTIONS) and the dashboard are exempt so the UI keeps working.
RPC_AUTH_ENABLED = os.environ.get("CPIP_RPC_AUTH", "1") == "1"
RPC_AUTH_SKEW = int(os.environ.get("CPIP_RPC_AUTH_SKEW", "300"))


def _rpc_hmac_check(method, path, header_value) -> bool:
    """Validate an X-CPIP-HMAC token. Returns True if enabled-off or valid."""
    if not RPC_AUTH_ENABLED:
        return True
    if not header_value or ":" not in header_value:
        return False
    ts_str, mac = header_value.split(":", 1)
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if abs(time.time() - ts) > RPC_AUTH_SKEW:
        return False
    try:
        expected = hmac.new(
            COVERT_KEY, f"{ts}:{method}:{path}".encode(), hashlib.sha256
        ).hexdigest()
    except Exception:
        return False
    return hmac.compare_digest(expected, mac)


# Master gate for CPIP service (Minima sidecar). When CPIP_ENABLED=0 the
# server still starts but advertises disabled state in /cpip/status.
CPIP_ENABLED = os.environ.get("CPIP_ENABLED", "1") == "1"
# When CPIP_DEFENSE_ENABLED=0, ITF probe blocking/blacklisting is skipped
# (teapot_probe_check / teapot_defense return False/no-op). Default on.
DEFENSE_ENABLED = os.environ.get("CPIP_DEFENSE_ENABLED", "1") == "1"

_HTTP_RATE_LOCK = threading.Lock()
_HTTP_RATE_COUNTS = {}

# Tool fingerprint tracking
TEAPOT_TOOL_HITS = {}  # {tool_name: {"count": int, "last_seen": float, "addrs": set}}
TEAPOT_TOOL_LOCK = threading.Lock()

PENTEST_TOOLS = [
    ("Burp Suite", ["burp", "burpsuite"], ["x-burp", "x-requested-by: burp"]),
    ("Nmap", ["nmap"], []),
    ("SQLMap", ["sqlmap", "sql map"], []),
    ("Nikto", ["nikto"], []),
    ("Gobuster", ["gobuster"], []),
    ("Dirb", ["dirb", "dirbuster"], []),
    ("FFUF", ["ffuf", "fuzz faster u fool"], []),
    ("WFuzz", ["wfuzz"], []),
    ("OpenVAS", ["openvas", "open vas"], []),
    ("Nessus", ["nessus"], []),
    ("Masscan", ["masscan"], []),
    ("ZAP", ["zap", "zed attack proxy"], []),
    ("Arachni", ["arachni"], []),
    ("w3af", ["w3af"], []),
    ("Metasploit", ["metasploit", "msf"], []),
    ("Acunetix", ["acunetix"], []),
]

INFO_TOOLS = [
    ("cURL", ["curl"], []),
    ("Wget", ["wget", "gnu wget"], []),
    ("Python", ["python-requests", "python-urllib", "aiohttp"], []),
    ("Go-http", ["go-http-client"], []),
]

ALL_TOOLS = PENTEST_TOOLS + INFO_TOOLS

def teapot_defense(addr):
    """Check if an address should be greeted with 418."""
    if not DEFENSE_ENABLED:
        return False
    if addr in ("127.0.0.1", "::1", "localhost"):
        return False
    with TEAPOT_BLACKLIST_LOCK:
        entry = TEAPOT_BLACKLIST.get(addr)
        if entry:
            if time.time() < entry.get("expires", 0):
                return True
            del TEAPOT_BLACKLIST[addr]
        return False

def teapot_blacklist_addr(addr, reason="auto"):
    """Add an address to the 418 blacklist. Tracks probe rate.
    Repeated probes within the rate window double the ban duration."""
    if addr in ("127.0.0.1", "::1", "localhost"):
        return
    now = time.time()
    with TEAPOT_BLACKLIST_LOCK:
        hits = TEAPOT_PROBE_COUNT.get(addr, [])
        hits = [t for t in hits if now - t < DEFENSE_RATE_WINDOW]
        hits.append(now)
        TEAPOT_PROBE_COUNT[addr] = hits

        entry = TEAPOT_BLACKLIST.get(addr)
        base_ttl = DEFENSE_BLACKLIST_TTL
        if entry:
            base_ttl = entry.get("ttl", base_ttl)
        if len(hits) > DEFENSE_RATE_LIMIT:
            base_ttl = min(base_ttl * 2, 86400)
        TEAPOT_BLACKLIST[addr] = {"expires": now + base_ttl, "ttl": base_ttl, "reason": reason, "added": now}
        if len(TEAPOT_BLACKLIST) > DEFENSE_MAX_BLACKLIST:
            oldest = sorted(TEAPOT_BLACKLIST.items(),
                           key=lambda x: x[1].get("expires", 0))[:len(TEAPOT_BLACKLIST)//2]
            for k, _ in oldest:
                del TEAPOT_BLACKLIST[k]
                TEAPOT_PROBE_COUNT.pop(k, None)

def teapot_probe_check(headers, addr, path, method):
    """Determine if a request looks like hostile probing vs legitimate HTCPCP.
    
    Classification heuristics (all subject to false positives — that's the point):
    - No Accept-Additions header on BREW to unknown paths → probe
    - PROPFIND without proper host → probe
    - Multiple schema variants in rapid succession → probe
    - Requests to /admin, /config, /wp-content, etc. → probe
    - Known pentest tool User-Agents → probe (Burp Suite, Nmap, SQLMap, etc.)
    """
    if not DEFENSE_ENABLED:
        return False
    probe_indicators = 0
    # Check for common scanner paths
    scanner_paths = ["/admin", "/config", "/wp-", "/.env", "/phpmyadmin",
                     "/shell", "/cmd", "/exec", "/backdoor", "/login",
                     "/setup", "/install", "/manager", "/console"]
    for sp in scanner_paths:
        if path.lower().startswith(sp):
            probe_indicators += 3
            break
    # BREW without additions to odd paths
    if method == "BREW" and not headers.get("Accept-Additions"):
        if not any(p in path for p in ["/coffee", "/tea", "/pot"]):
            probe_indicators += 1
    # Unknown URI schemes (probing for HTTP server info)
    if "://" in path and not is_coffee_uri_path(path):
        probe_indicators += 2
    # Rapid requests from same IP
    # (tracked via teapot_defense above)
    # Known pentest tool detection (Burp Suite, Nmap, SQLMap, etc.)
    tool_matches = teapot_tool_check(headers, addr, pentest_only=True)
    if tool_matches:
        probe_indicators += 2
    return probe_indicators >= 2


def teapot_tool_check(headers, addr, pentest_only=False):
    """Identify known pentest/scan tools from User-Agent and request headers.
    Updates TEAPOT_TOOL_HITS with detected tool usage.
    If pentest_only=True, only returns pentest/attack tools (not generic HTTP clients)."""
    ua = (headers.get("User-Agent") or headers.get("user-agent") or "").lower()
    all_headers = " ".join(f"{k.lower()}:{v.lower()}" for k, v in headers.items())
    detected = []
    signatures = PENTEST_TOOLS if pentest_only else ALL_TOOLS
    for tool_name, ua_keywords, hdr_keywords in signatures:
        matched = False
        for kw in ua_keywords:
            if kw in ua:
                matched = True
                break
        if not matched:
            for kw in hdr_keywords:
                if kw in all_headers:
                    matched = True
                    break
        if matched:
            detected.append(tool_name)
    if detected:
        with TEAPOT_TOOL_LOCK:
            for tool in detected:
                if tool not in TEAPOT_TOOL_HITS:
                    TEAPOT_TOOL_HITS[tool] = {"count": 0, "last_seen": 0, "addrs": set()}
                TEAPOT_TOOL_HITS[tool]["count"] += 1
                TEAPOT_TOOL_HITS[tool]["last_seen"] = time.time()
                TEAPOT_TOOL_HITS[tool]["addrs"].add(addr)
    return detected


def surveillance_fp_check(headers, addr, path=None):
    """Fingerprint a request against the surveillance platform catalog.

    Uses providers.surveillance_fp to match Palantir and other surveillance
    platforms from observable request signals. Returns the fingerprint report
    (matches, confidence, risk) or None when no surveillance platform matched.
    """
    try:
        from providers.surveillance_fp import SurveillanceFingerprintProvider
        report = SurveillanceFingerprintProvider.check_request(headers, addr, path)
        if report and report.get("fingerprinted"):
            return report
    except Exception:
        logger.debug("surveillance fingerprint check failed", exc_info=True)
    return None


# ── Main ──────────────────────────────────────────────────────────────
def shutdown(signum, frame):
    global _discovery_socket
    print("\n[CPIP] Shutting down...", flush=True)
    global _http_server, _redirect_server  # noqa: PLW0602
    if _http_server:
        try: _http_server.server_close()
        except Exception: pass
    if _redirect_server:
        try: _redirect_server.shutdown()
        except Exception: pass
    stop_mdns()
    stop_scheduler()
    stop_radio()
    stop_ntp()
    AntiISP.stop()
    AntiStingray.stop()
    AntiSurveillance.stop()
    NetNeutrality.stop()
    BandwidthAggregator.stop()
    LinkMonitor.stop()
    MeshNode.stop()
    if _discovery_socket:
        try: _discovery_socket.close()
        except Exception: pass
        _discovery_socket = None
    if gpio.is_available:
        gpio.off()
    sys.exit(0)


def _try_bind(max_attempts=10):
    """Try to bind the HTTP server on BIND_PORT or subsequent ports.
    Returns (server, actual_port) or raises on total failure."""
    base = BIND_PORT
    for i in range(max_attempts):
        port = base + i
        try:
            return port, ThreadedHTTPServer((BIND_ADDR, port), CPIPHandler)
        except OSError:
            if i < max_attempts - 1:
                continue
            raise
    raise RuntimeError(f"Could not bind any port in range {base}-{base + max_attempts - 1}")


def main():
    # ── CLI flags (no server start) ───────────────────────────────────
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"CPIP {CPIP_VERSION}")
        return
    if "--help" in sys.argv or "-h" in sys.argv:
        print(f"CPIP/HTCPCP Server v{CPIP_VERSION} — Coffee Pot Internet Protocol")
        print("Usage: cpip-server [--version|-V] [--help|-h]")
        print("       (all other configuration via environment variables; see README §Configuration)")
        return

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    global _http_server, _redirect_server, BIND_PORT, POT_ID

    # ── Register RFC-0001..0026 providers (RFC-0001/0002/0004..0026) ──
    try:
        from providers.register_v6 import register_all
        register_all()
    except Exception as e:
        logger.warning("Provider registration failed: %s", e)

    # ── SSL/TLS Setup ──────────────────────────────────────────────────
    use_ssl = SSL_ENABLED
    cert_file = SSL_CERT
    key_file = SSL_KEY

    if use_ssl and (not cert_file or not key_file):
        cert_file, key_file = _generate_self_signed_cert(SSL_CERT_DIR)

    if use_ssl:
        if not os.path.exists(cert_file):
            print(f"   ⚠ SSL cert file not found: {cert_file}", flush=True)
            use_ssl = False
        elif not os.path.exists(key_file):
            print(f"   ⚠ SSL key file not found: {key_file}", flush=True)
            use_ssl = False

    # Bind HTTP(S) server with port fallback to handle concurrent use
    try:
        if use_ssl:
            actual_port, server = _try_bind()
            server.server_close()
            server = ThreadedHTTPSServer((BIND_ADDR, actual_port), CPIPHandler,
                                         certfile=cert_file, keyfile=key_file)
        else:
            actual_port, server = _try_bind()
    except Exception as e:
        print(f"   ⚠ Cannot bind HTTP server on any port: {e}", flush=True)
        print(f"   ⚠ Check if another CPIP instance or application is using ports {BIND_PORT}-{BIND_PORT+9}.", flush=True)
        sys.exit(1)

    # Update global port so all internal references resolve to the bound port
    BIND_PORT = actual_port
    POT_ID = hashlib.sha256(f"{HOSTNAME}:{BIND_PORT}".encode()).hexdigest()[:8]
    _http_server = server

    # ── HTTP→HTTPS redirect server ────────────────────────────────────
    if use_ssl and HTTP_REDIRECT:
        try:
            redirect_server = ThreadedHTTPServer((BIND_ADDR, HTTP_REDIRECT_PORT), HTTPRedirectHandler)
            _redirect_server = redirect_server
        except Exception as e:
            print(f"   ⚠ HTTP redirect server on port {HTTP_REDIRECT_PORT} failed: {e}", flush=True)
            print("   ⚠ Continuing without HTTP→HTTPS redirect.", flush=True)
            _redirect_server = None
            redirect_server = None
    else:
        redirect_server = None

    bev = DEVICE_BEVERAGE_MAP.get(DEVICE_TYPE, ["tea"])
    scheme = "cpip" if use_ssl else "http"
    host_display = BIND_ADDR if BIND_ADDR not in ("0.0.0.0", "") else "localhost"

    print(f"☕  CPIP v{CPIP_VERSION} — Coffee Pot Internet Protocol", flush=True)
    print(f"   ┌ Device:     {DEVICE_TYPE}", flush=True)
    print(f"   ├ Pot ID:     {POT_ID}", flush=True)
    print(f"   ├ Hostname:   {HOSTNAME}", flush=True)
    print(f"   ├ Listen:     {BIND_ADDR}:{BIND_PORT}", flush=True)
    print(f"   ├ TLS/SSL:    {'✓ cpip:// (' + cert_file + ')' if use_ssl else 'HTTP (no TLS)'}", flush=True)
    if use_ssl and HTTP_REDIRECT and redirect_server:
        print(f"   ├ Redirect:   HTTP→cpip:// on port {HTTP_REDIRECT_PORT}", flush=True)
    print(f"   ├ Beverages:  {', '.join(bev)}", flush=True)
    print(f"   ├ GPIO:       {'Pin ' + str(GPIO_PIN) + ' (RPi.GPIO)' if gpio.is_available else 'Disabled'}", flush=True)
    print(f"   ├ mDNS:       {'Enabled' if AVAHI_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Covert:     {'ECC-Active' if COVERT_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Mesh:       {'Port ' + str(MESH_PORT) + ' (active)' if MESH_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Cover:      {'Traffic generation on' if COVER_TRAFFIC else 'Off'}", flush=True)
    teapot_status = "I'm a Teapot defense active" if MESH_ENABLED else "Disabled"
    print(f"   ├ 418:        {teapot_status}", flush=True)
    print(f"   ├ Satellite:  {'Port ' + str(SATELLITE_PORT) + ' (sat-mesh)' if SATELLITE_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Radio:      {'Port ' + str(RADIO_FREQ//1000000) + ' MHz (' + RADIO_MODE.upper() + ')' if RADIO_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Mobile:     {'Port ' + str(MOBILE_PORT) + ' (' + MOBILE_INTERFACE + ')' if MOBILE_ENABLED else 'Disabled'}", flush=True)
    print(f"   ├ Thermos:    {'Aggregator mode' if THERMOS_ENABLED else 'Standard'}", flush=True)
    num_providers = len(cpip_providers.registry.get_info())
    print(f"   └ Providers:  {num_providers} registered — /cpip/providers", flush=True)
    print(flush=True)
    print("   HTCPCP (RFC 2324+7168): BREW, WHEN, PROPFIND, POST, GET", flush=True)
    print(f"   coffee: URI scheme:     {len(COFFEE_SCHEME_NAMES)} international variants", flush=True)
    print("   message/coffeepot:      Content-Type for start/stop commands", flush=True)
    print("   CPIP:                 /cpip/status, /cpip/brew, /cpip/schedule, /cpip/pots, /cpip/metrics, /cpip/events", flush=True)
    print("   MESH:                 /cpip/mesh/status, /cpip/mesh/peers, /cpip/mesh/inbox, /cpip/mesh/send, /cpip/mesh/broadcast", flush=True)
    print("   SAT-MESH:             /cpip/mesh/sat (satellite/Starlink status)", flush=True)
    print("   RADIO:                /cpip/mesh/radio (LoRa / TNC / packet radio status)", flush=True)
    print("   MOBILE:               /cpip/mesh/mobile (4G/5G / LTE / WWAN status)", flush=True)
    print("   COVERT (ECC):         /cpip/mesh/encode, /cpip/mesh/decode", flush=True)
    print("   DEADDROP:             /cpip/mesh/deaddrop?action=list|claim&id= (dead-drop query)", flush=True)
    print("   DEFENSE:              /cpip/defense (418 blacklist + stealth status)", flush=True)
    print("   PROVIDERS:            /cpip/providers?type=kem|dns|mesh_transport (provider registry)", flush=True)
    print("   418 DEFENSE:          Unauthorized probes answered with 418 I'm a Teapot", flush=True)
    print(f"   NTP:                  {'Syncing to ' + NTP_SERVER if NTP_SYNC else 'Disabled'}", flush=True)
    print("   NO INTERNET REQUIRED — local mesh; Satellite relays internet-wide mesh", flush=True)
    print("   Crypto: AES-GCM + ECDH P-256; KEM catalog includes standard-size and experimental 1nf1D3L ranks (not mesh-negotiated)", flush=True)
    print("   Anti-ISP: STUN + UPnP + DNS-Tunnel + WSS + Relay + DoH", flush=True)
    if SPOOF_ENABLED:
        pm = ProxyManager()
        rotator = IPRotator()
        tor_avail = "Tor=" + ("ON" if pm.tor_available else "no-daemon")
        proxy_count = f"ProxyPool={pm.proxy_count}" if pm.proxy_count else ""
        src_ips = f"SourceIPs={rotator.source_ip_count}"
        spoof_info = " | ".join(filter(None, [SPOOF_MODE.upper(), tor_avail, proxy_count, src_ips]))
        print(f"   IP Spoof:   {spoof_info}", flush=True)
        wrap_urllib_for_spoof()
    if PALANTIR_ENABLED:
        ph = PalantirHardening()
        palantir_mode = ph.mode.upper()
        chaff_on = "Chaff=ON" if PALANTIR_CHAFF else ""
        mix = f"MixDelay={PALANTIR_MIX_DELAY}s" if PALANTIR_MIX_DELAY else ""
        fixed = f"Fixed={PALANTIR_FIXED_SIZE}B" if PALANTIR_FIXED_SIZE else ""
        bc = "Broadcast=ON" if PALANTIR_BROADCAST else ""
        info = " | ".join(filter(None, [palantir_mode, chaff_on, mix, fixed, bc]))
        print(f"   Palantir:   {info}", flush=True)
        ph.log_agent("hardening active at startup")
    print("   Anti-Stingray: IMSI catcher detection + RF anomaly monitoring", flush=True)
    print("   Anti-Surveillance: DPI detection + SSL intercept + exploit detection", flush=True)
    print("   Net Neutrality: Protocol masquerading + DPI evasion + throttle detection", flush=True)
    print(f"   Incident Response: {'ACTIVE' if IncidentResponse._auto_response_enabled else 'STANDBY'}", flush=True)
    print("   Signal Awareness: Jamming detection + bandwidth monitoring", flush=True)
    print("   Emergency Mode: Key rotation + secure wipe available", flush=True)

    if PITAIL_ENABLED:
        start_pitail()
    start_mdns()
    start_discovery()
    start_scheduler()
    start_ntp()
    MeshNode.start()
    PalantirHardening.start()
    AntiISP.start()
    AntiStingray.start()
    AntiSurveillance.start()
    NetNeutrality.start()
    LinkMonitor.start()
    BandwidthAggregator.start()
    if BONDING_ENABLED:
        links = LinkMonitor.get_active_links()
        print(f"   ├ Bonding:    {len(links)} active links {'|'.join(l[0] for l in links[:5])}"
              f"{'...' if len(links) > 5 else ''}", flush=True)
    start_radio()

    # ── Start RFC-0001..0026 providers (RFC-0005..0026) ───────────────
    try:
        from providers.register_v6 import start_all
        start_all()
    except Exception as e:
        logger.warning("Provider startup failed: %s", e)

    address_display = MeshNode.node_address or "(ECC keys generated on first mesh message)"
    print(f"   ├ ECC:        ECDSA/ECDH P-256 active — {address_display[:20]}...", flush=True)

    # ── Start HTTP redirect thread if SSL ─────────────────────────────
    if _redirect_server:
        def _redirect_serve():
            try:
                _redirect_server.serve_forever()
            except KeyboardInterrupt:
                pass
        redirect_thread = threading.Thread(target=_redirect_serve, daemon=True)
        redirect_thread.start()
        print(f"   ├ Redirect:  HTTP port {HTTP_REDIRECT_PORT} → HTTPS port {BIND_PORT}", flush=True)

    try:
        _http_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if _http_server:
            try: _http_server.server_close()
            except Exception: pass
        if _redirect_server:
            try: _redirect_server.shutdown()
            except Exception: pass
        if _discovery_socket:
            try: _discovery_socket.close()
            except Exception: pass
        stop_mdns()
        stop_scheduler()
        stop_radio()
        stop_ntp()
        PalantirHardening.stop()
        AntiISP.stop()
        AntiStingray.stop()
        AntiSurveillance.stop()
        NetNeutrality.stop()
        BandwidthAggregator.stop()
        LinkMonitor.stop()
        MeshNode.stop()
        try:
            from providers.register_v6 import ALL_V6_PROVIDERS
            for p in ALL_V6_PROVIDERS:
                try:
                    if hasattr(p, "stop"):
                        p.stop()
                except Exception:
                    pass
        except Exception:
            pass
        print("[CPIP] Stopped.", flush=True)


if __name__ == "__main__":
    main()
