# CPIP — Coffee Pot Internet Protocol

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://python.org)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux%20%7C%20Raspberry%20Pi-blue.svg)](deploy-pi.sh)
[![Version](https://img.shields.io/badge/version-7.0.0-blue.svg)]()
[![CI](https://img.shields.io/github/actions/workflow/status/WilliamMajanja/CPIP-/ci.yml?branch=master)](https://github.com/WilliamMajanja/CPIP-/actions)
[![RFC 2324](https://img.shields.io/badge/RFC-2324-green.svg)](https://datatracker.ietf.org/doc/html/rfc2324)
[![RFC 7168](https://img.shields.io/badge/RFC-7168-green.svg)](https://datatracker.ietf.org/doc/html/rfc7168)
[![Mesh](https://img.shields.io/badge/mesh-LAN%20%7C%20Satellite%20%7C%20Radio%20%7C%20Mobile-blueviolet.svg)]()
[![ITF Defense](https://img.shields.io/badge/ITF-defense-orange.svg)]()
[![Covert Channel](https://img.shields.io/badge/covert-channel-lightgrey.svg)]()
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20%7C%20ECDH%20%7C%20Kyber-success.svg)]()
[![K8s](https://img.shields.io/badge/Kubernetes-ready-326CE5.svg)]()
[![GPIO](https://img.shields.io/badge/GPIO-Raspberry%20Pi-green.svg)]()
[![FIPS](https://img.shields.io/badge/FIPS-197%20%7C%20186--4%20%7C%20180--4-blue.svg)]()
[![HSM](https://img.shields.io/badge/HSM-PKCS%2311-orange.svg)]()
[![Anti-ISP](https://img.shields.io/badge/Anti--ISP-STUN%20%7C%20UPnP%20%7C%20DNS%20Tunnel%20%7C%20WSS%20%7C%20DoH-red.svg)]()
[![Anti-Stingray](https://img.shields.io/badge/Anti--Stingray-IMSI%20Catcher%20Detection-red.svg)]()
[![Anti-Surveillance](https://img.shields.io/badge/Anti--Surveillance-DPI%20%7C%20Obfuscation%20%7C%20Metadata%20Strip-red.svg)]()
[![Anti-Palantir](https://img.shields.io/badge/Anti--Palantir-Traffic%20Analysis%20%7C%20Mix%20Net%20%7C%20Chaff-red.svg)]()
[![Net Neutrality](https://img.shields.io/badge/Net%20Neutrality-BW%20Monitor%20%7C%20Masquerade%20%7C%20Fragmentation-red.svg)]()
[![TUI](https://img.shields.io/badge/TUI-OpenTUI-brightgreen.svg)]()
[![b4dm4n-cw](https://img.shields.io/badge/b4dm4n--cw-Cipher%20Workbench-yellowgreen.svg)]()

Implementation of RFC 2324 (HTCPCP) and RFC 7168 (HTCPCP-TEA) with mesh networking, multi-transport routing, cryptographic defense, and active network defense.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Web Dashboard](#web-dashboard)
- [ITF Defense System](#itf-defense-system)
- [Multi-Transport Architecture](#multi-transport-architecture)
- [Covert Channel](#covert-channel)
- [Cryptography](#cryptography)
- [TLS/SSL](#tlsssl)
- [Deployment](#deployment)
- [Kubernetes](#kubernetes)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Specification and Request Records](#specification-and-request-records)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Hyper Text Coffee Pot Control Protocol (HTCPCP) was published as the humorous, Informational RFC 2324 on April 1, 1998; it is not an Internet Standards Track specification. RFC 7168, also Informational, updates it for tea. These protocol references do not certify CPIP's implementation, security, or conformance.

CPIP implements the full HTCPCP specification and extends it into a multi-transport mesh communication system with active network defense. The protocol operates over four transport layers — LAN, satellite, radio (LoRa/TNC), and mobile broadband — with end-to-end encryption, store-and-forward messaging, and covert channels. All HTCPCP brew requests and responses double as cover traffic for encrypted mesh messages.

The documents in `specs/` are draft RFC proposals. Their provider routes expose implemented/configured capabilities, but hardware-, carrier-, and third-party-service features remain unavailable until their real backends are installed and enabled. The dashboard's **RFC Providers** tab shows live provider state; it does not treat a draft or simulation as a deployed capability.

## Features

- **HTCPCP/HTCPCP-TEA** — RFC 2324 and RFC 7168 (BREW, WHEN, PROPFIND, OPTIONS)
- **Web dashboard** — Single-page application with tabs for Brew, Mesh, Covert, ITF Defense, Scheduling, and History
- **Mesh networking** — Peer-to-peer with store-and-forward, auto-discovery, and E2EE
- **Multi-transport routing** — LAN UDP, satellite (internet-wide), radio (LoRa/TNC), mobile 4G/5G with automatic message forwarding between transports
- **Runtime transport toggles** — Enable/disable satellite and mobile transports via API without restart
- **Runtime defense policy toggles** — Independent enable/disable of every Anti-ISP, Anti-Stingray, Anti-Surveillance, Anti-Palantir, and Net-Neutrality vector via API or dashboard
- **Covert channel** — Data embedded in Accept-Additions brew headers with LocalStorage-backed message history
- **ITF (In The Face) defense** — Active probe blocking with HTTP 418 responses
- **Pentest tool detection** — Fingerprinting of 16 security tools (Burp Suite, Nmap, SQLMap, Nikto, and 12 more)
- **IP blacklist management** — Rate-limited exponential ban duration
- **CoffeeCipher v5 (AES-256-GCM)** — FIPS 197 authenticated encryption with HKDF-SHA256 key derivation
- **ECDSA/ECDH P-256** — FIPS 186-4 signatures and key exchange
- **HybridKEM API** — ECDH P-256 combined with a selected KEM size; this API is separate from the active mesh E2EE transport
- **Post-quantum KEM** — Standard parameter-size options 512/768/1024; default 768. Experimental 1nf1D3L-2048/4096 ranks are separately named and are not security-level claims. A standard-library-only backend is available (`CPIP_ML_KEM_BACKEND=stdlib`); bundled variants are non-FIPS.
- **Optional hybrid KEM API** — ECDH P-256 + selected KEM backend; separate from active mesh E2EE
- **SHA-256 domain-separated hashing** — Tamper-evident audit chain
- **ECDSA/ECDH P-256** — FIPS 186-4 end-to-end encryption, address book, port hopping
- **Incident response** — Auto-detection, severity alerts, auto-mitigation
- **Signal awareness** — Bandwidth estimation, jamming detection, link quality monitoring
- **Emergency mode** — Instant key rotation, peer notification, secure wipe
- **GPIO relay control** — Physical coffee maker control on Raspberry Pi
- **HTTP security** — Rate limiting, request size limits, security headers
- **TLS/SSL** — Built-in HTTPS with auto-generated self-signed certificates, custom certificate support, and HTTP-to-HTTPS redirect
- **Kubernetes support** — Manifests with ConfigMap, Secret, Ingress, and NetworkPolicy (see Kubernetes section for version note)
- **Encrypted persistence** — Data at rest encrypted with HMAC integrity verification
- **CLI client** — Full-featured bash CLI
- **mDNS advertising** — Zero-config discovery via Avahi
- **Brew scheduling** — Timed brews with daily recurring option
- **SSE events** — Real-time server-sent events
- **Prometheus metrics** — Export at `/cpip/metrics`
- **2 HTCPCP beverages** — Coffee and tea (per RFC 2324/7168); device selects which are brewable (`hyper-text` brews both)
- **7 crypto recipes** — Espresso, latte, cappuccino, americano, cold-brew, mocha, matcha (recipe string feeds CoffeeCipher KDF)
- **Addition types** — Milk (6 kinds), syrup (5 kinds), sugar (5 kinds), spice (4 kinds), alcohol (5 kinds)
- **Pi-Apps support** — One-click install on Raspberry Pi

## Quick Start

```bash
# Start the server (SSL, auto-cert, and HTTP→HTTPS redirect are ON by default)
./server.py

# Web dashboard: https://localhost:4180/dashboard

# Brew coffee
curl -k -X BREW https://localhost:4180/coffee

# Brew tea with additions
curl -k -X BREW \
  -H "Accept-Additions: milk;variety=whole, sugar;variety=honey" \
  https://localhost:4180/tea

# Stop brewing
curl -k -X WHEN https://localhost:4180/

# Check status
curl -k https://localhost:4180/

# Run without SSL (HTTP only)
CPIP_SSL=0 ./server.py
```

### With additional transports

```bash
# Build the optional radio interface (requires gcc)
make -C radio

# Enable all transports
CPIP_SAT=1 CPIP_RADIO=1 CPIP_MOBILE=1 ./server.py
```

### Optional KEM backends

The built-in KEM backend uses only the Python standard library. Install an optional extra for acceleration or an alternative implementation:

```bash
pip install -e '.[pqc-accelerated]'  # NumPy-accelerated 1nf1D3L backend
pip install -e '.[pqc-standard]'     # pqcrypto standard KEM backend (512/768/1024 only)
```

Use `CPIP_ML_KEM_BACKEND=stdlib` to force the dependency-free KEM implementation.

### Using the CLI

```bash
./cpip status
./cpip brew coffee
./cpip mesh peers
./cpip mesh sat
./cpip mesh radio
./cpip mesh mobile
./cpip itf status
./cpip stats
```

## CLI Reference

The `cpip` command-line client communicates with a running CPIP server.

| Command | Description |
|---------|-------------|
| `cpip status` | Server status |
| `cpip version` | Server version |
| `cpip whoami` \| `cpip id` | Local node identity (POT_ID, address, hostname, device) |
| `cpip config` | Full node configuration (JSON) |
| `cpip stats` | All status at a glance (node, mesh, sat, radio, mobile) |
| `cpip brew coffee` \| `cpip pour coffee` | Brew coffee |
| `cpip brew tea` \| `cpip pour tea` | Brew tea |
| `cpip brew tea "milk;variety=whole, sugar;variety=honey"` | Brew with additions |
| `cpip when` | Stop brewing |
| `cpip info` | Pot metadata (PROPFIND) |
| `cpip 418` | Trigger 418 (brew coffee on a teapot) |
| `cpip 418-alcohol` | Trigger 418 (alcohol on a teapot) |
| `cpip additions` | List supported addition types |
| `cpip mesh status` | Mesh network status |
| `cpip mesh peers` | List mesh peers |
| `cpip mesh inbox` | Received messages |
| `cpip mesh send <pot> <msg>` | Send E2EE message |
| `cpip mesh send-raw <pot> <msg>` | Send raw (unencrypted) message — debugging |
| `cpip mesh broadcast <msg>` | Broadcast to all peers |
| `cpip mesh scan` | Discover peers |
| `cpip mesh routes` | Routing table |
| `cpip mesh sat` | Satellite mesh status |
| `cpip mesh radio` | Radio / LoRa status |
| `cpip mesh mobile` | Mobile broadband status |
| `cpip mesh queued` | Store-and-forward queue |
| `cpip covert encode <msg>` | Encode covert message |
| `cpip covert decode <header>` | Decode covert message |
| `cpip covert brew <msg>` | Brew with hidden message |
| `cpip covert status` | Covert channel status |
| `cpip ecc status` | ECC engine status |
| `cpip ecc address` | Show this node's ECC address |
| `cpip ecc book` | List address book |
| `cpip ecc resolve <addr>` | Resolve ECC address |
| `cpip deaddrop list` | List dead-drop messages |
| `cpip deaddrop claim <id>` | Claim a dead-drop message |
| `cpip defense status` | Defense posture (alias for `itf status`) |
| `cpip identity list` | List known identities |
| `cpip identity show <pot>` | Show one identity |
| `cpip identity publish` | Publish this node's identity to the mesh |
| `cpip identity vouch <pot> [level]` | Vouch for a peer (2=marginal, 3=full) |
| `cpip identity graph` | Show the web-of-trust graph |
| `cpip dns list` | List registered `.pot` names |
| `cpip dns register <name>` | Register a `.pot` DNS name |
| `cpip dns resolve <name>` | Resolve a `.pot` name to a pot_id |
| `cpip dns remove <name>` | Remove a `.pot` name |
| `cpip groups list` | List group chats |
| `cpip groups create <name>` | Create an E2EE group chat |
| `cpip groups join <id>` | Join a group |
| `cpip groups leave <id>` | Leave a group |
| `cpip groups send <id> <msg>` | Send an encrypted group message |
| `cpip groups history <id>` | View group message history |
| `cpip sync channels` | List offline-sync channels |
| `cpip sync pending` | Show pending undelivered messages |
| `cpip sync send <channel> <msg>` | Send an offline-sync message |
| `cpip sync clocks` | Show peer clock skew |
| `cpip sync request <pot>` | Request sync from a peer |
| `cpip cluster start [n]` | Launch an n-node local test cluster (`cluster.sh`) |
| `cpip cluster stop` | Stop the local test cluster |
| `cpip cluster status` | Local test cluster status |
| `cpip cluster connect [n]` | Connect to cluster node n |
| `cpip cluster demo [n]` | Run a demo against an n-node cluster |
| `cpip tui [host] [port]` | Launch Terminal UI (requires `opentui` — `pip install 'cpip[tui]'`) |
| `cpip itf status` | Full defense posture |
| `cpip itf blacklist` | List blacklisted IPs |
| `cpip itf whitelist <addr>` | Remove IP from blacklist |
| `cpip itf clear` | Clear entire blacklist |
| `cpip itf stealth` | Stealth mode status |
| `cpip itf probe <addr>` | Check if IP is blacklisted |

## Web Dashboard

CPIP includes a single-page application dashboard served at `/dashboard` with twenty tabs providing real-time control and monitoring:

| Tab | Features |
|-----|----------|
| **☕ Brew** | Device info, brew state, progress bar, total count, quick brew of 9 beverages, hot/iced toggle, milk (6), syrup (5), sugar (5), spice (4), alcohol (6), repeat last brew |
| **📡 Mesh** | Peer count, inbox, store-and-forward queue, satellite/mobile/radio status, send/broadcast, peer table, inbox table, routing table |
| **🔒 Covert** | Encode/decode Accept-Additions headers, copy-to-clipboard, persistent history (localStorage), clear history |
| **🛡 ITF** | 418 teapot, stealth toggle, port hopping, latent ports, blacklist management (add/bulk/import/export/clear), probe, detected pentest tools |
| **🔐 Crypto** | Cipher/ECC/PQ-KEM/E2EE status, key rotation, emergency mode |
| **🚨 IR** | Incident alerts, severity counts, audit chain, auto-response toggle |
| **🌐 Anti-ISP** | STUN/UPnP/relay/DNS-tunnel/WSS/DoH status + per-vector toggles, hole-punch test |
| **📶 Anti-Stingray** | Threat level, cell tower, signal, scans + per-vector toggles, rescan |
| **👁 Anti-Surveillance** | Threat level, DPI signatures, SSL intercept, process integrity + per-vector toggles, scan |
| **🕵️ Anti-Palantir** | Mix-net status, chaff traffic, identity rotation, traffic normalization + per-vector toggles |
| **⚖ Net Neutrality** | Throttle detection, masked/fragmented/jitter stats + per-vector toggles |
| **📊 Signal** | Mesh/HTTP/satellite traffic, human-readable uptime, link quality table, emergency status |
| **🔧 Diag** | TCP ping, port scan, DNS resolve, traceroute, network interfaces |
| **🔑 WoT** | Identity, known identities, trust signatures, publish, vouch (3 levels), trust graph edges |
| **🌍 DNS** | .pot name register/resolve/remove, TTL display, cleanup expired |
| **👥 Groups** | E2EE group create/join/leave/send, auto-load messages on select, member count |
| **🔄 Sync** | Offline-sync channels, pending messages, vector clocks, send/deliver/request |
| **📮 Drops** | Dead drops with live TTL countdown, create/claim, color-coded expiry |
| **🔗 Bond** | Bandwidth bonding status, aggregate BW, link table with color-coded latency/loss, toggle/probe |
| **⏰ Schedule** | Schedule brews in X seconds or at datetime, daily recurring, beverage icons, list/delete |
| **📜 History** | Brew history with beverage icons, time/additions/duration, filter (9 beverages), clear |
| **🧩 RFC Providers** | Live capability and configuration status for the RFC extension providers |

The 22 tabs are organized into 8 logical groups: Core (Brew, Mesh, Covert), Security (ITF, Crypto, IR), Defense (Anti-ISP, Anti-Stingray, Anti-Surveillance, Anti-Palantir, Net Neutrality), Network (Signal, Diag), Identity (WoT, DNS), Comms (Groups, Sync, Drops), Infra (Bond, Schedule, History), Integrations (RFC Providers). The tab bar is scrollable and supports keyboard shortcuts (Ctrl+1–9).

The defense groups (Anti-ISP, Anti-Stingray, Anti-Surveillance, Anti-Palantir, Net Neutrality) each have dedicated tabs with per-vector toggles reachable via API or dashboard.

The status bar displays live badges for brewing state, GPIO, mesh, covert, ITF stealth, NTP, and SSE connection status. A live event log shows real-time brew and mesh message events via Server-Sent Events.

## ITF Defense System

The ITF (In The Face) module implements active network defense by identifying and blocking hostile probes using multiple detection heuristics. Blocked probes receive HTTP 418 "I'm a teapot" responses.

### Detection Methods

| Method | Description |
|--------|-------------|
| Scanner paths | Requests to /admin, /config, /wp-, /.env, /phpmyadmin, /shell, /cmd, /exec, /backdoor, /login, /setup, /install, /manager, /console (+3 probe score) |
| Missing headers | BREW without Accept-Additions on non-standard paths (+1 probe score) |
| Unknown URI schemes | Non-coffee URIs (+2 probe score) |
| Pentest tool fingerprinting | User-Agent and header inspection for 16 security tools (+2 probe score) |
| Rate limiting | Repeated probes double the ban duration (up to 24 hours) |

Threshold: probe score >= 2 results in 418 response and IP blacklisting.

### Detected Tools

The following tools are detected by User-Agent fingerprinting: Burp Suite, Nmap, SQLMap, Nikto, Gobuster, Dirb, FFUF, WFuzz, OpenVAS, Nessus, Masscan, ZAP, Arachni, w3af, Metasploit, Acunetix.

Informational tools (cURL, Wget, Python, Go-http) are tracked in the dashboard but do not trigger blocking.

### Runtime Controls

- **Stealth mode** — Toggle via `POST /cpip/defense {"action":"stealth","enabled":true}` or dashboard button
- **Blacklist** — Whitelist individual IPs, clear entire blacklist, probe any IP
- **Transport toggles** — Enable or disable satellite/mobile at runtime via API

### Blacklist Behavior

- Base TTL: 1 hour (`CPIP_DEFENSE_BLACKLIST_TTL`)
- Rate limit: 10 probes within 60 seconds doubles the ban duration
- Maximum entries: 1000 (oldest half pruned on overflow)
- Localhost (127.0.0.1, ::1) is never blacklisted

## Multi-Transport Architecture

CPIP supports four mesh transports with automatic message forwarding between all transports (routing loops are prevented).

| Transport | Env Flag | Port | Runtime Toggle | Description |
|-----------|----------|------|----------------|-------------|
| LAN Mesh | `CPIP_MESH=1` | 4191 | None | UDP heartbeat mesh on local network |
| Satellite | `CPIP_SAT=1` | 4195 | `POST /cpip/mesh/sat` | Internet-wide UDP relay with GPS coordinates |
| Radio | `CPIP_RADIO=1` | Unix socket | None | LoRa SPI, KISS TNC serial, or simulation |
| Mobile | `CPIP_MOBILE=1` | 4196 | `POST /cpip/mesh/mobile` | 4G/5G WWAN mesh with signal telemetry |

Satellite and mobile transports can be enabled or disabled at runtime without restarting the server.

### LAN Mesh

Nodes discover each other via UDP heartbeats on port 4191. Messages use store-and-forward delivery with ECDH P-256 E2EE by default. Port hopping and stealth mode are supported. No internet connection required — works over Ethernet, WiFi, WiFi Direct, or any IP-based network.

### Satellite Mesh

Internet-wide mesh relay using UDP port 4195, designed for satellite links with high latency. Features GPS coordinate broadcasting (lat/lon/alt), bootstrap seed nodes for peer discovery, and configurable timeouts for high-latency links. Dual env var naming (`CPIP_SAT_*` / `CPIP_STARLINK_*`) for backward compatibility.

### Radio Transport (LoRa / TNC)

C-based radio interface with zero external dependencies. Built with `gcc -O2 -Wall -pthread`. Supports:
- **SX1276/SX1278 LoRa** via SPI (full register map)
- **KISS TNC** serial (AX.25 over serial via termios)
- **RTL-SDR receive** (requires librtlsdr, build with `make RTL=1`)
- **Simulation mode** — requires explicit `--sim` flag; LoRa mode requires real hardware
- Default mode is `lora` (not `sim`)
- Duty cycle enforcement and listen-before-talk

The Python bridge (`radio/radio_protocol.py`) communicates with the C binary over a Unix domain socket (`/tmp/cpip-radio.sock`).

### Mobile Broadband (4G/5G / LTE / WWAN)

UDP-based mesh transport over cellular data interfaces. Features include automatic signal quality reading via ModemManager (`mmcli`) and sysfs, bootstrap seed nodes for peer discovery, TCP keepalive-compatible heartbeat intervals, and RSRP/RSSI/SINR telemetry.

## Covert Channel

Messages can be embedded inside legitimate HTCPCP brew requests. The `Accept-Additions` header carries data disguised as coffee customization:

```
Accept-Additions: milk;variety=48656c6c, syrup;variety=6f20576f, sugar;variety=726c6421
```

The system generates cover traffic (random brew requests at configurable intervals) to obscure which requests carry real messages. The dashboard Covert tab provides encode, decode, and persistent history functionality.

## Cryptography

All cryptographic primitives use FIPS-compliant algorithms via the `cryptography` library, which provides constant-time implementations. The `secrets` module replaces `random` for all security-relevant operations. Post-quantum KEM is available via the `b4dm4n-cw` CLI (non-FIPS).

### CoffeeCipher v5 (AES-256-GCM)

- Cipher: AES-256-GCM (FIPS 197) with 12-byte nonce and 16-byte authentication tag
- Key derivation: HKDF-SHA256 with domain-separated info strings
- Format: `nonce(12B) || ciphertext || GCM-tag(16B)`
- Backward-compatible: reads v1 and v2 messages transparently

### ECDSA/ECDH P-256

- Key exchange: ECDH over NIST P-256 (FIPS 186-4)
- Signatures: ECDSA with P-256 (FIPS 186-4)
- Constant-time implementations via `cryptography` library
- Used for mesh E2EE, node identity, and address book

### 1nf1D3L's Kyber KEM (Post-Quantum, Non-FIPS)

The provider registry supports ML-KEM-512/768/1024 plus experimental `1nf1d3l_kem_2048` and `1nf1d3l_kem_4096`. The latter are custom module-rank experiments, not standardized ML-KEM security levels. The built-in standard-library backend can be selected with `CPIP_ML_KEM_BACKEND=stdlib`; the NumPy implementation remains available as the accelerated backend.

- Variant: Non-FIPS 1nf1D3L parameters at 512/768/1024 sizes; default size is 768. Experimental custom K=8/K=16 ranks are separately named 2048/4096.
- Parameters: n=256, q=3329, eta1=3, eta2=2; standard-size k=2/3/4, experimental k=8/16
- Domain tag: "1NF1D3L-KYBER-V1" on all hash/KDF inputs
- Wider noise: eta=3 (vs FIPS eta=2) for enhanced concrete security
- NTT twiddle perturbation: Per-session random twiddle factors for side-channel resistance
- Coffee recipe binding: Recipe string mixed into KDF
- Key confirmation: Re-encapsulation check (implicit rejection via KDF with z)
- ML-KEM-768 sizes: PK=1184B, SK=2400B, CT=1120B, SS=32B; other sizes use their corresponding parameter sizes
- CLI: `./b4dm4n_cw.py {keygen,encaps,decaps,bench,info,tui,coffee}` (positional
  pubkey for `encaps`; positional privkey + ciphertext for `decaps`)

### HybridKEM (Classical + Post-Quantum)

CPIP's optional hybrid KEM API combines ECDH P-256 with a configured KEM (768 by default; experimental 1nf1D3L ranks 2048/4096 are nonstandard):

- ECDH P-256 (FIPS 186-4) + selected non-FIPS bundled KEM
- Key derivation: HKDF-SHA256 from combined ECDH + Kyber shared secrets
  (domain tag `cpip-hybrid-kem-kyber-v1`)
- This composition has no independent security proof; extended ranks are experimental
- Sizes: PK~1251B, SK~2432B, CT~1187B, SS=32B
- Implemented in `server.HybridKEM` (server.py:1485)
- CLI: select hybrid via `-a hybrid` (alias for `hybrid-ecdh-kyber`), e.g.
  `./b4dm4n_cw.py keygen -a hybrid -o h` / `encaps -a hybrid h.pk` / `decaps -a hybrid h.sk ct`
  (there are no separate `hybrid-keygen`/`hybrid-encaps`/`hybrid-decaps` subcommands)

### HMAC-SHA256

Mesh heartbeat authentication and message integrity verification.

### SHA-256 / SHA3-256

Domain-separated hashing for audit chain and identity; SHA3-256 for Kyber KDF/H.

### Encrypted Persistence

v4 format with AES-256-GCM encryption and HMAC integrity verification. v1/v2 backward-compatible load.

Classical primitives (AES-256-GCM, ECDSA/ECDH P-256, HKDF-SHA256, HMAC-SHA256) are FIPS-compliant. The bundled KEM variants are not FIPS 203 validated and are intended for research and experimental use. The pure-Python backend has no third-party KEM dependencies; the accelerated backend requires NumPy. CPIP does not implement RSA-KEM.

## TLS/SSL

CPIP includes built-in HTTPS support with three modes.

### Auto Self-Signed Certificates

```bash
CPIP_SSL=1 CPIP_SSL_AUTO=1 ./server.py
```

On first startup, CPIP generates a self-signed certificate in `.ssl/cert.pem` and `.ssl/key.pem` using OpenSSL. If OpenSSL is unavailable, it falls back to the Python `cryptography` library, and finally to a minimal stub.

### Custom Certificates

```bash
CPIP_SSL=1 CPIP_SSL_CERT=/path/to/cert.pem CPIP_SSL_KEY=/path/to/key.pem ./server.py
```

### HTTP-to-HTTPS Redirect

```bash
CPIP_SSL=1 CPIP_SSL_AUTO=1 CPIP_HTTP_REDIRECT=1 CPIP_HTTP_REDIRECT_PORT=4181 ./server.py
```

When enabled, all HTTP requests on the redirect port receive a 301 Moved Permanently to the equivalent HTTPS URL.

### Security Headers

When SSL is active, CPIP adds Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Content-Security-Policy, and Upgrade-Insecure-Requests headers.

## Deployment

### Raspberry Pi

```bash
# Full deployment (run as root)
sudo ./deploy-pi.sh

# Manual installation
sudo mkdir -p /opt/cpip
sudo cp server.py /opt/cpip/
sudo chmod +x /opt/cpip/server.py
```

The deploy script installs:
- Server to `/opt/cpip/server.py`
- CLI to `/usr/local/bin/cpip`
- Web dashboard override to `/opt/cpip/web/` (only if `web/` contains files; otherwise the embedded dashboard in `server.py` is used)
- Systemd service (`cpip.service`)
- Pi-Apps package (if `pi-apps/` directory is present)

### Pi-Apps

Copy the `pi-apps/` directory to `~/.local/share/pi-apps/apps/Coffee-Protocol/` for one-click install in the Pi-Apps catalog.

### Systemd Service

```ini
[Unit]
Description=CPIP v7.0.0 — Coffee Pot Internet Protocol
After=network.target

[Service]
Type=simple
Environment=CPIP_DEVICE=hyper-text
Environment=CPIP_MESH=1
Environment=CPIP_COVERT=1
Environment=CPIP_COVERT_KEY=
Environment=CPIP_MESH_STEALTH=0
ExecStart=/usr/bin/python3 /opt/cpip/server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Radio Interface Build

```bash
cd radio
make
```

Produces `radio_if` — a standalone binary with zero external dependencies.

## Kubernetes

CPIP includes Kubernetes manifests for self-hosting, labeled for v7.0.0
and `image: cpip:7.0.0`.

### Quick Deploy

```bash
git clone https://github.com/WilliamMajanska/CPIP-.git
cd CPIP-
kubectl apply -f k8s/
```

### Architecture

| Resource | Description |
|----------|-------------|
| **Namespace** | `cpip` — isolated environment |
| **ConfigMap** | Environment variables (device, ports, mesh, SSL) |
| **Secret** | Sensitive keys (CPIP_COVERT_KEY) |
| **Deployment** | Single replica with health/readiness/startup probes |
| **Service** | ClusterIP exposing HTTPS (4180 by default), optional HTTP redirect (4181), and mesh UDP (4191/4195/4196) |
| **Ingress** | nginx Ingress with TLS passthrough |
| **NetworkPolicy** | Restrict ingress/egress to CPIP ports only |
| **PVC** | 1Gi persistent volume for mesh data |

### Configuration

```bash
kubectl edit configmap cpip-config -n cpip
```

Key settings:
- `CPIP_SSL=1` / `CPIP_SSL_AUTO=1` — HTTPS with auto certs
- `CPIP_MESH=1` — Enable mesh networking
- `CPIP_SAT=1` — Enable satellite transport
- `CPIP_COVERT_KEY` — Set in the Secret, not ConfigMap

### Docker Build

```bash
docker build -t cpip:7.0.0 .
docker run -p 4180:4180 -p 4181:4181 -p 4191:4191/udp \
  -e CPIP_SSL=1 -e CPIP_SSL_AUTO=1 -e CPIP_HTTP_REDIRECT=1 \
  cpip:7.0.0
```

### Access

```bash
# Port forward for local testing
kubectl port-forward -n cpip deployment/cpip 4180:4180
```

### Production Ingress

For external access with a real domain and Let's Encrypt:

```yaml
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - cpip.yourdomain.com
      secretName: cpip-tls-prod
```

## Configuration

All configuration is via environment variables. No configuration files are required.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_DEVICE` | `hyper-text` | Device type: `teapot`, `coffee-pot`, `hyper-text` |
| `CPIP_BIND` | `""` (all interfaces) | HTTP bind address |
| `CPIP_PORT` | `4180` | HTTP port |
| `CPIP_GPIO` | `0` | Enable GPIO relay control |
| `CPIP_GPIO_PIN` | `17` | GPIO pin number |
| `CPIP_AVAHI` | `1` | Enable mDNS advertising |

### Mesh Network

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_MESH` | `1` | Enable mesh networking |
| `CPIP_MESH_PORT` | `4191` | Mesh UDP heartbeat port |
| `CPIP_MESH_TTL` | `5` | Message time-to-live (hops) |
| `CPIP_MESH_HEARTBEAT` | `30` | Heartbeat interval (seconds) |
| `CPIP_MESH_STEALTH` | `0` | Stealth mode (togglable at runtime) |
| `CPIP_MESH_LATENT_PORTS` | `4192,4193,4194` | Port-knocking latent ports |
| `CPIP_MESH_HOP_INTERVAL` | `3600` | Port hop interval (seconds) |
| `CPIP_MESH_PERSIST_DIR` | `/tmp/cpip` | Message persistence directory |

### Covert Channel

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_COVERT` | `1` | Enable covert channel |
| `CPIP_COVERT_KEY` | `""` (auto-generated) | Encryption passphrase; auto-generates 32 random bytes if unset |
| `CPIP_COVER_TRAFFIC` | `1` | Generate random cover traffic |

### Satellite Mesh

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_SAT` | `0` | Enable satellite mesh (togglable at runtime) |
| `CPIP_SAT_PORT` | `4195` | UDP port |
| `CPIP_SAT_BOOTSTRAP` | None | Seed nodes (`host:port,host:port`) |
| `CPIP_SAT_LAT` | `0` | Node latitude |
| `CPIP_SAT_LON` | `0` | Node longitude |
| `CPIP_SAT_ALT` | `0` | Node altitude (meters) |
| `CPIP_SAT_RELAY` | `0` | Relay mode (forward traffic) |
| `CPIP_SAT_TIMEOUT` | `10` | Peer timeout (seconds) |
| `CPIP_SAT_HEARTBEAT` | `60` | Heartbeat interval (seconds) |



### Radio Transport

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_RADIO` | `0` | Enable radio transport |
| `CPIP_RADIO_MODE` | `lora` | Mode: `sim`, `lora`, `tnc`, `rtlsdr` |
| `CPIP_RADIO_FREQ` | `915000000` | Frequency (Hz) |
| `CPIP_RADIO_SF` | `9` | LoRa spreading factor |
| `CPIP_RADIO_BW` | `125000` | LoRa bandwidth (Hz) |
| `CPIP_RADIO_POWER` | `17` | Transmit power (dBm) |
| `CPIP_RADIO_DEVICE` | `/dev/spidev0.0` | TNC serial device |
| `CPIP_RADIO_BAUD` | `115200` | TNC serial baud rate |
| `CPIP_RADIO_HOP_SEQ` | `915000000,916000000,917000000` | Spectrum hop channels (Hz) |
| `CPIP_RADIO_HOP_INTERVAL` | `30` | Channel rotation interval (seconds) |
| `CPIP_RADIO_BURST_TX` | `0` | Explicitly allow RF burst transmissions; off by default |

Starting the spectrum hop controller does not transmit bursts unless `CPIP_RADIO_BURST_TX=1` is set.

### EM-Sec / Faraday Test

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_EMSEC` | `0` | Enable EM-security monitoring |
| `CPIP_EMSEC_ALLOW_TX` | `0` | Allow explicit Faraday-test RF transmissions; off by default |
| `CPIP_EMSEC_FARADAY_TEST_INTERVAL` | `3600` | Receive/test interval (seconds) |

### Mobile Broadband

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_MOBILE` | `0` | Enable mobile transport (togglable at runtime) |
| `CPIP_MOBILE_PORT` | `4196` | UDP port |
| `CPIP_MOBILE_IFACE` | `wwan0` | Network interface |
| `CPIP_MOBILE_APN` | None | Cellular APN |
| `CPIP_MOBILE_BOOTSTRAP` | None | Seed nodes (`host:port,host:port`) |
| `CPIP_MOBILE_HEARTBEAT` | `120` | Heartbeat interval (seconds) |
| `CPIP_MOBILE_KEEPALIVE` | `30` | Keepalive interval (seconds) |
| `CPIP_MOBILE_TELEMETRY` | `0` | Auto-read RSRP/RSSI/SINR via ModemManager/sysfs |

### Anti-Palantir / Counter-Surveillance

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_PALANTIR` | `0` | Enable Anti-Palantir hardening (disabled by default for performance) |
| `CPIP_PALANTIR_MODE` | `auto` | Operation mode: `auto` (reactive), `active` (always on), `passive` (monitor only) |
| `CPIP_PALANTIR_CHAFF` | `1` | Generate chaff traffic to all peers for plausible deniability |
| `CPIP_PALANTIR_MIX_DELAY` | `5.0` | Maximum mix-net delay in seconds (message reordering) |
| `CPIP_PALANTIR_FIXED_SIZE` | `1024` | Pad all messages to fixed size in bytes (traffic normalization) |
| `CPIP_PALANTIR_ID_ROTATE` | `3600` | Identity rotation interval in seconds (POT_ID + keys) |
| `CPIP_PALANTIR_BROADCAST` | `0` | Broadcast-all mode: send every message to every peer (anti-link-analysis) |
| `CPIP_PALANTIR_TIMING` | `cbr` | Timing profile: `cbr` (constant bitrate) or `vbr` (variable) |
| `CPIP_PALANTIR_COVER_BPS` | `500` | Cover traffic bitrate in bits per second |


### ITF Defense

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_DEFENSE_RATE_LIMIT` | `10` | Max probes before ban duration doubles |
| `CPIP_DEFENSE_RATE_WINDOW` | `60` | Rate tracking window (seconds) |
| `CPIP_DEFENSE_BLACKLIST_TTL` | `3600` | Base ban duration (seconds) |
| `CPIP_DEFENSE_MAX_BLACKLIST` | `1000` | Max blacklist entries |

### Anti-ISP Policy

All Anti-ISP transports default to **on** and are individually togglable at runtime via `POST /cpip/anti-isp` or `PUT /cpip/config`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_ANTI_ISP` | `1` | Master enable for Anti-ISP transports |
| `CPIP_STUN` | `1` | STUN NAT hole-punching |
| `CPIP_STUN_SERVERS` | (built-in) | Comma-separated STUN servers |
| `CPIP_STUN_REFRESH` | `300` | STUN refresh interval (seconds) |
| `CPIP_UPNP` | `1` | UPnP port mapping |
| `CPIP_UPNP_LEASE` | `3600` | UPnP lease duration (seconds) |
| `CPIP_DNS_TUNNEL` | `1` | DNS tunnel covert transport |
| `CPIP_DNS_TUNNEL_DOMAIN` | None | Tunnel domain |
| `CPIP_DNS_TUNNEL_SUBDOMAIN` | `cpip` | Tunnel subdomain label |
| `CPIP_DNS_CHUNK_SIZE` | `63` | DNS tunnel chunk size (bytes) |
| `CPIP_WSS` | `1` | WebSocket (WSS) relay tunnel |
| `CPIP_WSS_RELAYS` | (built-in) | Comma-separated WSS relays |
| `CPIP_WSS_TIMEOUT` | `10` | WSS relay timeout (seconds) |
| `CPIP_RELAY` | `1` | Mesh relay pool |
| `CPIP_RELAY_SERVERS` | (built-in) | Comma-separated relay servers |
| `CPIP_RELAY_TIMEOUT` | `5` | Relay timeout (seconds) |
| `CPIP_DOH` | `1` | DNS-over-HTTPS (oblivious) |

### Anti-Stingray Policy

All detection vectors default to **on** and are individually togglable at runtime via `POST /cpip/anti-stingray` or `PUT /cpip/config`. Set any variable to `0` to disable a vector at startup.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_ANTI_STINGRAY` | `1` | Master enable for Stingray detection |
| `CPIP_STINGRAY_SCAN` | `30` | Scan interval (seconds) |
| `CPIP_STINGRAY_SIGNAL_DB` | `50` | Signal-anomaly delta threshold (dB) |
| `CPIP_STINGRAY_KNOWN_MCC_MNC` | `310260,310030,...` | Known-good MCC/MNC allowlist |
| `CPIP_STINGRAY_PORTS` | `443,80,53,8080` | Ports watched for IMSI-catcher signatures |
| `CPIP_STINGRAY_CELL` | `1` | Cellular MCC/MNC/LAC scan |
| `CPIP_STINGRAY_RF` | `1` | RF spectrum anomaly scan |
| `CPIP_STINGRAY_SIG` | `1` | Signal-strength anomaly scan |
| `CPIP_STINGRAY_KNOWN` | `1` | Known-signature (IMSI-catcher DB) scan |

### Anti-Surveillance Policy

All defenses default to **on** and are individually togglable at runtime via `POST /cpip/anti-surveillance` or `PUT /cpip/config`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_ANTI_SURVEILLANCE` | `1` | Master enable for counter-surveillance |
| `CPIP_DPI_EVASION` | `1` | DPI evasion (traffic shaping) |
| `CPIP_DPI_EVASION_MODE` | `aggressive` | DPI evasion mode |
| `CPIP_TRAFFIC_OBFUSC` | `1` | Traffic obfuscation (pad/garble) |
| `CPIP_METADATA_STRIP` | `1` | Header/metadata stripping |
| `CPIP_TLS_FP_ROTATE` | `3600` | TLS fingerprint rotation (seconds) |
| `CPIP_EXPLOITKIT_DETECT` | `1` | 0-click exploit-kit detection |
| `CPIP_PROC_INJECT_DETECT` | `1` | Process-injection / hooking detection |

### Anti-Palantir / Counter-Surveillance Policy

All countermeasures default to **on** and are individually togglable at runtime via `POST /cpip/palantir` or `PUT /cpip/config`. This module hardens CPIP against mass surveillance platforms (Palantir Gotham/Foundry, Pegasus, FinFisher) by implementing traffic analysis countermeasures.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_PALANTIR` | `0` | Master enable for Anti-Palantir hardening |
| `CPIP_PALANTIR_MODE` | `auto` | Operation mode: `auto`|`active`|`passive` |
| `CPIP_PALANTIR_CHAFF` | `1` | Generate chaff traffic to all peers |
| `CPIP_PALANTIR_MIX_DELAY` | `5.0` | Maximum mix-net delay (seconds) |
| `CPIP_PALANTIR_FIXED_SIZE` | `1024` | Pad all messages to fixed size (bytes) |
| `CPIP_PALANTIR_ID_ROTATE` | `3600` | Identity (POT_ID + keys) rotation interval (seconds) |
| `CPIP_PALANTIR_BROADCAST` | `0` | Broadcast-all mode (every message to every peer) |
| `CPIP_PALANTIR_TIMING` | `cbr` | Timing profile: `cbr` (constant bitrate) or `vbr` |
| `CPIP_PALANTIR_COVER_BPS` | `500` | Cover traffic bitrate (bits per second) |

### Net-Neutrality Policy

All countermeasures default to **on** and are individually togglable at runtime via `POST /cpip/net-neutrality` or `PUT /cpip/config`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_NET_NEUTRALITY` | `1` | Master enable for net-neutrality defense |
| `CPIP_NN_BW_MONITOR` | `1` | Bandwidth sampling/monitoring |
| `CPIP_NN_PROTO_MASK` | `1` | Protocol masquerade (disguise as web traffic) |
| `CPIP_NN_MASK_AS` | `standard_web` | Masquerade protocol label |
| `CPIP_NN_FRAG_EVASION` | `1` | Packet fragmentation for DPI evasion |
| `CPIP_NN_THROTTLE_DETECT` | `1` | Throttling detection |
| `CPIP_NN_JITTER` | `1` | Jitter (timing-noise) injection |
| `CPIP_NN_COVER_MIN` | `256` | Cover-traffic minimum size (bytes) |
| `CPIP_NN_COVER_MAX` | `1024` | Cover-traffic maximum size (bytes) |

### USB Gadget (Pi-Tail)

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_PITAIL` | `0` | Enable USB gadget mode |
| `CPIP_PITAIL_ADDR` | `10.0.0.1` | USB gadget IP address |
| `CPIP_PITAIL_NETMASK` | `255.255.255.0` | USB gadget netmask |
| `CPIP_PITAIL_GADGET_DIR` | `/sys/kernel/config/usb_gadget` | Configfs path |

### Other

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_NTP` | `1` | Enable NTP sync |
| `CPIP_NTP_SERVER` | `pool.ntp.org` | NTP server |
| `CPIP_DISCOVERY_PORT` | `4190` | UDP pot discovery port |
| `CPIP_WEB_DIR` | `./web` | Web dashboard static files (override; dashboard is embedded by default) |
| `CPIP_THERMOS` | `0` | Enable dead-drop aggregator |
| `CPIP_THERMOS_MAX` | `1000000` | Maximum dead-drop storage (bytes) |
| `CPIP_FIPS` | `0` | Gate startup on FIPS self-tests (set `1` to require self-test pass) |
| `CPIP_DOH_SERVERS` | (built-in) | Comma-separated DoH servers |
| `CPIP_ENABLED` | `1` | Master gate for the CPIP service (Minima sidecar). Set `0` to advertise disabled in `/cpip/status` |
| `CPIP_RECIPE` | `espresso` | Default coffee recipe for CoffeeCipher KDF domain separation (Minima uses `minima`) |
| `CPIP_RPC_AUTH` | `1` | Require HMAC-SHA256 time-bounded tokens (header `X-CPIP-HMAC`) on mutating `/cpip/*` endpoints |
| `CPIP_RPC_AUTH_SKEW` | `300` | Max clock skew (seconds) for RPC auth tokens |
| `CPIP_DEFENSE_ENABLED` | `1` | Master gate for ITF probe blocking / blacklisting. Set `0` to disable defense |
| `CPIP_ML_KEM_SIZE` | `768` | Default KEM parameter size: `512`, `768`, `1024`, or experimental `2048`/`4096` |
| `CPIP_ML_KEM_BACKEND` | `auto` | Backend: `auto`, `stdlib` (no third-party KEM deps), `numpy`, `inf1del`, or `pqcrypto` |
| `CPIP_PQC_IDENTITY` | `hybrid` | Identity mode: `hybrid`, `1` (KEM-only), or `0` (legacy ECDH) |
| `CPIP_PQC_KEM` | `ml_kem_768` | Identity KEM: standardized-size IDs or experimental `1nf1d3l_kem_2048`/`1nf1d3l_kem_4096` |

### HTTP Security

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_HTTP_RATE_LIMIT` | `500` | Requests per window per IP |
| `CPIP_HTTP_RATE_WINDOW` | `120` | Rate-limit window (seconds) |
| `CPIP_MAX_REQUEST_SIZE` | `65536` | Max request body size (bytes) |
| `CPIP_CORS_ORIGINS` | `""` | Comma-separated allowed CORS origins (empty = no CORS) |

### HSM (PKCS#11)

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_HSM_MODULE` | `""` | Path to PKCS#11 module (`.so`) — empty = software crypto |
| `CPIP_HSM_PIN` | `""` | PKCS#11 token PIN |
| `CPIP_HSM_TOKEN_LABEL` | `cpip` | Token label to select |

### Bonded Transport

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_BONDING` | `1` | Enable bonded/MP-TCP transport aggregation |
| `CPIP_BOND_SUBFLOWS` | `8` | Max subflows |
| `CPIP_BOND_CHUNK_MIN` | `512` | Min chunk size (bytes) |
| `CPIP_BOND_CHUNK_MAX` | `4096` | Max chunk size (bytes) |
| `CPIP_BOND_RETRY` | `2.0` | Retry timeout (seconds) |
| `CPIP_BOND_HEALTH` | `5.0` | Health-check interval (seconds) |
| `CPIP_BOND_PROBE_SIZE` | `1024` | Health probe size (bytes) |
| `CPIP_BOND_STALE` | `30.0` | Stale-link threshold (seconds) |
| `CPIP_BOND_LOSS` | `0.2` | Loss threshold for a subflow |
| `CPIP_BOND_LAT_WIN` | `10` | Latency window (samples) |

### TLS/SSL

| Variable | Default | Description |
|----------|---------|-------------|
| `CPIP_SSL` | `1` | Enable HTTPS (TLS) — on by default |
| `CPIP_SSL_CERT` | None | Path to TLS certificate PEM file |
| `CPIP_SSL_KEY` | None | Path to TLS private key PEM file |
| `CPIP_SSL_AUTO` | `1` | Auto-generate self-signed certificate on first run — on by default |
| `CPIP_SSL_CERT_DIR` | `.ssl` | Directory for auto-generated certificates |
| `CPIP_HTTP_REDIRECT` | `1` | Enable HTTP-to-HTTPS redirect — on by default |
| `CPIP_HTTP_REDIRECT_PORT` | `4181` | Port for HTTP redirect server |

## API Reference

### HTCPCP (RFC 2324 + RFC 7168)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Server status |
| `BREW` | `/coffee` | Brew coffee |
| `BREW` | `/tea` | Brew tea |
| `POST` | `/coffee` | Brew coffee (fallback) |
| `POST` | `/tea` | Brew tea (fallback) |
| `WHEN` | `/` | Stop brewing |
| `PROPFIND` | `/` | Pot metadata |
| `OPTIONS` | `/` | Protocol capabilities |
| `GET` | `/health` `/healthz` | Liveness probe (k8s) |
| `GET` | `/ready` `/readyz` | Readiness probe (k8s) |

### CPIP REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/status` | Full system status |
| `GET` | `/cpip/config` | Node configuration (incl. live `policies` block) |
| `PUT` | `/cpip/config` | Update configuration / bulk-update policies |
| `POST` | `/cpip/brew` | Brew via JSON API |
| `GET` | `/cpip/history` | Brew history |
| `GET` | `/cpip/schedules` | Scheduled brews |
| `POST` | `/cpip/schedule` | Create schedule |
| `DELETE` | `/cpip/schedules/:id` | Delete schedule |
| `GET` | `/cpip/pots` | Discovered pots |
| `GET` | `/cpip/discover` | Force pot discovery |
| `GET` | `/cpip/metrics` | Prometheus metrics |
| `GET` | `/cpip/events` | SSE event stream |
| `POST` | `/cpip/webhooks` | Add webhook |
| `DELETE` | `/cpip/webhooks` | Clear webhooks |

### Mesh Network API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/mesh/status` | Mesh status (peers, inbox, ECC, defense) |
| `GET` | `/cpip/mesh/peers` | Peer list |
| `GET` | `/cpip/mesh/inbox` | Received messages |
| `GET` | `/cpip/mesh/routes` | Routing table |
| `GET` | `/cpip/mesh/queued` | Store-and-forward queue |
| `GET` | `/cpip/mesh/propfind` | Mesh PROPFIND (metadata) |
| `POST` | `/cpip/mesh/send` | Send E2EE message |
| `POST` | `/cpip/mesh/broadcast` | Broadcast to all peers |
| `POST` | `/cpip/mesh/encode` | Encode covert message |
| `POST` | `/cpip/mesh/decode` | Decode covert message |
| `POST` | `/cpip/mesh/brew_covert` | Brew with a hidden covert message |
| `GET` | `/cpip/mesh/covert_status` | Covert channel status |
| `GET` | `/cpip/mesh/sat` | Satellite transport status |
| `POST` | `/cpip/mesh/sat` | Enable/disable satellite |
| `GET` | `/cpip/mesh/radio` | Radio transport status |
| `GET` | `/cpip/mesh/mobile` | Mobile transport status |
| `POST` | `/cpip/mesh/mobile` | Enable/disable mobile |
| `GET` | `/cpip/mesh/deaddrop` | List dead drops |
| `POST` | `/cpip/mesh/deaddrop` | Create/deaddrop action (internal) |
| `POST` | `/cpip/mesh/deaddrop/claim` | Claim a dead drop |
| `POST` | `/cpip/mesh/identity/broadcast` | Broadcast this node's identity to the mesh |
| `GET` | `/cpip/mesh/ecc/address` | This node's ECC address |
| `GET` | `/cpip/mesh/ecc/book` | ECC address book |
| `GET` | `/cpip/defense` | Defense posture (418, stealth, blacklist, tools) |
| `POST` | `/cpip/defense` | Defense actions |
| `GET` | `/cpip/bond/status` | Bonded-transport status |
| `GET` | `/cpip/bond/links` | Bonded-transport links |
| `POST` | `/cpip/bond/config` | Configure bonded transport |

### Identity, DNS, Groups, Sync API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/identity` | List known identities |
| `GET` | `/cpip/identity/trust-graph` | Web-of-trust graph |
| `GET` | `/cpip/identity/trust-sigs` | Trust signatures |
| `GET` | `/cpip/identity/:pot` | Show one identity |
| `POST` | `/cpip/identity/publish` | Publish this node's identity |
| `POST` | `/cpip/identity/trust` | Vouch for a peer |
| `GET` | `/cpip/dns` | List registered `.pot` names |
| `POST` | `/cpip/dns/register` | Register a `.pot` name |
| `POST` | `/cpip/dns/resolve` | Resolve a `.pot` name |
| `POST` | `/cpip/dns/remove` | Remove a `.pot` name |
| `POST` | `/cpip/dns/cleanup` | Expire stale DNS entries |
| `GET` | `/cpip/groups` | List group chats |
| `POST` | `/cpip/groups/create` | Create an E2EE group chat |
| `POST` | `/cpip/groups/join` | Join a group |
| `POST` | `/cpip/groups/leave` | Leave a group |
| `POST` | `/cpip/groups/send` | Send an encrypted group message |
| `POST` | `/cpip/groups/:id/messages` | Group message history |
| `GET` | `/cpip/sync/channels` | List offline-sync channels |
| `GET` | `/cpip/sync/pending` | Pending undelivered messages |
| `GET` | `/cpip/sync/clocks` | Peer clock skew |
| `POST` | `/cpip/sync/send` | Send an offline-sync message |
| `POST` | `/cpip/sync/deliver` | Deliver a pending sync message |
| `POST` | `/cpip/sync/request` | Request sync from a peer |

### Crypto and Security API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/crypto` | Crypto status |
| `POST` | `/cpip/crypto` | Key rotation (`{"action":"rotate_keys"}`) |
| `GET` | `/cpip/incident` | Incident alerts and audit chain |
| `GET` | `/cpip/incident/alerts` | Alert list (filtered) |
| `POST` | `/cpip/incident` | Create alert |
| `GET` | `/cpip/signal` | Signal awareness (bandwidth, link quality, jamming) |
| `POST` | `/cpip/emergency` | Emergency actions (activate, rotate_keys, wipe, deactivate) |
| `GET` | `/cpip/diagnostics/ping` | TCP/UDP ping |
| `GET` | `/cpip/diagnostics/ports` | Port scan |
| `GET` | `/cpip/diagnostics/dns` | DNS resolution |
| `GET` | `/cpip/diagnostics/traceroute` | Traceroute |
| `GET` | `/cpip/diagnostics/interfaces` | Network interfaces |

### RFC Provider API (optional backends)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cpip/providers` | Provider capabilities and availability |
| `GET` | `/cpip/crypto/pqc-status` | Configured KEM size/backend; 512/768/1024 and experimental 1nf1D3L-2048/4096 |
| `POST` | `/cpip/crypto/pqc-keys` | Generate identity keys (private material stays server-side) |
| `POST` | `/cpip/crypto/pqc-handshake` | KEM handshake test |
| `GET` / `POST` | `/cpip/cell/status`, `/cpip/cell/scan` | Cellular observations and scan |
| `GET` / `POST` | `/cpip/sdr/status`, `/cpip/sdr/scan` | SDR capability and passive scan |
| `GET` | `/cpip/scorer/status`, `/cpip/scorer/explain` | Threat score and contributing signals |
| `GET` / `POST` | `/cpip/intel/status`, `/cpip/intel/share` | Local/peer threat intelligence and opt-in share toggle |
| `GET` / `POST` | `/cpip/hardware/status`, `/cpip/sensors/status`, `/cpip/tamper/status` | Physical adapter capability/state |
| `GET` | `/cpip/field/status`, `/cpip/deception/status`, `/cpip/duress/status` | Local operational-mode status |
| `GET` / `POST` | `/cpip/evidence/status`, `/cpip/evidence/verify` | Evidence-chain status and local verification |
| `GET` | `/cpip/modem/status`, `/cpip/ss7/status`, `/cpip/carrier/status` | Optional cellular/external service status |

These providers are draft/optional integrations. A registered route does not imply the required modem, SDR, GPIO, carrier account, remote service, or other backend is installed. Mutating `/cpip/*` requests require `X-CPIP-HMAC` when `CPIP_RPC_AUTH=1`.

### Defense API Actions

| Action | Payload | Description |
|--------|---------|-------------|
| `whitelist` | `{"action":"whitelist","addr":"1.2.3.4"}` | Remove IP from blacklist |
| `clear` | `{"action":"clear"}` | Clear entire blacklist |
| `probe` | `{"action":"probe","addr":"1.2.3.4"}` | Check if IP is blacklisted |
| `stealth` | `{"action":"stealth","enabled":true}` | Toggle stealth mode |

### Defense Policy API (Runtime Toggles)

Every defense vector is independently togglable at runtime without restart. The `feature` field accepts the per-vector names listed in the environment variable tables (e.g., `stun`, `upnp`, `cell_scan`, `dpi_evasion`, `fragmentation`).

| Method | Path | Payload | Description |
|--------|------|---------|-------------|
| `POST` | `/cpip/anti-isp` | `{"action":"toggle","feature":"stun","enabled":false}` | Toggle Anti-ISP transport |
| `POST` | `/cpip/anti-isp` | `{"action":"refresh"}` | Force refresh all transports |
| `POST` | `/cpip/anti-isp` | `{"action":"hole_punch","ip":...,"port":...}` | Punch a NAT hole |
| `POST` | `/cpip/anti-stingray` | `{"action":"toggle","feature":"cell_scan","enabled":false}` | Toggle detection vector |
| `POST` | `/cpip/anti-stingray` | `{"action":"rescan"}` | Force immediate rescan |
| `POST` | `/cpip/anti-surveillance` | `{"action":"toggle","feature":"dpi_evasion","enabled":false}` | Toggle defense vector |
| `POST` | `/cpip/anti-surveillance` | `{"action":"scan"}` | Force immediate scan |
| `POST` | `/cpip/palantir` | `{"action":"enable"}` | Enable Anti-Palantir hardening |
| `POST` | `/cpip/palantir` | `{"action":"disable"}` | Disable Anti-Palantir hardening |
| `POST` | `/cpip/palantir` | `{"action":"chaff_on"}` | Enable chaff traffic generation |
| `POST` | `/cpip/palantir` | `{"action":"chaff_off"}` | Disable chaff traffic |
| `POST` | `/cpip/palantir` | `{"action":"broadcast_on"}` | Enable broadcast-all mode |
| `POST` | `/cpip/palantir` | `{"action":"broadcast_off"}` | Disable broadcast-all |
| `POST` | `/cpip/palantir` | `{"action":"evasion"}` | Activate auto-evasion |
| `POST` | `/cpip/palantir` | `{"action":"log"}` | Show agent audit log |
| `POST` | `/cpip/net-neutrality` | `{"action":"toggle","feature":"fragmentation","enabled":false}` | Toggle countermeasure |
| `GET` | `/cpip/config` | None | Returns live `policies` block (all four groups) |
| `PUT` | `/cpip/config` | `{"policies":{"anti_isp":{"stun":false}}}` | Bulk-update policies at runtime |

Unknown `feature` names return HTTP 400. Toggling the master switch on any defense group starts or stops the background scan/reaction loop.

### Web Interface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Web dashboard |
| `GET` | `/static/*` | Static assets |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CPIP Server                                │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  HTCPCP  │  │  CPIP    │  │  Covert      │  │    ITF       │  │
│  │  Handler │  │  REST API│  │  Channel     │  │  Defense     │  │
│  │(RFC 2324)│  │(/cpip/*) │  │(Accept-Add)  │  │              │  │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └──────┬───────┘  │
│       │              │               │                  │         │
│  ┌────▼──────────────▼───────────────▼──────────────────▼──────┐  │
│  │             PotState Engine + Defense Engine                │  │
│  │    (state machine, history, scheduling, probe check)        │  │
│  └────────────────┬───────────────────────────────────────────┘  │
│                   │                                              │
│  ┌────────────────▼──────────────────────────────────────┐      │
│  │                Mesh Node Layer                         │      │
│  │   (peers, routing, store-and-forward, cross-transport) │      │
│  └───────┬──────────────────────┬──────────────┬─────────┘      │
│          │                      │              │                │
│  ┌───────▼──────┐  ┌───────────▼──────┐  ┌────▼─────────┐    │
│  │  LAN Mesh    │  │ Satellite Mesh   │  │ Radio (LoRa) │    │
│  │  UDP :4191   │  │ UDP :4195        │  │ Unix Socket  │    │
│  └──────────────┘  └─────────────────┘  └──────────────┘    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Mobile BB   │  │    GPIO      │  │   Web UI     │       │
│  │  UDP :4196   │  │  Control     │  │  Dashboard   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│  ┌──────────────────┐  ┌──────────────────┐                  │
│  │  Crypto Engine   │  │ Incident Response│                  │
│  │ (AES-256-GCM,    │  │ (auto-detect,    │                  │
│  │  ECDH P-256)     │  │  alert, mitigate)│                  │
│  └──────────────────┘  └──────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
├── server.py              # Main server (Python stdlib http.server, ~11k lines)
├── cpip                   # CLI client (bash)
├── cpip.1                 # CLI man page (roff)
├── cpip_tui.py            # Terminal UI (OpenTUI) — 12 pages
├── b4dm4n_cw.py           # Cipher Workbench CLI v2.0
├── b4dm4n-cw-commands.txt # b4dm4n-cw command reference
├── inf1del_kyber.py       # NumPy-accelerated custom ML-KEM-512/768/1024 backend
├── pure_mlkem.py          # Standard-library-only custom ML-KEM-size backend
├── pyproject.toml         # Package metadata (name: cpip, v7.0.0)
├── Dockerfile             # Docker image (Alpine, SSL-enabled)
├── docker-compose.yml      # Single-service compose with volumes + limits
├── deploy-pi.sh           # Raspberry Pi deployment script (systemd)
├── deploy-pi.sh           # Pi fleet deployer (scan/flash/provision/connect)
├── cluster.sh             # Local multi-node cluster launcher
├── test_crypto.py         # Cryptographic unit tests (pytest)
├── test_cpip.py           # Server integration tests (pytest)
├── test_key.{pk,sk}       # Kyber test fixtures (PK=1184B, SK=2400B)
├── test_ct                # Kyber test ciphertext (1120B)
├── test_hybrid.{hp,hs}     # Hybrid KEM test fixtures (PK=1251B, SK=2432B)
├── test_hybrid_ct          # Hybrid KEM test ciphertext (1187B; underscore, not dot)
├── mkcert                 # Self-signed cert generator (openssl/cryptography)
├── web/
│   └── .gitkeep           # Optional override slot — see note below
├── k8s/
│   ├── deployment.yaml    # Kubernetes manifests (Namespace→NetworkPolicy)
│   └── kustomization.yaml # Kustomize configuration
├── radio/
│   ├── radio_if.c         # C radio interface (LoRa SPI, KISS TNC, RTL-SDR, sim)
│   ├── radio_if.h         # C header
│   ├── radio_protocol.py  # Python bridge to C binary (Unix socket)
│   └── Makefile           # Build (zero external dependencies)
├── pi-apps/
│   ├── install            # Writes systemd cpip.service
│   ├── uninstall
│   ├── credits
│   ├── description
│   └── icon-64.png
└── .github/workflows/ci.yml  # CI matrix (Python 3.10–3.13 + Docker)
```

> **Web dashboard note:** `web/` ships empty (just `.gitkeep`). The dashboard is an
> inline `DASHBOARD_HTML` string embedded in `server.py` (~2100 lines). Drop a
> `web/index.html` to override the embedded UI at runtime (`CPIP_WEB_DIR=./web`).

## Minima / PiNet-OS Integration

CPIP v7.0.0 integrates with Minima blockchain nodes in the [PiNet-OS](https://github.com/WilliamMajanja/Minima-PiNet-Os) edge computing stack:

| Integration Surface | CPIP Capability |
|---------------------|-----------------|
| Data at rest | CoffeeCipher v5 (AES-256-GCM + HKDF-SHA256) |
| Node identity | ECDSA P-256 challenge-response authentication |
| RPC authentication | HMAC-SHA256 time-bounded tokens (replaces Basic Auth) |
| Key encapsulation | Optional standalone hybrid KEM API; not negotiated by active mesh E2EE |
| Message signatures | ECDSA P-256 (replaces RSA in Maxima messaging) |
| API defense | ITF Defense (probe blocking, pentest detection, IP blacklisting) |
| FIPS assurance | Power-on self-tests (AES-GCM, HMAC, HKDF, ECDSA, ECDH) |

**Deployment:** CPIP can run as a sidecar container (`cpip:7.0.0`, port 4180) in the Minima k3s DaemonSet and as a dedicated `cpip.service` systemd unit.

**Configuration:** `CPIP_ENABLED=1`, `CPIP_RECIPE=minima`, `CPIP_RPC_AUTH=1`, `CPIP_DEFENSE_ENABLED=1`. See [SECURITY.md](SECURITY.md) § Minima Integration for full details.

**PQ Complementarity:** Minima uses WOTS+ for consensus signatures. CPIP exposes separate non-FIPS KEM options for experiments; the configured KEM is not currently negotiated by the mesh E2EE transport.

## Specification and Request Records

The numbered files in [`specs/`](specs/README.md) are CPIP project proposals, not IETF RFC publications. Use a CPIP-RFF for a new feature, an RFC-CR for a change to existing behavior, and a CPIP-RFC for a substantial project protocol/architecture specification. Their statuses and target versions must be checked; a Draft does not imply implementation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This is free and unencumbered software released into the public domain. See [LICENSE](LICENSE) for details.

The CoffeeCipher v5 uses established classical primitives (AES-256-GCM, ECDSA/ECDH P-256, HKDF-SHA256, HMAC-SHA256). The optional hybrid KEM API combines ECDH P-256 with the configured custom KEM; the custom variants are non-FIPS and require independent review.
