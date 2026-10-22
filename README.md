# ZDA — Zero-Dep Anything

[![Tests](https://img.shields.io/badge/tests-22%20passing-brightgreen)](tests/test_zda.py)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](pyproject.toml)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

> **Identify and inspect 18+ binary formats with pure-Python, zero third-party
> dependencies.** A CLI and an MCP server in one package — like
> [rea](https://github.com/morluto/rea), but dependency-free and instantly
> runnable with `pip install zda`.

```
$ zda inspect ./hello.elf
format : elf  (confidence 1.0)
summary: ELF 64-bit LE DYN (PIE/shared), aarch64
  [mitigation  ] NX (non-executable stack): yes
  [mitigation  ] RELRO: yes
  [mitigation  ] PIE: yes
  [mitigation  ] stack canary (__stack_chk_fail): no
  [elf-note    ] NT_GNU_BUILD_ID: bd aa da 19 c1 b7 0f ae …
  [dynamic     ] SHT_DYNAMIC section present — linked against shared libraries
  [library     ] references glibc 2.x (libc.so.6)
  [strings     ] ≥50 printable ASCII strings ≥8 chars in the first 256 KiB
```

## Why ZDA

- **Zero dependencies.** Only the Python standard library. `pip install zda`
  works on a fresh interpreter with no network beyond the package itself.
- **One tool, many formats.** ELF, PE, Mach-O, APK/JAR/OOXML/EPUB, PDF,
  SQLite, GGUF, safetensors, WASM, JVM class, EVM, Erlang BEAM, Godot PCK,
  PNG/JPEG/GIF/WebP, PyInstaller.
- **Evidence, not guesses.** Every finding cites the byte offset, magic, or
  structure it came from. Every envelope carries a `limits` list of what the
  inspector did *not* do.
- **Agent-ready.** `zda mcp` runs a JSON-RPC 2.0 stdio MCP server exposing
  `zda_identify`, `zda_inspect`, `zda_list_formats`.

## Quick start

```bash
pip install -e .          # or: pip install zda (once published)
zda --version
zda list-formats
zda identify ./some.bin
zda inspect  ./some.bin --json
zda inspect  ./some.bin --format elf
```

## Formats

| Format | What ZDA returns |
|---|---|
| ELF | header, sections, segments, interpreter, mitigations (NX/RELRO/PIE/canary), notes, dynamic libs, strings |
| PE  | COFF + optional header, sections, imports (DLL + slot counts), subsystem, Authenticode presence, .NET CLR flag |
| Mach-O | thin/fat headers, load commands, dylibs, UUID, segments |
| ZIP family | apk / jar / docx / xlsx / pptx / epub / odf / war / plain zip inventory, manifest attrs, compression, encryption |
| PDF | version, page objects, trailer, encryption, JS/launch, producer/title |
| SQLite | page size, journal, schema, columns, row counts, indexes, views, triggers, WAL/SHM sidecars |
| GGUF | version, tensors (name/shape/dtype), metadata kv |
| safetensors | header JSON, tensor declarations, declared element/byte totals |
| WASM | sections, imports, exports, function type signatures |
| JVM class | version, access flags, this/super, interfaces, fields/methods, constant-pool stats |
| EVM | opcodes, dispatcher selectors, env access, mutability, jumpdests |
| BEAM | IFF chunks, atoms, exports/imports, code header |
| Godot PCK | format version, engine version, file inventory with codecs |
| PNG/JPEG/GIF/WebP | dimensions, color type, chunks/markers, frames, metadata |
| PyInstaller | CArchive cookie, TOC members, python runtime |

## MCP server

```bash
zda mcp            # speaks JSON-RPC 2.0 over stdio
```

Register with Claude Code / Codex / Cursor:

```json
{
  "mcpServers": {
    "zda": { "command": "zda", "args": ["mcp"] }
  }
}
```

Tools: `zda_identify`, `zda_inspect`, `zda_list_formats`.

## Design principles

1. **Stdlib only.** No `numpy`, no `lief`, no `pefile`. Every byte is parsed
   by hand with `struct` and slices.
2. **Bounded reads.** Every loop has a cap (4096 sections, 65536 tensors, …).
   A malformed file cannot OOM the process.
3. **Evidence + limits.** Findings carry `evidence`; envelopes carry `limits`.
   Nothing is presented as fact that was not actually read.
4. **No execution.** ZDA never runs the target. It reads bytes.

## Tests

```bash
python -m pytest -q
# 22 passed
```

## License

MIT. See [LICENSE](LICENSE).
