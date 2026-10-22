"""EVM: static deployed bytecode decode (selectors, opcodes, mutability), stdlib only."""

import binascii

from ..registry import Format, Inspection, hexdump, ellipsize

NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x20: "KECCAK256", 0x30: "ADDRESS", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
    0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x54: "SLOAD", 0x55: "SSTORE",
    0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS",
    0x5B: "JUMPDEST", 0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE",
    0xF3: "RETURN", 0xF5: "CREATE2", 0xF8: "EXTCALL", 0xFA: "STATICCALL",
    0xFF: "SELFDESTRUCT",
}
ENV = {0x30, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46}
MUTATING = {0x55, 0xF0, 0xF1, 0xF2, 0xF5, 0xFF}


class EvmFormat(Format):
    name = "evm"
    description = "EVM bytecode: function selectors (PUSH4 at dispatch), opcodes, env access, mutability"
    confidence = 0.75

    def match(self, buf, size):
        if len(buf) >= 12 and buf[0] == 0x60 and 0x60 <= buf[1] <= 0x7F:
            return 0.55
        if len(buf) >= 8:
            try:
                s = buf.decode("ascii")
                body = s.strip()
                if body.startswith("0x"):
                    body = body[2:]
                if len(body) >= 16 and all(ch in "0123456789abcdefABCDEF" for ch in body) and len(body) % 2 == 0:
                    return 0.65
            except UnicodeDecodeError:
                return 0.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("no execution or forking; selectors are heuristic PUSH4 candidates at dispatch-like sequences")
        ins.add_limit("constructor/runtime separation is not resolved here")
        with open(path, "rb") as fh:
            data = fh.read()
        if data.lstrip().startswith(b"0x"):
            data = bytes.fromhex(data.strip()[2:].decode())
        elif all(ch in b"0123456789abcdefABCDEF" for ch in data.strip()[:64]) and size:
            try:
                data = bytes.fromhex(data.decode("ascii"))
            except (UnicodeDecodeError, binascii.Error):
                pass
        ops = []
        i = 0
        push4s, jumpdests, counts = [], 0, {}
        while i < len(data):
            op = data[i]
            if 0x60 <= op <= 0x7F:
                n = op - 0x5F
                val = data[i + 1 : i + 1 + n]
                ops.append(("PUSH,%d" % n, val.hex()))
                if n == 4:
                    push4s.append("0x" + val.hex())
                i += 1 + n
            elif 0x80 <= op <= 0x8F:
                ops.append(("DUP", str(op - 0x7F)))
                i += 1
            elif 0x90 <= op <= 0x9F:
                ops.append(("SWAP", str(op - 0x8F)))
                i += 1
            else:
                name = NAMES.get(op, f"0x{op:02x}")
                counts[name] = counts.get(name, 0) + 1
                if op == 0x5B:
                    jumpdests += 1
                ops.append((name, None))
                i += 1
        ins.summary = f"EVM bytecode, {data.hex()[:8]}…, {len(ops)} opcodes, {len(push4s)} PUSH4 constant(s)"
        ins.add_finding("opcode-stats", ", ".join(f"{k}×{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:10]))
        ins.add_finding("jump-destinations", f"{jumpdests} JUMPDEST(s)")
        self._selectors(ins, data)
        env = sorted(NAMES.get(op, hex(op)) for op in ENV if op in counts)
        if env:
            ins.add_finding("env-access", f"environment ops: {', '.join(env)}")
        mut = sorted(NAMES.get(op, hex(op)) for op in MUTATING if op in counts)
        if mut:
            ins.add_finding("mutability", f"state-mutating ops: {', '.join(mut)}")
        else:
            ins.add_finding("mutability", "no SSTORE/CREATE/SELFDESTRUCT found — likely view/pure-only (heuristic)")
        ins.add_finding("first-opcodes", hexdump(data[:16]))
        return ins

    def _selectors(self, ins, data):
        # dispatcher pattern: 0x63 (PUSH4) followed by 0x14 (EQ): collect constants
        selectors = []
        i = 0
        while i + 5 < len(data) and len(selectors) < 32:
            if data[i] == 0x63:
                val = data[i + 1 : i + 5]
                nxt = data[i + 5] if i + 5 < len(data) else None
                if val and nxt == 0x14:
                    selectors.append("0x" + val.hex())
                    i += 5
                else:
                    i += 1
            else:
                i += 1
        if selectors:
            ins.add_finding(
                "selectors",
                f"{len(selectors)} PUSH4 dispatcher constant(s): {', '.join(selectors[:12])}" + ("…" if len(selectors) > 12 else ""),
            )
            ins.add_finding(
                "note",
                "resolve candidate selectors to signatures with `zda examples` tooling or a 4byte lookup (offline not bundled)",
            )
        else:
            ins.add_finding("selectors", "no classic dispatcher found")
        if b"IPFS" in data or b"metadata" in data:
            ins.add_finding("metadata-bytecode", "contract metadata (IPFS/swarm or 'metadata' marker) embedded — constructor tail")
