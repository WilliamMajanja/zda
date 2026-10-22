"""SQLite: static header + schema/row counts via the stdlib sqlite3 module, no external deps."""

import sqlite3
import os

from ..registry import Format, Inspection


class SqliteFormat(Format):
    name = "sqlite"
    description = "SQLite databases: header facts, schema (tables/views/triggers), row counts, index info, WAL/SHM presence"
    confidence = 1.0

    def match(self, buf, size):
        if buf[:16] == b"SQLite format 3\x00":
            return 1.0
        return 0.0

    def inspect(self, path, buf, size):
        ins = Inspection(self.name)
        ins.add_limit("schema and row counts are read; row contents are intentionally not dumped")
        ins.add_limit("WAL contents are not replayed here (use replay-aware tooling for in-WAL rows)")
        page_size_be = int.from_bytes(buf[16:18], "big")
        page_size = 65536 if page_size_be == 1 else page_size_be
        write_ver, read_ver = buf[18], buf[19]
        page_count = int.from_bytes(buf[28:32], "big")
        text_enc = {1: "utf-8", 2: "utf-16le", 3: "utf-16be"}.get(int.from_bytes(buf[56:60], "big"), "?")
        ins.summary = f"SQLite 3 database, page-size {page_size}, {page_count} pages, {text_enc}"
        ins.add_finding("header", ins.summary, evidence=buf[:16].hex(" "))
        ins.add_finding("journal", f"write journal version {write_ver}, read version {read_ver}")
        for suffix in ("-wal", "-shm", "-journal"):
            if os.path.exists(str(path) + suffix):
                p = os.path.getsize(str(path) + suffix)
                ins.add_finding("sidecar", f"{suffix} sidecar present ({p} bytes)")
        uri = f"file:{path}?mode=ro&immutable=1"
        try:
            con = sqlite3.connect(uri, uri=True, timeout=1.0)
            try:
                self._schema(ins, con)
            finally:
                con.close()
        except sqlite3.Error as e:
            ins.add_finding("database-error", f"sqlite3 read failed: {e}")
        return ins

    def _schema(self, ins, con):
        rows = con.execute(
            "SELECT type, name FROM sqlite_master ORDER BY rowid"
        ).fetchall()
        by_type = {}
        for t, n in rows:
            by_type.setdefault(t, []).append(n)
        ins.add_finding("schema", ", ".join(f"{k}={len(v)}" for k, v in sorted(by_type.items())))
        for name in by_type.get("table", [])[:20]:
            if name.startswith("sqlite_"):
                continue
            qi = self._quote_ident(name)
            try:
                cols = con.execute(f"PRAGMA table_info({qi})").fetchall()
                n = con.execute(f"SELECT count(*) FROM {qi}").fetchone()[0]
                ins.add_finding(
                    "table",
                    f"{name}: {', '.join(f'{c[1]} {c[2]}'.strip() for c in cols)} ({n} row(s))",
                    evidence=f"{n} row(s)",
                )
            except sqlite3.Error as e:
                ins.add_finding("table-error", f"{name}: {e}")
        try:
            idxs = [(r[0], r[1]) for r in con.execute('PRAGMA index_list("main")')]
        except sqlite3.Error:
            idxs = []
        ins.add_finding("auto-index", f"{len(idxs)} index/indexes declared")
        for view in by_type.get("view", [])[:10]:
            ins.add_finding("view", f"view: {view}")
        for trigger in by_type.get("trigger", [])[:10]:
            ins.add_finding("trigger", f"trigger: {trigger}")

    def _quote_ident(self, name):
        return '"' + str(name).replace('"', '""') + '"'
