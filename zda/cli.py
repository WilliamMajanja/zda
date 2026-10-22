"""CLI entrypoint: zda <command> [args]."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .registry import identify, inspect_file, list_formats

BANNER = r"""
  ╔═╗╦╔═╗╔╗╔╦  ╦  ╔═╗╦═╗╔╗╔╦╦╔╣╦ ╦
  ║ ║║║ ║║║║║  ║  ║ ║╠╦╝║║║║╠╣║ ║
  ╚═╝╩╚═╝╝╚╝╩═╝╩═╝╚═╝╩╚═╝╚╝╩╩╚╩ ╚═╝
       zero-dep anything — v{v}
"""


def _print(o):
    json.dump(o, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def cmd_identify(args):
    fmt, score, buf, size = identify(args.path)
    facts = inspect_file(args.path)
    ins = {
        "schema": "zda.v1",
        "format": facts.get("format", "unknown"),
        "confidence": facts.get("confidence"),
        "summary": facts.get("summary", ""),
        "file": facts.get("file"),
    }
    if args.json:
        _print(ins)
    else:
        print(BANNER.replace("{v}", __version__))
        print(f"format      : {ins['format']}")
        print(f"confidence  : {ins['confidence']}")
        print(f"summary     : {ins['summary']}")
        print(f"size        : {ins['file']['size'] if ins.get('file') else 'n/a'}")
        print(f"sha256      : {ins['file'].get('sha256', 'n/a') if ins.get('file') else 'n/a'}")
    return 0


def cmd_inspect(args):
    try:
        envelope = inspect_file(args.path, fmt_name=args.format)
    except ValueError as e:
        print(f"zda: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"zda: {e}", file=sys.stderr)
        return 2
    if args.json:
        _print(envelope)
    else:
        print("-" * 60)
        print(f"format : {envelope['format']}  (confidence {envelope['confidence']})")
        print(f"summary: {envelope['summary']}")
        if isinstance(envelope["file"], dict):
            print(f"file   : {envelope['file']['path']} ({envelope['file']['size']} bytes)")
            print(f"sha256 : {envelope['file'].get('sha256', 'n/a')}")
        print("-" * 60)
        for f in envelope.get("findings", []):
            ev = f.get("evidence")
            line = f"  [{f['kind']:>12}] {f['detail']}"
            if ev:
                line += f"  ㊮ evidence: {ev}"
            print(line)
        for lim in envelope.get("limits", []):
            print(f"  limit        : {lim}")
        print("-" * 60)
    return 0


def cmd_list_formats(args):
    fmts = list_formats()
    if args.json:
        _print(fmts)
        return 0
    width = max(len(f["format"]) for f in fmts) + 2
    for f in fmts:
        print(f"  {f['format']:<{width}} {f['description']}")
    print(f"\n  {len(fmts)} format(s), all inspectable with no third-party dependencies.")
    return 0


def cmd_mcp(args):
    from .mcp import serve
    return serve(args)


def build_parser():
    p = argparse.ArgumentParser(
        prog="zda",
        description="Zero-Dep Anything: identify and inspect 20+ binary formats with stdlib-only code.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("identify", help="identify a file's format (fast)")
    s.add_argument("path")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_identify)

    s = sub.add_parser("inspect", help="deep inspect: findings with evidence, limitations, sha256")
    s.add_argument("path")
    s.add_argument("--format", "-f", default=None, help="force a format (see list-formats)")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("list-formats", help="list inspectable formats")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list_formats)

    s = sub.add_parser("mcp", help="run as an MCP stdio server (-tools: zda_identify, zda_inspect, zda_list_formats)")
    s.set_defaults(func=cmd_mcp)

    p.add_argument("--version", action="version", version=f"zda {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "json", False):
        print(BANNER.replace("{v}", __version__))
    try:
        rc = args.func(args)
    except BrokenPipeError:
        rc = 0
    except FileNotFoundError as e:
        print(f"zda: {e}", file=sys.stderr)
        rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
