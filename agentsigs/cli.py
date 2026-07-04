"""agentsigs command line.

    agentsigs scan PATH        scan a file/dir (or - for stdin) against the signature library
    agentsigs list             list every signature (id, category, severity, mapping)
    agentsigs stats            counts by category
    agentsigs sarif PATH       emit SARIF for CI / GitHub Security tab

Exit code is non-zero when any critical/high signature matches.
"""
from __future__ import annotations
import argparse
import json
import sys

try:  # portable output on Windows cp1252 consoles
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from typing import List, Optional

from . import __version__
from .engine import Library, SEVERITY_ORDER

_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def _cats(arg: Optional[str]) -> Optional[List[str]]:
    return [c.strip() for c in arg.split(",")] if arg else None


def _worst(matches) -> str:
    sevs = [m.signature.severity for m in matches]
    for s in SEVERITY_ORDER:
        if s in sevs:
            return s
    return "info"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="agentsigs",
        description="The open detection-signature library for AI-agent threats.")
    p.add_argument("--version", action="version", version=f"agentsigs {__version__}")
    sub = p.add_subparsers(dest="cmd")

    ps = sub.add_parser("scan", help="scan a file/dir/stdin against the library")
    ps.add_argument("path", help="file, directory, or - for stdin")
    ps.add_argument("--category", "-c", default=None, help="comma-separated categories to apply")
    ps.add_argument("--format", "-f", default="text", choices=["text", "json"])
    ps.add_argument("--extra", default=None, help="extra signature dir to load")

    pl = sub.add_parser("list", help="list all signatures")
    pl.add_argument("--category", "-c", default=None)
    pl.add_argument("--format", "-f", default="text", choices=["text", "json"])

    sub.add_parser("stats", help="counts by category")

    pr = sub.add_parser("sarif", help="emit SARIF for a scan")
    pr.add_argument("path")

    args = p.parse_args(argv)
    cmd = args.cmd or "stats"
    lib = Library(extra_dirs=[args.extra] if getattr(args, "extra", None) else None)

    if cmd == "stats":
        st = lib.stats()
        print(f"agentsigs library: {st.pop('total')} signatures")
        for cat, n in sorted(st.items()):
            print(f"  {n:>3}  {cat}")
        return 0

    if cmd == "list":
        cats = _cats(args.category)
        sigs = [s for s in lib.signatures if not cats or s.category in cats]
        if args.format == "json":
            print(json.dumps([{"id": s.id, "name": s.name, "category": s.category,
                               "severity": s.severity, "atlas": s.atlas, "owasp": s.owasp}
                              for s in sigs], indent=2))
        else:
            for s in sigs:
                print(f"  {_TAG.get(s.severity,'')} {s.id:<7} {s.category:<18} {s.atlas}/{s.owasp}  {s.name}")
        return 0

    # scan / sarif read a target
    path = args.path
    if cmd == "scan" and path == "-":
        text = sys.stdin.read()
        matches = lib.scan_text(text, _cats(args.category))
        results = {"<stdin>": matches}
    else:
        results = lib.scan_path(path, _cats(getattr(args, "category", None)))

    if cmd == "sarif":
        runs = [{"tool": {"driver": {"name": "agentsigs", "version": __version__,
                                     "informationUri": "https://github.com/cognis-digital/agentsigs"}},
                 "results": [{"ruleId": m.signature.id,
                              "level": "error" if m.signature.severity in ("critical", "high") else "warning",
                              "message": {"text": f"{m.signature.name} ({m.signature.atlas}/{m.signature.owasp})"},
                              "locations": [{"physicalLocation": {
                                  "artifactLocation": {"uri": f}, "region": {"startLine": m.line}}}]}
                             for f, ms in results.items() for m in ms]}]
        print(json.dumps({"version": "2.1.0",
                          "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}, indent=2))
        return 0

    total = sum(len(v) for v in results.values())
    worst = "info"
    if getattr(args, "format", "text") == "json":
        print(json.dumps({f: [m.to_dict() for m in ms] for f, ms in results.items() if ms}, indent=2))
    else:
        for f, ms in results.items():
            if not ms:
                continue
            print(f"\n{f}")
            for m in ms:
                s = m.signature
                print(f"  {_TAG.get(s.severity,'')} L{m.line:<4} {s.id:<7} {s.category:<16} "
                      f"{s.atlas}/{s.owasp}  {s.name}")
                print(f"           > {m.excerpt}")
        print(f"\n{total} match(es) across {sum(1 for v in results.values() if v)} file(s).")
    for ms in results.values():
        for m in ms:
            if SEVERITY_ORDER.index(m.signature.severity) < SEVERITY_ORDER.index(worst) or worst == "info":
                worst = m.signature.severity
    return 1 if worst in ("critical", "high") else 0


if __name__ == "__main__":
    raise SystemExit(main())
