"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__
from .demo import materialize
from .engine import scan
from .model import SEVERITIES, SEVERITY_RANK
from .render import build_sarif, render_json, render_text
from .rules import all_rules, groups


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docklint",
        description="Security auditor for Dockerfiles, compose files and .dockerignore.",
    )
    parser.add_argument("--version", action="version", version=f"docklint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a directory or a single file")
    p_scan.add_argument("paths", nargs="*", default=["."], help="file or directory (default: .)")
    p_scan.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "none"],
        default="high",
        help="exit 1 when a finding at or above this severity exists (default: high)",
    )
    p_scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_scan.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    p_scan.add_argument("--ignore", action="append", default=[], metavar="RULE", help="skip a rule id")
    p_scan.add_argument(
        "--ignore-group", action="append", default=[], metavar="GROUP", help="skip a rule group"
    )
    p_scan.add_argument(
        "--min-severity", choices=SEVERITIES, help="hide findings below this severity"
    )
    p_scan.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    p_rules = sub.add_parser("rules", help="list every rule")
    p_rules.add_argument("--json", action="store_true")
    p_rules.add_argument("--group", help="only rules in this group")
    p_rules.add_argument("--pass", dest="pass_no", type=int, choices=[1, 2, 3])

    p_demo = sub.add_parser("demo", help="scan a built-in broken project")
    p_demo.add_argument("--keep", metavar="DIR", help="write the fixture project here and keep it")
    p_demo.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_demo.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="none")
    return parser


def _emit(payload: str, output: str | None) -> None:
    if output:
        Path(output).write_text(payload + "\n", encoding="utf-8")
    else:
        sys.stdout.write(payload + "\n")


def _scan_result(args: argparse.Namespace, target: Path):
    return scan(
        target,
        ignore_rules=set(args.ignore),
        ignore_groups=set(args.ignore_group),
        min_severity=args.min_severity,
        severity_rank=SEVERITY_RANK,
    )


def _render(result, fmt: str, no_color: bool) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return json.dumps(build_sarif(result), indent=2, ensure_ascii=False)
    return render_text(result, color=not no_color and sys.stdout.isatty())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        rules = all_rules()
        if args.group:
            rules = [r for r in rules if r.group == args.group]
        if args.pass_no:
            rules = [r for r in rules if r.pass_no == args.pass_no]
        if args.json:
            print(json.dumps([r.as_dict() for r in rules], indent=2, ensure_ascii=False))
        else:
            print(f"{len(rules)} rule(s), groups: {', '.join(groups())}")
            for r in rules:
                print(f"{r.id}  {r.severity:<8} p{r.pass_no}  {r.group:<16} {r.title}")
        return 0

    if args.command == "demo":
        if args.keep:
            root = materialize(Path(args.keep))
            tmp = None
        else:
            tmp = tempfile.TemporaryDirectory(prefix="docklint-demo-")
            root = materialize(Path(tmp.name))
        try:
            result = scan(root)
            payload = _render(result, args.format, no_color=True)
            _emit(payload, None)
            if tmp is not None:
                tmp.cleanup()
            if args.fail_on == "none":
                return 0
            return 1 if result.gate(args.fail_on) else 0
        except Exception:  # noqa: BLE001 - cleanup must survive a failed scan
            if tmp is not None:
                tmp.cleanup()
            raise

    targets = args.paths or ["."]
    exit_code = 0
    for target in targets:
        path = Path(target)
        if not path.exists():
            print(f"docklint: {target}: no such file or directory", file=sys.stderr)
            return 2
        result = _scan_result(args, path)
        _emit(_render(result, args.format, args.no_color), args.output)
        if result.gate(args.fail_on):
            exit_code = 1
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
