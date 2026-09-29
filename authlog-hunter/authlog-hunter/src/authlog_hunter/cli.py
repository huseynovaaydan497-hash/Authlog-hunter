"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .detectors import COMMAND_RULES, DetectionConfig, analyze, parse_networks
from .models import Severity
from .parser import LogParser
from .report import RENDERERS

DEFAULT_LOGS = ("/var/log/auth.log", "/var/log/secure")

EPILOG = """\
examples:
  authlog-hunter /var/log/auth.log
  authlog-hunter /var/log/auth.log* --min-severity high
  authlog-hunter auth.log --format json -o report.json
  authlog-hunter auth.log --allowlist 10.0.0.0/8 --fail-on high   # exit 1 if anything >= high
  zcat /var/log/auth.log.*.gz | authlog-hunter -

exit codes: 0 = ok, 1 = findings at or above --fail-on, 2 = usage or input error
"""


def _severity(value: str) -> Severity:
    try:
        return Severity.from_name(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authlog-hunter",
        description="Detect SSH brute force, account compromise and post-exploitation activity in Linux "
                    "auth logs, mapped to MITRE ATT&CK.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("logs", nargs="*", metavar="LOG",
                   help="auth log files (.gz supported, '-' for stdin). Default: /var/log/auth.log or /var/log/secure")
    out = p.add_argument_group("output")
    out.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text", help="report format (default: text)")
    out.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    out.add_argument("--min-severity", type=_severity, default=Severity.LOW, metavar="LEVEL",
                     help="hide findings below LEVEL: info, low, medium, high, critical (default: low)")
    out.add_argument("--fail-on", type=_severity, metavar="LEVEL",
                     help="exit with status 1 if any finding is at or above LEVEL (for cron/CI)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours in text output")

    det = p.add_argument_group("detection tuning")
    det.add_argument("--threshold", type=_positive_int, default=10, metavar="N",
                     help="failed logins from one IP within the window to flag brute force (default: 10)")
    det.add_argument("--window", type=_positive_int, default=10, metavar="MIN",
                     help="sliding window in minutes (default: 10)")
    det.add_argument("--spray-users", type=_positive_int, default=5, metavar="N",
                     help="distinct usernames from one IP within the window to flag spraying (default: 5)")
    det.add_argument("--success-after", type=_positive_int, default=5, metavar="N",
                     help="failures before a successful login to flag a compromise (default: 5)")
    det.add_argument("--allowlist", action="append", default=[], metavar="CIDR",
                     help="trusted IP or network, repeatable (e.g. 10.0.0.0/8)")
    det.add_argument("--allowlist-file", metavar="FILE", help="file with one IP/CIDR per line (# comments allowed)")
    det.add_argument("--year", type=int, help="year for classic syslog timestamps (default: inferred)")

    p.add_argument("--list-rules", action="store_true", help="print the detection rules and exit")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _list_rules() -> str:
    base = [
        ("AH-001", "SSH brute force", "T1110.001"),
        ("AH-002", "Password spraying / user enumeration", "T1110.003"),
        ("AH-003", "Successful SSH login after brute force", "T1110 + T1078"),
        ("AH-004", "Direct root login over SSH", "T1078.003"),
        ("AH-005", "Sudo authentication failures", "T1548.003"),
        ("AH-006", "Local account created", "T1136.001"),
        ("AH-007", "Account added to a privileged group", "T1098.007"),
        ("AH-008", "Account password changed", "T1098"),
        ("AH-009", "Newly created account used for SSH login", "T1078.003"),
    ]
    base += [(r.rule_id, r.title, r.technique) for r in COMMAND_RULES]
    return "\n".join(f"{rid}  {title:<42} {tech}" for rid, title, tech in base)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")  # never crash on a non-UTF-8 console
    except (AttributeError, ValueError):
        pass

    if args.list_rules:
        print(_list_rules())
        return 0

    logs = args.logs or [p for p in DEFAULT_LOGS if Path(p).exists()][:1]
    if not logs:
        parser.error("no log file given and neither /var/log/auth.log nor /var/log/secure exists")

    try:
        allow = list(args.allowlist)
        if args.allowlist_file:
            for line in Path(args.allowlist_file).read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    allow.append(line)
        networks = parse_networks(allow)
    except (OSError, ValueError) as exc:
        print(f"authlog-hunter: error: invalid allowlist: {exc}", file=sys.stderr)
        return 2

    cfg = DetectionConfig(
        bruteforce_threshold=args.threshold,
        window=timedelta(minutes=args.window),
        spray_min_users=args.spray_users,
        success_after_failures=args.success_after,
        allowlist=networks,
    )

    log_parser = LogParser(year=args.year)
    try:
        events = log_parser.parse_paths(logs)
    except OSError as exc:
        print(f"authlog-hunter: error: {exc}", file=sys.stderr)
        return 2

    result = analyze(events, cfg, stats=log_parser.stats)
    all_findings = result.findings
    result.findings = [f for f in all_findings if f.severity >= args.min_severity]
    result.summary["findings_by_severity"] = {
        s.name: sum(1 for f in result.findings if f.severity is s) for s in sorted(Severity, reverse=True)}

    use_color = (args.format == "text" and not args.no_color and not args.output
                 and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
    renderer = RENDERERS[args.format]
    report = renderer(result, color=use_color) if args.format == "text" else renderer(result)

    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"report written to {args.output} ({len(result.findings)} findings)", file=sys.stderr)
    else:
        print(report)

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in all_findings):
        return 1
    return 0
