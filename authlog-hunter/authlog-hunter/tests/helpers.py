"""Shared test helpers. Makes `src/` importable without installing the package."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "auth.log"
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from authlog_hunter.parser import LogParser  # noqa: E402

HOST = "srv01"
BASE = datetime(2026, 9, 28, 10, 0, 0)


def parse(lines: list[str], year: int = 2026):
    parser = LogParser(year=year)
    return list(parser.parse_lines(lines, source="test.log")), parser.stats


def line(ts: datetime, tag: str, msg: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {tag}: {msg}"


def failures(ip: str, users: list[str], start: datetime = BASE, step: int = 10, pid: int = 1000,
             invalid: bool = False) -> list[str]:
    """One sshd connection (unique pid) per failed password."""
    out = []
    for i, user in enumerate(users):
        who = f"invalid user {user}" if invalid else user
        out.append(line(start + timedelta(seconds=i * step), f"sshd[{pid + i}]",
                        f"Failed password for {who} from {ip} port {40000 + i} ssh2"))
    return out


def accepted(ip: str, user: str, ts: datetime, method: str = "password", pid: int = 5000) -> str:
    return line(ts, f"sshd[{pid}]", f"Accepted {method} for {user} from {ip} port 50000 ssh2")


def sudo(user: str, command: str, ts: datetime) -> str:
    return line(ts, "sudo", f"{user:>8} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")
