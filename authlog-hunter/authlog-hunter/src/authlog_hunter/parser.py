"""Parse Linux authentication logs (Debian/Ubuntu auth.log, RHEL/Fedora secure).

Supports both timestamp styles written by rsyslog:

  * classic BSD syslog:   ``Sep 28 11:02:11 web-01 sshd[2211]: ...``
  * RFC 3339 (Ubuntu 24.04+ default):
                          ``2026-09-28T11:02:11.123456+04:00 web-01 sshd[2211]: ...``

Only security-relevant messages become :class:`Event` objects; everything else
(CRON sessions, systemd-logind, PAM noise) is counted and skipped.
"""

from __future__ import annotations

import gzip
import io
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, TextIO

from .models import Event, EventType

MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<body>.*)$")
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<body>.*)$")
_TAG = re.compile(r"^(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")

# Usernames and commands are attacker-controlled. Escape control characters so a crafted
# username cannot inject ANSI escape sequences into the analyst's terminal or report.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _escape_controls(text: str) -> str:
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)

# --- sshd -----------------------------------------------------------------
SSHD_PROCESSES = {"sshd", "sshd-session", "sshd-auth"}  # OpenSSH >= 9.8 splits sshd
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]\s*$")
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?\s*$")
_PREAUTH = re.compile(
    r"^(?:Connection closed by|Disconnected from) (?P<kind>invalid|authenticating) user (?P<user>.*?) "
    r"(?P<ip>\S+) port (?P<port>\d+) \[preauth\]\s*$")

# --- sudo -----------------------------------------------------------------
_SUDO = re.compile(
    r"^\s*(?P<user>\S+)\s+:\s+(?:(?P<reason>[^;]*?)\s+;\s+)?TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>.*?)\s+;\s+"
    r"USER=(?P<runas>\S+)\s+;(?:\s+GROUP=\S+\s+;)?(?:\s+TSID=\S+\s+;)?(?:\s+ENV=.*?\s+;)?\s+COMMAND=(?P<cmd>.*)$")

# --- account management -----------------------------------------------------
_USERADD = re.compile(
    r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]*), "
    r"shell=(?P<shell>[^,\s]+)")
_GROUP_ADD = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
_GPASSWD = re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)")
_PASSWD = re.compile(r"pam_unix\((?:passwd|chpasswd|chage):chauthtok\): password changed for (?P<user>\S+)")


def _parse_iso(ts: str) -> datetime:
    """datetime.fromisoformat on Python 3.10 is strict; normalise first."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?([+-]\d{2}):?(\d{2})?$", ts)
    if m:
        base, frac, tz_h, tz_m = m.groups()
        frac = ((frac or "") + "000000")[:6]
        ts = f"{base}.{frac}{tz_h}:{tz_m or '00'}"
    else:
        m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?$", ts)
        if m:
            base, frac = m.groups()
            ts = f"{base}.{((frac or '') + '000000')[:6]}"
    # Keep the wall-clock time as logged so classic and ISO logs can be mixed.
    return datetime.fromisoformat(ts).replace(tzinfo=None)


class _YearTracker:
    """Classic syslog lines have no year. Infer it and handle Dec -> Jan rollover."""

    def __init__(self, year: int | None, now: datetime | None = None) -> None:
        self._fixed = year
        self._now = now or datetime.now()
        self._year: int | None = None
        self._last_month: int | None = None

    def resolve(self, month: int) -> int:
        if self._year is None:
            if self._fixed is not None:
                self._year = self._fixed
            else:
                # A month later than the current one must belong to last year.
                self._year = self._now.year if month <= self._now.month else self._now.year - 1
        elif self._last_month is not None and month < self._last_month and self._last_month - month >= 6:
            self._year += 1
        self._last_month = month
        return self._year


@dataclass
class ParseStats:
    files: list[str] = field(default_factory=list)
    lines: int = 0
    events: int = 0
    unrecognised: int = 0  # lines whose syslog header could not be parsed


def _open(path: str) -> TextIO:
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


class LogParser:
    def __init__(self, year: int | None = None, now: datetime | None = None) -> None:
        self.year = year
        self.now = now
        self.stats = ParseStats()

    # -- public API ---------------------------------------------------------
    def parse_paths(self, paths: Iterable[str]) -> list[Event]:
        events: list[Event] = []
        for path in paths:
            name = "<stdin>" if path == "-" else str(Path(path))
            with _open(path) as fh:
                events.extend(self.parse_lines(fh, source=name))
        events.sort(key=lambda e: (e.timestamp, e.source, e.line_no))
        return events

    def parse_lines(self, lines: Iterable[str], source: str = "<stdin>") -> Iterator[Event]:
        self.stats.files.append(source)
        years = _YearTracker(self.year, self.now)
        for line_no, raw in enumerate(lines, start=1):
            line = _escape_controls(raw.rstrip("\r\n"))
            if not line.strip():
                continue
            self.stats.lines += 1
            event = self._parse_line(line, source, line_no, years)
            if event is not None:
                self.stats.events += 1
                yield event

    # -- internals ----------------------------------------------------------
    def _parse_line(self, line: str, source: str, line_no: int, years: _YearTracker) -> Event | None:
        m = _CLASSIC.match(line)
        if m:
            month = MONTHS.get(m["mon"])
            if month is None:
                self.stats.unrecognised += 1
                return None
            hh, mm, ss = (int(x) for x in m["time"].split(":"))
            try:
                ts = datetime(years.resolve(month), month, int(m["day"]), hh, mm, ss)
            except ValueError:  # e.g. Feb 29 in a non-leap inferred year
                self.stats.unrecognised += 1
                return None
        else:
            m = _ISO.match(line)
            if not m:
                self.stats.unrecognised += 1
                return None
            try:
                ts = _parse_iso(m["ts"])
            except ValueError:
                self.stats.unrecognised += 1
                return None

        tag = _TAG.match(m["body"])
        if not tag:
            return None
        base = dict(
            timestamp=ts,
            host=m["host"],
            process=tag["proc"],
            pid=int(tag["pid"]) if tag["pid"] else None,
            source=source,
            line_no=line_no,
            raw=line,
        )
        proc = tag["proc"]
        msg = tag["msg"]
        if proc in SSHD_PROCESSES:
            return _parse_sshd(msg, base)
        if proc == "sudo":
            return _parse_sudo(msg, base)
        if proc in ("useradd", "usermod", "gpasswd", "adduser"):
            return _parse_account(msg, base)
        if proc in ("passwd", "chpasswd", "chage"):
            pm = _PASSWD.search(msg)
            if pm:
                return Event(type=EventType.PASSWORD_CHANGE, user=pm["user"], **base)
        return None


def _user(value: str) -> str:
    return value if value else "<empty>"


def _parse_sshd(msg: str, base: dict) -> Event | None:
    count = 1
    rep = _REPEATED.match(msg)
    if rep:
        count, msg = int(rep["n"]), rep["msg"]

    m = _FAILED.match(msg)
    if m:
        return Event(type=EventType.FAILED_LOGIN, user=_user(m["user"]), src_ip=m["ip"], port=int(m["port"]),
                     method=m["method"], invalid_user=bool(m["invalid"]), count=count, **base)
    m = _ACCEPTED.match(msg)
    if m:
        return Event(type=EventType.ACCEPTED_LOGIN, user=m["user"], src_ip=m["ip"], port=int(m["port"]),
                     method=m["method"], count=count, **base)
    m = _INVALID.match(msg)
    if m:
        return Event(type=EventType.INVALID_USER, user=_user(m["user"]), src_ip=m["ip"],
                     port=int(m["port"]) if m["port"] else None, invalid_user=True, count=count, **base)
    m = _PREAUTH.match(msg)
    if m:
        return Event(type=EventType.PREAUTH_CLOSE, user=_user(m["user"]), src_ip=m["ip"], port=int(m["port"]),
                     invalid_user=m["kind"] == "invalid", count=count, **base)
    return None


def _parse_sudo(msg: str, base: dict) -> Event | None:
    m = _SUDO.match(msg)
    if not m:
        return None
    if m["reason"]:
        return Event(type=EventType.SUDO_FAILURE, user=m["user"], run_as=m["runas"], command=m["cmd"],
                     reason=m["reason"].strip(), **base)
    return Event(type=EventType.SUDO_COMMAND, user=m["user"], run_as=m["runas"], command=m["cmd"], **base)


def _parse_account(msg: str, base: dict) -> Event | None:
    m = _USERADD.match(msg)
    if m:
        return Event(type=EventType.USER_CREATED, user=m["user"], uid=int(m["uid"]),
                     reason=f"home={m['home']}, shell={m['shell']}", **base)
    m = _GROUP_ADD.match(msg) or _GPASSWD.match(msg)
    if m:
        return Event(type=EventType.GROUP_ADD, user=m["user"], group=m["group"], **base)
    return None
