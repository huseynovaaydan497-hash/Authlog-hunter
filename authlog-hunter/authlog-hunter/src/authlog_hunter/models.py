"""Core data structures shared by the parser, detectors and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{name}' (expected one of: {valid})") from None

    def bump(self) -> "Severity":
        """Return the next severity level (capped at CRITICAL)."""
        return Severity(min(self + 1, Severity.CRITICAL))


class EventType(str, Enum):
    FAILED_LOGIN = "failed_login"        # sshd: Failed password/publickey for ...
    INVALID_USER = "invalid_user"        # sshd: Invalid user X from IP
    PREAUTH_CLOSE = "preauth_close"      # sshd: Connection closed by ... user X IP [preauth]
    ACCEPTED_LOGIN = "accepted_login"    # sshd: Accepted password/publickey for ...
    SUDO_COMMAND = "sudo_command"        # sudo: user : TTY=... ; COMMAND=...
    SUDO_FAILURE = "sudo_failure"        # sudo: user : 3 incorrect password attempts ; ...
    USER_CREATED = "user_created"        # useradd: new user: name=...
    GROUP_ADD = "group_add"              # usermod/gpasswd: add 'x' to group 'sudo'
    PASSWORD_CHANGE = "password_change"  # passwd: password changed for x


@dataclass(frozen=True)
class Event:
    """One security-relevant line from an auth log, normalised."""

    timestamp: datetime
    host: str
    process: str
    pid: int | None
    type: EventType
    user: str | None = None
    src_ip: str | None = None
    port: int | None = None
    method: str | None = None
    invalid_user: bool = False
    run_as: str | None = None
    command: str | None = None
    group: str | None = None
    uid: int | None = None
    reason: str | None = None
    count: int = 1  # >1 when rsyslog collapsed lines ("message repeated N times")
    source: str = "<stdin>"
    line_no: int = 0
    raw: str = ""

    @property
    def location(self) -> str:
        return f"{self.source}:{self.line_no}"


@dataclass
class Finding:
    """A detection produced by one rule."""

    rule_id: str
    title: str
    severity: Severity
    techniques: list[str]
    description: str
    recommendation: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    host: str | None = None
    src_ip: str | None = None
    users: list[str] = field(default_factory=list)
    evidence: list[Event] = field(default_factory=list)
    omitted_evidence: int = 0


@dataclass
class ChainStep:
    timestamp: datetime
    technique: str
    summary: str
    event: Event | None = None
    time_correlated: bool = False  # linked by time window, not by user/session


@dataclass
class AttackChain:
    """Ordered story of one compromise: brute force -> login -> activity."""

    host: str
    src_ip: str
    user: str
    compromised_at: datetime
    steps: list[ChainStep] = field(default_factory=list)
