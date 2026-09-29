"""Detection rules and correlation logic.

Rule overview (see docs/detections.md for the full rationale):

  AH-001  SSH brute force from one source              T1110.001
  AH-002  Password spraying / user enumeration         T1110.003
  AH-003  Successful login after failed attempts       T1110 + T1078
  AH-004  Direct root login over SSH                   T1078.003
  AH-005  Sudo authentication failures                 T1548.003
  AH-006  Local account created                        T1136.001
  AH-007  Account added to a privileged group          T1098.007
  AH-008  Account password changed                     T1098
  AH-009  Newly created account used for SSH login     T1078.003
  AH-010..AH-019  Suspicious commands run through sudo (see COMMAND_RULES)
"""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Sequence

from .models import AttackChain, ChainStep, Event, EventType, Finding, Severity
from .parser import ParseStats

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Groups that give root or root-equivalent power on common distributions.
# docker/lxd/disk membership is trivially escalated to root.
PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "root", "adm", "docker", "lxd", "lxc", "disk", "shadow"})

_TMP = r"/(?:tmp|var/tmp|dev/shm)/"


@dataclass(frozen=True)
class CommandRule:
    rule_id: str
    title: str
    technique: str
    severity: Severity
    pattern: re.Pattern
    recommendation: str
    escalate_if: re.Pattern | None = None  # raises severity to HIGH when it also matches

    def severity_for(self, command: str) -> Severity:
        if self.escalate_if is not None and self.escalate_if.search(command):
            return max(self.severity, Severity.HIGH)
        return self.severity


COMMAND_RULES: tuple[CommandRule, ...] = (
    CommandRule(
        "AH-010", "Reverse shell launched via sudo", "T1059.004", Severity.CRITICAL,
        re.compile(r"/dev/(?:tcp|udp)/|\bn(?:c|cat|etcat)\b[^|;]*\s-[a-zA-Z]*[ec]\b|\bsocat\b.*\bexec:"
                   r"|\b(?:ba)?sh\s+-i\b|\bmkfifo\b|\b(?:python[23]?|perl|ruby)\s+-\w*[ce]\b.*\bsocket\b"),
        "Isolate the host, capture memory and network connections, block the destination address."),
    CommandRule(
        "AH-011", "File downloaded with elevated privileges", "T1105", Severity.MEDIUM,
        re.compile(r"\b(?:curl|wget|tftp|fetch)\b.*?(?:https?|ftps?|tftp)://"),
        "Retrieve and hash the downloaded file, check the URL/IP against threat intelligence.",
        escalate_if=re.compile(r"\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b|\s-[oO]\s*" + _TMP + r"|>\s*" + _TMP)),
    CommandRule(
        "AH-012", "Execution from a world-writable directory", "T1059.004", Severity.HIGH,
        re.compile(r"^" + _TMP
                   + r"|\b(?:(?:ba|da|z|k)?sh|python[23]?|perl|ruby|php|node)\s+" + _TMP
                   + r"|\bchmod\s+(?:[ugoa]*\+[rwxst]*x[rwxst]*|[0-7]{3,4})\s+(?:\S+\s+){0,5}?" + _TMP),
        "Collect the file from /tmp, /var/tmp or /dev/shm before it is deleted and analyse it."),
    CommandRule(
        "AH-013", "SSH authorized_keys modified", "T1098.004", Severity.HIGH,
        re.compile(r"authorized_keys2?\b"),
        "Review every authorized_keys file on the host and remove unknown keys."),
    CommandRule(
        "AH-014", "Password hash file accessed", "T1003.008", Severity.HIGH,
        re.compile(r"/etc/g?shadow\b|\bunshadow\b"),
        "Assume local password hashes are exposed: rotate passwords for all local accounts."),
    CommandRule(
        "AH-015", "System logs deleted or disabled", "T1070.002", Severity.HIGH,
        re.compile(r"\b(?:rm|shred|truncate|unlink)\b.*(?:/var/log/|\bwtmp\b|\bbtmp\b|\blastlog\b)|>\s*/var/log/"
                   r"|\bjournalctl\b.*--(?:vacuum-\w+|rotate)|\bauditctl\s+-D\b"
                   r"|\bsystemctl\s+(?:stop|disable|mask)\s+(?:rsyslog|auditd|systemd-journald)\b"),
        "Treat local logs as incomplete; rely on centrally forwarded logs for the investigation."),
    CommandRule(
        "AH-016", "Shell history tampering", "T1070.003", Severity.HIGH,
        re.compile(r"\b(?:rm|shred|truncate|unlink|ln)\b.*\.\w*_history\b|>\s*\S*\.\w*_history\b"
                   r"|\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHISTSIZE=0\b"),
        "Someone is hiding their activity. Recover history from backups or EDR telemetry if available."),
    CommandRule(
        "AH-017", "Cron persistence", "T1053.003", Severity.MEDIUM,
        re.compile(r"\bcrontab\b(?!\s+-l\b)|/etc/cron(?:tab|\.d|\.hourly|\.daily|\.weekly|\.monthly)?\b"
                   r"|/var/spool/cron\b"),
        "Diff crontabs (/etc/cron*, /var/spool/cron) against a known-good baseline."),
    CommandRule(
        "AH-018", "Systemd service created or enabled", "T1543.002", Severity.LOW,
        re.compile(r"/etc/systemd/system/|\bsystemctl\s+(?:enable|link)\b"),
        "Confirm the unit file is expected and inspect its ExecStart command."),
    CommandRule(
        "AH-019", "Encoded payload decoded", "T1140", Severity.MEDIUM,
        re.compile(r"\bbase64\s+(?:-\w*d\w*|--decode)\b|\bxxd\s+-r\b"),
        "Decode the payload offline and review what it executes."),
)


def match_command_rules(command: str) -> list[CommandRule]:
    return [r for r in COMMAND_RULES if r.pattern.search(command)]


@dataclass
class DetectionConfig:
    bruteforce_threshold: int = 10          # failed attempts in `window` from one source
    window: timedelta = timedelta(minutes=10)
    spray_min_users: int = 5                # distinct accounts in `window` => spraying
    success_after_failures: int = 5         # failures before a success => AH-003
    lookback: timedelta = timedelta(hours=24)
    chain_window: timedelta = timedelta(hours=24)
    allowlist: tuple[IPNetwork, ...] = ()
    max_evidence: int = 6

    def is_allowlisted(self, ip: str | None) -> bool:
        if not ip or not self.allowlist:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowlist)


@dataclass
class Compromise:
    host: str
    ip: str
    user: str
    time: datetime
    event: Event
    failures: list[Event]


@dataclass
class AnalysisResult:
    findings: list[Finding]
    chains: list[AttackChain]
    summary: dict
    top_sources: list[dict]
    stats: ParseStats | None = None
    config: DetectionConfig = field(default_factory=DetectionConfig)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def parse_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip())


def _evidence(events: Sequence[Event], limit: int) -> tuple[list[Event], int]:
    events = list(events)
    if len(events) <= limit:
        return events, 0
    # keep the start of the activity and the most recent line
    return events[: limit - 1] + events[-1:], len(events) - limit


def _fmt_users(counter: Counter, limit: int = 5) -> str:
    items = [f"{u} ({n})" for u, n in counter.most_common(limit)]
    if len(counter) > limit:
        items.append(f"+{len(counter) - limit} more")
    return ", ".join(items)


def _fmt_delta(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60} min"


def auth_attempts(events: Sequence[Event]) -> list[Event]:
    """One entry per failed authentication attempt.

    A single SSH connection can log both ``Invalid user x`` and
    ``Failed password for invalid user x``; on key-only servers only the
    ``Invalid user`` / ``Connection closed ... [preauth]`` lines exist.
    Count explicit failures, and fall back to the other lines only for
    connections (host + sshd pid + ip) that logged no explicit failure.
    """
    failed = [e for e in events if e.type is EventType.FAILED_LOGIN]
    seen = {(e.host, e.pid, e.src_ip) for e in failed if e.pid is not None}
    attempts = list(failed)
    for e in events:
        if e.type not in (EventType.INVALID_USER, EventType.PREAUTH_CLOSE):
            continue
        key = (e.host, e.pid, e.src_ip)
        if e.pid is not None:
            if key in seen:
                continue
            seen.add(key)
        attempts.append(e)
    attempts.sort(key=lambda e: e.timestamp)
    return attempts


def _sliding_peaks(events: Sequence[Event], window: timedelta) -> tuple[int, int]:
    """Max attempts and max distinct users seen within any `window`."""
    peak_total = peak_users = 0
    left = total = 0
    users: Counter = Counter()
    for ev in events:
        total += ev.count
        users[ev.user] += ev.count
        while ev.timestamp - events[left].timestamp > window:
            old = events[left]
            total -= old.count
            users[old.user] -= old.count
            if users[old.user] <= 0:
                del users[old.user]
            left += 1
        peak_total = max(peak_total, total)
        peak_users = max(peak_users, len(users))
    return peak_total, peak_users


def _compromise_for(compromises: Sequence[Compromise], host: str, ts: datetime, cfg: DetectionConfig,
                    user: str | None = None) -> Compromise | None:
    for c in compromises:
        if c.host == host and c.time <= ts <= c.time + cfg.chain_window and (user is None or c.user == user):
            return c
    return None


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def detect_bruteforce(attempts: Sequence[Event], cfg: DetectionConfig) -> list[Finding]:
    by_src: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in attempts:
        if not cfg.is_allowlisted(e.src_ip):
            by_src[(e.host, e.src_ip or "unknown")].append(e)

    findings = []
    window_txt = _fmt_delta(cfg.window)
    for (host, ip), evs in by_src.items():
        peak_total, peak_users = _sliding_peaks(evs, cfg.window)
        users: Counter = Counter()
        for e in evs:
            users[e.user] += e.count
        total = sum(users.values())
        valid = sorted({e.user for e in evs if not e.invalid_user})
        evidence, omitted = _evidence(evs, cfg.max_evidence)
        common = dict(first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, event_count=total, host=host,
                      src_ip=ip, users=[u for u, _ in users.most_common()], evidence=evidence,
                      omitted_evidence=omitted)
        if peak_users >= cfg.spray_min_users:
            valid_txt = f" Existing accounts among them: {', '.join(valid)}." if valid else ""
            findings.append(Finding(
                rule_id="AH-002", title="Password spraying / user enumeration", severity=Severity.MEDIUM,
                techniques=["T1110.003"],
                description=(f"{ip} tried {len(users)} different usernames ({total} attempts); up to {peak_users} "
                             f"distinct accounts within {window_txt}. Users: {_fmt_users(users)}.{valid_txt}"),
                recommendation="Block the source at the firewall, enable fail2ban/sshguard, and disable password "
                               "authentication (PasswordAuthentication no) where possible.",
                **common))
        elif peak_total >= cfg.bruteforce_threshold:
            findings.append(Finding(
                rule_id="AH-001", title="SSH brute force", severity=Severity.HIGH if valid else Severity.MEDIUM,
                techniques=["T1110.001"],
                description=(f"{total} failed SSH logins from {ip} (peak {peak_total} within {window_txt}) "
                             f"against: {_fmt_users(users)}."
                             + (" Targets include existing accounts." if valid else "")),
                recommendation="Block the source, rate-limit SSH (fail2ban/sshguard), enforce key-based "
                               "authentication and check the targeted accounts for weak passwords.",
                **common))
    return findings


def detect_compromise(events: Sequence[Event], attempts: Sequence[Event],
                      cfg: DetectionConfig) -> tuple[list[Finding], list[Compromise]]:
    fails_by_src: dict[tuple[str, str | None], list[Event]] = defaultdict(list)
    for a in attempts:  # attempts are time-sorted, so each list is too
        fails_by_src[(a.host, a.src_ip)].append(a)
    times_by_src = {k: [f.timestamp for f in v] for k, v in fails_by_src.items()}

    findings: list[Finding] = []
    compromises: list[Compromise] = []
    seen: set[tuple] = set()
    for e in events:
        if e.type is not EventType.ACCEPTED_LOGIN or cfg.is_allowlisted(e.src_ip):
            continue
        key = (e.host, e.src_ip, e.user)
        if key in seen:
            continue
        src = (e.host, e.src_ip)
        if src not in fails_by_src:
            continue
        times = times_by_src[src]
        prior = fails_by_src[src][bisect_left(times, e.timestamp - cfg.lookback):bisect_right(times, e.timestamp)]
        n = sum(f.count for f in prior)
        if n < cfg.success_after_failures:
            continue
        seen.add(key)
        users: Counter = Counter()
        for f in prior:
            users[f.user] += f.count
        spray = len(users) >= cfg.spray_min_users
        guessed = e.user in users
        evidence, omitted = _evidence(prior, cfg.max_evidence - 1)
        compromises.append(Compromise(e.host, e.src_ip or "unknown", e.user or "?", e.timestamp, e, prior))
        findings.append(Finding(
            rule_id="AH-003", title="Successful SSH login after brute force", severity=Severity.CRITICAL,
            techniques=["T1110.003" if spray else "T1110.001", "T1078"],
            description=(f"{n} failed attempts from {e.src_ip} against {_fmt_users(users)} were followed by a successful "
                         f"{e.method} login as '{e.user}' at {e.timestamp:%Y-%m-%d %H:%M:%S}. "
                         + ("The password of this account was most likely guessed."
                            if guessed else "The attacker logged in with a different account than the ones guessed.")),
            recommendation=(f"Treat '{e.user}' as compromised: kill its sessions, reset credentials and keys, "
                            f"review everything it did after {e.timestamp:%H:%M:%S} (see attack chain), "
                            "and consider rebuilding the host."),
            first_seen=prior[0].timestamp, last_seen=e.timestamp, event_count=n + 1, host=e.host,
            src_ip=e.src_ip, users=[e.user or "?"], evidence=evidence + [e], omitted_evidence=omitted))
    return findings, compromises


def detect_root_login(events: Sequence[Event], cfg: DetectionConfig) -> list[Finding]:
    groups: dict[tuple[str, str | None], list[Event]] = defaultdict(list)
    for e in events:
        if e.type is EventType.ACCEPTED_LOGIN and e.user == "root" and not cfg.is_allowlisted(e.src_ip):
            groups[(e.host, e.src_ip)].append(e)
    findings = []
    for (host, ip), evs in groups.items():
        methods = sorted({e.method or "?" for e in evs})
        password = any(m.startswith(("password", "keyboard")) for m in methods)
        evidence, omitted = _evidence(evs, cfg.max_evidence)
        findings.append(Finding(
            rule_id="AH-004", title="Direct root login over SSH",
            severity=Severity.HIGH if password else Severity.MEDIUM, techniques=["T1078.003"],
            description=f"{len(evs)} successful root login(s) from {ip} using {', '.join(methods)}.",
            recommendation="Set 'PermitRootLogin no' (or 'prohibit-password') and use named accounts with sudo "
                           "so actions are attributable.",
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, event_count=len(evs), host=host,
            src_ip=ip, users=["root"], evidence=evidence, omitted_evidence=omitted))
    return findings


_ATTEMPTS = re.compile(r"(\d+) incorrect password attempts?")


def detect_sudo_failures(events: Sequence[Event], cfg: DetectionConfig) -> list[Finding]:
    groups: dict[tuple[str, str | None], list[Event]] = defaultdict(list)
    for e in events:
        if e.type is EventType.SUDO_FAILURE:
            groups[(e.host, e.user)].append(e)
    findings = []
    for (host, user), evs in groups.items():
        attempts = 0
        not_allowed = False
        for e in evs:
            m = _ATTEMPTS.search(e.reason or "")
            attempts += int(m[1]) if m else 1
            not_allowed |= "NOT in sudoers" in (e.reason or "") or "not allowed" in (e.reason or "")
        reasons = sorted({e.reason or "" for e in evs})
        severity = Severity.MEDIUM if (not_allowed or attempts >= 3) else Severity.LOW
        evidence, omitted = _evidence(evs, cfg.max_evidence)
        findings.append(Finding(
            rule_id="AH-005", title="Sudo authentication failures", severity=severity, techniques=["T1548.003"],
            description=f"'{user}' failed sudo {attempts} time(s): {'; '.join(reasons)}.",
            recommendation="Confirm with the account owner; an unauthorised user probing sudo often indicates "
                           "a compromised low-privilege account.",
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, event_count=len(evs), host=host,
            users=[user or "?"], evidence=evidence, omitted_evidence=omitted))
    return findings


def detect_suspicious_commands(events: Sequence[Event], compromises: Sequence[Compromise],
                               cfg: DetectionConfig) -> list[Finding]:
    groups: dict[tuple[str, str, str | None], list[tuple[Event, Severity, Compromise | None]]] = defaultdict(list)
    for e in events:
        if e.type is not EventType.SUDO_COMMAND or not e.command:
            continue
        comp = _compromise_for(compromises, e.host, e.timestamp, cfg, user=e.user)
        for rule in match_command_rules(e.command):
            sev = rule.severity_for(e.command)
            if comp is not None:
                sev = sev.bump()
            groups[(rule.rule_id, e.host, e.user)].append((e, sev, comp))

    rules = {r.rule_id: r for r in COMMAND_RULES}
    findings = []
    for (rule_id, host, user), items in groups.items():
        rule = rules[rule_id]
        evs = [i[0] for i in items]
        comp = next((i[2] for i in items if i[2] is not None), None)
        commands = list(dict.fromkeys(e.command for e in evs))
        desc = f"'{user}' ran {len(evs)} matching command(s) as {evs[0].run_as}: " + "; ".join(
            f"`{c}`" for c in commands[:3]) + (f" (+{len(commands) - 3} more)" if len(commands) > 3 else "") + "."
        if comp is not None:
            desc += (f" Run from the session opened by the brute-force login from {comp.ip} "
                     f"at {comp.time:%H:%M:%S} (AH-003), so severity was raised.")
        evidence, omitted = _evidence(evs, cfg.max_evidence)
        findings.append(Finding(
            rule_id=rule_id, title=rule.title, severity=max(i[1] for i in items), techniques=[rule.technique],
            description=desc, recommendation=rule.recommendation, first_seen=evs[0].timestamp,
            last_seen=evs[-1].timestamp, event_count=len(evs), host=host,
            src_ip=comp.ip if comp else None, users=[user or "?"], evidence=evidence, omitted_evidence=omitted))
    return findings


def detect_account_changes(events: Sequence[Event], compromises: Sequence[Compromise],
                           cfg: DetectionConfig) -> list[Finding]:
    findings = []
    created: dict[tuple[str, str | None], Event] = {}
    account_types = (EventType.USER_CREATED, EventType.GROUP_ADD, EventType.PASSWORD_CHANGE)
    for e in events:
        comp, after = None, ""
        if e.type in account_types:
            comp = _compromise_for(compromises, e.host, e.timestamp, cfg)
            if comp is not None:
                after = (f" This happened {_fmt_delta(e.timestamp - comp.time)} after '{comp.user}' was "
                         f"compromised from {comp.ip}.")
        if e.type is EventType.USER_CREATED:
            created[(e.host, e.user)] = e
            sev = Severity.CRITICAL if e.uid == 0 else Severity.MEDIUM
            if comp is not None:
                sev = sev.bump()
            uid_txt = " UID 0 makes this account equivalent to root." if e.uid == 0 else ""
            findings.append(Finding(
                rule_id="AH-006", title="Local account created", severity=sev, techniques=["T1136.001"],
                description=f"New account '{e.user}' (UID {e.uid}, {e.reason}).{uid_txt}{after}",
                recommendation="Verify the account against a change ticket; lock it (usermod -L) if unknown.",
                first_seen=e.timestamp, last_seen=e.timestamp, event_count=1, host=e.host,
                src_ip=comp.ip if comp else None, users=[e.user or "?"], evidence=[e]))
        elif e.type is EventType.GROUP_ADD and e.group in PRIVILEGED_GROUPS:
            sev = Severity.CRITICAL if comp else Severity.HIGH
            findings.append(Finding(
                rule_id="AH-007", title="Account added to a privileged group", severity=sev,
                techniques=["T1098.007"],
                description=f"'{e.user}' was added to group '{e.group}', which grants root or root-equivalent "
                            f"access.{after}",
                recommendation=f"Remove '{e.user}' from '{e.group}' unless approved (gpasswd -d {e.user} {e.group}).",
                first_seen=e.timestamp, last_seen=e.timestamp, event_count=1, host=e.host,
                src_ip=comp.ip if comp else None, users=[e.user or "?"], evidence=[e]))
        elif e.type is EventType.PASSWORD_CHANGE:
            sev = Severity.MEDIUM if e.user == "root" else Severity.LOW
            if comp is not None:
                sev = sev.bump()
            findings.append(Finding(
                rule_id="AH-008", title="Account password changed", severity=sev, techniques=["T1098"],
                description=f"Password changed for '{e.user}'.{after}",
                recommendation="Confirm the change with the account owner.",
                first_seen=e.timestamp, last_seen=e.timestamp, event_count=1, host=e.host,
                src_ip=comp.ip if comp else None, users=[e.user or "?"], evidence=[e]))
        elif (e.type is EventType.ACCEPTED_LOGIN and (e.host, e.user) in created
              and not cfg.is_allowlisted(e.src_ip)):
            c = created[(e.host, e.user)]
            findings.append(Finding(
                rule_id="AH-009", title="Newly created account used for SSH login", severity=Severity.HIGH,
                techniques=["T1078.003"],
                description=(f"'{e.user}' logged in from {e.src_ip} via {e.method} "
                             f"{_fmt_delta(e.timestamp - c.timestamp)} after the account was created."),
                recommendation="Check whether this login was expected; a fresh account logging in from an external "
                               "address is a classic backdoor pattern.",
                first_seen=c.timestamp, last_seen=e.timestamp, event_count=2, host=e.host, src_ip=e.src_ip,
                users=[e.user or "?"], evidence=[c, e]))
    return findings


# ---------------------------------------------------------------------------
# correlation: attack chains
# ---------------------------------------------------------------------------

def build_attack_chains(events: Sequence[Event], compromises: Sequence[Compromise],
                        cfg: DetectionConfig) -> list[AttackChain]:
    chains = []
    times = [e.timestamp for e in events]  # events are time-sorted
    for c in compromises:
        chain = AttackChain(host=c.host, src_ip=c.ip, user=c.user, compromised_at=c.time)
        users = Counter()
        for f in c.failures:
            users[f.user] += f.count
        tech = "T1110.003" if len(users) >= cfg.spray_min_users else "T1110.001"
        first, last = c.failures[0].timestamp, c.failures[-1].timestamp
        chain.steps.append(ChainStep(first, tech,
                                     f"{sum(users.values())} failed SSH logins from {c.ip} against "
                                     f"{_fmt_users(users, 3)}, until {last:%H:%M:%S}", c.failures[0]))
        chain.steps.append(ChainStep(c.time, "T1078", f"Successful {c.event.method} login as '{c.user}' from {c.ip}",
                                     c.event))
        end = c.time + cfg.chain_window
        created: set[str | None] = set()
        recent_sudo: deque[Event] = deque()
        for e in events[bisect_right(times, c.time):bisect_right(times, end)]:
            if e.host != c.host:
                continue
            while recent_sudo and e.timestamp - recent_sudo[0].timestamp > timedelta(minutes=1):
                recent_sudo.popleft()
            if e.type is EventType.SUDO_COMMAND and e.user == c.user:
                recent_sudo.append(e)
                rules = match_command_rules(e.command or "")
                chain.steps.append(ChainStep(e.timestamp, rules[0].technique if rules else "T1548.003",
                                             f"sudo ({e.run_as}): {e.command}", e))
            elif e.type is EventType.SUDO_FAILURE and e.user == c.user:
                chain.steps.append(ChainStep(e.timestamp, "T1548.003", f"sudo failure: {e.reason}", e))
            elif e.type in (EventType.USER_CREATED, EventType.GROUP_ADD, EventType.PASSWORD_CHANGE):
                # Account tools do not log who ran them. Link them to the attacker when one of the
                # attacker's sudo commands in the previous minute mentions the account.
                linked = bool(e.user) and any(e.user in (s.command or "") for s in recent_sudo)
                if e.type is EventType.USER_CREATED:
                    created.add(e.user)
                    chain.steps.append(ChainStep(e.timestamp, "T1136.001",
                                                 f"Local account '{e.user}' created (UID {e.uid})", e, not linked))
                elif e.type is EventType.GROUP_ADD and e.group in PRIVILEGED_GROUPS:
                    chain.steps.append(ChainStep(e.timestamp, "T1098.007",
                                                 f"'{e.user}' added to privileged group '{e.group}'", e, not linked))
                elif e.type is EventType.PASSWORD_CHANGE:
                    chain.steps.append(ChainStep(e.timestamp, "T1098", f"Password set for '{e.user}'", e, not linked))
            elif e.type is EventType.ACCEPTED_LOGIN:
                if e.user in created:
                    chain.steps.append(ChainStep(e.timestamp, "T1078.003",
                                                 f"Backdoor account '{e.user}' logged in from {e.src_ip}", e))
                elif e.src_ip == c.ip:
                    chain.steps.append(ChainStep(e.timestamp, "T1078", f"Attacker logged in again as '{e.user}'", e))
        chain.steps.sort(key=lambda s: s.timestamp)
        chains.append(chain)
    return chains


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _top_sources(events: Sequence[Event], attempts: Sequence[Event], limit: int = 10) -> list[dict]:
    table: dict[str, dict] = defaultdict(lambda: {"failed": 0, "users": set(), "accepted": 0})
    for a in attempts:
        row = table[a.src_ip or "unknown"]
        row["failed"] += a.count
        row["users"].add(a.user)
    for e in events:
        if e.type is EventType.ACCEPTED_LOGIN:
            table[e.src_ip or "unknown"]["accepted"] += 1
    rows = [{"ip": ip, "failed": r["failed"], "distinct_users": len(r["users"]), "accepted": r["accepted"]}
            for ip, r in table.items() if r["failed"]]
    rows.sort(key=lambda r: (-r["failed"], -r["accepted"], r["ip"]))
    return rows[:limit]


def analyze(events: Sequence[Event], cfg: DetectionConfig | None = None,
            stats: ParseStats | None = None) -> AnalysisResult:
    cfg = cfg or DetectionConfig()
    events = sorted(events, key=lambda e: (e.timestamp, e.source, e.line_no))
    attempts = auth_attempts(events)

    findings: list[Finding] = []
    findings += detect_bruteforce(attempts, cfg)
    compromise_findings, compromises = detect_compromise(events, attempts, cfg)
    findings += compromise_findings
    findings += detect_root_login(events, cfg)
    findings += detect_sudo_failures(events, cfg)
    findings += detect_suspicious_commands(events, compromises, cfg)
    findings += detect_account_changes(events, compromises, cfg)
    findings.sort(key=lambda f: (-f.severity, f.first_seen, f.rule_id))

    by_type = Counter(e.type for e in events)
    summary = {
        "first_event": events[0].timestamp if events else None,
        "last_event": events[-1].timestamp if events else None,
        "hosts": sorted({e.host for e in events}),
        "failed_attempts": sum(a.count for a in attempts),
        "attacking_ips": len({a.src_ip for a in attempts}),
        "accepted_logins": by_type[EventType.ACCEPTED_LOGIN],
        "sudo_commands": by_type[EventType.SUDO_COMMAND],
        "findings_by_severity": {s.name: sum(1 for f in findings if f.severity is s)
                                 for s in sorted(Severity, reverse=True)},
    }
    return AnalysisResult(findings=findings, chains=build_attack_chains(events, compromises, cfg), summary=summary,
                          top_sources=_top_sources(events, attempts), stats=stats, config=cfg)
