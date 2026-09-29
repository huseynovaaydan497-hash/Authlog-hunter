"""Render an AnalysisResult as coloured text, JSON or Markdown."""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone

from . import __version__, mitre
from .detectors import AnalysisResult
from .models import AttackChain, ChainStep, Finding, Severity

TS = "%Y-%m-%d %H:%M:%S"

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"


def _ts(value: datetime | None) -> str:
    return value.strftime(TS) if value else "-"


def _span(f: Finding) -> str:
    if f.first_seen == f.last_seen:
        return _ts(f.first_seen)
    end = f.last_seen.strftime("%H:%M:%S" if f.first_seen.date() == f.last_seen.date() else TS)
    return f"{_ts(f.first_seen)} -> {end}"


def _step_time(step: ChainStep, chain: AttackChain) -> str:
    fmt = "%H:%M:%S" if step.timestamp.date() == chain.compromised_at.date() else "%m-%d %H:%M"
    return step.timestamp.strftime(fmt)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _severity_counts(result: AnalysisResult) -> str:
    counts = result.summary["findings_by_severity"]
    parts = [f"{n} {name.lower()}" for name, n in counts.items() if n]
    return ", ".join(parts) if parts else "none"


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------

def render_text(result: AnalysisResult, color: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out: list[str] = []
    s = result.summary
    stats = result.stats
    title = f"authlog-hunter {__version__} - Linux auth log threat report"
    out += [c(_BOLD, title), "=" * len(title)]
    if stats:
        out.append(f"Sources    {', '.join(stats.files)} ({stats.lines} lines, {stats.events} security events)")
    out.append(f"Period     {_ts(s['first_event'])} -> {_ts(s['last_event'])}")
    out.append(f"Hosts      {', '.join(s['hosts']) or '-'}")
    out.append(f"Activity   {s['failed_attempts']} failed logins from {s['attacking_ips']} IPs, "
               f"{s['accepted_logins']} accepted logins, {s['sudo_commands']} sudo commands")
    out.append(f"Findings   {_severity_counts(result)}")
    out.append("")

    out.append(c(_BOLD, f"FINDINGS ({len(result.findings)})"))
    out.append("-" * 60)
    if not result.findings:
        out.append("No findings at the selected severity.")
    wrap = textwrap.TextWrapper(width=108, initial_indent=" " * 12, subsequent_indent=" " * 12)
    for f in result.findings:
        badge = c(_COLORS[f.severity], f"[{f.severity.name}]")
        out.append(f"{badge} {c(_BOLD, f.rule_id)}  {c(_BOLD, f.title)}")
        out.append(f"  when      {_span(f)} ({_plural(f.event_count, 'event')})")
        where = f"{f.src_ip} -> {f.host}" if f.src_ip else f.host
        users = ", ".join(f.users[:8]) + (f" (+{len(f.users) - 8})" if len(f.users) > 8 else "")
        out.append(f"  where     {where}    users: {users}")
        out.append(f"  mitre     {'; '.join(mitre.label(t) for t in f.techniques)}")
        out.append("  what      " + wrap.fill(f.description)[12:])
        out.append("  action    " + wrap.fill(f.recommendation)[12:])
        for i, ev in enumerate(f.evidence):
            prefix = "  evidence  " if i == 0 else " " * 12
            raw = ev.raw if len(ev.raw) <= 150 else ev.raw[:147] + "..."
            out.append(prefix + c(_DIM, f"{ev.location}") + f"  {raw}")
        if f.omitted_evidence:
            out.append(" " * 12 + c(_DIM, f"... {f.omitted_evidence} more matching lines"))
        out.append("")

    for n, chain in enumerate(result.chains, start=1):
        header = (f"ATTACK CHAIN {n}: '{chain.user}'@{chain.host} compromised from {chain.src_ip} "
                  f"on {chain.compromised_at:%Y-%m-%d}")
        out.append(c(_BOLD, header))
        out.append("-" * len(header))
        out.append(f"  {'TIME':<9} {'TACTIC':<21} {'TECHNIQUE':<10} ACTIVITY")
        for step in chain.steps:
            marker = "~" if step.time_correlated else " "
            summary = step.summary if len(step.summary) <= 90 else step.summary[:87] + "..."
            out.append(f" {marker}{_step_time(step, chain):<9} {mitre.tactic(step.technique):<21} "
                       f"{step.technique:<10} {summary}")
        if any(st.time_correlated for st in chain.steps):
            out.append(c(_DIM, "  ~ linked by time window only (the log does not record who ran it)"))
        out.append("")

    if result.top_sources:
        out.append(c(_BOLD, "TOP SOURCES OF FAILED LOGINS"))
        out.append("-" * 60)
        out.append(f"  {'IP':<40} {'FAILED':>7} {'USERS':>6} {'ACCEPTED':>9}")
        for r in result.top_sources:
            accepted = str(r["accepted"])
            if r["accepted"]:
                accepted = c(_COLORS[Severity.HIGH], f"{r['accepted']:>9}")
            else:
                accepted = f"{accepted:>9}"
            out.append(f"  {r['ip']:<40} {r['failed']:>7} {r['distinct_users']:>6} {accepted}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# json
# ---------------------------------------------------------------------------

def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def to_dict(result: AnalysisResult) -> dict:
    cfg = result.config
    stats = result.stats
    summary = dict(result.summary)
    summary["first_event"] = _iso(summary["first_event"])
    summary["last_event"] = _iso(summary["last_event"])
    return {
        "tool": "authlog-hunter",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": stats.files if stats else [],
        "parse_stats": ({"lines": stats.lines, "events": stats.events, "unrecognised": stats.unrecognised}
                        if stats else None),
        "config": {
            "bruteforce_threshold": cfg.bruteforce_threshold,
            "window_minutes": cfg.window.total_seconds() / 60,
            "spray_min_users": cfg.spray_min_users,
            "success_after_failures": cfg.success_after_failures,
            "allowlist": [str(n) for n in cfg.allowlist],
        },
        "summary": summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.name,
                "techniques": [{"id": t, "name": mitre.name(t), "tactic": mitre.tactic(t), "url": mitre.url(t)}
                               for t in f.techniques],
                "description": f.description,
                "recommendation": f.recommendation,
                "host": f.host,
                "src_ip": f.src_ip,
                "users": f.users,
                "first_seen": _iso(f.first_seen),
                "last_seen": _iso(f.last_seen),
                "event_count": f.event_count,
                "evidence": [{"location": e.location, "raw": e.raw} for e in f.evidence],
                "omitted_evidence": f.omitted_evidence,
            }
            for f in result.findings
        ],
        "attack_chains": [
            {
                "host": ch.host,
                "src_ip": ch.src_ip,
                "user": ch.user,
                "compromised_at": _iso(ch.compromised_at),
                "steps": [
                    {
                        "timestamp": _iso(st.timestamp),
                        "tactic": mitre.tactic(st.technique),
                        "technique": st.technique,
                        "technique_name": mitre.name(st.technique),
                        "summary": st.summary,
                        "location": st.event.location if st.event else None,
                        "time_correlated": st.time_correlated,
                    }
                    for st in ch.steps
                ],
            }
            for ch in result.chains
        ],
        "top_sources": result.top_sources,
    }


def render_json(result: AnalysisResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------

def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(result: AnalysisResult) -> str:
    s = result.summary
    stats = result.stats
    out = ["# authlog-hunter report", ""]
    out += ["| | |", "|---|---|"]
    if stats:
        out.append(f"| Sources | {_md(', '.join(stats.files))} ({stats.lines} lines, {stats.events} events) |")
    out.append(f"| Period | {_ts(s['first_event'])} → {_ts(s['last_event'])} |")
    out.append(f"| Hosts | {_md(', '.join(s['hosts']) or '-')} |")
    out.append(f"| Failed logins | {s['failed_attempts']} from {s['attacking_ips']} IPs |")
    out.append(f"| Accepted logins | {s['accepted_logins']} |")
    out.append(f"| Findings | {_severity_counts(result)} |")
    out.append(f"| Generated | {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} by authlog-hunter {__version__} |")
    out.append("")

    out += ["## Findings", ""]
    if not result.findings:
        out.append("_No findings at the selected severity._")
    else:
        out += ["| # | Severity | Rule | Title | Source | Users | First seen | MITRE ATT&CK |",
                "|---|---|---|---|---|---|---|---|"]
        for i, f in enumerate(result.findings, start=1):
            techs = ", ".join(f"[{t}]({mitre.url(t)})" for t in f.techniques)
            users = ", ".join(f.users[:5]) + (" …" if len(f.users) > 5 else "")
            out.append(f"| {i} | **{f.severity.name}** | {f.rule_id} | {_md(f.title)} | {_md(f.src_ip or '-')} "
                       f"| {_md(users)} | {_ts(f.first_seen)} | {techs} |")
        out.append("")
        for i, f in enumerate(result.findings, start=1):
            out.append(f"### {i}. [{f.severity.name}] {f.rule_id} — {f.title}")
            out.append("")
            out.append(f"- **Host:** {f.host or '-'}  ")
            out.append(f"- **Source IP:** {f.src_ip or '-'}  ")
            out.append(f"- **Time:** {_span(f)} ({_plural(f.event_count, 'event')})  ")
            out.append(f"- **MITRE ATT&CK:** " + ", ".join(f"[{mitre.label(t)}]({mitre.url(t)})"
                                                            for t in f.techniques))
            out.append("")
            out.append(f.description)
            out.append("")
            out.append(f"**Recommended action:** {f.recommendation}")
            out.append("")
            out.append("```text")
            out += [f"{e.location}  {e.raw}" for e in f.evidence]
            if f.omitted_evidence:
                out.append(f"... {f.omitted_evidence} more matching lines")
            out.append("```")
            out.append("")

    if result.chains:
        out += ["## Attack chains", ""]
        for n, chain in enumerate(result.chains, start=1):
            out.append(f"### Chain {n}: `{chain.user}@{chain.host}` compromised from `{chain.src_ip}`")
            out.append("")
            out += ["| Time | Tactic | Technique | Activity |", "|---|---|---|---|"]
            for st in chain.steps:
                marker = " *(time-correlated)*" if st.time_correlated else ""
                out.append(f"| {_ts(st.timestamp)} | {mitre.tactic(st.technique)} | "
                           f"[{st.technique}]({mitre.url(st.technique)}) | {_md(st.summary)}{marker} |")
            out.append("")

    if result.top_sources:
        out += ["## Top sources of failed logins", "", "| IP | Failed | Distinct users | Accepted |",
                "|---|---:|---:|---:|"]
        out += [f"| {r['ip']} | {r['failed']} | {r['distinct_users']} | {r['accepted']} |" for r in result.top_sources]
        out.append("")
    return "\n".join(out)


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}
