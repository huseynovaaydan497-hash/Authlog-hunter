# Detection logic

This page explains how each rule decides, why the defaults are set where they are, and when a rule is likely to produce false positives. All thresholds can be changed from the command line.

## Event model

| Event | Source line (example) |
|---|---|
| `failed_login` | `sshd[…]: Failed password for [invalid user] X from IP port P ssh2` |
| `invalid_user` | `sshd[…]: Invalid user X from IP port P` |
| `preauth_close` | `sshd[…]: Connection closed by invalid\|authenticating user X IP port P [preauth]` |
| `accepted_login` | `sshd[…]: Accepted password\|publickey for X from IP port P ssh2` |
| `sudo_command` | `sudo: X : TTY=… ; PWD=… ; USER=root ; COMMAND=…` |
| `sudo_failure` | `sudo: X : 3 incorrect password attempts ; …` / `user NOT in sudoers ; …` |
| `user_created` | `useradd[…]: new user: name=X, UID=N, …` |
| `group_add` | `usermod[…]: add 'X' to group 'G'` / `gpasswd[…]: user X added by Y to group G` |
| `password_change` | `passwd[…]: pam_unix(passwd:chauthtok): password changed for X` |

`sshd`, `sshd-session` and `sshd-auth` are all treated as sshd. OpenSSH 9.8 and later split the daemon into separate processes. PAM lines such as `pam_unix(sshd:auth): authentication failure` are ignored on purpose, because they repeat the `Failed password` line.

## Counting failed attempts

A "failed attempt" is:

1. every `failed_login` event, multiplied by N for `message repeated N times`, **plus**
2. an `invalid_user` or `preauth_close` event, but only for SSH connections (same host, sshd PID and source IP) that logged no `failed_login`.

The second rule matters on servers with `PasswordAuthentication no`. There, scanners never produce a `Failed password` line; they show up only as `Invalid user` or `Connection closed by authenticating user … [preauth]`.

## Rules

### AH-001: SSH brute force (T1110.001)

**Logic:** at least `--threshold` (10) attempts from one source IP to one host within any `--window` (10 min) sliding window, targeting fewer than `--spray-users` distinct usernames.
**Severity:** Medium. High when at least one targeted account really exists, i.e. the failure was not logged as `invalid user`. This shows the attacker knows valid usernames.
**False positives:** a misconfigured script or monitoring check retrying with an old password. Allowlist it.

### AH-002: Password spraying / user enumeration (T1110.003)

**Logic:** at least `--spray-users` (5) distinct usernames from one IP within the window. This is reported instead of AH-001 for that IP.
**Severity:** Medium. Existing accounts among the targets are listed in the description.

### AH-003: Successful login after brute force (T1110 + T1078)

**Logic:** an `Accepted` login from an IP that produced at least `--success-after` (5) failed attempts against the same host in the previous 24 h. Only the first success per (host, IP, user) is reported. The finding says whether the account that logged in was one of those being guessed.
**Severity:** Critical. It opens an attack chain and triggers severity escalation for later activity.
**Why 5:** people mistype passwords, but rarely five times in a row from one IP. Lower it for high-value hosts. Raise it if users sit behind a shared NAT.
**False positives:** users behind the same NAT/VPN egress IP as an attacker; a user who finally remembers their password.

### AH-004: Direct root login (T1078.003)

**Logic:** any accepted SSH login as `root` from a non-allowlisted IP.
**Severity:** High with a password, Medium with a key. Direct root login removes attribution, because every admin is just "root".
**False positives:** configuration management (Ansible, Salt) that uses root keys. Allowlist those hosts.

### AH-005: Sudo authentication failures (T1548.003)

**Logic:** `sudo` lines with a failure reason, grouped per user.
**Severity:** Medium for `NOT in sudoers` / `command not allowed` or for 3+ bad passwords, otherwise Low. A user without sudo rights trying `sudo` is a common sign of a compromised low-privilege account.

### AH-006: Local account created (T1136.001)

**Severity:** Medium. Critical for UID 0, a second root. Raised one level when the account is created within 24 h after an AH-003 compromise on the same host.

### AH-007: Account added to a privileged group (T1098.007)

**Privileged groups:** `sudo`, `wheel`, `admin`, `root`, `adm`, `docker`, `lxd`, `lxc`, `disk`, `shadow`. Members of `docker`, `lxd` and `disk` can become root trivially, e.g. `docker run -v /:/host`.
**Severity:** High, Critical after a compromise. Non-privileged groups are ignored.

### AH-008: Password changed (T1098)

**Severity:** Low (root: Medium), raised after a compromise. This rule is mostly useful inside attack chains.

### AH-009: Newly created account used for SSH login (T1078.003)

**Logic:** an account created in the analysed period later logs in over SSH from a non-allowlisted IP. This is the classic "create backdoor user, come back later" pattern.
**Severity:** High.

### AH-010 to AH-019: Suspicious commands through sudo

These rules match regular expressions against the `COMMAND=` field of sudo log lines. Findings are grouped per (rule, host, user). If the user is inside a compromised session (after AH-003 for that user, same host, within 24 h), severity is raised one level.

| Rule | Pattern (simplified) | Severity |
|---|---|---|
| AH-010 reverse shell | `/dev/tcp/`, `nc … -e`, `socat … exec:`, `bash -i`, `mkfifo`, `python -c … socket` | Critical |
| AH-011 download | `curl`/`wget`/`tftp` with a URL. High if the output goes to `/tmp`, `/var/tmp`, `/dev/shm` or is piped to a shell | Medium |
| AH-012 exec from temp dir | command starts with a temp path, `sh /tmp/…`, `python /tmp/…`, `chmod +x /tmp/…` | High |
| AH-013 authorized_keys | any command that references `authorized_keys` | High |
| AH-014 shadow | `/etc/shadow`, `/etc/gshadow`, `unshadow` | High |
| AH-015 logs | `rm`/`shred`/`truncate` on `/var/log/*`, `wtmp`, `btmp`, `lastlog`; `journalctl --vacuum-*`; `auditctl -D`; stopping rsyslog/auditd/journald | High |
| AH-016 history | deleting or linking `*_history`, `history -c`, `unset HISTFILE`, `HISTSIZE=0` | High |
| AH-017 cron | `crontab` (except `crontab -l`), `/etc/cron*`, `/var/spool/cron` | Medium |
| AH-018 systemd | writes to `/etc/systemd/system/`, `systemctl enable/link` | Low |
| AH-019 decode | `base64 -d`, `xxd -r` | Medium |

The test suite also checks commands that must **not** match, such as `crontab -l`, `cat ~/.bash_history`, `nc -zv host 5432`, `cat /etc/passwd`, `journalctl -u nginx` and `tail /var/log/nginx/error.log`. This keeps the rules from becoming noisy as they evolve.

**Blind spot:** sudo logs only the command it was given. Anything typed inside `sudo -i`, `sudo su` or `sudo bash` is invisible here. Use `auditd` (`execve` rules) to see it.

## Attack chains

For every AH-003 compromise, the chain contains:

1. the failed-login phase (first attempt, count, targeted users)
2. the successful login
3. within 24 h on the same host:
   - every `sudo` command and sudo failure by the compromised user, labelled with the matching rule's technique, or T1548.003 if no rule matched
   - account creation, privileged group additions and password changes. These are **linked** when one of the attacker's sudo commands in the previous minute mentions the account name, and otherwise marked **time-correlated** (`~`)
   - logins by accounts created during the chain (backdoor use) and further logins from the attacker's IP

Steps are sorted by time, and each shows the ATT&CK tactic, so the chain reads as a kill chain from Credential Access through Defense Evasion.
