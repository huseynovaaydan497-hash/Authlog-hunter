import gzip
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from helpers import parse

from authlog_hunter.models import EventType
from authlog_hunter.parser import LogParser


class ParserTests(unittest.TestCase):
    def one(self, raw: str):
        events, _ = parse([raw])
        self.assertEqual(len(events), 1, f"expected one event from: {raw}")
        return events[0]

    def test_failed_password_valid_user(self):
        e = self.one("Sep 28 03:40:12 web sshd[2060]: Failed password for root from 203.0.113.45 port 46929 ssh2")
        self.assertEqual(e.type, EventType.FAILED_LOGIN)
        self.assertEqual((e.user, e.src_ip, e.port, e.method), ("root", "203.0.113.45", 46929, "password"))
        self.assertFalse(e.invalid_user)
        self.assertEqual(e.timestamp, datetime(2026, 9, 28, 3, 40, 12))
        self.assertEqual((e.host, e.process, e.pid), ("web", "sshd", 2060))

    def test_failed_password_invalid_user_with_spaces_and_empty(self):
        e = self.one("Sep 28 03:40:12 web sshd[1]: Failed password for invalid user john doe from 192.0.2.1 port 22 ssh2")
        self.assertEqual(e.user, "john doe")
        self.assertTrue(e.invalid_user)
        e = self.one("Sep 28 03:40:12 web sshd[1]: Failed password for invalid user  from 192.0.2.1 port 22 ssh2")
        self.assertEqual(e.user, "<empty>")

    def test_accepted_publickey_with_fingerprint(self):
        e = self.one("Sep 28 06:00:02 web sshd[2480]: Accepted publickey for root from 10.10.5.5 port 59047 ssh2: "
                     "ED25519 SHA256:6D+tghIQHVoKY4gGT2sF3kTH7swIathb")
        self.assertEqual((e.type, e.user, e.method), (EventType.ACCEPTED_LOGIN, "root", "publickey"))

    def test_ipv6_source(self):
        e = self.one("Sep 28 06:00:02 web sshd[7]: Failed password for root from 2001:db8::5 port 4000 ssh2")
        self.assertEqual(e.src_ip, "2001:db8::5")

    def test_message_repeated_is_counted(self):
        e = self.one("Sep 28 03:40:24 web sshd[2060]: message repeated 5 times: "
                     "[ Failed password for root from 203.0.113.45 port 46929 ssh2]")
        self.assertEqual((e.type, e.count), (EventType.FAILED_LOGIN, 5))

    def test_openssh_98_sshd_session_process(self):
        e = self.one("Sep 28 03:40:12 web sshd-session[99]: Invalid user admin from 192.0.2.1 port 5555")
        self.assertEqual((e.type, e.user, e.process), (EventType.INVALID_USER, "admin", "sshd-session"))

    def test_preauth_close(self):
        e = self.one("Sep 28 02:17:41 web sshd[1814]: Connection closed by invalid user pi 198.51.100.23 port 33 "
                     "[preauth]")
        self.assertEqual((e.type, e.user, e.invalid_user), (EventType.PREAUTH_CLOSE, "pi", True))

    def test_iso_timestamps(self):
        cases = {
            "2026-09-28T11:02:11.123456+04:00": datetime(2026, 9, 28, 11, 2, 11, 123456),
            "2026-09-28T11:02:11Z": datetime(2026, 9, 28, 11, 2, 11),
            "2026-09-28T11:02:11.5+0400": datetime(2026, 9, 28, 11, 2, 11, 500000),
            "2026-09-28T11:02:11": datetime(2026, 9, 28, 11, 2, 11),
        }
        for ts, expected in cases.items():
            with self.subTest(ts=ts):
                e = self.one(f"{ts} web sshd[5]: Failed password for root from 192.0.2.1 port 22 ssh2")
                self.assertEqual(e.timestamp, expected)

    def test_sudo_command(self):
        e = self.one("Sep 28 11:11:02 web sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; "
                     "COMMAND=/usr/bin/sh -c echo a ; echo b")
        self.assertEqual(e.type, EventType.SUDO_COMMAND)
        self.assertEqual((e.user, e.run_as, e.command), ("deploy", "root", "/usr/bin/sh -c echo a ; echo b"))

    def test_sudo_failures(self):
        e = self.one("Sep 28 09:21:47 web sudo:      bob : 3 incorrect password attempts ; TTY=pts/2 ; "
                     "PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")
        self.assertEqual((e.type, e.reason), (EventType.SUDO_FAILURE, "3 incorrect password attempts"))
        e = self.one("Sep 28 09:21:47 web sudo[88]: bob : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/bob ; "
                     "USER=root ; COMMAND=/bin/bash")
        self.assertEqual(e.reason, "user NOT in sudoers")

    def test_account_management(self):
        e = self.one("Sep 28 11:12:40 web useradd[3418]: new user: name=svc, UID=0, GID=0, home=/home/svc, "
                     "shell=/bin/bash, from=/dev/pts/1")
        self.assertEqual((e.type, e.user, e.uid), (EventType.USER_CREATED, "svc", 0))
        e = self.one("Sep 28 11:12:58 web usermod[3419]: add 'svc' to group 'sudo'")
        self.assertEqual((e.type, e.user, e.group), (EventType.GROUP_ADD, "svc", "sudo"))
        e = self.one("Sep 28 11:12:58 web gpasswd[3420]: user svc added by root to group docker")
        self.assertEqual((e.user, e.group), ("svc", "docker"))
        e = self.one("Sep 28 11:13:27 web passwd[3421]: pam_unix(passwd:chauthtok): password changed for svc")
        self.assertEqual((e.type, e.user), (EventType.PASSWORD_CHANGE, "svc"))

    def test_shadow_group_line_not_double_counted(self):
        events, _ = parse(["Sep 28 11:12:58 web usermod[1]: add 'svc' to shadow group 'sudo'"])
        self.assertEqual(events, [])

    def test_control_characters_are_escaped(self):
        # a malicious "username" trying to clear the analyst's terminal
        e = self.one("Sep 28 03:40:12 web sshd[1]: Invalid user \x1b[2J\x1b[31mx from 192.0.2.1 port 22")
        self.assertEqual(e.user, "\\x1b[2J\\x1b[31mx")
        self.assertNotIn("\x1b", e.raw)

    def test_noise_ignored_and_garbage_counted(self):
        events, stats = parse([
            "Sep 28 00:17:01 web CRON[1837]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "Sep 28 00:17:01 web systemd-logind[612]: New session 12 of user alice.",
            "this is not a syslog line",
            "",
        ])
        self.assertEqual(events, [])
        self.assertEqual((stats.lines, stats.unrecognised), (3, 1))

    def test_year_rollover(self):
        events, _ = parse([
            "Dec 31 23:59:58 web sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
            "Jan  1 00:00:03 web sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
        ], year=2025)
        self.assertEqual([e.timestamp.year for e in events], [2025, 2026])

    def test_year_inferred_from_current_date(self):
        parser = LogParser(now=datetime(2026, 3, 1))
        events = list(parser.parse_lines(["Dec 30 10:00:00 web sshd[1]: Invalid user a from 192.0.2.1 port 1"]))
        self.assertEqual(events[0].timestamp.year, 2025)

    def test_gzip_and_multiple_files_are_merged_in_time_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "auth.log.2.gz"
            new = Path(tmp) / "auth.log"
            with gzip.open(old, "wt") as fh:
                fh.write("Sep 27 10:00:00 web sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n")
            new.write_text("Sep 28 10:00:00 web sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2\n")
            events = LogParser(year=2026).parse_paths([str(new), str(old)])
        self.assertEqual([e.timestamp.day for e in events], [27, 28])


if __name__ == "__main__":
    unittest.main()
