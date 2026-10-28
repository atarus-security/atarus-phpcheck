import os
import tempfile
import unittest
from unittest import mock

from phpcheck import scope
from phpcheck.scope import Scope, is_valid_host, is_valid_name, read_tty_line, safe_text, target_hostname, tty_available


class SafeText(unittest.TestCase):
    """Text from a target must never carry a control character to the terminal."""

    def assert_inert(self, text):
        for ch in text:
            self.assertGreaterEqual(ord(ch), 0x20, repr(text))
            self.assertNotEqual(ord(ch), 0x7F, repr(text))

    def test_plain_text_unchanged(self):
        self.assertEqual(safe_text("PHP/8.2.28 (Debian)"), "PHP/8.2.28 (Debian)")

    def test_escape_sequence_made_visible(self):
        out = safe_text("PHP/8.2.0\x1b[2J\x1b]0;owned\x07")
        self.assertEqual(out, "PHP/8.2.0\\x1b[2J\\x1b]0;owned\\x07")
        self.assert_inert(out)

    def test_line_breaks_become_spaces(self):
        self.assertEqual(safe_text("a\r\nb\tc\x0bd\x0ce"), "a b c d e")

    def test_del_and_c1(self):
        out = safe_text("x\x7fy\x9bz")
        self.assertEqual(out, "x\\x7fy\\x9bz")
        self.assert_inert(out)

    def test_bidi_override_and_zero_width(self):
        out = safe_text("8.2.35‮53.1.8​")
        self.assertEqual(out, "8.2.35\\u202e53.1.8\\u200b")

    def test_unicode_separators(self):
        self.assertEqual(safe_text("a b c"), "a b c")

    def test_runs_of_spaces_collapse_and_strip(self):
        self.assertEqual(safe_text("  a   b  "), "a b")

    def test_limit(self):
        self.assertEqual(safe_text("abcdefghij", 5), "abcde [cut]")
        self.assertEqual(safe_text("abc", 5), "abc")

    def test_non_string_and_none(self):
        self.assertEqual(safe_text(None), "")
        self.assertEqual(safe_text(404), "404")

    def test_everything_below_space(self):
        out = safe_text("".join(chr(i) for i in range(0x20)))
        self.assert_inert(out)
        self.assertIn("\\x00", out)
        self.assertIn("\\x1b", out)


class Names(unittest.TestCase):
    def test_fqdn(self):
        self.assertTrue(is_valid_name("app.example.com"))
        self.assertTrue(is_valid_name("xn--bcher-kva.example"))
        self.assertFalse(is_valid_name("web-01"))
        self.assertFalse(is_valid_name("-bad.example.com"))
        self.assertFalse(is_valid_name("a" * 254))

    def test_host_allows_single_label(self):
        self.assertTrue(is_valid_host("web-01"))
        self.assertTrue(is_valid_host("app.example.com"))
        self.assertFalse(is_valid_host("web 01"))
        self.assertFalse(is_valid_host("-x"))
        self.assertFalse(is_valid_host(""))


class ScopeEntries(unittest.TestCase):
    def test_four_forms(self):
        s = Scope(["app.example.com", "*.example.org", "203.0.113.7", "203.0.113.0/24", "web-01"])
        self.assertEqual(s.entries, ["app.example.com", "*.example.org", "203.0.113.7", "203.0.113.0/24", "web-01"])
        self.assertEqual(s.describe(), "app.example.com, *.example.org, 203.0.113.7, 203.0.113.0/24, web-01")

    def test_urls_and_ssh_forms_reduce_to_the_host(self):
        s = Scope(["https://App.Example.com:8443/path", "deploy@web-02", "ssh://root@web-03:2222"])
        self.assertEqual(sorted(s.hosts), ["app.example.com", "web-02", "web-03"])

    def test_comma_list_and_file(self):
        s = Scope.from_option(" app.example.com , 203.0.113.0/24 ")
        self.assertEqual(s.entries, ["app.example.com", "203.0.113.0/24"])
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# production\n*.example.com\n\n198.51.100.0/25  # dmz\nweb-01\n")
        try:
            s = Scope.from_option(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(s.entries, ["*.example.com", "198.51.100.0/25", "web-01"])

    def test_empty_and_invalid(self):
        for bad in ("", "   ", ","):
            with self.assertRaises(ValueError):
                Scope.from_option(bad)
        with self.assertRaises(ValueError):
            Scope(["not a host"])
        with self.assertRaises(ValueError):
            Scope(["*.single"])
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# only comments\n\n")
        try:
            with self.assertRaises(ValueError):
                Scope.from_option(fh.name)
        finally:
            os.unlink(fh.name)

    def test_covers_by_name(self):
        s = Scope(["app.example.com", "*.example.org", "web-01"])
        self.assertTrue(s.covers("app.example.com"))
        self.assertTrue(s.covers("APP.example.com."))
        self.assertTrue(s.covers("web-01"))
        self.assertTrue(s.covers("a.b.example.org"))
        self.assertFalse(s.covers("example.org"), "the wildcard does not cover the apex")
        self.assertFalse(s.covers("notexample.org"))
        self.assertFalse(s.covers("www.example.com"))
        self.assertFalse(s.covers(""))

    def test_covers_by_address(self):
        s = Scope(["203.0.113.0/24", "2001:db8::/32"])
        self.assertTrue(s.covers("anything.example", ["203.0.113.9"]))
        self.assertTrue(s.covers("v6.example", ["2001:db8::1"]))
        self.assertTrue(s.covers("203.0.113.9", ["203.0.113.9"]))
        self.assertFalse(s.covers("mixed.example", ["203.0.113.9", "198.51.100.1"]), "every address must be inside")
        self.assertFalse(s.covers("unresolved.example", []))
        self.assertFalse(s.covers("garbage.example", ["not-an-ip"]))

    def test_single_address_entry(self):
        s = Scope(["203.0.113.7"])
        self.assertEqual(s.entries, ["203.0.113.7"])
        self.assertTrue(s.covers("h", ["203.0.113.7"]))
        self.assertFalse(s.covers("h", ["203.0.113.8"]))


class TargetHostname(unittest.TestCase):
    def test_forms(self):
        cases = {
            "https://www.Example.com/path": "www.example.com",
            "http://127.0.0.1:8089": "127.0.0.1",
            "www.example.com": "www.example.com",
            "www.example.com:8443": "www.example.com",
            "web-01": "web-01",
            "deploy@web-01": "web-01",
            "ssh://deploy@web-01:2222": "web-01",
            "[2001:db8::1]": "2001:db8::1",
            "2001:db8::1": "2001:db8::1",
            "https://[2001:db8::1]:8443/": "2001:db8::1",
            "": "",
        }
        for raw, want in cases.items():
            self.assertEqual(target_hostname(raw), want, raw)


class Terminal(unittest.TestCase):
    """The confirmation comes from the controlling terminal and nowhere else."""

    def test_no_terminal(self):
        with mock.patch.object(scope, "TTY_PATH", "/nonexistent/tty"):
            self.assertFalse(tty_available())
            self.assertIsNone(read_tty_line("Type yes: "))

    def test_eof_is_none(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
            path = fh.name
        try:
            with mock.patch.object(scope, "TTY_PATH", path):
                self.assertTrue(tty_available())
                self.assertIsNone(read_tty_line("Type yes: "))
            with open(path) as fh:
                self.assertEqual(fh.read(), "Type yes: ")
        finally:
            os.unlink(path)

    def test_reads_one_line(self):
        # A file stands in for the terminal. With an empty prompt nothing is
        # written over the answer, so readline returns the first line only.
        with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
            fh.write("  yes  \nsecond\n")
            path = fh.name
        try:
            with mock.patch.object(scope, "TTY_PATH", path):
                self.assertEqual(read_tty_line(""), "yes")
        finally:
            os.unlink(path)

    def test_stdin_is_not_consulted(self):
        import io
        with mock.patch.object(scope, "TTY_PATH", "/nonexistent/tty"), mock.patch("sys.stdin", io.StringIO("yes\n")):
            self.assertIsNone(read_tty_line("Type yes: "))


if __name__ == "__main__":
    unittest.main()
