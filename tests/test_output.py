import json
import unittest
from datetime import datetime, timezone

from phpcheck.model import NOT_FOUND, RunInfo, build_result
from phpcheck.report import render_explain, render_json, render_run_info, render_table, render_text, summary


def sample():
    a = build_result("php:8.1-cli", "image", "8.1.33", sapi="cli", path="/usr/local/bin/php",
                     settings={"memory_limit": "128M", "file_uploads": "On"})
    b = build_result("php:8.2-cli", "image", "8.2.35", sapi="cli")
    c = build_result("web-01", "fleet", "8.2.34", sapi="fpm")
    d = build_result("web-02", "fleet", None)
    d.status = NOT_FOUND
    return [a, b, c, d]


class Table(unittest.TestCase):
    def test_columns_align(self):
        lines = render_table(sample()).splitlines()
        self.assertEqual(lines[0].split(), ["TARGET", "SAPI", "VERSION", "BRANCH", "FIXED", "IN", "STATUS", "CONFIDENCE"])
        col = lines[0].index("STATUS")
        self.assertTrue(lines[1][col:].startswith("end-of-life-unfixed"))
        self.assertTrue(lines[2][col:].startswith("fixed"))
        self.assertTrue(lines[3][col:].startswith("vulnerable"))
        self.assertIn("none (EOL)", lines[1])

    def test_text_report(self):
        out = render_text(sample(), "image")
        self.assertIn("Summary: 4 results across 4 targets: 1 vulnerable, 1 end-of-life-unfixed, 1 fixed, 0 unknown, 1 with no PHP found", out)
        self.assertIn("8.2.35", out)
        self.assertIn("      - memory_limit=128M is finite", out)
        self.assertNotIn("\u2014", out)

    def test_remote_note(self):
        out = render_text([build_result("http://x.test", "remote", None)], "remote")
        self.assertIn("proves nothing", out)

    def test_empty(self):
        self.assertIn("Nothing was checked", render_text([], "fleet"))


class Json(unittest.TestCase):
    def test_shape(self):
        now = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        doc = json.loads(render_json(sample(), "image", now=now))
        self.assertEqual(doc["tool"], "atarus-phpcheck")
        self.assertEqual(doc["generated_at"], "2026-10-21T12:00:00Z")
        self.assertEqual(doc["summary"]["vulnerable"], 1)
        self.assertEqual(doc["summary"]["end-of-life-unfixed"], 1)
        r0 = doc["results"][0]
        for key in ("target", "sapi", "version", "branch", "fixed_in", "status", "confidence",
                    "affected_by", "settings", "mitigations_in_place", "mitigation_gaps", "notes"):
            self.assertIn(key, r0)
        self.assertEqual(r0["affected_by"], ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertNotIn("explain", doc)

    def test_explain_in_json(self):
        doc = json.loads(render_json([], "remote", include_explain=True))
        self.assertIn("note", doc)
        ex = doc["explain"]
        self.assertEqual([a["ghsa"] for a in ex["advisories"]], ["GHSA-w8hw-w9fx-j79w", "GHSA-6wmf-4rv5-p3rp"])
        self.assertEqual(ex["fixed_in"][0], {"branch": "8.5", "fixed_in": "8.5.12",
                                             "cves": ["CVE-2026-109618", "CVE-2026-109619"]})


class Explain(unittest.TestCase):
    def test_contents(self):
        out = render_explain()
        for s in ("8.5.12", "8.4.27", "8.3.36", "8.2.35", "GHSA-w8hw-w9fx-j79w", "GHSA-6wmf-4rv5-p3rp",
                  "end of life", "pm.max_requests", "file_uploads", "OOM", "Patch"):
            self.assertIn(s, out)
        self.assertNotIn("\u2014", out)


class Summary(unittest.TestCase):
    def test_counts(self):
        s = summary(sample())
        self.assertEqual((s["checked"], s["fixed"], s[NOT_FOUND]), (4, 1, 1))


class RunInfoBlock(unittest.TestCase):
    def run_info(self):
        return RunInfo(scope=["*.example.com", "203.0.113.0/24"], confirmation="typed yes on the terminal",
                       out_of_scope=[{"target": "https://cdn.example.net", "host": "cdn.example.net", "ips": ["198.51.100.4"]},
                                     {"target": "web-02", "host": "web-02", "ips": []}])

    def test_text_block(self):
        lines = render_run_info(self.run_info(), "remote")
        self.assertEqual(lines, [
            "Scope: *.example.com, 203.0.113.0/24",
            "Confirmation: typed yes on the terminal",
            "Out of scope, not checked (2):",
            "  https://cdn.example.net -> cdn.example.net (198.51.100.4)",
            "  web-02 -> web-02 (did not resolve)",
        ])

    def test_refused(self):
        lines = render_run_info(RunInfo(scope=["a.example.com"], refused="confirmation not given on the terminal"), "fleet")
        self.assertEqual(lines[1], "Confirmation: not given (confirmation not given on the terminal). Nothing was sent to any target.")

    def test_only_for_scoped_modes(self):
        self.assertEqual(render_run_info(self.run_info(), "local"), [])
        self.assertEqual(render_run_info(None, "remote"), [])
        self.assertNotIn("scope", json.loads(render_json(sample(), "image")))

    def test_json_fields(self):
        doc = json.loads(render_json([], "fleet", run=self.run_info()))
        self.assertEqual(doc["scope"], ["*.example.com", "203.0.113.0/24"])
        self.assertEqual(doc["confirmation"], "typed yes on the terminal")
        self.assertIsNone(doc["refused"])
        self.assertEqual(len(doc["out_of_scope"]), 2)
        # Keys come before the results so a reader sees the authorisation first.
        keys = list(doc)
        self.assertLess(keys.index("scope"), keys.index("results"))

    def test_json_without_run(self):
        doc = json.loads(render_json([], "remote"))
        self.assertIsNone(doc["scope"])
        self.assertIsNone(doc["confirmation"])
        self.assertEqual(doc["out_of_scope"], [])


class NoControlCharacters(unittest.TestCase):
    """Whatever a target put in a result, the rendered text is inert."""

    def hostile(self):
        r = build_result("web-\x1b[31m01", "fleet", "8.2.28\x07", sapi="fpm\x1b[2J", path="/usr/bin/php\u202e")
        r.error = "ssh failed: \x1b]0;owned\x07"
        r.evidence = ["Server: nginx\x1b[2J"]
        r.findings = ["HEAD /info.php\r\n returned 200"]
        r.notes = ["banner\x9b"]
        r.settings = {"memory_limit": "128M\x1b[0m"}
        r.mitigation_gaps = ["gap\x07"]
        r.mitigations_in_place = ["ok\x1b"]
        return r

    def assert_inert(self, text):
        for ch in text:
            if ch == "\n":
                continue
            self.assertGreaterEqual(ord(ch), 0x20, repr(text))
            self.assertNotEqual(ord(ch), 0x7F)
            self.assertNotIn(ch, "\u202e\u2028\u2029")

    def test_text_report(self):
        out = render_text([self.hostile()], "fleet", run=RunInfo(scope=["web-\x1b[31m01"], confirmation="typed yes\x07",
                                                                 out_of_scope=[{"target": "x\x1b", "host": "x\x1b", "ips": ["1.2.3.4\x1b"]}]))
        self.assert_inert(out)
        self.assertIn("\\x1b[31m01", out)
        self.assertIn("\\u202e", out)

    def test_table(self):
        out = render_table([self.hostile()])
        self.assert_inert(out)

    def test_json_is_escaped(self):
        # Raw control characters planted straight into a result (bypassing
        # collection) still cannot reach the output: json.dumps escapes them.
        out = render_json([self.hostile()], "fleet")
        self.assert_inert(out)
        self.assertIn("\\u001b[31m01", out)
        self.assertIn("\\u202e", out)


if __name__ == "__main__":
    unittest.main()
