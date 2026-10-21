import json
import unittest
from datetime import datetime, timezone

from phpcheck.model import NOT_FOUND, build_result
from phpcheck.report import render_explain, render_json, render_table, render_text, summary


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


if __name__ == "__main__":
    unittest.main()
