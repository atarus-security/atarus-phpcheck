import unittest

from phpcheck.remote import HttpResponse, Pacer, analyze_headers, check_target, normalise_target


class AnalyzeHeaders(unittest.TestCase):
    def test_x_powered_by(self):
        a = analyze_headers([("X-Powered-By", "PHP/8.2.28")])
        self.assertEqual([v for v, _ in a.versions], ["8.2.28"])
        self.assertTrue(a.php_present)

    def test_case_and_multiple_values(self):
        a = analyze_headers([("x-powered-by", "PHP/7.4.33, ASP.NET")])
        self.assertEqual([v for v, _ in a.versions], ["7.4.33"])

    def test_server_header(self):
        a = analyze_headers([("Server", "Apache/2.4.57 (Debian) PHP/8.1.2-1ubuntu2.20 OpenSSL/3.0.2")])
        self.assertEqual([v for v, _ in a.versions], ["8.1.2-1ubuntu2.20"])

    def test_server_without_php(self):
        a = analyze_headers([("Server", "nginx")])
        self.assertEqual(a.versions, [])
        self.assertFalse(a.php_present)
        self.assertEqual(a.evidence, ["Server: nginx"])

    def test_bare_php(self):
        a = analyze_headers([("X-Powered-By", "PHP")])
        self.assertEqual(a.versions, [])
        self.assertTrue(a.php_present)

    def test_phpsessid_cookie(self):
        a = analyze_headers([("Set-Cookie", "PHPSESSID=abc; path=/"), ("Set-Cookie", "other=1")])
        self.assertTrue(a.php_present)
        self.assertEqual(len(a.evidence), 1)
        self.assertIn("PHPSESSID", a.evidence[0])

    def test_not_php(self):
        a = analyze_headers([("X-Powered-By", "Express"), ("Set-Cookie", "sid=1")])
        self.assertFalse(a.php_present)
        self.assertEqual(a.versions, [])

    def test_rc_in_header(self):
        a = analyze_headers([("X-Powered-By", "PHP/8.5.12RC1")])
        self.assertEqual([v for v, _ in a.versions], ["8.5.12RC1"])


class FakeSite:
    """Records every request; never touches the network."""

    def __init__(self, routes, down=()):
        self.routes = routes
        self.down = down
        self.calls = []

    def __call__(self, url, method):
        self.calls.append((method, url))
        for prefix in self.down:
            if url.startswith(prefix):
                return HttpResponse(url, method, error="ConnectionRefusedError: refused")
        path = "/" + url.split("://", 1)[1].split("/", 1)[1] if url.count("/") > 2 else "/"
        status, headers = self.routes.get(path, self.routes.get("*", (404, [])))
        return HttpResponse(url, method, status, list(headers))


def pacer():
    return Pacer(0, sleep=lambda s: None)


class CheckTarget(unittest.TestCase):
    def test_banner_vulnerable(self):
        site = FakeSite({"/": (200, [("X-Powered-By", "PHP/8.3.14"), ("Set-Cookie", "PHPSESSID=1")])})
        r = check_target("http://example.test", site, pacer(), baseline_name="b.php")
        self.assertEqual((r.status, r.version, r.confidence, r.fixed_in), ("vulnerable", "8.3.14", "medium", "8.3.36"))
        self.assertEqual(r.findings, [])
        methods = {m for m, _ in site.calls}
        self.assertEqual(methods, {"HEAD", "GET"})
        # Every leak path is HEAD only.
        for m, u in site.calls:
            if u.endswith(".php"):
                self.assertEqual(m, "HEAD")

    def test_no_banner_is_unknown(self):
        site = FakeSite({"/": (200, [("Server", "nginx")])})
        r = check_target("http://example.test", site, pacer(), probe_paths=False)
        self.assertEqual((r.status, r.confidence), ("unknown", "none"))
        self.assertTrue(any("proves nothing" in n for n in r.notes))
        self.assertEqual(len(site.calls), 2)

    def test_php_without_version(self):
        site = FakeSite({"/": (200, [("Set-Cookie", "PHPSESSID=1")])})
        r = check_target("http://example.test", site, pacer(), probe_paths=False)
        self.assertEqual((r.status, r.confidence), ("unknown", "low"))

    def test_phpinfo_presence_reported(self):
        site = FakeSite({"/": (200, []), "/info.php": (200, [("X-Powered-By", "PHP/8.1.31")])})
        r = check_target("http://example.test", site, pacer(), baseline_name="b.php")
        self.assertEqual(r.status, "end-of-life-unfixed")
        self.assertEqual(len(r.findings), 1)
        self.assertIn("/info.php", r.findings[0])
        self.assertIn("not fetched", r.findings[0])

    def test_soft_404_inconclusive(self):
        site = FakeSite({"*": (200, [])})
        r = check_target("http://example.test", site, pacer(), baseline_name="b.php")
        self.assertTrue(r.findings)
        self.assertTrue(all("inconclusive" in f for f in r.findings))

    def test_bare_host_falls_back_to_http(self):
        site = FakeSite({"/": (200, [("X-Powered-By", "PHP/8.4.27")])}, down=("https://",))
        r = check_target("example.test", site, pacer(), probe_paths=False)
        self.assertEqual(r.target, "http://example.test")
        self.assertEqual(r.status, "fixed")

    def test_unreachable(self):
        site = FakeSite({}, down=("http",))
        r = check_target("example.test", site, pacer())
        self.assertEqual(r.status, "unknown")
        self.assertIn("refused", r.error)

    def test_same_host_redirect_followed_other_host_not(self):
        routes = {"/": (301, [("Location", "/en/")]), "/en/": (200, [("X-Powered-By", "PHP/8.2.35")])}
        r = check_target("http://example.test", FakeSite(routes), pacer(), probe_paths=False)
        self.assertEqual(r.status, "fixed")
        routes = {"/": (302, [("Location", "https://elsewhere.test/")])}
        site = FakeSite(routes)
        r = check_target("http://example.test", site, pacer(), probe_paths=False)
        self.assertFalse(any("elsewhere" in u for _, u in site.calls))
        self.assertTrue(any("not followed" in n for n in r.notes))

    def test_worst_of_several_versions(self):
        site = FakeSite({"/": (200, [("X-Powered-By", "PHP/8.4.27")]), "/info.php": (403, [("X-Powered-By", "PHP/8.2.20")])})
        r = check_target("http://example.test", site, pacer(), baseline_name="b.php")
        self.assertEqual((r.version, r.status), ("8.2.20", "vulnerable"))
        self.assertTrue(any("several" in n for n in r.notes))


class PacerTest(unittest.TestCase):
    def test_delay_between_requests(self):
        t = [0.0]
        slept = []
        p = Pacer(1.0, sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s)), clock=lambda: t[0])
        p.wait()
        p.wait()
        p.wait()
        self.assertEqual(slept, [1.0, 1.0])


class Normalise(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(normalise_target("example.test"), ["https://example.test", "http://example.test"])
        self.assertEqual(normalise_target("http://example.test:8080/app"), ["http://example.test:8080/app"])


class HostileHeaders(unittest.TestCase):
    """Header values are target text: control characters never reach a result as they are."""

    def test_escape_in_banner(self):
        a = analyze_headers([("X-Powered-By", "PHP/8.2.28\x1b[2J\x1b]0;owned\x07"), ("Server", "nginx\r\nX-Fake: 1")])
        self.assertEqual([v for v, _ in a.versions], ["8.2.28"])
        joined = " | ".join(a.evidence) + " | ".join(w for _, w in a.versions)
        self.assertNotIn("\x1b", joined)
        self.assertNotIn("\r", joined)
        self.assertIn("\\x1b[2J", joined)
        self.assertIn("nginx X-Fake: 1", joined)

    def test_long_header_is_cut(self):
        a = analyze_headers([("Server", "A" * 1000)])
        self.assertTrue(a.evidence[0].endswith("[cut]"))
        self.assertLess(len(a.evidence[0]), 400)

    def test_cookie_name_with_control_characters(self):
        a = analyze_headers([("Set-Cookie", "PHPSESSID\x1b[2J=abc; path=/")])
        self.assertFalse(a.php_present, "a cookie name with an escape in it is not a PHP session cookie")
        a = analyze_headers([("Set-Cookie", "PHPSESSID=abc\x07; path=/")])
        self.assertTrue(a.php_present)
        self.assertNotIn("\x07", " ".join(a.evidence))

    def test_redirect_location_is_made_safe(self):
        responses = {
            ("HEAD", "https://h.test"): HttpResponse("https://h.test", "HEAD", 302, [("Location", "https://evil.test/\x1b[2J")]),
        }

        def fetch(url, method):
            return responses.get((method, url), HttpResponse(url, method, 200, [("X-Powered-By", "PHP/8.3.1")]))

        r = check_target("https://h.test", fetch, Pacer(0, sleep=lambda s: None), probe_paths=False)
        note = next(n for n in r.notes if "another host" in n)
        self.assertNotIn("\x1b", note)
        self.assertIn("evil.test/\\x1b[2J", note)
        self.assertNotIn("\x1b", "\n".join(r.evidence + r.notes + r.findings))


if __name__ == "__main__":
    unittest.main()
