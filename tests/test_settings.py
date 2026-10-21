import unittest

from phpcheck.settings import (PROBE_PHP, assess_settings, merge_pools, parse_phpinfo,
                               parse_pool_file, parse_probe, sapi_kind)

TEXT_PHPINFO = """phpinfo()
PHP Version => 8.4.26

System => Linux web 6.1.0
Server API => FPM/FastCGI
Loaded Configuration File => /etc/php/8.4/fpm/php.ini
file_uploads => On => On
max_file_uploads => 20 => 20
memory_limit => 128M => 128M
post_max_size => 8M => 8M
session.upload_progress.enabled => On => On
Server API (SAPI) Abstraction Layer => people
"""

HTML_PHPINFO = """<h1 class="p">PHP Version 8.5.11</h1>
<tr><td class="e">Server API </td><td class="v">CGI/FastCGI </td></tr>
<tr><td class="e">fatal_error_backtraces</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">upload_max_filesize</td><td class="v">2M</td><td class="v">2M</td></tr>
"""


class Probe(unittest.TestCase):
    def test_probe_is_read_only_php(self):
        for word in ("ini_set", "file_put", "exec", "system", "fopen", "unlink"):
            self.assertNotIn(word, PROBE_PHP)

    def test_parse_probe(self):
        d = parse_probe("noise\nphp.version=8.3.1\nphp.sapi=cli\nphp.ini_loaded=\n"
                        "ini.file_uploads=\nini.memory_limit=-1\nini.session.upload_progress.enabled=1\n"
                        "ini.unrelated=1\n")
        self.assertEqual((d.version, d.sapi, d.ini_loaded), ("8.3.1", "cli", None))
        self.assertEqual(d.settings, {"file_uploads": "Off", "memory_limit": "-1",
                                      "session.upload_progress.enabled": "On"})


class PhpInfo(unittest.TestCase):
    def test_text(self):
        d = parse_phpinfo(TEXT_PHPINFO)
        self.assertEqual((d.version, d.sapi, d.ini_loaded), ("8.4.26", "FPM/FastCGI", "/etc/php/8.4/fpm/php.ini"))
        self.assertEqual(d.settings["file_uploads"], "On")
        self.assertEqual(d.settings["memory_limit"], "128M")

    def test_html(self):
        d = parse_phpinfo(HTML_PHPINFO)
        self.assertEqual((d.version, d.sapi), ("8.5.11", "CGI/FastCGI"))
        self.assertEqual(d.settings, {"fatal_error_backtraces": "On", "upload_max_filesize": "2M"})

    def test_sapi_kind(self):
        self.assertEqual(sapi_kind("FPM/FastCGI", "x"), "fpm")
        self.assertEqual(sapi_kind("Apache 2.0 Handler", "x"), "apache2handler")
        self.assertEqual(sapi_kind(None, "cli"), "cli")
        self.assertEqual(sapi_kind("LiteSpeed V8.1", "x"), "lsapi")


class Pools(unittest.TestCase):
    def test_parse_and_merge(self):
        text = "[global]\npid = /run/fpm.pid\n[www]\npm = dynamic\n;pm.max_requests = 500\n"
        text2 = "[www]\npm.max_requests = 200 ; recycle\nphp_admin_value[memory_limit] = 512M\n"
        pools = merge_pools(parse_pool_file("/etc/php-fpm.d/a.conf", text) +
                            parse_pool_file("/etc/php-fpm.d/b.conf", text2))
        self.assertEqual(len(pools), 1)
        p = pools[0]
        self.assertEqual((p.name, p.pm, p.max_requests), ("www", "dynamic", "200"))
        self.assertEqual(p.overrides, {"memory_limit": "512M"})
        self.assertTrue(p.recycles)


class AssessSettings(unittest.TestCase):
    def test_unpatched_defaults(self):
        in_place, gaps = assess_settings({"memory_limit": "128M", "file_uploads": "On",
                                          "session.upload_progress.enabled": "On"}, "8.3")
        self.assertEqual(in_place, [])
        self.assertEqual(len(gaps), 3)

    def test_patched_does_not_push_memory_limit(self):
        _, gaps = assess_settings({"memory_limit": "128M"}, "8.3", patched=True)
        self.assertEqual(gaps, [])

    def test_hardened(self):
        pools = parse_pool_file("/p.conf", "[www]\npm.max_requests = 1\n")
        in_place, gaps = assess_settings({"memory_limit": "-1", "file_uploads": "Off",
                                          "session.upload_progress.enabled": "Off",
                                          "fatal_error_backtraces": "Off"}, "8.5", pools)
        self.assertEqual(gaps, [])
        self.assertEqual(len(in_place), 5)

    def test_backtraces_only_matter_on_85(self):
        _, gaps = assess_settings({"fatal_error_backtraces": "On"}, "8.4")
        self.assertEqual(gaps, [])
        _, gaps = assess_settings({"fatal_error_backtraces": "On"}, "8.5")
        self.assertEqual(len(gaps), 1)

    def test_pool_without_recycling(self):
        pools = parse_pool_file("/p.conf", "[www]\npm = ondemand\n")
        _, gaps = assess_settings({}, "8.2", pools)
        self.assertIn("never recycled", gaps[0])


if __name__ == "__main__":
    unittest.main()
