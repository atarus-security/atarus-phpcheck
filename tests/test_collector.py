import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from phpcheck.collector import SCRIPT, parse_output, results_from_inventory, version_from_php_v

HERE = os.path.dirname(__file__)


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as fh:
        return fh.read()


class ParseCollector(unittest.TestCase):
    def setUp(self):
        self.inv = parse_output(fixture("collector_debian.txt"))
        self.results = results_from_inventory(self.inv, "web-01", "fleet")
        self.by = {(r.sapi, r.path): r for r in self.results}

    def test_inventory(self):
        self.assertTrue(self.inv.complete)
        self.assertEqual(self.inv.reported_host, "web-01")
        self.assertEqual(len(self.inv.bins), 3)
        self.assertEqual(sorted(p.name for p in self.inv.pools), ["api", "www"])

    def test_cli_debian(self):
        r = self.by[("cli", "/usr/bin/php8.2")]
        self.assertEqual((r.version, r.status, r.confidence), ("8.2.28-1~deb12u1", "vulnerable", "medium"))
        self.assertIn("memory_limit=-1 (interim setting from GHSA-w8hw-w9fx-j79w, partial)", r.mitigations_in_place)

    def test_fpm_html_and_pools(self):
        r = self.by[("fpm", "/usr/sbin/php-fpm8.2")]
        self.assertEqual(r.settings["file_uploads"], "Off")
        self.assertEqual(r.settings["memory_limit"], "256M")
        self.assertTrue(any("pool api: pm.max_requests=500" == m for m in r.mitigations_in_place))
        self.assertTrue(any("pool www" in g and "never recycled" in g for g in r.mitigation_gaps))
        self.assertTrue(any("pool api sets memory_limit=-1" == m for m in r.mitigations_in_place))

    def test_eol_cli(self):
        r = self.by[("cli", "/usr/bin/php7.4")]
        self.assertEqual((r.status, r.fixed_in), ("end-of-life-unfixed", "none (EOL)"))

    def test_apache_module(self):
        r = self.by[("apache2handler", "/usr/lib/apache2/modules/libphp8.2.so")]
        self.assertEqual((r.version, r.status), ("8.2.28-1~deb12u1", "vulnerable"))
        self.assertEqual(r.settings["session.upload_progress.enabled"], "On")
        self.assertTrue(any("mods-enabled/php8.2.load" in n for n in r.notes))
        self.assertTrue(any("mod_php" in n for n in r.notes))

    def test_truncated_output(self):
        text = fixture("collector_debian.txt").split("@@MODULE")[0]
        inv = parse_output(text)
        self.assertFalse(inv.complete)
        self.assertEqual(len(inv.bins), 3)

    def test_php_v(self):
        self.assertEqual(version_from_php_v("PHP Warning: x\nPHP 8.3.0RC1 (cli) (built: x)"), "8.3.0RC1")
        self.assertIsNone(version_from_php_v("sh: php: not found"))


@unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
class RunCollector(unittest.TestCase):
    """Runs the real inventory script against a fake php binary. Local only."""

    def test_script_syntax(self):
        p = subprocess.run(["sh", "-n"], input=SCRIPT, text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_finds_fake_php(self):
        d = tempfile.mkdtemp()
        try:
            fake = os.path.join(d, "php8.2")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\n"
                         'case "$1" in\n'
                         '  -v) echo "PHP 8.2.34 (cli) (built: Oct  1 2026 00:00:00) (NTS)" ;;\n'
                         "  -r) printf 'php.version=8.2.34\\nphp.sapi=cli\\nini.memory_limit=128M\\nini.file_uploads=1\\n' ;;\n"
                         "esac\n")
            os.chmod(fake, stat.S_IRWXU)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
            p = subprocess.run(["sh", "-s"], input=SCRIPT, text=True, capture_output=True, env=env, timeout=120)
            inv = parse_output(p.stdout)
            self.assertTrue(inv.complete, p.stderr)
            results = results_from_inventory(inv, "localhost", "local")
            mine = [r for r in results if r.path and r.path.endswith("/php8.2") and r.version == "8.2.34"]
            self.assertEqual(len(mine), 1, [(r.path, r.version) for r in results])
            self.assertEqual(mine[0].status, "vulnerable")
            self.assertEqual(mine[0].settings["file_uploads"], "On")
        finally:
            shutil.rmtree(d)


class HostileInventory(unittest.TestCase):
    """Everything the inventory script prints comes from the target host."""

    def test_control_characters_are_escaped_on_every_line(self):
        text = ("@@PHPCHECK 1\n@@HOST web\x1b[2J01\n@@BIN cli /usr/bin/php\x1b]0;owned\x07\n@@V\n"
                "PHP 8.2.28\x1b[31m (cli) (built: x) (NTS)\n@@INFO\nphp.version=8.2.28\nphp.sapi=cli\n"
                "ini.memory_limit=128M\x07\n@@END\n@@APACHE_CONF /etc/apache2/mods-enabled/php8.2.load\x1b[0m\n@@DONE\n")
        inv = parse_output(text)
        self.assertTrue(inv.complete)
        self.assertEqual(inv.reported_host, "web\\x1b[2J01")
        results = results_from_inventory(inv, "web-01", "fleet")
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.version, "8.2.28")
        self.assertEqual(r.path, "/usr/bin/php\\x1b]0;owned\\x07")
        self.assertEqual(r.settings["memory_limit"], "128M\\x07")
        everything = "\n".join([r.path or "", r.version or ""] + r.notes + r.evidence + list(r.settings.values()) + inv.apache_confs)
        self.assertNotIn("\x1b", everything)
        self.assertNotIn("\x07", everything)

    def test_php_v_with_escape(self):
        self.assertEqual(version_from_php_v("PHP 8.1.2\x1b[0m (cli) (built: x)"), "8.1.2")
        self.assertEqual(version_from_php_v("PHP 8.1.2-1ubuntu2.20 (cli) (built: x)"), "8.1.2-1ubuntu2.20")


if __name__ == "__main__":
    unittest.main()
