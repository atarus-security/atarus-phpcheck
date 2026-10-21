import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from phpcheck import __version__, cli, modes
from phpcheck.model import build_result

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "collector_debian.txt")


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


class ModuleInvocation(unittest.TestCase):
    """`python3 -m phpcheck` is the documented install-free path."""

    def module(self, *args):
        return subprocess.run([sys.executable, "-m", "phpcheck"] + list(args), cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def test_version(self):
        p = self.module("--version")
        self.assertEqual(p.returncode, 0)
        self.assertIn(__version__, p.stdout)

    def test_explain(self):
        p = self.module("--explain")
        self.assertEqual(p.returncode, 0)
        self.assertIn("8.2.35", p.stdout)

    def test_help_lists_modes(self):
        p = self.module("--help")
        for m in ("local", "remote", "image", "fleet"):
            self.assertIn(m, p.stdout)

    def test_no_mode(self):
        self.assertEqual(self.module().returncode, 2)


class ExitCodes(unittest.TestCase):
    def patch_results(self, results):
        return mock.patch.object(cli, "run_mode", return_value=results)

    def test_vulnerable_is_1(self):
        with self.patch_results([build_result("h", "local", "8.2.34")]):
            self.assertEqual(run(["local"])[0], 1)

    def test_eol_is_1(self):
        with self.patch_results([build_result("h", "local", "8.1.33")]):
            self.assertEqual(run(["local"])[0], 1)

    def test_fixed_is_0(self):
        with self.patch_results([build_result("h", "local", "8.5.12")]):
            self.assertEqual(run(["local"])[0], 0)

    def test_unknown(self):
        with self.patch_results([build_result("h", "remote", None)]):
            self.assertEqual(run(["local"])[0], 0)
            self.assertEqual(run(["local", "--fail-on-unknown"])[0], 1)

    def test_json_flag_either_side(self):
        with self.patch_results([build_result("h", "local", "8.5.12")]):
            for argv in (["--json", "local"], ["local", "--json"]):
                code, out = run(argv)
                self.assertEqual(json.loads(out)["mode"], "local")

    def test_explain_appended(self):
        with self.patch_results([build_result("h", "local", "8.5.12")]):
            _, out = run(["local", "--explain"])
        self.assertIn("Mitigation checklist", out)


class Targets(unittest.TestCase):
    def test_file_and_inline(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# web tier\nweb-01\n\nweb-02  # primary\nweb-01\n")
        try:
            self.assertEqual(cli.read_targets([fh.name, "db-01"]), ["web-01", "web-02", "db-01"])
        finally:
            os.unlink(fh.name)


class FakeRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, argv, input_text, timeout):
        self.calls.append((list(argv), input_text))
        for match, resp in self.responses:
            if match(argv):
                return resp
        return (127, "", "not found")


class ImageMode(unittest.TestCase):
    def test_image(self):
        probe = "php.version=8.1.33\nphp.sapi=cli\nini.memory_limit=128M\nini.file_uploads=1\n"
        runner = FakeRunner([
            (lambda a: a[-1] == "-v", (0, "PHP 8.1.33 (cli) (built: x) (NTS)\n", "")),
            (lambda a: "-r" in a, (0, probe, "")),
            (lambda a: a[-1] == "-s", (126, "", "exec: sh: not found")),
        ])
        results = modes.check_image("php:8.1-cli", runner=runner)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual((r.status, r.version, r.settings["file_uploads"]), ("end-of-life-unfixed", "8.1.33", "On"))
        self.assertTrue(any("no usable sh" in n for n in r.notes))
        first = runner.calls[0][0]
        self.assertEqual(first[:5], ["docker", "run", "--rm", "--network", "none"])
        self.assertEqual(first[5:], ["--entrypoint", "php", "php:8.1-cli", "-v"])

    def test_rejects_option_like_image(self):
        with self.assertRaises(ValueError):
            modes.check_image("--privileged", runner=FakeRunner([]))

    def test_no_php_in_image(self):
        runner = FakeRunner([(lambda a: True, (127, "", "exec: \"php\": executable file not found"))])
        r = modes.check_image("alpine", runner=runner, php_only=True)[0]
        self.assertEqual(r.status, "unknown")
        self.assertIn("php -v failed", r.error)


class FleetMode(unittest.TestCase):
    def test_ssh_argv(self):
        argv = modes.ssh_argv("web-01")
        self.assertEqual(argv, ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-T", "--", "web-01", "sh -s"])
        with self.assertRaises(ValueError):
            modes.ssh_argv("-oProxyCommand=x")

    def test_fleet_aggregates(self):
        with open(FIXTURE, encoding="utf-8") as fh:
            out = fh.read()
        runner = FakeRunner([
            (lambda a: "web-01" in a, (0, out, "")),
            (lambda a: "web-02" in a, (255, "", "web-02: Permission denied (publickey).")),
            (lambda a: "web-03" in a, (0, "@@PHPCHECK 1\n@@HOST web-03\n@@DONE\n", "")),
        ])
        results = modes.check_fleet(["web-01", "web-02", "web-03"], runner=runner, parallel=2)
        targets = [r.target for r in results]
        self.assertEqual(targets.count("web-01"), 4)
        bad = [r for r in results if r.target == "web-02"][0]
        self.assertIn("Permission denied", bad.error)
        none = [r for r in results if r.target == "web-03"][0]
        self.assertEqual(none.status, "no-php-found")
        self.assertTrue(all(call[1] and "@@PHPCHECK" in call[1] for call in runner.calls))

    def test_local_uses_same_script(self):
        with open(FIXTURE, encoding="utf-8") as fh:
            out = fh.read()
        runner = FakeRunner([(lambda a: a == ["sh", "-s"], (0, out, ""))])
        results = modes.check_local(runner=runner)
        self.assertEqual({r.target for r in results}, {"localhost"})
        self.assertEqual(len(results), 4)


if __name__ == "__main__":
    unittest.main()
