import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from phpcheck import __version__, cli, modes, scope
from phpcheck.model import build_result
from phpcheck.remote import HttpResponse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "collector_debian.txt")


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(io.StringIO()):
        code = cli.main(argv)
    return code, buf.getvalue()


def run3(argv):
    """Like run(), also returning stderr; a usage error (SystemExit) becomes its code."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


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
        return mock.patch.object(cli, "run_mode", return_value=(results, None))

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
        self.assertEqual(first[:3], ["docker", "run", "--rm"])
        self.assertEqual(first[-4:], ["--entrypoint", "php", "php:8.1-cli", "-v"])
        self.assertEqual(first, modes.docker_argv() + ["--entrypoint", "php", "php:8.1-cli", "-v"])

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


class ImageHardening(unittest.TestCase):
    """Every docker run in image mode: no pull, no network, read-only, no capabilities, non-root."""

    def test_docker_argv(self):
        argv = modes.docker_argv()
        self.assertEqual(argv[:3], ["docker", "run", "--rm"])
        self.assertIn("--pull=never", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(argv[argv.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(argv[argv.index("--user") + 1], "65534:65534")
        self.assertTrue(argv[argv.index("--tmpfs") + 1].startswith("/tmp:"))
        self.assertNotIn("--user", modes.docker_argv(user=None))
        self.assertEqual(modes.docker_argv("/usr/local/bin/podman")[0], "/usr/local/bin/podman")

    def test_every_run_is_hardened(self):
        probe = "php.version=8.2.35\nphp.sapi=cli\nini.memory_limit=128M\n"
        runner = FakeRunner([
            (lambda a: a[-1] == "-v", (0, "PHP 8.2.35 (cli) (built: x) (NTS)\n", "")),
            (lambda a: "-r" in a, (0, probe, "")),
            (lambda a: a[-1] == "-s", (0, "@@PHPCHECK 1\n@@HOST img\n@@DONE\n", "")),
        ])
        modes.check_image("php:8.2-cli", runner=runner)
        self.assertEqual(len(runner.calls), 3)
        for argv, _ in runner.calls:
            self.assertEqual(argv[:len(modes.docker_argv())], modes.docker_argv(), argv)
        self.assertIn("-i", runner.calls[2][0])

    def test_missing_image_is_not_pulled(self):
        err = ("docker: Error response from daemon: No such image: php:8.2-cli.\n"
               "See 'docker run --help'.\n")
        runner = FakeRunner([(lambda a: True, (125, "", err))])
        r = modes.check_image("php:8.2-cli", runner=runner, php_only=True)[0]
        self.assertEqual(len(runner.calls), 1, "a docker-level failure is not retried as another user")
        self.assertIn("never pulls", r.error)
        self.assertIn("docker pull php:8.2-cli", r.error)
        self.assertIn("No such image", r.error)
        self.assertNotIn("docker run --help", r.error)

    def test_falls_back_to_image_user_when_nobody_cannot_run_php(self):
        probe = "php.version=8.3.36\nphp.sapi=cli\nini.memory_limit=128M\n"

        def as_nobody(a):
            return "--user" in a

        runner = FakeRunner([
            (lambda a: as_nobody(a) and a[-1] == "-v", (126, "", "exec /usr/local/bin/php: permission denied")),
            (lambda a: not as_nobody(a) and a[-1] == "-v", (0, "PHP 8.3.36 (cli) (built: x) (NTS)\n", "")),
            (lambda a: not as_nobody(a) and "-r" in a, (0, probe, "")),
        ])
        r = modes.check_image("locked:latest", runner=runner, php_only=True)[0]
        self.assertEqual((r.status, r.version), ("fixed", "8.3.36"))
        self.assertTrue(any("could not run as uid 65534" in n and "default user" in n for n in r.notes), r.notes)
        self.assertEqual(len(runner.calls), 3)
        for argv, _ in runner.calls[1:]:
            self.assertNotIn("--user", argv)
            self.assertIn("--pull=never", argv)
            self.assertIn("--read-only", argv)

    def test_php_missing_in_image_is_not_retried(self):
        runner = FakeRunner([(lambda a: True, (127, "", 'exec: "php": executable file not found in $PATH'))])
        r = modes.check_image("alpine", runner=runner, php_only=True)[0]
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("php -v failed", r.error)

    def test_docker_stderr_is_made_safe(self):
        runner = FakeRunner([(lambda a: True, (1, "", "boom\x1b[2J\x1b]0;x\x07"))])
        r = modes.check_image("x:1", runner=runner, php_only=True)[0]
        self.assertNotIn("\x1b", r.error)
        self.assertIn("\\x1b", r.error)


def ok_response(url, method, headers=()):
    return HttpResponse(url=url, method=method, status=200, headers=list(headers))


class ScopeGate(unittest.TestCase):
    """remote and fleet need --scope and the typed word; nothing is sent before the gate opens."""

    RESOLVE = {"www.example.com": ["203.0.113.10"], "cdn.example.net": ["198.51.100.4"],
               "web-01": ["203.0.113.21"], "web-02": [], "127.0.0.1": ["127.0.0.1"]}

    def setUp(self):
        self.sent = []
        patches = [
            mock.patch.object(cli, "resolve_host", lambda h: list(self.RESOLVE.get(h, []))),
            mock.patch.object(cli, "tty_available", lambda: True),
            mock.patch("phpcheck.remote.http_fetch", self.fetch),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def fetch(self, url, method, **kw):
        self.sent.append((method, url))
        hdrs = [("X-Powered-By", "PHP/8.2.28"), ("Server", "nginx")]
        if "baseline" in url or "info" in url:
            return HttpResponse(url=url, method=method, status=404, headers=[])
        return ok_response(url, method, hdrs)

    def answer(self, text):
        return mock.patch.object(cli, "read_tty_line", lambda prompt: text)

    # usage errors, before anything runs

    def test_remote_requires_scope(self):
        code, _, err = run3(["remote", "https://www.example.com"])
        self.assertEqual(code, 2)
        self.assertIn("requires --scope", err)
        self.assertEqual(self.sent, [])

    def test_fleet_requires_scope(self):
        code, _, err = run3(["fleet", "web-01"])
        self.assertEqual(code, 2)
        self.assertIn("requires --scope", err)

    def test_yes_needs_scope(self):
        code, _, err = run3(["remote", "https://www.example.com", "--yes"])
        self.assertEqual(code, 2)
        self.assertIn("--yes is only accepted together with --scope", err)
        self.assertEqual(self.sent, [])

    def test_bad_scope(self):
        code, _, err = run3(["remote", "https://www.example.com", "--scope", "not a host"])
        self.assertEqual(code, 2)
        self.assertIn("--scope:", err)

    def test_no_terminal_and_no_yes(self):
        with mock.patch.object(cli, "tty_available", lambda: False):
            code, _, err = run3(["remote", "https://www.example.com", "--scope", "www.example.com"])
        self.assertEqual(code, 2)
        self.assertIn("needs a terminal", err)
        self.assertEqual(self.sent, [])

    def test_local_and_image_need_no_scope(self):
        with mock.patch.object(cli, "run_mode", return_value=([build_result("h", "local", "8.5.12")], None)):
            self.assertEqual(run3(["local"])[0], 0)
            self.assertEqual(run3(["image", "php:8.2-cli"])[0], 0)

    # the gate itself

    def test_typed_yes_opens_the_gate(self):
        with self.answer("yes"):
            code, out, err = run3(["remote", "https://www.example.com", "--scope", "*.example.com", "--delay", "0"])
        self.assertEqual(code, 1, out)
        self.assertTrue(self.sent)
        self.assertTrue(all("www.example.com" in u for _, u in self.sent))
        self.assertIn("Remote checks requested", err)
        self.assertIn("Scope: *.example.com", err)
        self.assertIn("https://www.example.com -> www.example.com (203.0.113.10)", err)
        self.assertIn("Confirmation: typed yes on the terminal", out)
        self.assertIn("Scope: *.example.com", out)

    def test_wrong_word_refuses_and_sends_nothing(self):
        for word in ("no", "y", "YES please", ""):
            self.sent = []
            with self.answer(word):
                code, out, err = run3(["remote", "https://www.example.com", "--scope", "*.example.com", "--json"])
            self.assertEqual(code, 2, word)
            self.assertEqual(self.sent, [], word)
            self.assertIn("nothing was checked: confirmation not given on the terminal", err)
            doc = json.loads(out)
            self.assertEqual(doc["refused"], "confirmation not given on the terminal")
            self.assertIsNone(doc["confirmation"])
            self.assertEqual(doc["results"][0]["error"], "not checked: confirmation not given on the terminal")

    def test_eof_on_terminal_refuses(self):
        with self.answer(None):
            code, out, _ = run3(["remote", "https://www.example.com", "--scope", "*.example.com"])
        self.assertEqual(code, 2)
        self.assertEqual(self.sent, [])
        self.assertIn("Confirmation: not given (no terminal to confirm on", out)

    def test_yes_flag_is_recorded(self):
        code, out, err = run3(["remote", "https://www.example.com", "--scope", "203.0.113.0/24", "--yes", "--json", "--delay", "0"])
        self.assertEqual(code, 1)
        self.assertIn("--yes given", err)
        doc = json.loads(out)
        self.assertEqual(doc["confirmation"], "--yes flag (no terminal confirmation)")
        self.assertEqual(doc["scope"], ["203.0.113.0/24"])
        self.assertEqual(doc["out_of_scope"], [])
        self.assertIsNone(doc["refused"])

    def test_out_of_scope_target_is_refused_not_warned(self):
        code, out, err = run3(["remote", "https://www.example.com", "https://cdn.example.net", "web-02",
                               "--scope", "*.example.com", "--yes", "--json", "--delay", "0"])
        self.assertTrue(all("www.example.com" in u for _, u in self.sent), self.sent)
        self.assertFalse(any("cdn.example.net" in u or "web-02" in u for _, u in self.sent))
        doc = json.loads(out)
        self.assertEqual(doc["out_of_scope"], [
            {"target": "https://cdn.example.net", "host": "cdn.example.net", "ips": ["198.51.100.4"]},
            {"target": "web-02", "host": "web-02", "ips": []},
        ])
        by = {r["target"]: r for r in doc["results"]}
        self.assertEqual(by["https://cdn.example.net"]["error"], "not checked: outside --scope (cdn.example.net: 198.51.100.4)")
        self.assertEqual(by["web-02"]["error"], "not checked: outside --scope (web-02: did not resolve)")
        self.assertEqual(by["web-02"]["status"], "unknown")
        self.assertIn("Out of scope, not checked (2):", err)
        self.assertIn("https://cdn.example.net -> cdn.example.net (198.51.100.4)", err)

    def test_nothing_in_scope_refuses(self):
        code, out, err = run3(["remote", "https://cdn.example.net", "--scope", "*.example.com", "--yes"])
        self.assertEqual(code, 2)
        self.assertEqual(self.sent, [])
        self.assertIn("nothing was checked: no target inside --scope", err)

    def test_text_report_carries_scope_block(self):
        with self.answer("yes"):
            code, out, _ = run3(["remote", "https://www.example.com", "https://cdn.example.net",
                                 "--scope", "www.example.com", "--delay", "0"])
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("atarus-phpcheck"))
        self.assertEqual(lines[1], "Scope: www.example.com")
        self.assertEqual(lines[2], "Confirmation: typed yes on the terminal")
        self.assertEqual(lines[3], "Out of scope, not checked (1):")
        self.assertEqual(lines[4], "  https://cdn.example.net -> cdn.example.net (198.51.100.4)")

    def fake_fleet(self, inventory):
        """Stands in for modes.check_fleet (imported by the CLI at call time), so no ssh runs."""
        contacted = []
        real_check_fleet = modes.check_fleet

        def check_fleet(hosts, **kw):
            contacted.extend(hosts)
            runner = FakeRunner([(lambda a: True, (0, inventory, ""))])
            return real_check_fleet(hosts, runner=runner, **kw)

        return contacted, mock.patch.object(modes, "check_fleet", check_fleet)

    def test_fleet_gate_by_alias_name(self):
        with open(FIXTURE, encoding="utf-8") as fh:
            inventory = fh.read()
        contacted, patch = self.fake_fleet(inventory)
        with patch, self.answer("yes"):
            code, out, err = run3(["fleet", "web-01", "web-02", "cdn.example.net", "--scope", "web-01,web-02"])
        self.assertEqual(sorted(contacted), ["web-01", "web-02"])
        self.assertIn("web-02 -> web-02 (listed by name, not resolved)", err)
        self.assertIn("cdn.example.net -> cdn.example.net (198.51.100.4)", err)
        self.assertIn("not checked: outside --scope (cdn.example.net: 198.51.100.4)", out)
        self.assertEqual(code, 1, "web-01's fixture has vulnerable installs")

    def test_fleet_prompt_wording(self):
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return "yes"

        contacted, patch = self.fake_fleet("@@PHPCHECK 1\n@@HOST web-01\n@@DONE\n")
        with mock.patch.object(cli, "read_tty_line", ask), patch:
            code, out, _ = run3(["fleet", "web-01", "--scope", "203.0.113.0/24"])
        self.assertEqual(prompts, ["Type yes to open SSH sessions to the 1 target(s) listed above (scope: 203.0.113.0/24): "])
        self.assertEqual(contacted, ["web-01"])
        self.assertEqual(code, 0)
        self.assertIn("no-php-found", out)

    def test_fleet_refused_runs_no_ssh(self):
        contacted, patch = self.fake_fleet("")
        with patch, self.answer("nope"):
            code, out, _ = run3(["fleet", "web-01", "--scope", "203.0.113.0/24"])
        self.assertEqual(code, 2)
        self.assertEqual(contacted, [])
        self.assertIn("not checked: confirmation not given on the terminal", out)

    def test_remote_prompt_wording(self):
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return "no"

        with mock.patch.object(cli, "read_tty_line", ask):
            run3(["remote", "https://www.example.com", "--scope", "*.example.com"])
        self.assertEqual(prompts, ["Type yes to send requests to the 1 target(s) listed above (scope: *.example.com): "])

    def test_gate_output_is_made_safe(self):
        hostile = "https://www.example.com/\x1b[2J"
        with self.answer("yes"):
            _, out, err = run3(["remote", hostile, "--scope", "*.example.com", "--delay", "0"])
        self.assertNotIn("\x1b", err)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b[2J", err)


if __name__ == "__main__":
    unittest.main()
