# Changelog

All notable changes to this project are listed here. Versions follow semantic versioning.

## 0.2.0 (unreleased, refresh-2026-10)

### Security

- **remote and fleet need `--scope` and a typed confirmation.**

  What was wrong: `python3 -m phpcheck remote hosts.txt` sent requests to every host in the file, and `fleet` opened an ssh session to every host, with no question asked and no record of who had agreed to it. A mistyped host name, a stale host list or an automation driving the tool with the wrong file reached hosts the operator was not authorized to touch. The README asked for authorization but the tool did not.

  What changed, in plain terms: both modes now need `--scope`, a list of the hosts, networks or domains you are authorized to check (a file or a comma-separated list; `app.example.com`, `*.example.com`, `203.0.113.7`, `203.0.113.0/24`, and single-label ssh aliases such as `web-01`). Before the first request the tool resolves every target, prints the scope, every target it would contact with its addresses, and every target that falls outside the scope, then waits for you to type `yes` on the terminal. Out-of-scope targets are refused, not warned about: nothing is sent to them, and they appear in the report as "not checked: outside --scope". For scripted runs `--yes` stands in for the typed word; it is accepted only together with `--scope`, is printed at the start of the run and is recorded in the report. The report (text and JSON) now opens with the scope, how the run was confirmed and the out-of-scope list, so a result cannot be read without seeing what was authorized.

  Technically: `phpcheck/scope.py` carries `Scope` (parsing and `covers(name, ips)`: by name, by `*.domain` suffix excluding the apex, or by every resolved address falling inside a listed network), `resolve_host`, `target_hostname` (URL, bare host, `user@host` and `ssh://` forms) and the terminal helpers `tty_available` and `read_tty_line`, which read `/dev/tty` and nothing else: stdin, environment variables and configuration files are not consulted, and argparse reads no environment variables for these options. The terminal is opened through a raw descriptor (`os.open`), not `open(path, "r+")`: a buffered read-write text file demands a seekable stream, a terminal is not one, and the resulting `io.UnsupportedOperation` is an `OSError`, so the `open` form reports "no terminal" on every real terminal. The gate was exercised on a pseudo-terminal: `yes` opens it, `no` or end of file refuses, and an out-of-scope-only run refuses without prompting. `cli.Gate` runs once per invocation, writes its listing to stderr so `--json > out.json` stays clean, and records the outcome in `model.RunInfo` (`scope`, `confirmation`, `out_of_scope`, `refused`). `remote` or `fleet` without `--scope`, `--yes` without `--scope`, an unparseable `--scope`, and a run with neither a terminal nor `--yes` exit with a usage error (code 2) before anything runs. A refused gate exits 2 and still writes the report with every target marked not checked. `local` and `image` are unchanged: they only touch this machine.

- **Control characters from a target never reach the terminal or a report as they are.**

  What was wrong: a response header such as `X-Powered-By: PHP/8.2.0<ESC>[2J`, a path or version string printed by a hostile host's shell in fleet mode, or an image's `php -v` output went straight into the table and the details. A target could clear the operator's screen, retitle the terminal window, hide text with a bidirectional override or forge a line of output.

  What changed: `scope.safe_text()` is applied at every point where target text enters the tool (response header names and values, redirect `Location` values, HTTP error text, every line of the inventory script's output, `php -v` output, docker and ssh stderr) and again to every string the text renderer prints. Line breaks and tabs become single spaces; every other control, format or separator character (C0 and C1 controls, DEL, bidirectional overrides and zero-width characters, lone surrogates, line and paragraph separators) is shown in escaped form, `\x1b` or `‮`, so it stays visible in the evidence but inert. Header values kept in a report are cut at 300 characters. JSON output was already escaped by `json.dumps`; the values inside it are now clean too.

- **image mode never pulls and runs the container locked down.**

  What was wrong: `docker run <image>` pulled the image from the registry when it was not present, which the README stated but which made a typo in an image name into a download of someone else's image, and the container ran as the image's default user (root in the official PHP images) with the default capability set and a writable filesystem.

  What changed: every `docker run` in image mode now passes `--pull=never` (an image that is not present locally is reported with the exact `docker pull` command to run yourself if you trust it), `--network none`, `--read-only` with a 16 MiB private `--tmpfs /tmp` for shells that need it, `--cap-drop ALL`, `--security-opt no-new-privileges`, and `--user 65534:65534`. If php cannot run as uid 65534 in a given image, the tool reruns once as the image's own default user and records that in the result's notes. Docker-level failures (missing image, daemon down, timeout) are not retried. The flags are in one place, `modes.docker_argv()`, and the tests check every run uses it.

### Changed
- Version 0.2.0. The `remote` and `fleet` command lines are not backward compatible: `--scope` is required.
- Text and JSON reports for `remote` and `fleet` carry `scope`, `confirmation`, `refused` and `out_of_scope`.
- `php -v` parsing accepts only version characters after `PHP `, so a control character ends the token instead of being carried into the version.
- docker and ssh error lines: the daemon's own error line is reported rather than the trailing "See 'docker run --help'" hint.

### Added
- `tests/test_scope.py` (safe text, scope entries and coverage, target host extraction, terminal helpers) and gate, image-hardening and control-character tests in the existing files. 145 tests, up from 83. The tests still block outbound connections; the gate tests also stand in for DNS resolution and the terminal.

### Docs
- SECURITY.md: contact is security@atarussecurity.com, two business days to acknowledge, pointer to https://atarussecurity.com/security/ and security.txt, what counts as a security bug in this tool, safe harbour.
- README: scope and confirmation rules, a per-mode table of what the tool sends over the network, the image hardening flags, corrected image-mode text (no pulls), updated samples and a Known issues section.

## 0.1.0 (2026-10-21)

First release.

- Checks for CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp). Fixed releases 8.5.12, 8.4.27, 8.3.36 and 8.2.35, verified against the php-src advisories. PHP 8.1 and older are reported as end-of-life-unfixed.
- Advisory table kept as data in `phpcheck/advisories.py`, one line per CVE.
- `local` mode: read-only inventory of PHP binaries, SAPIs, `libphp` modules, the settings named in the advisories, and FPM pool `pm.max_requests`.
- `remote` mode: passive HEAD and GET checks of `X-Powered-By`, `Server` and PHP session cookies, plus HEAD-only presence checks of common phpinfo paths with a soft-404 baseline. Rate limited.
- `image` mode: `docker run --rm --network none --entrypoint php <image> -v`, the settings probe, and an optional in-container inventory.
- `fleet` mode: the local inventory over `ssh -o BatchMode=yes`, aggregated across hosts.
- Table output by default, `--json`, `--explain`, `--fail-on-unknown`. Exit code 1 when anything is vulnerable or end of life.
- Handles release candidates, `-dev` builds and vendor version suffixes such as `-1~deb12u1`.
- Standard library only. Runs with `python3 -m phpcheck` on Python 3.9 and newer.
