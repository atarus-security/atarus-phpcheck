"""Command line entry point: phpcheck / python3 -m phpcheck."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence, TextIO, Tuple

from . import __version__
from .model import Result, RunInfo, build_result
from .report import render_explain, render_json, render_text
from .scope import CONFIRM_WORD, Scope, read_tty_line, resolve_host, safe_text, target_hostname, tty_available
from .versions import UNKNOWN

DESCRIPTION = (
    "Detection and inventory for PHP core CVE-2026-109618 and CVE-2026-109619. "
    "Reads versions and settings only; never sends a malformed or oversized request. "
    "remote and fleet touch other hosts: they need --scope and the word yes typed on the terminal."
)

# Modes that touch hosts other than this machine. They need --scope and the gate.
SCOPED_MODES = ("remote", "fleet")

SCOPE_HELP = (
    "hosts, networks or domains you are authorized to check: a file with one entry per line, "
    "or a comma-separated list (app.example.com, *.example.com, 203.0.113.0/24). Required."
)
YES_HELP = (
    "stand in for the typed confirmation on non-interactive runs. "
    "Accepted only with --scope; its use is recorded in the report."
)


def read_targets(items: Sequence[str]) -> List[str]:
    """Each item is a target, or a file with one target per line (# comments allowed)."""
    out: List[str] = []
    for item in items:
        if os.path.isfile(item):
            with open(item, encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        out.append(line)
        else:
            out.append(item)
    seen = set()
    return [t for t in out if not (t in seen or seen.add(t))]


def build_parser() -> argparse.ArgumentParser:
    def options(sub_level: bool) -> argparse.ArgumentParser:
        # Subcommand copies use SUPPRESS so `phpcheck --json local` and
        # `phpcheck local --json` both work.
        d = {"default": argparse.SUPPRESS} if sub_level else {}
        c = argparse.ArgumentParser(add_help=False)
        c.add_argument("--json", action="store_true", help="machine-readable JSON output", **d)
        c.add_argument("--explain", action="store_true", help="also print fix versions, EOL note and mitigation checklist", **d)
        c.add_argument("--fail-on-unknown", action="store_true", help="exit 1 when any status is unknown", **d)
        return c

    common = options(True)
    p = argparse.ArgumentParser(prog="phpcheck", description=DESCRIPTION, parents=[options(False)])
    p.add_argument("--version", action="version", version="atarus-phpcheck " + __version__)
    sub = p.add_subparsers(dest="mode", metavar="MODE")

    lp = sub.add_parser("local", parents=[common], help="check PHP installs on this host")
    lp.add_argument("--timeout", type=float, default=120.0, help="seconds for the whole inventory (default 120)")

    rp = sub.add_parser("remote", parents=[common],
                        help="passive header check of URLs or hosts inside --scope, after a typed confirmation")
    rp.add_argument("targets", nargs="+", help="URL, host, or a file with one per line")
    rp.add_argument("--scope", dest="scope_spec", default="", help=SCOPE_HELP)
    rp.add_argument("--yes", dest="assume_yes", action="store_true", help=YES_HELP)
    rp.add_argument("--delay", type=float, default=1.0, help="seconds between requests (default 1.0)")
    rp.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (default 10)")
    rp.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    rp.add_argument("--no-paths", action="store_true", help="skip the HEAD checks for phpinfo-style paths")

    ip = sub.add_parser("image", parents=[common], help="check Docker images already present locally (never pulls)")
    ip.add_argument("images", nargs="+", help="image references, or a file with one per line")
    ip.add_argument("--docker", default="docker", help="docker binary (default docker)")
    ip.add_argument("--php-only", action="store_true", help="only run php -v and the settings probe")
    ip.add_argument("--timeout", type=float, default=300.0, help="seconds per docker run (default 300)")

    fp = sub.add_parser("fleet", parents=[common],
                        help="run the local checks over SSH on hosts inside --scope, after a typed confirmation")
    fp.add_argument("hosts", nargs="+", help="ssh hosts as in your ssh config, or a file with one per line")
    fp.add_argument("--scope", dest="scope_spec", default="", help=SCOPE_HELP)
    fp.add_argument("--yes", dest="assume_yes", action="store_true", help=YES_HELP)
    fp.add_argument("--ssh", default="ssh", help="ssh binary (default ssh)")
    fp.add_argument("--connect-timeout", type=int, default=10, help="ssh ConnectTimeout (default 10)")
    fp.add_argument("--timeout", type=float, default=180.0, help="seconds per host (default 180)")
    fp.add_argument("--parallel", type=int, default=4, help="hosts checked at once (default 4)")
    return p


class Gate:
    """The confirmation gate for remote and fleet. Runs once, before the first
    packet to any target.

    Resolves every target, splits them into in scope and out of scope against
    --scope, prints the exact scope and every host that would be contacted,
    then waits for the word "yes" typed on the terminal. --yes (assume_yes)
    stands in for the typed word on non-interactive runs and is recorded in
    the result. No environment variable or configuration file is read.
    Out-of-scope targets are refused: nothing is sent to them, and they are
    listed in the report.
    """

    VERB = {"remote": "send requests to", "fleet": "open SSH sessions to"}

    def __init__(self, mode: str, scope: Scope, assume_yes: bool = False,
                 err: Optional[TextIO] = None, resolver=None, ask=None):
        self.mode = mode
        self.scope = scope
        self.assume_yes = bool(assume_yes)
        self.err = err if err is not None else sys.stderr
        # Looked up at construction, not at import, so a test can stand in for
        # the resolver and the terminal without touching the real ones.
        self.resolver = resolver if resolver is not None else resolve_host
        self.ask = ask if ask is not None else read_tty_line
        self.in_scope: List[str] = []
        self.run = RunInfo(scope=list(scope.entries))
        self.reason = ""

    def split(self, targets: Sequence[str]) -> None:
        self.in_scope = []
        self.run.out_of_scope = []
        for t in targets:
            host = target_hostname(t)
            ips = self.resolver(host) if host else []
            if host and self.scope.covers(host, ips):
                self.in_scope.append(t)
            else:
                self.run.out_of_scope.append({"target": t, "host": host, "ips": list(ips)})

    def confirm(self, targets: Sequence[str]) -> bool:
        self.split(targets)
        w = self.err.write
        w("%s checks requested\n" % self.mode.capitalize())
        w("  Scope: %s\n" % self.scope.describe())
        if self.in_scope:
            w("  Targets to check (%d):\n" % len(self.in_scope))
            for t in self.in_scope:
                host = target_hostname(t)
                ips = self.resolver(host) if host else []
                w("    %s -> %s (%s)\n" % (safe_text(t), safe_text(host), ", ".join(ips) or "listed by name, not resolved"))
        else:
            w("  Targets to check: none\n")
        if self.run.out_of_scope:
            w("  Out of scope, not checked (%d):\n" % len(self.run.out_of_scope))
            for item in self.run.out_of_scope:
                w("    %s -> %s (%s)\n" % (safe_text(item["target"]), safe_text(item["host"]),
                                           ", ".join(item["ips"]) or "did not resolve"))
        w("\n")

        if not self.in_scope:
            self.reason = "no target inside --scope"
            return False

        if self.assume_yes:
            self.run.confirmation = "--yes flag (no terminal confirmation)"
            w("Confirmation taken from --yes; recorded in the report.\n\n")
            return True

        prompt = "Type %s to %s the %d target(s) listed above (scope: %s): " % (
            CONFIRM_WORD, self.VERB.get(self.mode, "contact"), len(self.in_scope), self.scope.describe())
        answer = self.ask(prompt)
        if answer is None:
            self.reason = "no terminal to confirm on; pass --yes with --scope for non-interactive runs"
            return False
        if answer.lower() != CONFIRM_WORD:
            self.reason = "confirmation not given on the terminal"
            return False
        self.run.confirmation = "typed %s on the terminal" % CONFIRM_WORD
        w("\n")
        return True


def _not_checked(target: str, mode: str, reason: str) -> Result:
    r = build_result(target, mode, None, confidence="none")
    r.error = "not checked: %s" % reason
    r.notes = ["nothing was sent to this target"]
    return r


def run_scoped(args: argparse.Namespace, targets: Sequence[str], gate: Gate) -> Tuple[List[Result], RunInfo]:
    """remote and fleet: the gate first, then the checks on in-scope targets only."""
    opened = gate.confirm(targets)
    results: List[Result] = []
    if not opened:
        gate.run.refused = gate.reason
        sys.stderr.write("phpcheck: nothing was checked: %s\n" % gate.reason)
        for t in targets:
            results.append(_not_checked(t, args.mode, gate.reason))
        return results, gate.run

    if args.mode == "remote":
        from .remote import Pacer, check_target, http_fetch
        pacer = Pacer(args.delay)

        def fetch(url: str, method: str):
            return http_fetch(url, method, timeout=args.timeout, insecure=args.insecure)

        results = [check_target(t, fetch, pacer, probe_paths=not args.no_paths) for t in gate.in_scope]
    else:
        from .modes import check_fleet
        results = check_fleet(gate.in_scope, ssh=args.ssh, connect_timeout=args.connect_timeout,
                              timeout=args.timeout, parallel=args.parallel)
    for item in gate.run.out_of_scope:
        where = ", ".join(item["ips"]) if item["ips"] else "did not resolve"
        results.append(_not_checked(item["target"], args.mode, "outside --scope (%s: %s)" % (item["host"] or "no host", where)))
    return results, gate.run


def run_mode(args: argparse.Namespace, gate: Optional[Gate] = None) -> Tuple[List[Result], Optional[RunInfo]]:
    if args.mode == "local":
        from .modes import check_local
        return check_local(timeout=args.timeout), None
    if args.mode == "image":
        from .modes import check_image
        out: List[Result] = []
        for img in read_targets(args.images):
            out.extend(check_image(img, docker=args.docker, timeout=args.timeout, php_only=args.php_only))
        return out, None
    if args.mode in SCOPED_MODES:
        if gate is None:
            raise ValueError("%s needs a confirmation gate" % args.mode)
        items = args.targets if args.mode == "remote" else args.hosts
        return run_scoped(args, read_targets(items), gate)
    raise ValueError(args.mode)


def exit_code(results: Sequence[Result], fail_on_unknown: bool = False, run: Optional[RunInfo] = None) -> int:
    if run is not None and run.refused:
        return 2
    if any(r.failing for r in results):
        return 1
    if fail_on_unknown and any(r.status == UNKNOWN for r in results):
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.mode:
        if args.explain:
            sys.stdout.write(render_json([], "explain", True) if args.json else render_explain())
            return 0
        parser.print_help()
        return 2

    gate = None
    if args.mode in SCOPED_MODES:
        # The gate rules. A flag alone never opens it: --yes needs --scope, and
        # the mode needs --scope plus either a terminal or --yes. argparse reads
        # no environment variables for these options and there is no config file.
        if args.assume_yes and not args.scope_spec:
            parser.error("--yes is only accepted together with --scope")
        if not args.scope_spec:
            parser.error("%s requires --scope: a file or comma-separated list of the hosts, "
                         "networks or domains you are authorized to check" % args.mode)
        try:
            scope = Scope.from_option(args.scope_spec)
        except (ValueError, OSError) as e:
            parser.error("--scope: %s" % e)
        if not args.assume_yes and not tty_available():
            parser.error("%s needs a terminal to type the confirmation on; run interactively, "
                         "or pass --yes together with --scope for a non-interactive run" % args.mode)
        if args.assume_yes:
            sys.stderr.write("--yes given: the terminal confirmation will be skipped and this is recorded in the report.\n")
        gate = Gate(args.mode, scope, assume_yes=args.assume_yes)

    try:
        results, run = run_mode(args, gate)
    except ValueError as e:
        sys.stderr.write("phpcheck: %s\n" % safe_text(e))
        return 2
    except KeyboardInterrupt:
        return 130
    if args.json:
        sys.stdout.write(render_json(results, args.mode, args.explain, run=run))
    else:
        sys.stdout.write(render_text(results, args.mode, run=run))
        if args.explain:
            sys.stdout.write("\n" + render_explain())
    return exit_code(results, args.fail_on_unknown, run)
