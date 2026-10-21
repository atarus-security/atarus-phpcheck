"""Command line entry point: phpcheck / python3 -m phpcheck."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .model import Result
from .report import render_explain, render_json, render_text
from .versions import UNKNOWN

DESCRIPTION = (
    "Detection and inventory for PHP core CVE-2026-109618 and CVE-2026-109619. "
    "Reads versions and settings only; never sends a malformed or oversized request."
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

    rp = sub.add_parser("remote", parents=[common], help="passive header check of URLs or hosts you are authorised to test")
    rp.add_argument("targets", nargs="+", help="URL, host, or a file with one per line")
    rp.add_argument("--delay", type=float, default=1.0, help="seconds between requests (default 1.0)")
    rp.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (default 10)")
    rp.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    rp.add_argument("--no-paths", action="store_true", help="skip the HEAD checks for phpinfo-style paths")

    ip = sub.add_parser("image", parents=[common], help="check Docker images")
    ip.add_argument("images", nargs="+", help="image references, or a file with one per line")
    ip.add_argument("--docker", default="docker", help="docker binary (default docker)")
    ip.add_argument("--php-only", action="store_true", help="only run php -v and the settings probe")
    ip.add_argument("--timeout", type=float, default=300.0, help="seconds per docker run (default 300)")

    fp = sub.add_parser("fleet", parents=[common], help="run the local checks over SSH")
    fp.add_argument("hosts", nargs="+", help="ssh hosts as in your ssh config, or a file with one per line")
    fp.add_argument("--ssh", default="ssh", help="ssh binary (default ssh)")
    fp.add_argument("--connect-timeout", type=int, default=10, help="ssh ConnectTimeout (default 10)")
    fp.add_argument("--timeout", type=float, default=180.0, help="seconds per host (default 180)")
    fp.add_argument("--parallel", type=int, default=4, help="hosts checked at once (default 4)")
    return p


def run_mode(args: argparse.Namespace) -> List[Result]:
    if args.mode == "local":
        from .modes import check_local
        return check_local(timeout=args.timeout)
    if args.mode == "remote":
        from .remote import Pacer, check_target, http_fetch
        pacer = Pacer(args.delay)

        def fetch(url: str, method: str):
            return http_fetch(url, method, timeout=args.timeout, insecure=args.insecure)

        return [check_target(t, fetch, pacer, probe_paths=not args.no_paths) for t in read_targets(args.targets)]
    if args.mode == "image":
        from .modes import check_image
        out: List[Result] = []
        for img in read_targets(args.images):
            out.extend(check_image(img, docker=args.docker, timeout=args.timeout, php_only=args.php_only))
        return out
    if args.mode == "fleet":
        from .modes import check_fleet
        return check_fleet(read_targets(args.hosts), ssh=args.ssh, connect_timeout=args.connect_timeout,
                           timeout=args.timeout, parallel=args.parallel)
    raise ValueError(args.mode)


def exit_code(results: Sequence[Result], fail_on_unknown: bool = False) -> int:
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
    try:
        results = run_mode(args)
    except ValueError as e:
        sys.stderr.write("phpcheck: %s\n" % e)
        return 2
    except KeyboardInterrupt:
        return 130
    if args.json:
        sys.stdout.write(render_json(results, args.mode, args.explain))
    else:
        sys.stdout.write(render_text(results, args.mode))
        if args.explain:
            sys.stdout.write("\n" + render_explain())
    return exit_code(results, args.fail_on_unknown)
