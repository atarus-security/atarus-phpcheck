"""local, image and fleet modes. Each runs read-only commands only."""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Sequence, Tuple

from .collector import SCRIPT, parse_output, results_from_inventory, version_from_php_v
from .model import NOT_FOUND, Result, build_result
from .settings import PROBE_PHP, parse_probe, sapi_kind

Runner = Callable[[Sequence[str], Optional[str], float], Tuple[int, str, str]]


def run_command(argv: Sequence[str], input_text: Optional[str] = None, timeout: float = 120.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(list(argv), input=input_text, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s: command not found" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout


def _last_line(text: str) -> str:
    lines = [l for l in (text or "").strip().splitlines() if l.strip()]
    return lines[-1][:200] if lines else ""


def check_local(runner: Runner = run_command, timeout: float = 120.0) -> List[Result]:
    rc, out, err = runner(["sh", "-s"], SCRIPT, timeout)
    if "@@PHPCHECK" not in out:
        r = build_result("localhost", "local", None)
        r.error = "inventory script failed: %s" % (_last_line(err) or "rc=%d" % rc)
        return [r]
    inv = parse_output(out)
    results = results_from_inventory(inv, "localhost", "local")
    if not results:
        r = build_result("localhost", "local", None)
        r.status = NOT_FOUND
        r.notes = ["no PHP binaries or modules found in the usual locations"]
        results = [r]
    if not inv.complete:
        for r in results:
            r.notes.append("inventory did not finish; results may be partial")
    return results


def _validate_name(value: str, what: str) -> None:
    if not value or value.startswith("-") or any(c in value for c in "\n\r\0"):
        raise ValueError("refusing %s %r" % (what, value))


def check_image(image: str, runner: Runner = run_command, docker: str = "docker",
                timeout: float = 300.0, php_only: bool = False) -> List[Result]:
    _validate_name(image, "image name")
    base = [docker, "run", "--rm", "--network", "none"]
    rc, vout, verr = runner(base + ["--entrypoint", "php", image, "-v"], None, timeout)
    version = version_from_php_v(vout)
    results: List[Result] = []
    if version is None:
        r = build_result(image, "image", None)
        r.error = "php -v failed in image: %s" % (_last_line(verr or vout) or "rc=%d" % rc)
        results.append(r)
    else:
        rc2, pout, perr = runner(base + ["--entrypoint", "php", image, "-r", PROBE_PHP], None, timeout)
        data = parse_probe(pout)
        notes = [] if data.settings else ["settings probe failed: %s" % (_last_line(perr) or "rc=%d" % rc2)]
        results.append(build_result(image, "image", version, sapi=sapi_kind(data.sapi, "cli"),
                                    path="php (entrypoint override)", settings=data.settings, notes=notes))
    if php_only:
        return results
    rc3, sout, _ = runner(base + ["-i", "--entrypoint", "sh", image, "-s"], SCRIPT, timeout)
    if "@@PHPCHECK" not in sout:
        if results and not results[0].error:
            results[0].notes.append("image has no usable sh; FPM and Apache module checks skipped")
        return results
    for r in results_from_inventory(parse_output(sout), image, "image"):
        if r.sapi == "cli" and version is not None and r.version == version:
            continue  # same php as the entrypoint run
        results.append(r)
    return results


def ssh_argv(host: str, ssh: str = "ssh", connect_timeout: int = 10) -> List[str]:
    _validate_name(host, "host")
    return [ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % connect_timeout, "-T", "--", host, "sh -s"]


def check_fleet_host(host: str, runner: Runner = run_command, ssh: str = "ssh",
                     connect_timeout: int = 10, timeout: float = 180.0) -> List[Result]:
    rc, out, err = runner(ssh_argv(host, ssh, connect_timeout), SCRIPT, timeout)
    if "@@PHPCHECK" not in out:
        r = build_result(host, "fleet", None)
        r.error = "ssh failed: %s" % (_last_line(err) or "rc=%d" % rc)
        return [r]
    inv = parse_output(out)
    results = results_from_inventory(inv, host, "fleet")
    if not results:
        r = build_result(host, "fleet", None)
        r.status = NOT_FOUND
        r.notes = ["no PHP binaries or modules found in the usual locations"]
        results = [r]
    if not inv.complete:
        for r in results:
            r.notes.append("inventory did not finish; results may be partial")
    return results


def check_fleet(hosts: Sequence[str], runner: Runner = run_command, ssh: str = "ssh",
                connect_timeout: int = 10, timeout: float = 180.0, parallel: int = 4) -> List[Result]:
    def one(h: str) -> List[Result]:
        return check_fleet_host(h, runner, ssh, connect_timeout, timeout)

    with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
        batches = list(ex.map(one, hosts))
    return [r for b in batches for r in b]
