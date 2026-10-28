"""local, image and fleet modes. Each runs read-only commands only."""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Sequence, Tuple

from .collector import SCRIPT, parse_output, results_from_inventory, version_from_php_v
from .model import NOT_FOUND, Result, build_result
from .scope import safe_text
from .settings import PROBE_PHP, parse_probe, sapi_kind

Runner = Callable[[Sequence[str], Optional[str], float], Tuple[int, str, str]]

# image mode: the uid:gid a container runs as when the image itself does not
# say otherwise. 65534 is "nobody" on every common base image.
CONTAINER_USER = "65534:65534"

# Exit codes that mean docker itself failed (125: daemon or CLI error, such as
# a missing image; 124: our own timeout; 127: the docker binary was not found).
# Rerunning as another user cannot help with these.
_DOCKER_LEVEL_RC = (124, 125, 127)


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
    """The most useful line of a command's stderr, made safe to print.
    docker prints its own error first and a 'See docker run --help' hint last,
    so a daemon error line wins over the last line."""
    lines = [l for l in (text or "").strip().splitlines() if l.strip()]
    if not lines:
        return ""
    for l in lines:
        if "Error response from daemon" in l or l.startswith("docker: "):
            return safe_text(l, 200)
    return safe_text(lines[-1], 200)


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


def docker_argv(docker: str = "docker", user: Optional[str] = CONTAINER_USER) -> List[str]:
    """The fixed part of every `docker run` in image mode.

    --pull=never      the image must already be present; the tool never pulls
    --network none    nothing inside the container can reach the network
    --read-only       the image filesystem cannot be written; /tmp is a small
                      private tmpfs because some shells need it for here-documents
    --cap-drop ALL    no capabilities, and no-new-privileges so setuid binaries
                      cannot regain any
    --user            run as nobody (65534) unless the image cannot run php that way
    """
    argv = [docker, "run", "--rm", "--pull=never", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if user:
        argv += ["--user", user]
    return argv


def _image_error(image: str, err: str, out: str, rc: int) -> str:
    line = _last_line(err or out) or "rc=%d" % rc
    if "No such image" in line or "not found locally" in line or "pull access denied" in line:
        return ("image is not present locally and the tool never pulls (--pull=never); "
                "run `docker pull %s` yourself if you trust it, then rerun. docker said: %s" % (image, line))
    return "php -v failed in image: %s" % line


def check_image(image: str, runner: Runner = run_command, docker: str = "docker",
                timeout: float = 300.0, php_only: bool = False) -> List[Result]:
    _validate_name(image, "image name")
    user: Optional[str] = CONTAINER_USER
    base = docker_argv(docker, user)
    rc, vout, verr = runner(base + ["--entrypoint", "php", image, "-v"], None, timeout)
    version = version_from_php_v(vout)
    user_notes: List[str] = []
    if version is None and rc not in _DOCKER_LEVEL_RC:
        # The image may not let uid 65534 run php (unusual, but a locked-down
        # image can do it). One retry as the image's own default user, recorded.
        user = None
        base = docker_argv(docker, user)
        rc_nobody, err_nobody = rc, _last_line(verr or vout)
        rc, vout, verr = runner(base + ["--entrypoint", "php", image, "-v"], None, timeout)
        version = version_from_php_v(vout)
        if version is not None:
            user_notes.append("php could not run as uid %s (rc=%d%s); reran as the image's default user"
                              % (CONTAINER_USER.split(":")[0], rc_nobody, ": " + err_nobody if err_nobody else ""))
    results: List[Result] = []
    if version is None:
        r = build_result(image, "image", None)
        r.error = _image_error(image, verr, vout, rc)
        results.append(r)
    else:
        rc2, pout, perr = runner(base + ["--entrypoint", "php", image, "-r", PROBE_PHP], None, timeout)
        data = parse_probe(pout)
        notes = list(user_notes)
        if not data.settings:
            notes.append("settings probe failed: %s" % (_last_line(perr) or "rc=%d" % rc2))
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
        # ssh's stderr can carry the remote side's banner, so it is made safe like any target text.
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
