"""Passive remote checks: ordinary HEAD and GET requests, headers only.

Nothing here sends a malformed, oversized or multipart request. Response
bodies are read up to a small cap and discarded. Version-leaking paths are
probed with HEAD only, so their content is never fetched.
"""

from __future__ import annotations

import http.client
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit

from . import __version__
from .model import Result, build_result
from .versions import assess

USER_AGENT = "atarus-phpcheck/%s (passive PHP version check)" % __version__
MAX_BODY = 64 * 1024
MAX_REDIRECTS = 3

# Paths whose mere presence is worth reporting. Probed with HEAD only.
LEAK_PATHS = ("/phpinfo.php", "/info.php", "/php_info.php", "/php-info.php")

# Cookie names that indicate PHP without revealing a version.
PHP_COOKIES = ("phpsessid", "laravel_session", "ci_session", "symfony", "cakephp")

NO_BANNER_NOTE = "Remote mode: absence of a PHP banner proves nothing. Banners are often removed (expose_php=Off) or rewritten by proxies."

_PHP_IN_HEADER_RE = re.compile(r"\bPHP/(\d[0-9A-Za-z.~+-]*)", re.I)
_PHP_BARE_RE = re.compile(r"\bPHP\b", re.I)


@dataclass
class HttpResponse:
    url: str
    method: str
    status: Optional[int] = None
    headers: List[Tuple[str, str]] = field(default_factory=list)
    error: Optional[str] = None


Fetcher = Callable[[str, str], HttpResponse]


def http_fetch(url: str, method: str, *, timeout: float = 10.0, insecure: bool = False,
               user_agent: str = USER_AGENT) -> HttpResponse:
    """One plain HTTP request. No redirects are followed here."""
    parts = urlsplit(url)
    res = HttpResponse(url=url, method=method)
    try:
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout, context=ctx)
        elif parts.scheme == "http":
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
        else:
            res.error = "unsupported scheme %r" % parts.scheme
            return res
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request(method, path, headers={"User-Agent": user_agent, "Accept": "*/*", "Connection": "close"})
        resp = conn.getresponse()
        res.status = resp.status
        res.headers = list(resp.getheaders())
        if method == "GET":
            resp.read(MAX_BODY)
        conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout, ValueError) as e:
        res.error = "%s: %s" % (type(e).__name__, e)
    return res


@dataclass
class HeaderAnalysis:
    versions: List[Tuple[str, str]] = field(default_factory=list)  # (version, where seen)
    php_present: bool = False
    evidence: List[str] = field(default_factory=list)


def analyze_headers(headers: Sequence[Tuple[str, str]]) -> HeaderAnalysis:
    """Look for PHP in X-Powered-By, Server and Set-Cookie."""
    out = HeaderAnalysis()
    for name, value in headers:
        lname = name.lower()
        if lname in ("x-powered-by", "server"):
            found = _PHP_IN_HEADER_RE.findall(value)
            for v in found:
                v = v.rstrip(".,;")
                out.versions.append((v, "%s: %s" % (name, value.strip())))
                out.php_present = True
            if not found and _PHP_BARE_RE.search(value):
                out.php_present = True
                out.evidence.append("%s mentions PHP without a version: %s" % (name, value.strip()))
            if lname == "server" and not found:
                out.evidence.append("Server: %s" % value.strip())
            elif found:
                out.evidence.append("%s: %s" % (name, value.strip()))
        elif lname == "set-cookie":
            cname = value.split("=", 1)[0].strip()
            if cname.lower() in PHP_COOKIES:
                out.php_present = True
                out.evidence.append("Set-Cookie %s (PHP session cookie, no version)" % cname)
    return out


def normalise_target(target: str) -> List[str]:
    """Return candidate base URLs. A bare host tries https first, then http."""
    t = target.strip()
    if "://" in t:
        return [t]
    return ["https://" + t, "http://" + t]


def _same_host(a: str, b: str) -> bool:
    return (urlsplit(a).hostname or "").lower() == (urlsplit(b).hostname or "").lower()


class Pacer:
    """Sequential rate limit: at least `delay` seconds between requests."""

    def __init__(self, delay: float, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.delay = max(0.0, delay)
        self.sleep = sleep
        self.clock = clock
        self._last: Optional[float] = None

    def wait(self) -> None:
        if self._last is not None and self.delay:
            remaining = self.delay - (self.clock() - self._last)
            if remaining > 0:
                self.sleep(remaining)
        self._last = self.clock()


def _request(fetch: Fetcher, pacer: Pacer, url: str, method: str, follow: bool,
             log: List[str]) -> HttpResponse:
    resp = HttpResponse(url=url, method=method)
    for _ in range(MAX_REDIRECTS + 1):
        pacer.wait()
        resp = fetch(url, method)
        if not follow or resp.status not in (301, 302, 303, 307, 308):
            return resp
        loc = next((v for k, v in resp.headers if k.lower() == "location"), None)
        if not loc:
            return resp
        nxt = urljoin(url, loc)
        if not _same_host(url, nxt):
            log.append("%s %s redirects to another host, not followed: %s" % (method, url, nxt))
            return resp
        url = nxt
    return resp


def check_target(target: str, fetch: Fetcher, pacer: Pacer, *, probe_paths: bool = True,
                 baseline_name: Optional[str] = None) -> Result:
    log: List[str] = []
    analysis = HeaderAnalysis()
    responses: List[HttpResponse] = []
    base = None
    errors = []
    for cand in normalise_target(target):
        head = _request(fetch, pacer, cand, "HEAD", True, log)
        if head.error and head.status is None:
            errors.append("%s: %s" % (cand, head.error))
            continue
        base = cand
        responses.append(head)
        responses.append(_request(fetch, pacer, cand, "GET", True, log))
        break

    result: Result
    if base is None:
        result = build_result(target, "remote", None, confidence="none")
        result.error = "; ".join(errors) or "no response"
        result.notes = ["host did not answer; nothing can be said about it"]
        return result

    findings: List[str] = []
    if probe_paths:
        origin = "%s://%s" % (urlsplit(base).scheme, urlsplit(base).netloc)
        name = baseline_name or "atarus-phpcheck-baseline-%s.php" % os.urandom(4).hex()
        baseline = _request(fetch, pacer, origin + "/" + name, "HEAD", False, log)
        responses.append(baseline)
        soft_404 = baseline.status == 200
        for p in LEAK_PATHS:
            r = _request(fetch, pacer, origin + p, "HEAD", False, log)
            responses.append(r)
            if r.status == 200:
                if soft_404:
                    findings.append("HEAD %s returned 200, but so does a random path: inconclusive" % p)
                else:
                    findings.append("HEAD %s returned 200: possible phpinfo page exposed (content not fetched); remove it" % p)

    seen_on: dict = {}
    answered = [r for r in responses if r.status is not None]
    for r in answered:
        a = analyze_headers(r.headers)
        analysis.versions.extend(a.versions)
        analysis.php_present = analysis.php_present or a.php_present
        for e in a.evidence:
            seen_on.setdefault(e, []).append("%s %s" % (r.method, urlsplit(r.url).path or "/"))
    for e, places in seen_on.items():
        where = places[0] if len(places) == 1 else "%s and %d more" % (places[0], len(places) - 1)
        analysis.evidence.append("%s [%s]" % (e, where))

    distinct = []
    for v, _ in analysis.versions:
        if v not in distinct:
            distinct.append(v)
    if distinct:
        # Report the version with the worst status if several are seen.
        order = {"end-of-life-unfixed": 0, "vulnerable": 1, "unknown": 2, "fixed": 3}
        chosen = sorted(distinct, key=lambda v: order.get(assess(v).status, 2))[0]
        a = assess(chosen)
        conf = "low" if (a.version and (a.version.is_vendor_build or a.version.patch is None)) else "medium"
        result = build_result(base, "remote", chosen, confidence=conf)
        result.notes.insert(0, "version taken from a response banner; banners can be stale, rewritten or spoofed")
        if len(distinct) > 1:
            result.notes.append("several PHP versions seen: %s" % ", ".join(distinct))
    else:
        result = build_result(base, "remote", None, confidence="low" if analysis.php_present else "none")
        result.notes = ["PHP indicated but no version exposed" if analysis.php_present else "no PHP indicator seen", NO_BANNER_NOTE]
    result.evidence = analysis.evidence
    result.findings = findings
    result.notes.extend(log)
    if answered:
        result.evidence.insert(0, "%d requests answered: %s" % (
            len(answered), ", ".join("%s %s %s" % (r.method, urlsplit(r.url).path or "/", r.status) for r in answered)))
    return result
